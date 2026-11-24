# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from unittest import mock

import pytest

from ansible_collections.cyberark.isp.plugins.module_utils import feature_adoption as fa

TOKEN = {"access_token": "jwt-token", "token_type": "Bearer", "expires_in": 3600}


class FakeModule:
    def __init__(self, check_mode=False, **params):
        self.check_mode = check_mode
        self.params = {
            "api_base_url": "https://tenant.privilegecloud.cyberark.cloud",
            "cyberark_session": TOKEN,
            "validate_certs": True,
            "state": "present",
        }
        self.params.update(params)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv(fa.DISABLE_ENV_VAR, raising=False)
    monkeypatch.delenv(fa.FAS_BASE_URL_ENV_VAR, raising=False)


@pytest.mark.parametrize(
    "base_url, expected",
    [
        ("https://tenant.id.cyberark.cloud", "https://us-east-1-featureadopt.featureadopt.cyberark.cloud/api/feature-adoption"),
        ("https://tenant.privilegecloud.cyberark.cloud/", "https://us-east-1-featureadopt.featureadopt.cyberark.cloud/api/feature-adoption"),
        ("https://tenant.privilegecloud.integration-cyberark.cloud", "https://us-east-1-featureadopt.featureadopt.integration-cyberark.cloud/api/feature-adoption"),
        ("https://vault.example.com", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_get_fas_url(base_url, expected):
    assert fa.get_fas_url(base_url) == expected


def test_get_fas_url_env_override(monkeypatch):
    monkeypatch.setenv(fa.FAS_BASE_URL_ENV_VAR, "http://localhost:9000/")
    assert fa.get_fas_url("https://vault.example.com") == "http://localhost:9000/api/feature-adoption"


def test_report_sends_expected_request():
    response = mock.Mock()
    response.getcode.return_value = 202
    with mock.patch.object(fa, "open_url", return_value=response) as open_url:
        assert fa.report_adoption(FakeModule(), "cyberark_safe", fa.start_timer(), changed=True) is True

    args, kwargs = open_url.call_args
    assert args[0] == "https://us-east-1-featureadopt.featureadopt.cyberark.cloud/api/feature-adoption"
    assert kwargs["method"] == "POST"
    assert kwargs["headers"]["Authorization"] == "Bearer jwt-token"
    assert kwargs["timeout"] == fa.FAS_TIMEOUT_SECONDS
    body = json.loads(kwargs["data"])
    assert body["metric_key"] == fa.METRIC_KEY
    assert body["number_of_events"] == 1
    assert body["triggered_by"] == "BE"
    assert body["tags"]["module"] == "cyberark_safe"
    assert body["tags"]["state"] == "present"
    assert body["custom_data"]["changed"] == "true"
    assert "user_id" not in body


def test_tag_keys_are_fas_compatible():
    import re
    event = fa.build_event("cyberark_safe", "present", False, 12.4)
    assert all(re.match(r"^[a-zA-Z0-9_]+$", k) for k in event["tags"])
    assert all(isinstance(v, str) for v in event["tags"].values())


def test_explicit_session_overrides_param():
    response = mock.Mock()
    response.getcode.return_value = 202
    module = FakeModule(cyberark_session=None)
    with mock.patch.object(fa, "open_url", return_value=response) as open_url:
        assert fa.report_adoption(module, "cyberark_authentication", fa.start_timer(), session=TOKEN)
    assert open_url.call_args[1]["headers"]["Authorization"] == "Bearer jwt-token"


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv(fa.DISABLE_ENV_VAR, "true")
    with mock.patch.object(fa, "open_url") as open_url:
        assert fa.report_adoption(FakeModule(), "cyberark_safe", fa.start_timer()) is False
    open_url.assert_not_called()


@pytest.mark.parametrize(
    "module",
    [
        FakeModule(check_mode=True),
        FakeModule(cyberark_session={}),
        FakeModule(cyberark_session="not-a-dict"),
        FakeModule(cyberark_session={"access_token": ""}),
        FakeModule(api_base_url="https://vault.example.com"),
    ],
)
def test_skipped_without_prerequisites(module):
    with mock.patch.object(fa, "open_url") as open_url:
        assert fa.report_adoption(module, "cyberark_safe", fa.start_timer()) is False
    open_url.assert_not_called()


@pytest.mark.parametrize("exc", [OSError("boom"), ValueError("bad"), TimeoutError()])
def test_failures_never_propagate(exc):
    with mock.patch.object(fa, "open_url", side_effect=exc):
        assert fa.report_adoption(FakeModule(), "cyberark_safe", fa.start_timer()) is False


def test_non_accepted_status_returns_false():
    response = mock.Mock()
    response.getcode.return_value = 500
    with mock.patch.object(fa, "open_url", return_value=response):
        assert fa.report_adoption(FakeModule(), "cyberark_safe", fa.start_timer()) is False
