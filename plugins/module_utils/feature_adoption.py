# -*- coding: utf-8 -*-
# Copyright: (c) 2025, CyberArk Business Development
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Feature Adoption Service (FAS) usage reporting for the CyberArk ISP collection.

Mirrors the reporting done by the idsec SDK / CLI: after a module finishes
successfully, a single event is POSTed to the FAS ``/api/feature-adoption``
endpoint, authenticated with the same platform token the module already uses.

Reporting is strictly best effort. Every failure is swallowed so that usage
reporting can never fail or noticeably slow down a task.

Opt out by setting ``IDSEC_DISABLE_TELEMETRY_COLLECTION`` to any non-empty
value in the module environment, for example with the task keyword::

    environment:
      IDSEC_DISABLE_TELEMETRY_COLLECTION: "true"
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import time

from ansible.module_utils.six.moves.urllib.parse import urlparse
from ansible.module_utils.urls import open_url

# Metric key format: <service_code>.<master_feature_name>.<metric_name>.
# The FAS rejects events for keys that are not enrolled in the Developer Portal.
ADOPTION_SERVICE_CODE = "IDIINT"
ADOPTION_FEATURE_NAME = "ansible_isp_collection"
ADOPTION_METRIC_NAME = "integration_executed"
METRIC_KEY = "{0}.{1}.{2}".format(ADOPTION_SERVICE_CODE, ADOPTION_FEATURE_NAME, ADOPTION_METRIC_NAME)

# Keep in sync with ``version`` in galaxy.yml.
COLLECTION_VERSION = "1.0.9"

FAS_PATH = "/api/feature-adoption"
FAS_HOST_PREFIX = "us-east-1-featureadopt.featureadopt"
FAS_TIMEOUT_SECONDS = 5
TRIGGERED_BY_BACKEND = "BE"

DISABLE_ENV_VAR = "IDSEC_DISABLE_TELEMETRY_COLLECTION"
FAS_BASE_URL_ENV_VAR = "FAS_BASE_URL"

# Service labels that may precede the root domain in a tenant URL, for example
# ``tenant.id.cyberark.cloud`` or ``tenant.privilegecloud.cyberark.cloud``.
_TENANT_SERVICE_LABELS = (".id.", ".privilegecloud.")


def get_fas_url(api_base_url):
    """Return the FAS endpoint URL, or an empty string when it cannot be determined.

    ``FAS_BASE_URL`` takes precedence. Otherwise the root domain is taken from the
    tenant host in ``api_base_url``; vanity URLs without a known service label
    are skipped rather than guessed.
    """
    override = os.environ.get(FAS_BASE_URL_ENV_VAR)
    if override:
        return override.rstrip("/") + FAS_PATH

    host = urlparse(api_base_url or "").hostname or ""
    for label in _TENANT_SERVICE_LABELS:
        _, separator, root_domain = host.partition(label)
        if separator and root_domain:
            return "https://{0}.{1}{2}".format(FAS_HOST_PREFIX, root_domain, FAS_PATH)
    return ""


def build_event(module_name, state, changed, duration_ms, status="success"):
    """Build the FAS event body. Tag keys must be snake_case alphanumeric strings."""
    tags = {
        "tool": "ansible",
        "collection_version": COLLECTION_VERSION,
        "module": module_name,
    }
    if state:
        tags["state"] = str(state)

    return {
        "metric_key": METRIC_KEY,
        "number_of_events": 1,
        "triggered_by": TRIGGERED_BY_BACKEND,
        "tags": tags,
        "custom_data": {
            "duration": str(int(duration_ms)),
            "ops": status,
            "changed": str(bool(changed)).lower(),
        },
    }


def start_timer():
    """Return a start marker to pass as ``started_at`` to :func:`report_adoption`."""
    return time.monotonic()


def _access_token(session):
    if isinstance(session, dict):
        return session.get("access_token") or ""
    return ""


def report_adoption(module, module_name, started_at, changed=False, session=None):
    """Report one successful module execution to the Feature Adoption Service.

    Args:
        module: The AnsibleModule instance (used for parameters and debug logging).
        module_name: Short module name used as a tag, e.g. ``cyberark_safe``.
        started_at: ``time.monotonic()`` value captured at the start of ``main()``.
        changed: Whether the module reported a change.
        session: The platform-token session dict holding ``access_token``. Defaults
            to the module's ``cyberark_session`` parameter.

    Returns:
        bool: True when an event was accepted by the service, otherwise False.
    """
    try:
        if os.environ.get(DISABLE_ENV_VAR) or module.check_mode:
            return False

        if session is None:
            session = module.params.get("cyberark_session")
        token = _access_token(session)
        if not token:
            return False

        url = get_fas_url(module.params.get("api_base_url"))
        if not url:
            return False

        event = build_event(
            module_name,
            module.params.get("state"),
            changed,
            (time.monotonic() - started_at) * 1000,
        )
        response = open_url(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer {0}".format(token),
            },
            data=json.dumps(event),
            validate_certs=module.params.get("validate_certs", True),
            timeout=FAS_TIMEOUT_SECONDS,
        )
        return response.getcode() in (200, 202)
    except Exception:  # noqa: BLE001 - reporting must never affect the task
        return False
