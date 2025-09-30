#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)


__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: cyberark_safe
short_description: CyberArk Safe Management using Privilege Cloud Shared Services REST APIs.
author:
  - Edward Nunez (@enunez-cyberark)
  - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - CyberArk Safe Management using Privilege Cloud Shared Services REST APIs.
      It currently supports the following actions Get Safe Details, Add Safe,
      Update Safe, Delete Safe.

options:
    api_base_url:
        description:
            - A string containing the base URL of the server hosting
              CyberArk's Privileged Cloud ISP SDK.
        type: str
        required: true
    safe_name:
        description:
            - The unique name of the Safe.
        type: str
        required: true
    state:
        description:
            - Specifies the state needed for the user present for create user,
              absent for delete user.
        type: str
        choices: [absent, present]
        default: present
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output to
              the C(logging_file) value.
        required: false
        choices: [NOTSET, DEBUG, INFO]
        type: str
    logging_file:
        description:
            - Setting the log file name and location for troubleshooting logs.
        required: false
        default: /tmp/ansible_cyberark.log
        type: str
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the
              different values to perform actions on a logged-on CyberArk
              session. Please see M(cyberark.isp.cyberark_authentication) module for an
              example of cyberark_session.
        type: dict
        required: true
    description:
        description:
            - The description of the Safe.
        type: str
    location:
        description:
            - The location of the Safe in the Vault.
        type: str
    managing_cpm:
        description:
            - The name of the CPM user who will manage the new Safe.
        type: str
    number_of_versions_retention:
        description:
            - The number of retained versions of every password that is stored in the Safe.
        type: int
    number_of_days_retention:
        description:
            - The number of days that password versions are saved in the Safe.
        type: int
    auto_purge_enabled:
        description:
            - Whether or not to automatically purge files after the end of the Object History
              Retention Period defined in the Safe properties.
        type: bool
        default: false
    timeout:
        description:
            - How long to wait for the server to send data before giving up.
        type: float
        default: 10
"""

EXAMPLES = r"""
- name: Safe
  cyberark.isp.cyberark_safe:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    description: "Safe for Partner EdwardTest"
    logging_level: DEBUG
    safe_name: "Partner-Test"
    number_of_days_retention: 7
    state: present
    cyberark_session: '{{ cyberark_session }}'
    register: cyberark_result
"""

RETURN = r"""
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
cyberark_safe:
    description: Dictionary containing result properties.
    returned: always
    type: complex
    contains:
        result:
            description: Safe properties.
            type: dict
            returned: success
status_code:
    description: Result HTTP Status code.
    returned: success
    type: int
    sample: 200
"""

import json
import base64

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.six.moves import http_client as httplib
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import quote
import logging


def construct_url(api_base_url, end_point):
    return "{baseurl}/{endpoint}".format(baseurl=api_base_url.rstrip("/"), endpoint=end_point.lstrip("/"))


def telemetryHeaders(session=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.isp)",
        "x-cybr-telemetry": base64.b64encode(
            b'in=Ansible ISP Collection&iv=1.0&vn=Red Hat&it=Identity Automation and workflows').decode("utf-8")
    }

    if session is not None:
        headers["Authorization"] = "Bearer " + session["access_token"]
    return headers


def safe_details(module):
    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    safe_name = module.params["safe_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, end_point, and headers
    result = {}

    end_point = "/PasswordVault/api/Safes/{psafename}".format(psafename=quote(safe_name))
    url = construct_url(api_base_url, end_point)

    headers = telemetryHeaders(cyberark_session)
    logging.info(headers)

    try:
        response = open_url(
            url,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )
        result = {"result": json.loads(response.read())}
        return False, result, response.getcode()

    except (HTTPError, httplib.HTTPException) as http_exception:
        if http_exception.code == 404:
            return False, None, http_exception.code
        else:
            module.fail_json(
                msg=(
                    "Error while performing safe_details."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, to_text(http_exception))
                ),
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:
        module.fail_json(
            msg=(
                "Unknown error while performing safe_details."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def safe_add_or_update(module, HTTPMethod, existing_info):
    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    safe_name = module.params["safe_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, paylod, and headers
    result = {}
    payload = {"safeName": safe_name}
    end_point = ""
    headers = telemetryHeaders(cyberark_session)

    # end_point and payload sets different depending on POST/PUT
    # for POST -- create -- payload contains safename
    # for PUT -- update -- safename is part of the endpoint
    if HTTPMethod == "POST":
        end_point = "PasswordVault/api/Safes"
    elif HTTPMethod == "PUT":
        end_point = "PasswordVault/api/Safes/{psafename}".format(psafename=quote(safe_name))

    # --- Optionally populate payload based on parameters passed ---
    if "description" in module.params and module.params["description"] is not None:
        payload["description"] = module.params["description"]

    if "location" in module.params and module.params["location"] is not None:
        payload["Location"] = module.params["location"]

    if "managing_cpm" in module.params and module.params["managing_cpm"] is not None:
        payload["managingCPM"] = module.params["managing_cpm"]

    if "number_of_versions_retention" in module.params and module.params["number_of_versions_retention"] is not None:
        payload["numberOfVersionsRetention"] = module.params["number_of_versions_retention"]

    if "number_of_days_retention" in module.params and module.params["number_of_days_retention"] is not None:
        payload["numberOfDaysRetention"] = module.params["number_of_days_retention"]

    if ("number_of_versions_retention" in module.params and module.params["number_of_versions_retention"] is None and
       "number_of_days_retention" in module.params and module.params["number_of_days_retention"] is None):
        payload["numberOfDaysRetention"] = 7

    if "auto_purge_enabled" in module.params and module.params["auto_purge_enabled"] is not None:
        payload["AutoPurgeEnabled"] = module.params["auto_purge_enabled"]

    # --------------------------------------------------------------
    if HTTPMethod == "PUT":
        logging.info("Verifying if needs to be updated")
        proceed = False
        updateable_fields = [
            "description",
            "location",
            "managingCPM",
            "numberOfVersionsRetention",
            "numberOfDaysRetention",
        ]
        for field_name in updateable_fields:
            if (
                    field_name in payload
                    and field_name in existing_info
                    and payload[field_name] != existing_info[field_name]
            ):
                logging.info("Changing value for %s", field_name)
                proceed = True
                break

    else:
        proceed = True

    if proceed:
        logging.info("Proceeding to either update or create")
        url = construct_url(api_base_url, end_point)
        try:
            # execute REST action
            response = open_url(
                url,
                method=HTTPMethod,
                headers=headers,
                data=json.dumps(payload),
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )

            result = {"result": json.loads(response.read())}

            return True, result, response.getcode()

        except (HTTPError, httplib.HTTPException) as http_exception:
            exception_body = http_exception.read().decode("utf-8")
            logging.info("response: %s", exception_body)
            module.fail_json(
                msg=(
                    "Error while performing safe_add_or_update."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, to_text(http_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=http_exception.code,
                exception_body=exception_body
            )
        except Exception as unknown_exception:
            module.fail_json(
                msg=(
                    "Unknown error while performing safe_add_or_update."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=-1,
            )
    else:
        return False, existing_info, 200


def safe_delete(module):
    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    safe_name = module.params["safe_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]

    # Prepare result, end_point, and headers
    result = {}

    end_point = "PasswordVault/api/Safes/{psafename}".format(psafename=quote(safe_name))
    headers = telemetryHeaders(cyberark_session)
    url = construct_url(api_base_url, end_point)

    try:
        # execute REST action
        response = open_url(
            url,
            method="DELETE",
            headers=headers,
            # validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return True, result, response.getcode()

    except (HTTPError, httplib.HTTPException) as http_exception:
        exception_text = to_text(http_exception)
        if http_exception.code == 404 and "ITATS003E" in exception_text:
            # Safe does not exist
            result = {"result": {}}
            return False, result, http_exception.code
        else:
            module.fail_json(
                msg=(
                    "Error while performing safe_delete."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, exception_text)
                ),
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:
        module.fail_json(
            msg=(
                "Unknown error while performing safe_delete."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            safe_name=dict(type="str", required=True),
            description=dict(type="str"),
            location=dict(type="str"),
            managing_cpm=dict(type="str"),
            number_of_versions_retention=dict(type="int", default=None),
            number_of_days_retention=dict(type="int", default=None),
            auto_purge_enabled=dict(type="bool", default=False),
            logging_level=dict(
                type="str", choices=["NOTSET", "DEBUG", "INFO"]
            ),
            logging_file=dict(type="str", default="/tmp/ansible_cyberark.log"),
            cyberark_session=dict(type="dict", required=True),
            api_base_url=dict(type="str", required=True),
            timeout=dict(type="float", default=10),
        )
    )

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"], level=module.params["logging_level"]
        )

    logging.info("Starting Module")

    state = module.params["state"]

    if state == "present":
        changed, result, status_code = safe_details(module)

        if status_code == 200:
            # Safe already exists
            changed, result, status_code = safe_add_or_update(
                module, "PUT", result["result"]
            )
        elif status_code == 404:
            # Safe does not exist, proceed to create it
            changed, result, status_code = safe_add_or_update(module, "POST", None)
    elif state == "absent":
        changed, result, status_code = safe_delete(module)

    module.exit_json(changed=changed, cyberark_safe=result, status_code=status_code)


if __name__ == "__main__":
    main()
