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
module: cyberark_platform
short_description: CyberArk User Management using PAS Web Services SDK.
author:
  - Edward Nunez (@enunez-cyberark)
  - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - CyberArk User Management using PAS Web Services SDK,
      It currently supports the following actions Get User Details, Add User,
      Update User, Delete User.

options:
    api_base_url:
        description:
            - A string containing the base URL of the server hosting
              CyberArk's Privileged Cloud ISP SDK.
        type: str
        required: true
    platform_id:
        description:
            - The unique ID/Name of the platform.
        type: str
        required: true
    duplicate_from_platform:
        description:
            - The unique ID/Name of the platform to duplicate from in case of a non-existing
              platform and state is specified as active or inactive.
        type: str
        required: false
    platform_class:
        description:
            - The class/kind of platform.
        choices: [ target, dependent, group, rotationalGroup ]
        default: target
        type: str
        required: false
    state:
        description:
            - Specifies the state needed for the platform. Either active, inactive or absent.
        type: str
        choices: [ active, inactive, absent]
        default: active
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output to
              the C(logging_file) value.
        required: false
        choices: [NOTSET, DEBUG, INFO]
        default: NOTSET
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
              session, please see M(cyberark.isp.cyberark_authentication) module for an
              example of cyberark_session.
        type: dict
        required: true
    timeout:
        description:
            - How long to wait for the server to send data before giving up
        type: float
        default: 10
        required: false
"""

EXAMPLES = r"""
- name: Platform
    cyberark_platform:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    logging_level: DEBUG
    platform_id: "TEST-NEW"
    duplicate_from_platform: "TEST-BASE"
    state: active
    cyberark_session: '{{ cyberark_session }}'
    register: cyberark_result
"""

RETURN = r"""
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
cyberark_platform:
    description: Dictionary containing result properties.
    returned: always
    type: complex
    contains:
        result:
            description: user properties when state is present
            type: dict
            returned: success
            elements: dict
            suboptions:
                platform_base:
                    description: Platform properties
                    type: complex
                class_platform_details:
                    description: Properties for the class platform
                    type: complex
                platform_class:
                    description: Platform class
                    type: str
status_code:
    description: Result HTTP Status code
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
from urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.parse import quote
import logging
import copy


def construct_url(api_base_url, end_point):
    return "{baseurl}/{endpoint}".format(baseurl=api_base_url.rstrip("/"), endpoint=end_point.lstrip("/"))

def telemetryHeaders(session = None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.isp)",
        "x-cybr-telemetry": base64.b64encode(b'in=Ansible ISP Collection&iv=1.0&vn=Red Hat&it=Identity Automation and workflows').decode("utf-8")
    }

    if session is not None:
        headers["Authorization"] = "Bearer " + session["access_token"]
    return headers

def platform_details_for_class(base_result, module):
    # Get platform_id from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    platform_id = module.params["platform_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    platform_class = module.params["platform_class"]
    validate_certs = False
    platform_name = base_result["Details"]["PolicyName"]

    # Prepare result, end_point, and headers
    result = {}

    end_point = "/PasswordVault/api/Platforms/{pplatformclass}s?search={pplatformname}".format(pplatformclass=quote(platform_class), pplatformname=quote(platform_name))
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
        platforms = json.loads(response.read())["Platforms"]
        found = False
        for platform in platforms:
            if platform["PlatformID"] == platform_id:
                found = True
                result = platform
                break

        return (found, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing platform_details_for_class."
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
                "Unknown error while performing platform_details_for_class."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def platform_details(module, error_if_details_not_found=True):

    # Get platform_id from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    platform_id = module.params["platform_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, end_point, and headers
    result = {}

    end_point = "/PasswordVault/api/Platforms/{pplatformid}".format(pplatformid=quote(platform_id))
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
        base_result = json.loads(response.read())
        result = {"result" : {"platform_base" : base_result}}

        if module.params["platform_class"] != "general":
            (found, platform_details, response_code) = platform_details_for_class(base_result, module)
            if found:
                result["result"]["platform_class"] = module.params["platform_class"]
                result["result"]["class_platform_details"] = platform_details
            else:
                if error_if_details_not_found:
                    # If the platform class is not found, fail the module
                    # with a message
                    module.fail_json(
                        msg=(
                            "Platform details for class %s and ID %s not found."
                            % (module.params["platform_class"], platform_id)
                        ),
                    )

        return (False, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing platform_details."
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
                "Unknown error while performing platform_details."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )

def platform_class_update(module, existing_info):
    # Get platform_id from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    internal_id = existing_info["class_platform_details"]["ID"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    platform_class = module.params["platform_class"]
    validate_certs = False

    # Prepare end_point, and headers
    end_point = ""
    if existing_info["class_platform_details"]["Active"] == False and module.params["state"] == "active":
        end_point = "/PasswordVault/api/platforms/{pplatformclass}s/{pinternalid}/activate/".format(pplatformclass=quote(platform_class), pinternalid=internal_id)
    elif existing_info["class_platform_details"]["Active"] == True and module.params["state"] == "inactive":
        end_point = "/PasswordVault/api/platforms/{pplatformclass}s/{pinternalid}/deactivate/".format(pplatformclass=quote(platform_class), pinternalid=internal_id)

    logging.info("**ENDPOINT=" + end_point)
    if end_point != "":

        url = construct_url(api_base_url, end_point)

        headers = telemetryHeaders(cyberark_session)
        logging.info(headers)

        try:

            open_url(
                url,
                method="POST",
                headers=headers,
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )
            (changed, result, response_code) = platform_details(module)
            changed = True
            return (changed, result, response_code)

        except (HTTPError, httplib.HTTPException) as http_exception:

            if http_exception.code == 404:
                return (False, None, http_exception.code)
            else:
                module.fail_json(
                    msg=(
                        "Error while performing platform_class_update."
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
                    "Unknown error while performing platform_class_update."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                headers=headers,
                status_code=-1,
            )
    else:
        logging.info("NO UPDATE on class platform")
        return (False, {"result" : existing_info}, 200)

def platform_class_duplicate(module):
    # Get platform_id from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    platform_class = module.params["platform_class"]
    validate_certs = False
    duplicate_from_platform_id = module.params["duplicate_from_platform"]
    duplicate_module = copy.deepcopy(module)
    duplicate_module.params["platform_id"] = duplicate_from_platform_id
    (changed, base_result, status_code) = platform_details(duplicate_module)
    logging.info("duplicate " + str(status_code) + " result: " + json.dumps(base_result))
    if status_code == 200: 
        # found a base platform to duplicate from
        duplicate_from_internal_id = base_result["result"]["class_platform_details"]["ID"]
        end_point = "/PasswordVault/api/platforms/{pplatformclass}s/{pinternalid}/duplicate/".format(pplatformclass=quote(platform_class), pinternalid=duplicate_from_internal_id)
        payload_dict = {
            "name": module.params["platform_id"],
            "description": "Duplicated from " + duplicate_from_platform_id
        }
        payload = json.dumps(payload_dict)
        logging.info("payload: " + payload)
        url = construct_url(api_base_url, end_point)

        headers = telemetryHeaders(cyberark_session)
        logging.info(headers)

        try:

            open_url(
                url,
                method="POST",
                headers=headers,
                data=payload,
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )
            (changed, new_result, status_code) = platform_details(module)
            (changed, result, response_code) = platform_class_update(module, new_result["result"])
            changed = True
            return (changed, result, response_code)

        except (HTTPError, httplib.HTTPException) as http_exception:

            if http_exception.code == 404:
                return (False, None, http_exception.code)
            else:
                module.fail_json(
                    msg=(
                        "Error while performing platform_class_duplicate."
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
                    "Unknown error while performing platform_class_duplicate."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                headers=headers,
                status_code=-1,
            )

    else:
        module.fail_json(
            msg=(
                "ERROR: %s platform to duplicate from (%s) was not found"
                % (platform_class, duplicate_from_platform_id)
            ),
        )



def platform_delete(module):

    # Get platform_id from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    platform_class = module.params["platform_class"]
    validate_certs = False
    result = {}

    (changed, result, status_code) = platform_details(module, error_if_details_not_found=False)
    if status_code == 404:
        # Platform does not exist, nothing to do
        result = {"result": {}}
        return (False, result, status_code)
    elif status_code == 200:
        internal_id = result["result"]["class_platform_details"]["ID"]

        # Prepare end_point, and headers
        end_point = "/PasswordVault/api/Platforms/{pplatformclass}s/{pinternalid}/".format(pplatformclass=quote(platform_class), pinternalid=internal_id)
        headers = telemetryHeaders(cyberark_session)
        url = construct_url(api_base_url, end_point)

        try:

            # execute REST action
            response = open_url(
                url,
                method="DELETE",
                headers=headers,
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )

            result = {"result": {}}

            return (True, result, response.getcode())

        except (HTTPError, httplib.HTTPException) as http_exception:

            exception_text = to_text(http_exception)
            if http_exception.code == 404 and "ITATS003E" in exception_text:
                # Platform does not exist
                result = {"result": {}}
                return (False, result, http_exception.code)
            else:
                module.fail_json(
                    msg=(
                        "Error while performing platform_delete."
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
                    "Unknown error while performing platform_delete."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                headers=headers,
                status_code=-1,
            )


def main():

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="active", choices=["absent", "active", "inactive"]),
            platform_id=dict(type="str", required=True),
            duplicate_from_platform=dict(type="str"),
            platform_class=dict(
                type="str", choices=["target", "dependent", "group", "rotationalGroup"], default="target"
            ),
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

    if state in ["active", "inactive"]:
        (changed, result, status_code) = platform_details(module)

        if status_code == 200:
            # Platform already exists
            (changed, result, status_code) = platform_class_update(module, result["result"])
        elif status_code == 404:
            # Platform does not exist, proceed to create it if parameter duplicate_from_platform was specified
            if module.params["duplicate_from_platform"] is not None:
                (changed, result, status_code) = platform_class_duplicate(module)
    elif state == "absent":
        (changed, result, status_code) = platform_delete(module)

    module.exit_json(changed=changed, cyberark_platform=result, status_code=status_code)

if __name__ == "__main__":
    main()
