#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)


__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = """
---
module: cyberark_authentication
short_description: Authentication using API token authentication for CyberArk Identity Security Platform Shared Services.
author:
    - Edward Nunez (@enunez-cyberark)
    - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - Authenticates to CyberArk API token authentication for CyberArk Identity
      Security Platform Shared Services and creates a session fact that can
      be used by other modules. It returns an Ansible fact called I(cyberark_session).
      Every module can use this fact as C(cyberark_session) parameter.
options:
    state:
        default: present
        choices: [present, absent]
        description:
            - Specifies if an authentication logon and a
              cyberark_session should be added.
        type: str
    grant_type:
        default: client_credentials
        description:
            - The type of grant for the authentication.
        type: str
        choices: [client_credentials]
    client_id:
        description:
            - The login name of the service account for authentication.
        type: str
    client_secret:
        description:
            - The password of the service account.
        type: str
    api_base_url:
        description:
            - A string containing the base URL of the server hosting
              CyberArk's Privileged Cloud ISP SDK.
        type: str
    timeout:
        description:
            - Allows you set a timeout for when your authenticating to Cyberark
        default: 10
        type: int
"""

EXAMPLES = """
- name: Logon
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"

- name: Logoff
  cyberark_authentication:
    state: absent
"""

RETURN = """
cyberark_session:
    description: Authentication facts.
    returned: success
    type: complex
    contains:
        access_token:
            description:
                - The token that identifies the session, encoded in BASE 64.
            type: str
            returned: always
        token_type:
            description:
                - Whether or not Shared Logon Authentication was used to
                  establish the session.
            type: str
            returned: always
        expires_in:
            description: Whether or not SSL certificates should be validated.
            type: int
            returned: always
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.http_client import HTTPException
import base64
import json


def telemetryHeaders(session=None):
    """
    Generate telemetry headers for the CyberArk API.

    Args:
        session (dict, optional): Session information containing the access token.

    Returns:
        dict: Headers for the API request.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.isp)",
        "x-cybr-telemetry": base64.b64encode(
            b"in=Ansible ISP Collection&iv=1.0&vn=Red Hat&it=Identity Automation and workflows"
        ).decode("utf-8"),
    }

    if session is not None:
        headers["Authorization"] = f"Bearer {session['access_token']}"
    return headers


def processAuthentication(module):
    """
    Process authentication to CyberArk API.

    Args:
        module (AnsibleModule): The Ansible module instance.

    Returns:
        tuple: A tuple containing changed status, result, and return code.
    """
    api_base_url = module.params["api_base_url"]
    grant_type = module.params["grant_type"]
    client_id = module.params["client_id"]
    client_secret = module.params["client_secret"]
    state = module.params["state"]
    timeout = module.params["timeout"]

    result = None
    changed = False
    response = None
    return_code = -1

    if state == "present":  # Logon Action

        end_point = f"{api_base_url}/oauth2/platformtoken"
        payload_dict = {
            "grant_type": grant_type,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        headers = telemetryHeaders()

        try:
            response = open_url(
                end_point,
                method="POST",
                headers=headers,
                data=urlencode(payload_dict).encode("utf-8"),
                validate_certs=False,
                timeout=timeout,
            )

        except (HTTPError, HTTPException) as http_exception:
            module.fail_json(
                msg=(
                    f"Error while performing authentication. Please validate parameters provided, and ability to logon to "
                    f"CyberArk.\n*** end_point={end_point}\n ==> {to_text(http_exception)}"
                ),
                headers=headers,
                status_code=http_exception.code,
            )

        except Exception as unknown_exception:
            module.fail_json(
                msg=(
                    f"Unknown error while performing authentication.\n*** end_point={end_point}\n{to_text(unknown_exception)}"
                ),
                headers=headers,
                status_code=-1,
            )

        return_code = response.getcode()
        if return_code == 200:  # Success
            token = ""
            try:
                token = str(json.loads(response.read()))
            except Exception as e:
                module.fail_json(
                    msg=f"Error obtaining token\n{to_text(e)}",
                    headers=headers,
                    status_code=-1,
                )

            # Preparing result of the module
            result = {"cyberark_session": token}

        else:
            module.fail_json(msg=f"Error in end_point => {end_point}", headers=headers)

    else:  # Logoff Action clears cyberark_session
        result = {"cyberark_session": {}}

    return changed, result, return_code


def main():
    """Main entry point for the module."""
    fields = {
        "api_base_url": {"type": "str"},
        "client_id": {"type": "str"},
        "client_secret": {"type": "str", "no_log": True},
        "grant_type": {
            "type": "str",
            "choices": ["client_credentials"],
            "default": "client_credentials",
        },
        "state": {
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "timeout": {"default": 10, "type": "int"},
    }

    mutually_exclusive = []

    required_if = [
        ("state", "present", ["api_base_url"]),
    ]

    required_together = [["api_base_url", "client_id", "client_secret"]]

    module = AnsibleModule(
        argument_spec=fields,
        mutually_exclusive=mutually_exclusive,
        required_if=required_if,
        required_together=required_together,
        supports_check_mode=True,
    )

    changed, result, status_code = processAuthentication(module)

    module.exit_json(changed=changed, ansible_facts=result, status_code=status_code)


if __name__ == "__main__":
    main()
