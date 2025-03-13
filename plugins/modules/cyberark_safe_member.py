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
    username:
        description:
            - The name of the user who will be queried (for details), added,
              updated or deleted.
        type: str
        required: true
    state:
        description:
            - Specifies the state needed for the user present for create user,
              absent for delete user.
        type: str
        choices: [ absent, present ]
        default: present
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
    initial_password:
        description:
            - The password that the new user will use to log on the first time.
            - This password must meet the password policy requirements.
            - This parameter is required when state is present -- Add User.
        type: str
    new_password:
        description:
            - The user updated password. Make sure that this password meets
              the password policy requirements.
        type: str
    email:
        description:
            - The user email address.
        type: str
    first_name:
        description:
            - The user first name.
        type: str
    last_name:
        description:
            - The user last name.
        type: str
    change_password_on_the_next_logon:
        description:
            - Whether or not the user must change their password in their
              next logon.
        type: bool
        default: false
    domain_name:
        description:
            - The name of the user domain.
        type: str
    member_type:
        description:
            - The type of member.
        type: str
    expiry_date:
        description:
            - The date and time when the user account will expire and become
              disabled.
        type: str
    user_type_name:
        description:
            - The type of user.
            - The parameter defaults to C(EPVUser).
        type: str
    enable_user:
        description:
            - Whether or not the user will be disabled.
        type: bool
        default: false
    location:
        description:
            - The Vault Location for the user.
        type: str
    group_name:
        description:
            - The name of the group the user will be added to.
            - Causes an additional lookup in cyberark
            - Will be ignored if vault_id is used
            - Will cause a failure if group is missing or more than one group with that name exists
        type: str
    timeout:
        description:
            - How long to wait for the server to send data before giving up
        type: float
        default: 10
    vault_id:
        description:
            - The ID of the user group to add the user to
            - Prefered over group_name
        type: int
    authorization:
        description:
            - A list of authorization options for this user.
            - Options can include AddSafes and AuditUsers
            - The default provides backwards compatability with older versions of the collection
        type: list
        elements: str
        default:
          - AddSafes
          - AuditUsers
    business_address:
        description:
            - The user's postal address, including city, state, zip, country and street
        type: dict
    internet:
        description:
            - The user's email addresses, including home page and email, business and other email
        type: dict
    phones:
        description:
            - The user's phone numbers, including home, business, cellular, fax and pager
        type: dict
    description:
        description:
            - Notes and comments.
        type: str
    personalDetails:
        description:
            - The user's personal details including: 
            - firstName, middleName, lastName, address
            - city, state, zip, country
            - title, organization, department, profession
        type: dict
"""

EXAMPLES = r"""
- name: Logon to CyberArk Vault using PAS Web Services SDK
  cyberark_authentication:
    api_base_url: https://components.cyberark.local
    use_shared_logon_authentication: true

- name: Create user & immediately add it to a group
  cyberark_user:
    username: username
    initial_password: password
    user_type_name: EPVUser
    change_password_on_the_next_logon: false
    group_name: GroupOfUser
    state: present
    cyberark_session: '{{ cyberark_session }}'

- name: Make sure user is present and reset user credential if present
  cyberark_user:
    username: Username
    new_password: password
    enable_user: false
    state: present
    cyberark_session: '{{ cyberark_session }}'

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: '{{ cyberark_session }}'
"""

RETURN = r"""
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
cyberark_user:
    description: Dictionary containing result properties.
    returned: always
    type: complex
    contains:
        result:
            description: user properties when state is present
            type: dict
            returned: success
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
from ansible.module_utils.six.moves.urllib.parse import quote
import logging


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


def safe_member_details(module):

    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    safe_name = module.params["safe_name"]
    member_name = module.params["member_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, end_point, and headers
    result = {}

    end_point = "/PasswordVault/api/Safes/{psafename}/Members/{pmembername}/".format(psafename=quote(safe_name), pmembername=quote(member_name))
    url = construct_url(api_base_url, end_point)

    logging.debug("URL for safe_member_details = " + url)

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
        return (False, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
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



def safe_member_add_or_update(module, HTTPMethod, existing_info):

    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    safe_name = module.params["safe_name"]
    member_name = module.params["member_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, paylod, and headers
    result = {}
    payload = {"safeName": safe_name, "memberName": member_name}
    end_point = ""
    headers = telemetryHeaders(cyberark_session)

    # end_point and payload sets different depending on POST/PUT
    # for POST -- create -- payload contains safename
    # for PUT -- update -- safename is part of the endpoint
    if HTTPMethod == "POST":
         end_point = "PasswordVault/api/Safes/{psafename}/Members".format(psafename=quote(safe_name))
    elif HTTPMethod == "PUT":
        end_point = "PasswordVault/api/Safes/{psafename}/Members/{pmembername}/".format(psafename=quote(safe_name), pmembername=quote(member_name))

    # --- Optionally populate payload based on parameters passed ---
    if "membership_expiration_date" in module.params and module.params["membership_expiration_date"] is not None:
        payload["membershipExpirationDate"] = module.params["membership_expiration_date"]

    if "permissions" in module.params and module.params["permissions"] is not None:
        payload["permissions"] = module.params["permissions"]

    if "is_read_only" in module.params and module.params["is_read_only"] is not None:
        payload["isReadOnly"] = module.params["is_read_only"]

    if "member_type" in module.params and module.params["member_type"] is not None:
        payload["memberType"] = module.params["member_type"]

    # --------------------------------------------------------------
    logging.debug(
        "HTTPMethod = " + HTTPMethod + " module.params = " + json.dumps(module.params)
    )
    logging.debug("Existing Info: %s", json.dumps(existing_info))
    logging.debug("payload => %s", json.dumps(payload))

    if HTTPMethod == "PUT":
        logging.info("Verifying if needs to be updated")
        proceed = False
        updateable_fields = [
            "membershipExpirationDate",
            "permissions",
            "isReadOnly",
        ]
        for field_name in updateable_fields:
            logging.debug("#### field_name : %s", field_name)
            if (
                field_name in payload
                and field_name in existing_info
                and payload[field_name] != existing_info[field_name]
            ):
                logging.debug("Changing value for %s", field_name)
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

            return (True, result, response.getcode())

        except (HTTPError, httplib.HTTPException) as http_exception:
            logging.info("response: " + http_exception.read().decode("utf-8"))
            module.fail_json(
                msg=(
                    "Error while performing safe_member_add_or_update."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, to_text(http_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=http_exception.code,
            )
        except Exception as unknown_exception:

            module.fail_json(
                msg=(
                    "Unknown error while performing safe_member_add_or_update."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=-1,
            )
    else:
        return (False, existing_info, 200)


def safe_member_delete(module):

    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    safe_name = module.params["safe_name"]
    member_name = module.params["member_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]

    # Prepare result, end_point, and headers
    result = {}

    end_point = "PasswordVault/api/Safes/{psafename}/Members/{pmembername}/".format(psafename=quote(safe_name), pmembername=quote(member_name))
    headers = telemetryHeaders(cyberark_session)
    url = construct_url(api_base_url, end_point)

    logging.debug("DELETE URL: " + url)

    try:

        # execute REST action
        response = open_url(
            url,
            method="DELETE",
            headers=headers,
            #validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:
        exception_text = to_text(http_exception)
        error_body = http_exception.read().decode()
        logging.debug("exception text: " + exception_text)
        logging.debug("error body => " + error_body)
        if http_exception.code == 404 and error_body is not None:
            return (False, {"result": error_body}, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing safe_member_delete."
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
                "Unknown error while performing safe_member_delete."
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
            member_name=dict(type="str", required=True),
            search_in=dict(type="str", default="Vault"),
            membership_expiration_date=dict(type=int),
            permissions=dict(type="dict",
                             options=dict(
                                useAccounts=dict(type="bool", default=False),
                                retrieveAccounts=dict(type="bool", default=False),
                                listAccounts=dict(type="bool", default=False),
                                addAccounts=dict(type="bool", default=False),
                                updateAccountContent=dict(type="bool", default=False),
                                updateAccountProperties=dict(type="bool", default=False),
                                initiateCPMAccountManagementOperations=dict(type="bool", default=False),
                                specifyNextAccountContent=dict(type="bool", default=False),
                                renameAccounts=dict(type="bool", default=False),
                                deleteAccounts=dict(type="bool", default=False),
                                unlockAccounts=dict(type="bool", default=False),
                                manageSafe=dict(type="bool", default=False),
                                manageSafeMembers=dict(type="bool", default=False),
                                backupSafe=dict(type="bool", default=False),
                                viewAuditLog=dict(type="bool", default=False),
                                viewSafeMembers=dict(type="bool", default=False),
                                requestsAuthorizationLevel1=dict(type="bool", default=False),
                                requestsAuthorizationLevel2=dict(type="bool", default=False),
                                accessWithoutConfirmation=dict(type="bool", default=False),
                                createFolders=dict(type="bool", default=False),
                                deleteFolders=dict(type="bool", default=False),
                                moveAccountsAndFolders=dict(type="bool", default=False)
                            )
                        ),
            is_read_only=dict(type="bool", default=False),
            member_type=dict(type="str", choices=["User", "Group", "Role"], default="User"),
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
        (changed, result, status_code) = safe_member_details(module)
        logging.debug("After safe_member_Details: status_code = " + str(status_code) + "  \nresult=" + json.dumps(result))

        if status_code == 200:
            # Safe already exists
            (changed, result, status_code) = safe_member_add_or_update(
               module, "PUT", result["result"]
            )
        elif status_code == 404:
            # Safe does not exist, proceed to create it
            (changed, result, status_code) = safe_member_add_or_update(module, "POST", None)
    elif state == "absent":
        (changed, result, status_code) = safe_member_delete(module)

    module.exit_json(changed=changed, cyberark_safe_member=result, status_code=status_code)

if __name__ == "__main__":
    main()
