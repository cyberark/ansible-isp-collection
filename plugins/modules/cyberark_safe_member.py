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
short_description: CyberArk Safe Member Management using Privilege Cloud Services Shared Services REST APIs.
author:
  - Edward Nunez (@enunez-cyberark)
  - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - CyberArk Safe Member Management using Privilege Cloud Services Shared Services REST APIs,
      It currently supports the following actions Get Details, Add, Update, Delete.

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
    member_name:
        description:
            - The CyberArk user name or group name of the Safe member.
        type: str
        required: true
    search_in:
        description:
            - You can search within the domain using the domain ID,
            - or within Privilege Cloud for a system component user.
        type: str
        default: Vault
    membership_expiration_date:
        description:
            - The member's expiration date for this Safe. For members that do not have
              an expiration date, this value will be null. Datetime.
        type: int
    permissions:
        description:
            - The permissions that the user or group has on this Safe.
        type: dict
        elements: dict
        suboptions:
            useAccounts:
                description:
                    - Use accounts but cannot view passwords.
                type: bool
                default: false
            retrieveAccounts:
                description:
                    - Retrieve and view accounts in the Safe.
                type: bool
                default: false
            listAccounts:
                description:
                    - View accounts list.
                type: bool
                default: false
            addAccounts:
                description:
                    - Add accounts in the Safe.
                type: bool
                default: false
            updateAccountContent:
                description:
                    - Update existing account content.
                type: bool
                default: false
            updateAccountProperties:
                description:
                    - Update existing account properties.
                type: bool
                default: false
            initiateCPMAccountManagementOperations:
                description:
                    - Initiate password management operations through CPM such as changing, verifying, and reconciling passwords.
                type: bool
                default: false
            specifyNextAccountContent:
                description:
                    - Specify the password that is used when the CPM changes the password value.
                    - This parameter can only be specified when the InitiateCPMAccountManagementOperations
                      parameter is set to True.
                type: bool
                default: false
            renameAccounts:
                description:
                    - Rename existing accounts in the Safe.
                type: bool
                default: false
            deleteAccounts:
                description:
                    - Delete existing passwords in the Safe.
                type: bool
                default: false
            unlockAccounts:
                description:
                    - Unlock accounts that are locked by other users.
                type: bool
                default: false
            manageSafe:
                description:
                    - Perform administrative tasks in the Safe, including:
                    - Update Safe properties
                    - Recover the Safe
                    - Delete the Safe
                type: bool
                default: false
            manageSafeMembers:
                description:
                    - Add and remove Safe members, and update their authorizations in the Safe.
                type: bool
                default: false
            backupSafe:
                description:
                    - Create a backup of a Safe and its contents, and store it in another location.
                type: bool
                default: false
            viewAuditLog:
                description:
                    - View account and user activity in the Safe.
                type: bool
                default: false
            viewSafeMembers:
                description:
                    - View permissions of Safe members.
                type: bool
                default: false
            requestsAuthorizationLevel1:
                description:
                    - Request Authorization Level 1.
                type: bool
                default: false
            requestsAuthorizationLevel2:
                description:
                    - Request Authorization Level 2.
                type: bool
                default: false
            accessWithoutConfirmation:
                description:
                    - Access the Safe without confirmation from authorized users. This overrides the Safe
                      properties that specify that Safe members require confirmation to access the Safe.
                type: bool
                default: false
            createFolders:
                description:
                    - Create folders in the Safe.
                type: bool
                default: false
            deleteFolders:
                description:
                    - Delete folders in the Safe.
                type: bool
                default: false
            moveAccountsAndFolders:
                description:
                    - Move accounts and folders in the Safe to different folders and subfolders.
                type: bool
                default: false
    timeout:
        description:
            - How long to wait for the server to send data before giving up
        type: float
        default: 10
"""

EXAMPLES = r"""
- name: Add member
    cyberark_safe_member:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    logging_level: DEBUG
    safe_name: "Partner-Test"
    member_name: "BD Tech"
    permissions: 
        useAccounts: True
        retrieveAccounts: True
        listAccounts: True
        addAccounts: True
        updateAccountContent: True
        updateAccountProperties: True
        initiateCPMAccountManagementOperations: True
        specifyNextAccountContent: True
        renameAccounts: True
        deleteAccounts: True
        unlockAccounts: True
        manageSafe: True
        manageSafeMembers: True
        backupSafe: True
        viewAuditLog: True
        viewSafeMembers: True
        requestsAuthorizationLevel1: True
        requestsAuthorizationLevel2: False
        accessWithoutConfirmation: True
        createFolders: True
        deleteFolders: True
        moveAccountsAndFolders: True
    cyberark_session: '{{ cyberark_session }}'
    state: present
    register: cyberark_result

- name: Show message
    debug:
    var: cyberark_result
"""

RETURN = r"""
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
cyberark_safe_member:
    description: Dictionary containing result properties.
    returned: always
    type: complex
    contains:
        result:
            description: safe member properties and permissions
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

    # --------------------------------------------------------------
    if HTTPMethod == "PUT":
        logging.info("Verifying if needs to be updated")
        proceed = False
        updateable_fields = [
            "membershipExpirationDate",
            "permissions",
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
