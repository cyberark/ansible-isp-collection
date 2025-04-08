#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Ansible Project
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
module: cyberark_user
short_description: CyberArk User Management using Privilege Cloud Share Services REST APIs.
author:
  - Edward Nunez (@enunez-cyberark)
  - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - CyberArk User Management using Privilege Cloud Share Services REST APIs,
      It currently supports the following actions Get User Details, Add User,
      Update User, Delete User.

options:
    api_base_url:
        description:
            - A string containing the base URL of the server hosting
              CyberArk's Privileged Cloud ISP SDK.
        type: str
        required: true
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
import logging

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.six.moves import http_client as httplib
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import quote


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


def user_details(module):

    # Get username from module parameters, and api base url
    # along with the cyberark_session established
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, end_point, and headers
    result = {}
    userid = resolve_username_to_id(module)

    if userid is not None:
        end_point = "/PasswordVault/api/Users/{puserid}".format(puserid=userid)
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
                        "Error while performing user_details."
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
                    "Unknown error while performing user_details."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                headers=headers,
                status_code=-1,
            )

    else:
        return (False, None, 404)



def user_add_or_update(module, HTTPMethod, existing_info):

    # Get username from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    username = module.params["username"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, paylod, and headers
    result = {}
    payload = {}
    payload["username"] = username
    end_point = ""
    headers = telemetryHeaders(cyberark_session)

    # end_point and payload sets different depending on POST/PUT
    # for POST -- create -- payload contains username
    # for PUT -- update -- username is part of the endpoint
    if HTTPMethod == "POST":
        end_point = "PasswordVault/api/Users"
        if (
            "initial_password" in list(module.params.keys())
            and module.params["initial_password"] is not None
        ):
            payload["InitialPassword"] = module.params["initial_password"]

    elif HTTPMethod == "PUT":
        userid = resolve_username_to_id(module)
        end_point = "PasswordVault/api/Users/{puserid}".format(puserid=userid)

    # --- Optionally populate payload based on parameters passed ---
    if (
        "user_type" in module.params and module.params["user_type"] is not None
    ):
        payload["userType"] = module.params["user_type"]

    if "non_authorized_interfaces" in module.params and module.params["non_authorized_interfaces"] is not None:
        payload["nonAuthorizedInterfaces"] = module.params["non_authorized_interfaces"]

    if "location" in module.params and module.params["location"] is not None:
        payload["Location"] = module.params["location"]

    if "expiry_date" in module.params and module.params["expiry_date"] is not None:
        payload["ExpiryDate"] = module.params["expiry_date"]

    if "enable_user" in module.params and module.params["enable_user"] is not None:
        payload["enableUser"] = module.params["enable_user"]

    if "authentication_method" in module.params and module.params["authentication_method"] is not None:
        payload["authenticationMethod"] = module.params["authentication_method"]

    if "initial_password" in module.params and module.params["initial_password"] is not None:
        payload["initialPassword"] = module.params["initial_password"]

    if (
        "change_pass_on_next_logon" in module.params
        and module.params["change_pass_on_next_logon"] is not None
    ):
        payload["changePassOnNextLogon"] = module.params[
            "change_pass_on_next_logon"
        ]

    if "password_never_expires" in module.params and module.params["password_never_expires"] is not None:
        payload["passwordNeverExpires"] = module.params["password_never_expires"]

    if "distinguished_name" in module.params and module.params["distinguished_name"] is not None:
        payload["distinguishedName"] = module.params["distinguished_name"]

    if "vault_authorization" in module.params and module.params["vault_authorization"] is not None:
        payload["vaultAuthorization"] = module.params["vault_authorization"]

    if "business_address" in module.params and module.params["business_address"] is not None:
        payload["businessAddress"] = module.params["business_address"]

    if "internet" in module.params and module.params["internet"] is not None:
        payload["internet"] = module.params["internet"]

    if "phones" in module.params and module.params["phones"] is not None:
        payload["phones"] = module.params["phones"]

    if "personal_details" in module.params and module.params["personal_details"] is not None:
        payload["personalDetails"] = module.params["personal_details"]

    # --------------------------------------------------------------

    if HTTPMethod == "PUT" and (
        "new_password" not in module.params or module.params["new_password"] is None
    ):
        logging.info("Verifying if needs to be updated")
        proceed = False
        updateable_fields = [
            "description",
            "personalDetails",
            "businessAddress",
            "internet",
            "phones",
            "changePassOnTheNextLogon",
            "expiryDate",
            "enableUser",
            "location",
            "userType",
            "vaultAuthorization",
        ]
        empty_object_fields = {}
        empty_object_fields["personalDetails"] = {
            "street": "", 
            "city": "", 
            "state": "", 
            "zip": "", 
            "country": "", 
            "title": "", 
            "organization": "", 
            "department": "", 
            "profession": "", 
            "firstName": "", 
            "middleName": "", 
            "lastName": ""
        }
        empty_object_fields["businessAddress"] = {
            "workStreet": "",
            "workCity": "",
            "workState": "",
            "workZip": "",
            "workCountry": ""
        }
        empty_object_fields["internet"] = {
            "homePage": "",
            "homeEmail": "",
            "businessEmail": "",
            "otherEmail": ""
        }
        empty_object_fields["phones"] = {
            "homeNumber": "",
            "businessNumber": "",
            "cellularNumber": "",
            "faxNumber": "",
            "pagerNumber": ""
        }

        for field_name in updateable_fields:
            if (
                field_name in payload
                and field_name in existing_info
            ):
                if isinstance(payload[field_name], str) and payload[field_name] != existing_info[field_name]:
                    logging.info("Changing value for %s", field_name)
                    proceed = True
                elif isinstance(payload[field_name], dict):
                    full_field = empty_object_fields[field_name]
                    full_field.update(payload[field_name])
                    if full_field != existing_info[field_name]:
                        logging.info("Changing OBJECT value for %s", field_name)
                        proceed = True

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
                    "Error while performing user_add_or_update."
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
                    "Unknown error while performing user_add_or_update."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=-1,
            )
    else:
        return (False, existing_info, 200)


def resolve_username_to_id(module):
    username = module.params["username"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    url = construct_url(api_base_url, "PasswordVault/api/Users?userName={pusername}".format(pusername=username))
    headers = telemetryHeaders(cyberark_session)

    try:
        response = open_url(
            url,
            method="GET",
            headers=headers,
            timeout=module.params['timeout'],
        )
        users = json.loads(response.read())
        # Return None if the user does not exist
        user_id = None
        if users["Total"] > 0:
            user_id = users["Users"][0]["id"]

        # If we made it here we had 1 or 0 users, return them
        logging.info("Resolved username {%s} to ID {%s}", username, user_id)
        return user_id

    except (HTTPError, httplib.HTTPException) as http_exception:
        logging.info("url: " + url)
        exception_text = to_text(http_exception)
        module.fail_json(msg=(
            "Error while performing user_search."
            "Please validate parameters provided."
            "\n*** end_point=%s\n ==> %s"
            % (url, exception_text)),
            headers=headers,
            status_code=http_exception.code,
        )
    except Exception as unknown_exception:
        module.fail_json(msg=(
            "Unknown error while performing user search."
            "\n*** end_point=%s\n%s"
            % (url, to_text(unknown_exception))),
            headers=headers,
            status_code=-1,
        )


def user_delete(module):

    # Get username from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]

    # Prepare result, end_point, and headers
    result = {}
    vault_user_id = resolve_username_to_id(module)
    # If the user was not found by username we can return unchanged
    if vault_user_id is None:
        return (False, result, None)

    end_point = ("PasswordVault/api/Users/{pvaultuserid}").format(pvaultuserid=vault_user_id)
    headers = telemetryHeaders(cyberark_session)
    url = construct_url(api_base_url, end_point)

    try:

        # execute REST action
        response = open_url(
            url,
            method="DELETE",
            headers=headers,
            timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        exception_text = to_text(http_exception)
        if http_exception.code == 404 and "ITATS003E" in exception_text:
            # User does not exist
            result = {"result": {}}
            return (False, result, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing user_delete."
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
                "Unknown error while performing user_delete."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def resolve_group_name_to_id(module):
    group_name = module.params["group_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False
    headers = telemetryHeaders(cyberark_session)
    url = construct_url(api_base_url, "/PasswordVault/api/UserGroups?filter=groupName%20eq%20{pgroupname}".format(pgroupname=quote(group_name)))
    try:
        response = open_url(
            url,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )
        groups = json.loads(response.read())
        # Return None if the user does not exist
        group_id = None
        if groups["count"] > 0:
            group_id = groups["value"][0]["id"]
        # If we made it here we had 1 or 0 users, return them
        logging.info("Resolved group_name %s to ID %s", group_name, group_id)
        return group_id

    except (HTTPError, httplib.HTTPException) as http_exception:
        module.fail_json(msg=(
            "Error while looking up group %s.\n*** end_point=%s\n ==> %s"
            % (group_name, url, to_text(http_exception))),
            payload={},
            headers=headers,
            status_code=http_exception.code,
        )
    except Exception as unknown_exception:
        module.fail_json(msg=(
            "Unknown error while looking up group %s.\n*** end_point=%s\n%s"
            % (group_name, url, to_text(unknown_exception))),
            payload={},
            headers=headers,
            status_code=-1,
        )


def user_add_to_group(module):

    # Get username, and groupname from module parameters, and api base url
    # along with the cyberark_session established
    username = module.params["username"]
    group_name = module.params["group_name"]
    vault_id = module.params["vault_id"]
    member_type = (
        "Vault"
        if module.params["member_type"] is None
        else module.params["member_type"]
    )
    domain_name = module.params["domain_name"] if member_type == "domain" else None

    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, end_point, headers and payload
    result = {}
    headers = telemetryHeaders(cyberark_session)

    # If we went "old school" and were provided a group_name instead of a vault_id we need to resolve it
    if group_name and not vault_id:
        # If we were given a group_name we need to lookup the vault_id
        vault_id = resolve_group_name_to_id(module)
        if vault_id is None:
            module.fail_json(msg="Unable to find a user group named {pgroupname}, please create that before adding a user to it".format(pgroupname=group_name))

    end_point = ("/PasswordVault/api/UserGroups/{pvaultid}/Members").format(pvaultid=vault_id)

    # For some reason the group add uses username instead of id
    payload = {"memberId": username, "memberType": member_type}
    if domain_name:
        payload["domainName"] = domain_name

    url = construct_url(api_base_url, end_point)
    try:

        # execute REST action
        response = open_url(
            url,
            method="POST",
            headers=headers,
            data=json.dumps(payload),
            validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        exception_text = to_text(http_exception)
        exception_body = json.loads(http_exception.read().decode())
        if http_exception.code == 409 and ("ITATS262E" in exception_text or exception_body.get("ErrorCode", "") == "PASWS213E"):
            # User is already member of Group
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing user_add_to_group."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, exception_text)
                ),
                payload=payload,
                headers=headers,
                status_code=http_exception.code,
                response=http_exception.read().decode(),
            )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing user_add_to_group."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            payload=payload,
            headers=headers,
            status_code=-1,
        )

def main():

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            username=dict(type="str", required=True),
            user_type=dict(type="str"),
            non_authorized_interfaces=dict(type="list", elements="str", required=False),
            location=dict(type="str"),
            expiry_date=dict(type="str"),
            enable_user=dict(type="bool", default=True),
            authentication_method=dict(
                type="str", choices=["AuthTypePass", "AuthTypeRadius", "AuthTypeLDAP"]
            ),
            initial_password=dict(type="str", no_log=True),
            change_pass_on_next_logon=dict(type="bool", default=False, no_log=False),
            password_never_expires=dict(type="bool", default=False, no_log=False),
            distinguished_name=dict(type="str"),
            vault_authorization=dict(type="list", elements="str", required=False, default=["AddSafes", "AuditUsers"],
                choices=["AddSafes", "AuditUsers", "AddUpdateUsers", "ResetUsersPasswords", "ActivateUsers",
                         "AddNetworkAreas", "ManageDirectoryMapping", "ManageServerFileCategories", "BackupAllSafes",
                         "RestoreAllSafes"]
            ),
            business_address=dict(type="dict",
                                  options=dict(
                                      workStreet=dict(type="str", default=""),
                                      workCity=dict(type="str", default=""),
                                      workState=dict(type="str", default=""),
                                      workZip=dict(type="str", default=""),
                                      workCountry=dict(type="str", default="")
                                    )
                                ),
            internet=dict(type="dict",
                                  options=dict(
                                      homePage=dict(type="str", default=""),
                                      homeEmail=dict(type="str", default=""),
                                      businessEmail=dict(type="str", default=""),
                                      otherEmail=dict(type="str", default="")
                                    )
                                ),
            phones=dict(type="dict",
                                  options=dict(
                                      homeNumber=dict(type="str", default=""),
                                      businessNumber=dict(type="str", default=""),
                                      cellularNumber=dict(type="str", default=""),
                                      faxNumber=dict(type="str", default=""),
                                      pagerNumber=dict(type="str", default="")
                                    )
                                ),
            personal_details=dict(type="dict", 
                                  options=dict(
                                      firstName=dict(type="str", default=""),
                                      lastName=dict(type="str", default=""),
                                      middleName=dict(type="str", default=""),
                                      street=dict(type="str", default=""),
                                      city=dict(type="str", default=""),
                                      state=dict(type="str", default=""),
                                      zip=dict(type="str", default=""),
                                      country=dict(type="str", default=""),
                                      title=dict(type="str", default=""),
                                      organization=dict(type="str", default=""),
                                      department=dict(type="str", default=""),
                                      profession=dict(type="str", default="")
                                    )
                                ),
            description=dict(type="str"),
            logging_level=dict(
                type="str", choices=["NOTSET", "DEBUG", "INFO"]
            ),
            logging_file=dict(type="str", default="/tmp/ansible_cyberark.log"),
            cyberark_session=dict(type="dict", required=True),
            api_base_url=dict(type="str", required=True),
            group_name=dict(type="str"),
            vault_id=dict(type="int"),
            member_type=dict(type="str"),
            domain_name=dict(type="str"),
            timeout=dict(type="float", default=10),
        )
    )

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"], level=module.params["logging_level"]
        )

    logging.info("Starting Module")

    state = module.params["state"]
    group_name = module.params["group_name"]
    vault_id = module.params["vault_id"]

    if state == "present":
        (changed, result, status_code) = user_details(module)

        if status_code == 200:
            # User already exists
            (changed, result, status_code) = user_add_or_update(
               module, "PUT", result["result"]
            )

        elif status_code == 404:
            # User does not exist, proceed to create it
            (changed, result, status_code) = user_add_or_update(module, "POST", None)

        # Add user to group if needed
        if group_name is not None or vault_id is not None:
            (group_change, no_result, no_status_code) = user_add_to_group(module)
            changed = changed or group_change

    elif state == "absent":
        (changed, result, status_code) = user_delete(module)

    module.exit_json(changed=changed, cyberark_user=result, status_code=status_code)

if __name__ == "__main__":
    main()
