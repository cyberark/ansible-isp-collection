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


def application_details(module):

    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, end_point, and headers
    result = {}

    end_point = "/PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}".format(pappid=quote(app_id))
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
        result = {"result": json.loads(response.read())["application"]}
        # Get app authentication methods
        end_point = "/PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/Authentications".format(pappid=quote(app_id))
        url = construct_url(api_base_url, end_point)
        response = open_url(
            url,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )
        auth_methods = json.loads(response.read())
        logging.debug("auth_methods => " + json.dumps(auth_methods))
        result["result"]["authentication"] = auth_methods["authentication"]
        
        return (False, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing application_details."
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
                "Unknown error while performing application_details."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )

def key_for_auth_type(auth):
    logging.debug("key_for_auth_type auth: " + json.dumps(auth))
    key_value = ""
    if auth["AuthType"].lower() == "certificateattr":
        issuer = ""
        subject = ""
        subjectAlternativeName = ""
        if "Issuer" in auth and auth["Issuer"] is not None:
            issuer = ", ".join(auth["Issuer"]) if isinstance(auth["Issuer"], list) else auth["Issuer"]

        if "Subject" in auth and auth["Subject"] is not None:
            subject = ", ".join(auth["Subject"]) if isinstance(auth["Subject"], list) else auth["Subject"]

        if "SubjectAlternativeName" in auth and auth["SubjectAlternativeName"] is not None:
            subjectAlternativeName = ", ".join(auth["SubjectAlternativeName"]) if isinstance(auth["SubjectAlternativeName"], list) else auth["SubjectAlternativeName"]
        
        key_value = issuer + "-" + subject + "-" + subjectAlternativeName
    else:
        key_value = auth["AuthValue"]
    
    logging.debug("key_value=" + key_value)
    return key_value

def authentication_method_process(module, existing_info) -> bool:
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False
    headers = telemetryHeaders(cyberark_session)

    # Verify if Authentication Methods have to be updated
    existing_authentication = existing_info["authentication"]
    authentication = module.params["authentication"]
    logging.debug("existing_authentication: " + json.dumps(existing_authentication))
    logging.debug("authentication: " + json.dumps(authentication))
    # required_if = [
    #     ("AuthType", "path", ["AuthValue", "IsFolder", "AllowInternalScripts"]),
    #     ("AuthType", "hash", ["AuthValue"]),
    #     ("AuthType", "osUser", ["AuthValue"]),
    #     ("AuthType", "machineAddress", ["AuthValue"]),
    #     ("AuthType", "certificateserialnumber", ["AuthValue"]),
    #     ("AuthType", "certificateattr", ["Subject", "Issuer", "SubjectAlternativeName"], True),
    # ]
    updated = False
    existing_set = set((x["AuthType"].lower(),key_for_auth_type(x)) for x in existing_authentication)
    new_set = set((x["AuthType"].lower(),key_for_auth_type(x)) for x in authentication)
    logging.debug("existing_set: " + json.dumps(list(existing_set)))
    logging.debug("new_set: " + json.dumps(list(new_set)))
    # for auth in existing_authentication:

    for auth in existing_authentication:
        if ((auth["AuthType"].lower(), key_for_auth_type(auth)) not in new_set):
            logging.debug("EXISTING COMBINATION TO REMOVE: " + json.dumps(auth))
            delete_end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/Authentications/{pauthid}/".format(pappid=quote(app_id),pauthid=auth["authID"])
            delete_url = construct_url(api_base_url, delete_end_point)
            try:
                logging.debug("DELETE_URL = " + delete_url)
                # execute REST action
                open_url(
                    delete_url,
                    method="DELETE",
                    headers=headers,
                    data=None,
                    # data=json.dumps({"application": payload}),
                    validate_certs=validate_certs,
                    timeout=module.params['timeout'],
                )
                updated = True

            except (HTTPError, httplib.HTTPException) as http_exception:
                logging.info("response: " + http_exception.read().decode("utf-8"))
                module.fail_json(
                    msg=(
                        "Error while performing action on authentication_method."
                        "Please validate parameters provided."
                        "\n*** end_point=%s\n ==> %s"
                        % (delete_url, to_text(http_exception))
                    ),
                    # payload=payload,
                    headers=headers,
                    status_code=http_exception.code,
                )
            except Exception as unknown_exception:

                module.fail_json(
                    msg=(
                        "Unknown error while performing action on authentication_method."
                        "\n*** end_point=%s\n%s"
                        % (delete_url, to_text(unknown_exception))
                    ),
                    # payload=payload,
                    headers=headers,
                    status_code=-1,
                )

    for auth in authentication:
        if ((auth["AuthType"].lower(), key_for_auth_type(auth)) not in existing_set):
            logging.debug("COMBINATION TO ADD: " + json.dumps(auth))
            auth_payload = {"AuthType": auth["AuthType"]}
            if auth["AuthType"].lower() == "certificateattr":
                if "Issuer" in auth and auth["Issuer"] is not None:
                    auth_payload["Issuer"] = auth["Issuer"]

                if "Subject" in auth and auth["Subject"] is not None:
                    auth_payload["Subject"] = auth["Subject"]

                if "SubjectAlternativeName" in auth and auth["SubjectAlternativeName"] is not None:
                    auth_payload["SubjectAlternativeName"] = auth["SubjectAlternativeName"]
            else:
                auth_payload["AuthValue"] = auth["AuthValue"]

            if auth["AuthType"].lower() in ["hash", "certificateserialnumber"]:
                if "Comment" in auth and auth["Comment"] is not None:
                    auth_payload["Comment"] = auth["Comment"]
                
            if auth["AuthType"] == "path":
                logging.debug("**** AuthType=" + auth["AuthType"])
                if "IsFolder" in auth and auth["IsFolder"] is not None:
                    auth_payload["IsFolder"] = auth["IsFolder"]
                
                if "AllowInternalScripts" in auth and auth["AllowInternalScripts"] is not None:
                    auth_payload["AllowInternalScripts"] = auth["AllowInternalScripts"]
                
            add_end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/Authentications/".format(pappid=quote(app_id))
            add_url = construct_url(api_base_url, add_end_point)
            try:
                logging.debug("ADD_URL = " + add_url)
                logging.debug("auth_payload: " + json.dumps(auth_payload))
                # execute REST action
                open_url(
                    add_url,
                    method="POST",
                    headers=headers,
                    data=json.dumps({"authentication": auth_payload}),
                    validate_certs=validate_certs,
                    timeout=module.params['timeout'],
                )
                updated = True

            except (HTTPError, httplib.HTTPException) as http_exception:
                logging.info("response: " + http_exception.read().decode("utf-8"))
                module.fail_json(
                    msg=(
                        "Error while performing action on authentication_method."
                        "Please validate parameters provided."
                        "\n*** end_point=%s\n ==> %s"
                        % (add_url, to_text(http_exception))
                    ),
                    payload=auth_payload,
                    headers=headers,
                    status_code=http_exception.code,
                )
            except Exception as unknown_exception:

                module.fail_json(
                    msg=(
                        "Unknown error while performing action on authentication_method."
                        "\n*** end_point=%s\n%s"
                        % (add_url, to_text(unknown_exception))
                    ),
                    payload=auth_payload,
                    headers=headers,
                    status_code=-1,
                )
                
        else:
            pass # Possible UPDATE?

    return updated

def application_add_or_update(module, HTTPMethod, existing_info):

    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    # Prepare result, paylod, and headers
    result = {}
    payload = {"AppID": app_id}
    end_point = ""
    headers = telemetryHeaders(cyberark_session)

    # end_point and payload sets different depending on POST/PUT
    # for POST -- create -- payload contains safename
    # for PUT -- update -- safename is part of the endpoint
    if HTTPMethod == "POST":
        end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/"
    elif HTTPMethod == "PUT":
        end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/".format(pappid=quote(app_id))

    # --- Optionally populate payload based on parameters passed ---
    if "description" in module.params and module.params["description"] is not None:
        payload["Description"] = module.params["description"]

    if "location" in module.params and module.params["location"] is not None:
        payload["Location"] = module.params["location"]

    if "access_permitted_from" in module.params and module.params["access_permitted_from"] is not None:
        payload["AccessPermittedFrom"] = module.params["access_permitted_from"]

    if "access_permitted_to" in module.params and module.params["access_permitted_to"] is not None:
        payload["AccessPermittedTo"] = module.params["access_permitted_to"]

    if "expiration_date" in module.params and module.params["expiration_date"] is not None:
        payload["ExpirationDate"] = module.params["expiration_date"]

    if "disabled" in module.params and module.params["disabled"] is not None:
        payload["Disabled"] = module.params["disabled"]

    if "business_owner_f_name" in module.params and module.params["business_owner_f_name"] is not None:
        payload["BusinessOwnerFName"] = module.params["business_owner_f_name"]

    if "business_owner_l_name" in module.params and module.params["business_owner_l_name"] is not None:
        payload["BusinessOwnerLName"] = module.params["business_owner_l_name"]

    if "business_owner_email" in module.params and module.params["business_owner_email"] is not None:
        payload["BusinessOwnerEmail"] = module.params["business_owner_email"]

    if "business_owner_phone" in module.params and module.params["business_owner_phone"] is not None:
        payload["BusinessOwnerPhone"] = module.params["business_owner_phone"]


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
            "Description",
            "Location",
            "AccessPermittedFrom",
            "AccessPermittedTo",
            "ExpirationDate",
            "Disabled",
            "BusinessOwnerFName",
            "BusinessOwnerLName",
            "BusinessOwnerEmail",
            "BusinessOwnerPhone",
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

    updated = authentication_method_process(module, existing_info)
    response_code = 0

    if proceed:
        logging.info("Proceeding to either update or create")
        url = construct_url(api_base_url, end_point)
        logging.debug("URL[{method}] = {url}".format(method=HTTPMethod, url=url))
        try:

            # execute REST action
            response = open_url(
                url,
                method=HTTPMethod,
                headers=headers,
                data=json.dumps({"application": payload}),
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )

            updated = True
            response_code = response.status

        except (HTTPError, httplib.HTTPException) as http_exception:
            logging.info("response: " + http_exception.read().decode("utf-8"))
            module.fail_json(
                msg=(
                    "Error while performing application_add_or_update."
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
                    "Unknown error while performing application_add_or_update."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=-1,
            )
    
    if updated == False:
        return (False, existing_info, 200)
    else:
        (_, result, _) = application_details(module)

        return (True, result, response_code)
        


def application_delete(module):

    # Get safename from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]

    # Prepare result, end_point, and headers
    result = {}

    end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}".format(pappid=quote(app_id))
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
        if http_exception.code == 404 and "ITATS003E" in exception_text:
            # Safe does not exist
            result = {"result": {}}
            return (False, result, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing application_delete."
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
                "Unknown error while performing application_delete."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def main():

    required_if = [
        ("AuthType", "path", ["AuthValue", "IsFolder", "AllowInternalScripts"]),
        ("AuthType", "hash", ["AuthValue"]),
        ("AuthType", "osUser", ["AuthValue"]),
        ("AuthType", "machineAddress", ["AuthValue"]),
        ("AuthType", "certificateSerialNumber", ["AuthValue"]),
        ("AuthType", "certificateattr", ["Subject", "Issuer", "SubjectAlternativeName"]),
    ]

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            app_id=dict(type="str", required=True),
            description=dict(type="str"),
            location=dict(type="str"),
            access_permitted_from=dict(type="int"),
            access_permitted_to=dict(type="int"),
            expiration_date=dict(type="str"),
            disabled=dict(type="bool", default=False),
            business_owner_f_name=dict(type="str"),
            business_owner_l_name=dict(type="str"),
            business_owner_email=dict(type="str"),
            business_owner_phone=dict(type="str"),
            authentication=dict(type="list", elements="dict",
                                required_if=required_if,
                                options=dict(
                                    AllowInternalScripts=dict(type="bool", default=False),
                                    AuthType=dict(type="str", required=True, choices=["path", "osUser", "hash", "machineAddress", "certificateSerialNumber", "certificateAttr"]),
                                    AuthValue=dict(type="str"),
                                    Comment=dict(type="str"),
                                    IsFolder=dict(type="bool", default=False),
                                    Subject=dict(type="list", elements="str"),
                                    Issuer=dict(type="list", elements="str"),
                                    SubjectAlternativeName=dict(type="list", elements="str")
                                )),
            logging_level=dict(
                type="str", choices=["NOTSET", "DEBUG", "INFO"]
            ),
            logging_file=dict(type="str", default="/tmp/ansible_cyberark.log"),
            cyberark_session=dict(type="dict", required=True),
            api_base_url=dict(type="str", required=True),
            timeout=dict(type="float", default=10),
        ),
        required_if=required_if
    )

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"], level=module.params["logging_level"]
        )
    
    # if module.params["authentication"] is not None:
    #     authentication_list = module.params["authentication"]
    #     for authentication in authentication_list:
    #         match authentication["AuthType"]:
    #             case "path":
    #                 pass
    #             case "osUser":
    #                 pass

    logging.info("Starting Module")

    state = module.params["state"]

    if state == "present":
        (changed, result, status_code) = application_details(module)

        if status_code == 200:
            # Safe already exists
            (changed, result, status_code) = application_add_or_update(
               module, "PUT", result["result"]
            )
        elif status_code == 404:
            # Safe does not exist, proceed to create it
            (changed, result, status_code) = application_add_or_update(module, "POST", None)
    elif state == "absent":
        (changed, result, status_code) = application_delete(module)

    module.exit_json(changed=changed, cyberark_application=result, status_code=status_code)

if __name__ == "__main__":
    main()
