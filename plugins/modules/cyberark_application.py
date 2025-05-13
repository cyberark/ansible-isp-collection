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
module: cyberark_application
short_description: CyberArk Application Management using Privilege Cloud Web Shared Services REST API.
author:
  - Edward Nunez (@enunez-cyberark)
  - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - CyberArk Application Management using Privilege Cloud Web Shared Services REST API,
      It currently supports the following actions Get Details, Add, Update, Delete.

options:
    api_base_url:
        description:
            - A string containing the base URL of the server hosting CyberArk's
              Privileged Account Security Web Services SDK.
            - Example U(https://<IIS_Server_Ip>/PasswordVault/api/)
        required: true
        type: str
    app_id:
        description:
            - The name of the Application.
        type: str
        required: true
    state:
        description:
            - Specifies the state needed for the application. present to ensure application exists,
              absent to ensure application does not exist.
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
    description:
        description:
            - A description of the application.
            - Specify up to 29 characters.
        type: str
    location:
        description:
            - The location of the application in Privilege Cloud hierarchy.
            - To insert a backslash in the location path, use a double backslash.
        type: str
    access_permitted_from:
        description:
            - The start hour that access is permitted to the application.
            - Valid values between 0-23
        type: int
    access_permitted_to:
        description:
            - The end hour that access is permitted to the application.
            - Valid values between 0-23
        type: int
    expiration_date:
        description:
            - The date when the application expires.
            - In format mm-dd-yyyy
        type: str
    disabled:
        description:
            - Whether the application is disabled.
        type: bool
        default: false
    business_owner_f_name:
        description:
            - The first name of the business owner.
        type: str
    business_owner_l_name:
        description:
            - The last name of the business owner.
        type: str
    business_owner_email:
        description:
            - The email of the business owner.
        type: str
    business_owner_phone:
        description:
            - The phone number of the business owner.
        type: str
    authentication:
        description:
            - A list of authentication methods for the application.
            - Options can include AddSafes and AuditUsers.
            - The default provides backwards compatability with older versions of the collection.
        type: list
        elements: dict
        suboptions:
            AllowInternalScripts:
                description:
                    - Relevant for Path authentication only.
                type: bool
                default: false
            AuthType:
                description:
                    - The type of authentication.
                type: str
                required: true
                choices: [path, osUser, hash, machineAddress, certificateSerialNumber, certificateAttr]
            AuthValue:
                description:
                    - The content of the authentication.
                type: str
            Comment:
                description:
                    - Comment for the authentication.
                type: str
            IsFolder:
                description:
                    - Relevant for Path authentication only.
                type: bool
                default: false
            Subject:
                description:
                    - The content of the subject attribute for certificateAttr AuthType.
                type: list
                elements: str
            Issuer:
                description: The content of the issuer attribute for certificateAttr AuthType.
                type: list
                elements: str
            SubjectAlternativeName:
                description: The content of the subject alternative name attribute for certificateAttr AuthType.
                type: list
                elements: str
    timeout:
        description:
            - How long to wait for the server to send data before giving up
        type: float
        default: 10
"""

EXAMPLES = r"""
- name: Application
  cyberark.isp.cyberark_application:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    logging_level: DEBUG
    app_id: "EdwardTest_AppID"
    authentication:
      - AuthType: path
        AuthValue: "/tmp"
        IsFolder: true
      - AuthType: path
        AuthValue: "/var/tmp"
        IsFolder: true
        AllowInternalScripts: true
      - AuthType: path
        AuthValue: "/shr/apps"
        IsFolder: true
        AllowInternalScripts: true
      - AuthType: osUser
        AuthValue: "Edward/Edward"
      - AuthType: osUser
        AuthValue: "BizDevTech/Simon"
      - AuthType: hash
        AuthValue: "HASH123332223"
        Comment: "This is the hash for version 1"
      - AuthType: machineAddress
        AuthValue: "2.2.2.2"
        Comment: "Set of address"
      - AuthType: machineAddress
        AuthValue: "3.3.3.3"
      - AuthType: certificateSerialNumber
        AuthValue: "1E8AB650DC258AE3"
        Comment: "Certificate for authentication"
      - AuthType: certificateSerialNumber
        AuthValue: "2E8AB650DC258AE3"
        Comment: "Authentication 2"
      - AuthType: certificateAttr
        Issuer: "CN=Thawte RSA CA 2018,OU=www.digicert.com"
        Subject: ["CN=yourcompany.com", "OU=IT", "C=IL"]
        SubjectAlternativeName: ["DNS Name=www.example.com", "IP Address=1.2.3.4"]
    state: present
    cyberark_session: '{{ cyberark_session }}'
    register: cyberark_result
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


def telemetry_headers(session=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.isp)",
        "x-cybr-telemetry": base64.b64encode(
            b'in=Ansible ISP Collection&iv=1.0&vn=Red Hat&it=Identity Automation and workflows'
        ).decode("utf-8")
    }

    if session is not None:
        headers["Authorization"] = "Bearer " + session["access_token"]
    return headers


def application_details(module):
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    result = {}
    end_point = "/PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}".format(pappid=quote(app_id))
    url = construct_url(api_base_url, end_point)

    headers = telemetry_headers(cyberark_session)
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
        result["result"]["authentication"] = auth_methods["authentication"]

        return False, result, response.getcode()

    except (HTTPError, httplib.HTTPException) as http_exception:
        if http_exception.code == 404:
            return False, None, http_exception.code
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
    key_value = ""
    if auth["AuthType"].lower() == "certificateattr":
        issuer = ""
        subject = ""
        subject_alternative_name = ""
        if "Issuer" in auth and auth["Issuer"] is not None:
            issuer = ", ".join(auth["Issuer"]) if isinstance(auth["Issuer"], list) else auth["Issuer"]

        if "Subject" in auth and auth["Subject"] is not None:
            subject = ", ".join(auth["Subject"]) if isinstance(auth["Subject"], list) else auth["Subject"]

        if "SubjectAlternativeName" in auth and auth["SubjectAlternativeName"] is not None:
            if isinstance(auth["SubjectAlternativeName"], list):
                subject_alternative_name = ", ".join(auth["SubjectAlternativeName"])
            else:
                subject_alternative_name = auth["SubjectAlternativeName"]

        key_value = issuer + "-" + subject + "-" + subject_alternative_name
    else:
        key_value = auth["AuthValue"]

    return key_value


def authentication_method_process(module, existing_info) -> bool:
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False
    headers = telemetry_headers(cyberark_session)

    authentication = module.params["authentication"]
    logging.info("authentication: %s", json.dumps(authentication))
    updated = False
    existing_set = set()
    if existing_info is not None and "authentication" in existing_info:
        existing_authentication = existing_info["authentication"]
        logging.info("existing_authentication: %s", json.dumps(existing_authentication))
        existing_set = set((x["AuthType"].lower(), key_for_auth_type(x)) for x in existing_authentication)
        new_set = set((x["AuthType"].lower(), key_for_auth_type(x)) for x in authentication)

        for auth in existing_authentication:
            if (auth["AuthType"].lower(), key_for_auth_type(auth)) not in new_set:
                logging.info("EXISTING COMBINATION TO REMOVE: %s", json.dumps(auth))
                delete_end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/Authentications/{pauthid}/".format(
                    pappid=quote(app_id), pauthid=auth["authID"]
                )
                delete_url = construct_url(api_base_url, delete_end_point)
                try:
                    open_url(
                        delete_url,
                        method="DELETE",
                        headers=headers,
                        data=None,
                        validate_certs=validate_certs,
                        timeout=module.params['timeout'],
                    )
                    updated = True

                except (HTTPError, httplib.HTTPException) as http_exception:
                    logging.info("Response: %s", http_exception.read().decode("utf-8"))
                    module.fail_json(
                        msg=(
                            "Error while performing action on authentication_method."
                            "Please validate parameters provided."
                            "\n*** end_point=%s\n ==> %s"
                            % (delete_url, to_text(http_exception))
                        ),
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
                        headers=headers,
                        status_code=-1,
                    )
    if authentication is not None and len(authentication) > 0:
        for auth in authentication:
            if (auth["AuthType"].lower(), key_for_auth_type(auth)) not in existing_set:
                logging.info("COMBINATION TO ADD: %s", json.dumps(auth))
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
                    if "IsFolder" in auth and auth["IsFolder"] is not None:
                        auth_payload["IsFolder"] = auth["IsFolder"]

                    if "AllowInternalScripts" in auth and auth["AllowInternalScripts"] is not None:
                        auth_payload["AllowInternalScripts"] = auth["AllowInternalScripts"]

                add_end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/Authentications/".format(pappid=quote(app_id))
                add_url = construct_url(api_base_url, add_end_point)
                try:
                    logging.info("ADD_URL = %s", add_url)
                    logging.info("auth_payload: %s", json.dumps(auth_payload))
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
                    logging.info("response: %s", http_exception.read().decode("utf-8"))
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

    return updated


def application_add_or_update(module, http_method, existing_info):
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]
    validate_certs = False

    result = {}
    payload = {"AppID": app_id}
    end_point = ""
    headers = telemetry_headers(cyberark_session)

    if http_method == "POST":
        end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/"
    elif http_method == "PUT":
        end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}/".format(pappid=quote(app_id))

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

    logging.info(
        "http_method = " + http_method + " module.params = " + json.dumps(module.params)
    )

    if http_method == "PUT":
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

    updated = False
    response_code = 0

    if proceed:
        logging.info("Proceeding to either update or create")
        url = construct_url(api_base_url, end_point)
        try:
            response = open_url(
                url,
                method=http_method,
                headers=headers,
                data=json.dumps({"application": payload}),
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )

            authentication_method_process(module, existing_info)
            updated = True
            response_code = response.status

        except (HTTPError, httplib.HTTPException) as http_exception:
            logging.info("response: %s", http_exception.read().decode("utf-8"))
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

    if not updated:
        return False, existing_info, 200
    else:
        no_use01, result, no_use02 = application_details(module)

        return True, result, response_code


def application_delete(module):
    app_id = module.params["app_id"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = module.params["api_base_url"]

    result = {}
    end_point = "PasswordVault/WebServices/PIMServices.svc/Applications/{pappid}".format(pappid=quote(app_id))
    headers = telemetry_headers(cyberark_session)
    url = construct_url(api_base_url, end_point)

    try:
        response = open_url(
            url,
            method="DELETE",
            headers=headers,
            timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return True, result, response.getcode()

    except (HTTPError, httplib.HTTPException) as http_exception:
        exception_text = to_text(http_exception)
        if http_exception.code == 404 and "ITATS003E" in exception_text:
            result = {"result": {}}
            return False, result, http_exception.code
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
    # required_if = [
    #     ("AuthType", "path", ["AuthValue", "IsFolder", "AllowInternalScripts"]),
    #     ("AuthType", "hash", ["AuthValue"]),
    #     ("AuthType", "osUser", ["AuthValue"]),
    #     ("AuthType", "machineAddress", ["AuthValue"]),
    #     ("AuthType", "certificateSerialNumber", ["AuthValue"]),
    #     ("AuthType", "certificateattr", ["Subject", "Issuer", "SubjectAlternativeName"]),
    # ]

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
                                required_if=[
                                    ("AuthType", "path", ["AuthValue", "IsFolder", "AllowInternalScripts"]),
                                    ("AuthType", "hash", ["AuthValue"]),
                                    ("AuthType", "osUser", ["AuthValue"]),
                                    ("AuthType", "machineAddress", ["AuthValue"]),
                                    ("AuthType", "certificateSerialNumber", ["AuthValue"]),
                                    ("AuthType", "certificateattr", ["Subject", "Issuer", "SubjectAlternativeName"]),
                                ],
                                options=dict(
                                    AllowInternalScripts=dict(type="bool", default=False),
                                    AuthType=dict(type="str", required=True,
                                                  choices=["path", "osUser", "hash",
                                                           "machineAddress", "certificateSerialNumber",
                                                           "certificateAttr"]),
                                    AuthValue=dict(type="str"),
                                    Comment=dict(type="str"),
                                    IsFolder=dict(type="bool", default=False),
                                    Subject=dict(type="list", elements="str"),
                                    Issuer=dict(type="list", elements="str"),
                                    SubjectAlternativeName=dict(type="list", elements="str")
                                )),
            logging_level=dict(
                type="str", choices=["NOTSET", "DEBUG", "INFO"], default="NOTSET"
            ),
            logging_file=dict(type="str", default="/tmp/ansible_cyberark.log"),
            cyberark_session=dict(type="dict", required=True),
            api_base_url=dict(type="str", required=True),
            timeout=dict(type="float", default=10),
        ),
        # required_if=required_if
    )

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"], level=module.params["logging_level"]
        )

    logging.info("Starting Module")

    state = module.params["state"]

    if state == "present":
        changed, result, status_code = application_details(module)

        if status_code == 200:
            changed, result, status_code = application_add_or_update(module, "PUT", result["result"])
        elif status_code == 404:
            changed, result, status_code = application_add_or_update(module, "POST", None)
    elif state == "absent":
        changed, result, status_code = application_delete(module)

    module.exit_json(changed=changed, cyberark_application=result, status_code=status_code)


if __name__ == "__main__":
    main()
