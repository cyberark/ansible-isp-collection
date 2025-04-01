# cyberark_application

This module allows admins to Add, Delete, and Modify CyberArk Applications.

#### Available Fields
    
```
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
            - Options can include AddSafes and AuditUsers
            - The default provides backwards compatability with older versions of the collection
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
                choices:
                    - path
                    - osUser
                    - hash
                    - machineAddress
                    - certificateSerialNumber
                    - certificateAttr
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
                type: str
            Issuer:
                description: The content of the issuer attribute for certificateAttr AuthType.
                type: str
            SubjectAlternativeName:
                description: The content of the subject alternative name attribute for certificateAttr AuthType.
                type: str
    timeout:
        description:
            - How long to wait for the server to send data before giving up
        type: float
        default: 10
```
## Example Playbooks

This playbook will check if application `Test_AppID` exists, if it does not, it will provision the application in the Vault. It will also make sure the application has different authentication methods.

```yaml
- name: Logon 
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"

- name: Application
    cyberark_application:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    app_id: "Test_AppID"
    authentication:
        - AuthType: path
        AuthValue: "/tmp"
        IsFolder: True
        - AuthType: path
        AuthValue: "/var/tmp"
        IsFolder: True
        AllowInternalScripts: True
        - AuthType: path
        AuthValue: "/shr/apps"
        IsFolder: True
        AllowInternalScripts: True
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
        Subject: ["CN=yourcompany.com","OU=IT","C=IL"]
        SubjectAlternativeName: ["DNS Name=www.example.com","IP Address=1.2.3.4"]
    state: present
    cyberark_session: '{{ cyberark_session }}'
    register: cyberark_result

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    state: absent
    cyberark_session: '{{ cyberark_session }}'
```
