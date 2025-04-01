# cyberark_safe

This module allows admins to Add, Delete, and Modify CyberArk Safes.

#### Available Fields
    
```
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

- name: Safe
    cyberark_safe:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    description: "Safe for Partner Test"
    logging_level: DEBUG
    safe_name: "Partner-Test"
    number_of_days_retention: 7
    state: present
    cyberark_session: '{{ cyberark_session }}'
    register: cyberark_result

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    state: absent
    cyberark_session: '{{ cyberark_session }}'
```
