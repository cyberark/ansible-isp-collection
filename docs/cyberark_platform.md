# cyberark_platform

This module allows admins to manage platforms with the following actions: activate, deactivate, duplicate and delete.

#### Available Fields
    
```
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
```
## Example Playbooks

This playbook will check if platform `TEST-NEW` exists, if it does not, it will duplicate it from `TEST-BASE` platform. It will also make sure the platform is active (updating it if needed).

```yaml
- name: Logon 
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"

- name: Platform
  cyberark_platform:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    logging_level: DEBUG
    platform_id: "TEST-NEW"
    duplicate_from_platform: "TEST-BASE"
    state: active
    cyberark_session: '{{ cyberark_session }}'
  register: cyberark_result

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    state: absent
    cyberark_session: '{{ cyberark_session }}'
```
