# cyberark_safe_member

This module allows admins to Add, Delete, and Modify CyberArk Safe Members.

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
```
## Example Playbooks

This playbook will check if application `Test_AppID` exists, if it does not, it will provision the application in the Vault. It will also make sure the application has different authentication methods.

```yaml
- name: Logon 
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"

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

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    state: absent
    cyberark_session: '{{ cyberark_session }}'
```
