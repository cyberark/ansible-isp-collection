# cyberark_user

This module allows admins to Add, Delete, and Modify CyberArk Vault Users.  The ability to modify consists of the following:

* Enable User<br>
* Disable User<br>
* Add/Remove Group<br>
* Set New Password<br>
* Force "change password at next login"<br>
* Modify User Information Fields<br>
  * Email<br>
  * First Name<br>
  * Last Name<br>
  * Expiry Date<br>
  * User Type<br>
  * Location<br>

#### Limitations
**Idempotency** - All actions taken in the playbook adhere to the Ansible idempotency guidelines _except_ for password change.  If you have the playbook set to modify a password it will "modify" the password every time the playbook is run, even if it is the same password.<br>
**Group Creation** - If the value for `group_name` does not exist in the Vault it will not create that group, the user action that was expected will fail.

#### Available Fields
    
```
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
    password:
        description:
            - The password that the user will use to log on for the first time.
            - This password must meet the password policy requirements.
            - Not required for PKI or LDAP.
        type: str
    authentication_method:
        description:
            - The user authentication method.
        type: str
        choices: [AuthTypePass, AuthTypeRadius, AuthTypeLDAP]
    change_pass_on_next_logon:
        description:
            - Whether or not the user must change their password in their
              next logon.
        type: bool
        default: false
    password_never_expires:
        description:
            - Password never expires.
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
    user_type:
        description:
            - The type of user.
            - The parameter defaults to C(EPVUser).
        type: str
    non_authorized_interfaces:
        description:
            - The CyberArk interfaces that this user is not authorized to use.
        type: list
        elements: str
    enable_user:
        description:
            - Whether or not the user will be disabled.
        type: bool
        default: true
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
    distinguished_name:
        description:
            - The user's distinguished name. The usage is for PKI authentication,
            - this will match the certificate Subject Name or domain name.
        type: str
    vault_authorization:
        description:
            - A list of authorization options for this user.
            - Options can include AddSafes and AuditUsers
            - The default provides backwards compatability with older versions of the collection
        type: list
        elements: str
        choices:
          - AddSafes
          - AuditUsers
          - AddUpdateUsers
          - ResetUsersPasswords
          - ActivateUsers
          - AddNetworkAreas
          - ManageDirectoryMapping
          - ManageServerFileCategories
          - BackupAllSafes
          - RestoreAllSafes
        default:
          - AddSafes
          - AuditUsers
    business_address:
        description:
            - The user's postal address, including city, state, zip, country and street
        type: dict
        suboptions:
            workStreet:
                description: Street for work address.
                type: str
                default: ""
            workCity:
                description: City for work address.
                type: str
                default: ""
            workState:
                description: State.
                type: str
                default: ""
            workZip:
                description: Zip code.
                type: str
                default: ""
            workCountry:
                description: Country.
                type: str
                default: ""
    internet:
        description:
            - The user's email addresses, including home page and email, business and other email
        type: dict
        suboptions:
            homePage:
                description: Homepage URL.
                type: str
                default: ""
            homeEmail:
                description: Personal email.
                type: str
                default: ""
            businessEmail:
                description: Work email.
                type: str
                default: ""
            otherEmail:
                description: Other email.
                type: str
                default: ""
    phones:
        description:
            - The user's phone numbers, including home, business, cellular, fax and pager
        type: dict
        suboptions:
            homeNumber:
                description: Home phone number.
                type: str
                default: ""
            businessNumber:
                description: Work phone number.
                type: str
                default: ""
            cellularNumber:
                description: Cellular phone number.
                type: str
                default: ""
            faxNumber:
                description: Fax number.
                type: str
                default: ""
            pagerNumber:
                description: Pager number.
                type: str
                default: ""
    description:
        description:
            - Notes and comments.
        type: str
    personal_details:
        description:
            - The user's personal details including
            - firstName, middleName, lastName, address
            - city, state, zip, country
            - title, organization, department, profession
        type: dict
        suboptions:
            firstName:
                description: First name.
                default: ""
                type: str
            lastName:
                description: Last name.
                default: ""
                type: str
            middleName:
                description: Middle Name.
                default: ""
                type: str
            street:
                description: Street.
                default: ""
                type: str
            city:
                description: City.
                default: ""
                type: str
            state:
                description: State.
                default: ""
                type: str
            zip:
                description: Zip.
                default: ""
                type: str
            country:
                description: Country.
                default: ""
                type: str
            title:
                description: Title.
                default: ""
                type: str
            organization:
                description: Organization.
                default: ""
                type: str
            department:
                description: Department.
                default: ""
                type: str
            profession:
                description: Profession.
                default: ""
                type: str
```
## Example Playbooks

This playbook will check if username `admin` exists, if it does not, it will provision the user in the Vault, add it to the `Auditors` group and set the account to be changed at first logon.

```yaml
- name: Logon 
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"

- name: Create user, add to Group
  cyberark_user:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    username: admin
    first_name: "Cyber"
    last_name: "Admin"
    email: "cyber.admin@ansibledev.com"
    initial_password: PA$$Word123
    user_type_name: EPVUser
    change_password_on_the_next_logon: true
    group_name: Auditors
    state: present
    cyberark_session: '{{ cyberark_session }}'
  register: cyberarkaction

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "https://tenant.id.cyberark.cloud"
    state: absent
    cyberark_session: '{{ cyberark_session }}'
```

This playbook will identify the user and delete it from the CyberArk Vault based on the `state: absent` parameter.

```yaml
- name: Logon 
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"

- name: Removing a CyberArk User
  cyberark_user:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    username: "ansibleuser"
    state: absent
    cyberark_session: "{{ cyberark_session }}"
  register: cyberarkaction
    
- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    state: absent
    cyberark_session: "{{ cyberark_session }}"
```
This playbook is an example of disabling a user based on the `disabled: true` value with that authentication using the credential set in Tower.
```yaml
- name: Logon 
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    client_id: "{{ password_object.password }}"
    client_secret: "{{ password_object.passprops.username }}"
    
- name: Disabling a CyberArk User
  cyberark_user:
    api_base_url: "https://tenant.privilegecloud.cyberark.cloud"
    username: "ansibleuser"
    disabled: true
    cyberark_session: "{{ cyberark_session }}"
  register: cyberarkaction

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    state: absent
    cyberark_session: "{{ cyberark_session }}"
```
