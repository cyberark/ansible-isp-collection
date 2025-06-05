# CyberArk Identity Security Platform (ISP) Collection

<!-- please note this has to be a absolute URL since otherwise it will not show up on galaxy.ansible.com -->
![cyberark logo|](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/images/full-cyberark-logo.jpg?raw=true)

*************

## Description
This collection is the CyberArk Identity Security Platform (ISP) project and can be found on [ansible galaxy](https://galaxy.ansible.com/cyberark/isp). This is aimed to enable the automation of securing privileged access by storing privileged accounts in the Enterprise Password Vault (EPV), controlling user's access to privileged accounts in EPV, and securely retrieving secrets using Central Credential Provider (CCP).

## Requirements

- Ansible Core 2.15.0 or above
- CyberArk Privilege Cloud REST APIs
- CyberArk Central Credential Provider (**Only required for cyberark_credential**)

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install cyberark.isp
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: cyberark.isp
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install cyberark.isp --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```
ansible-galaxy collection install cyberark.isp:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

There is a list of different modules to perform different tasks:

- Add, Delete, Update CyberArk Users
- Add, Delete, Update Application and App Authentications
- Add, Delete, Update Safe and Safe Members
- Add, Delete, Update CyberArk Accounts
- Rotate Account Credentials

### Modules

#### cyberark_authentication

- Using the CyberArk Privilege Cloud REST APIs, authenticate and obtain an auth token to be passed as a variable in playbooks
- Logoff of an authenticated REST API session<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_authentication.md)

#### cyberark_user

- Add a CyberArk User
- Delete a CyberArk User
- Update a CyberArk User's account parameters
- Enable/Disable, change password, mark for change at next login, etc
<br>[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_user.md)<br/>

#### cyberark_account

- Add Privileged Account to the EPV
- Delete account objects
- Modify account properties
- Rotatate privileged credentials
- Retrieve account password<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_account.md)

#### cyberark_safe

- Create Safe
- Delete Safe
- Update Safe
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_safe.md)

#### cyberark_safe_member

- Add Safe Member
- Delete Safe Member
- Update Safe Member
- Add/Update/Delete Safe Member Permissions
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_safe_member.md)

#### cyberark_application

- Create Application
- Delete Aplication
- Update Application
- Add/Update/Delete Application Authentication
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_application.md)

#### cyberark_credential

- Using CyberArk Central Credential Provider (CCP), to securely retrieve secrets and account properties from EPV to be registered for use in playbooks<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/main/docs/cyberark_credential.md)


### Author Information
- CyberArk Business Development Technical Team 
    - @cyberark-bizdev
    - @nitsan-tzur
    - @compostCY

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the Create issue button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may community help available on the [Ansible Forum](https://forum.ansible.com/).

## License

Apache License

For the full license text see [LICENSE](https://github.com/cyberark/ansible-isp-collection/blob/main/LICENSE)
