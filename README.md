<!-- please note this has to be a absolute URL since otherwise it will not show up on galaxy.ansible.com -->
![cyberark logo|](https://github.com/cyberark/ansible-isp-collection/blob/master/docs/images/full-cyberark-logo.jpg?raw=true)

## CyberArk Identity Security Platform (ISP) Collection

*************

## Collection

#### cyberark.isp

This collection is the CyberArk Identity Security Platform (ISP) project and can be found on [ansible galaxy](https://galaxy.ansible.com/cyberark/isp). This is aimed to enable the automation of securing privileged access by storing privileged accounts in the Enterprise Password Vault (EPV), controlling user's access to privileged accounts in EPV, and securely retrieving secrets using Central Credential Provider (CCP).


The following modules will allow CyberArk administrators to automate the following tasks:

#### Requirements

- Ansible Core 2.15.0 or above
- CyberArk Privilege Cloud REST APIs
- CyberArk Central Credential Provider (**Only required for cyberark_credential**)

## Modules

#### cyberark_authentication

- Using the CyberArk Privilege Cloud REST APIs, authenticate and obtain an auth token to be passed as a variable in playbooks
- Logoff of an authenticated REST API session<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/master/docs/cyberark_authentication.md)

#### cyberark_user

- Add a CyberArk User
- Delete a CyberArk User
- Update a CyberArk User's account parameters
- Enable/Disable, change password, mark for change at next login, etc
<br>[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/master/docs/cyberark_user.md)<br/>

#### cyberark_account

- Add Privileged Account to the EPV
- Delete account objects
- Modify account properties
- Rotatate privileged credentials
- Retrieve account password<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/master/docs/cyberark_account.md)

#### cyberark_credential

- Using CyberArk Central Credential Provider (CCP), to securely retrieve secrets and account properties from EPV to be registered for use in playbooks<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-isp-collection/blob/master/docs/cyberark_credential.md)


#### Python3

- The modules will work with either python2 or python3.

#### Author Information
- CyberArk Business Development Technical Team 
    - @cyberark-bizdev

