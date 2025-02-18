# cyberark_authentication


Authenticates to CyberArk Vault using Privilege Cloud REST APIs and creates a session fact that can be used by other modules. It returns an Ansible fact called `cyberark_session`. Every module can use this fact as `cyberark_session` parameter.


#### Available Fields
```
options:
    state:
        default: present
        choices: [present, absent]
        description:
            - Specifies if an authentication logon and a
              cyberark_session should be added.
        type: str
    grant_type:
        default: client_credentials
        description:
            - The type of grant for the authentication.
        type: str
    client_id:
        description:
            - The login name of the service account for authentication.
        type: str
    client_secret:
        description:
            - The password of the service account.
        type: str
    api_base_url:
        description:
            - A string containing the base URL of the server hosting
              CyberArk's Privileged Cloud ISP SDK.
        type: str
    timeout:
        description:
            - Allows you set a timeout for when your authenticating to Cyberark
        default: 10
        type: int
```
## Example Playbooks

In addition to SSL, use Client Authentication to authenticate Ansible using a client certificate.

[Configuring client authentication via certificates](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Configuring%20Client%20Authentication%20via%20Client%20Certificates.htm)

**CyberArk Authentication**<br/>
This method authenticates a user to the Vault and returns a token that can be used in subsequent web services calls. In addition, this method allows you to set a new password.

Users can authenticate using **CyberArk**, **LDAP** or **RADIUS** authentication.

```yaml
- name: Logon to CyberArk Vault using Privilege Cloud REST APIs - Not use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    username: "{{ password_object.password }}"
    password: "{{ password_object.passprops.username }}"
    use_shared_logon_authentication: false
```
**Logoff**<br/>
This method logs off the user and removes the Vault session.

```yaml
- name: Logoff from CyberArk Vault
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    state: absent
    cyberark_session: "{{ cyberark_session }}
```
