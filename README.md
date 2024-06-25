# id-unibe-ch.sys.secretserver - Reads and writes to a Thycotic Secret Server instance

## Synopsis

This module allows you to interact with an Instance of a Thycotic (formerly Delinea) Secret Server
To execute this module, the host it is running on must be cleared to access the Secret Server by both the Firewall
and the ACL. This is why you see `delegate_to` used extensively in the examples.
You can test if your system can reach the Secret Server by doing 
````bash
curl -X POST "https://secretserver.example.com/SecretServer/oauth2/token" \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Accept: */*" \
--data-urlencode "grant_type=password" \
--data-urlencode "username=$USERNAME" \
--data-urlencode "password=$PASSWORD
````

## Installation

Sadly, custom modules (that are not part of a collection) cannot be installed via ansible-galaxy.
So the installation process is a bit more tedious.
If anyone wants to initialize a collection of our own, i'm ready for the PR.

1. Find out where ansible looks for your modules
   ```bash 
   ansible-config dump |grep DEFAULT_MODULE_PATH
   ```
2. Clone the module to one of those locations
3. Make sure you have the `requests` python module installed on all machines that will run this ansible module
4. Use the module like any other (without the FQCN because, again, not part of a collection)

## Parameters

- `secretserver_password`:
  - **Description**: The Password you use to authenticate to the Secret Server. You must specify either the `secretserver_token` or the `secretserver_password`. If both are specified, the token takes precedence.
  - **Required**: `false`
  - **Type**: `str`

- `secretserver_token`:
  - **Description**: The Token you use to authenticate to the Secret Server. You must specify either the `secretserver_token` or the `secretserver_password`. If both are specified, the token takes precedence. You can get a Token by going to the Web UI, clicking the badge on the top right, and navigating to "User Preferences". At the bottom of the page, you have the option to "Generate API Token and Copy to Clipboard".
  - **Required**: `false`
  - **Type**: `str`

- `secretserver_username`:
  - **Description**: The Username you use to authenticate to the Secret Server.
  - **Required**: `true`
  - **Type**: `str`

- `secretserver_base_url`:
  - **Description**: The Base URL of your Secret Server Instance. If your Web UI is at `https://secretserver.example.com/SecretServer/app/#/secrets/view/all`, your Base URL is `https://secretserver.example.com/`.
  - **Required**: `true`
  - **Type**: `str`

- `action`:
  - **Description**: The Action you want to take on the Secret Server. Must be one of "search", "get", "upsert", "update". "search" performs a text search over all the secret names your user has access to. "get" looks up a single secret by its ID. "upsert" will look for the secret_name and folder_id you specify. If no secret exists that matches those two criteria, a new secret will be created. If a secret already exists that matches both criteria, the secret will be updated with the values you provided. If more than one secret matches both criteria, no secret will be changed. You cannot change the secret type or its name with this method. Any other fields you set will be overwritten with that value. If you do not specify a field that was previously set, it will not be overwritten. If you want to explicitly clear a field of any values, specify it to `set_to_none`. "update" updates the password of an existing secret. "get" and "search" will run in check mode, "upsert" and "update" will skip after doing the input validation (ergo the module will still fail in check mode if the input you have given is nonsense or incomplete)
  - **Required**: `true`
  - **Type**: `str`

- `search_text`:
  - **Description**: The text you want to look for. Required for the "search" action.
  - **Required**: `false`
  - **Type**: `str`

- `secret_id`:
  - **Description**: The ID of the Secret you want to target. You can get the ID of a Secret by looking at it in the Web UI. If the URL of the Secret is `https://secretserver.example.com/SecretServer/app/#/secret/1234/general`, its ID is 1234. Required for the "get" and "update" actions.
  - **Required**: `false`
  - **Type**: `int`

- `folder_id`:
  - **Description**: The ID of the folder you want to target. You can get the ID of a folder by looking at it in the Web UI. If the URL of the folder is `https://secretserver.example.com/SecretServer/app/#/secrets/view/folder/9876`, its ID is 9876. Required for the "upsert" action.
  - **Required**: `false`
  - **Type**: `int`

- `type`:
  - **Description**: The type of secret you want to create. Different types have different fields, some of which are required fields. The types and their required fields are:
    - "server": 
      - "secret_name"
      - "user_name"
      - "password"
    - "database": 
      - "secret_name"
      - "database"
      - "user_name"
      - "password"
    - "website":
      - "secret_name"
      - "url"
      - "user_name"
      - "password"
    - "generic":
      - "secret_name"
      - "user_name"
      - "password"
    - "x509"
      - "secret_name"
  - **Required**: `false`
  - **Type**: `str`

- `secret_name`:
  - **Description**: The name of the secret you want to create or update. Required for the "upsert" action with all secret types.
  - **Required**: `false`
  - **Type**: `str`

- `user_name`:
  - **Description**: The value for the "Username" field of the Secret. Required for the "upsert" action with all secret types except for "keypair".
  - **Required**: `false`
  - **Type**: `str`

- `password`:
  - **Description**: The value for the "Password" field. Required for the "upsert" action with all secret types. Required for the "update" action.
  - **Required**: `false`
  - **Type**: `str`

- `database`:
  - **Description**: The value for the "Database" field. Required for the "upsert" action with the "database" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `connection_string`:
  - **Description**: The value for the "Connection string" field. Optional for the "upsert" action with the "database" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `url`:
  - **Description**: The value for the "URL" field. Required for the "upsert" action with the "website" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `fqdn`:
  - **Description**: The value for the "FQDN" field. Optional for the "upsert" action with the "server" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `logon_domain`:
  - **Description**: The value for the "Logon Domain" field. Optional for the "upsert" action with the "server" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `notes`:
  - **Description**: The value for the "Notes" field. Optional for the "upsert" action with any secret type.
  - **Required**: `false`
  - **Type**: `str`

- `common_name`:
  - **Description**: The value for the "CN" field. Optional for the "upsert" action with the "x509" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `alt_name`:
  - **Description**: The value for the "SubjAltName" field. Optional for the "upsert" action with the "x509" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `location`:
  - **Description**: The value for the "Location" field. Optional for the "upsert" action with the "x509" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `private_key`:
  - **Description**: The value for the "Private key" field. Optional for the "upsert" action with the "x509" secret type.
  - **Required**: `false`
  - **Type**: `str`

- `certificate`:
  - **Description**: The value for the "Certificate" field. Optional for the "upsert" action with the "x509" secret type.
  - **Required**: `false`
  - **Type**: `str`

### Full overview of all the parameters for the "upsert" action and with which type they can/must be used

| parameter name                                          | `generic` | `website` | `server` | `database` | `x509`   |
|---------------------------------------------------------|-----------|-----------|----------|------------|----------|
| either secretserver_password <br> or secretserver_token | required  | required  | required | required   | required |
| secretserver_username                                   | required  | required  | required | required   | required |
| secretserver_base_url                                   | required  | required  | required | required   | required |
| action                                                  | required  | required  | required | required   | required |
| folder_id                                               | required  | required  | required | required   | required |
| type                                                    | required  | required  | required | required   | required |
| secret_name                                             | required  | required  | required | required   | required |
| user_name                                               | required  | required  | required | required   | ignored  |
| password                                                | required  | required  | required | required   | optional |
| database                                                | ignored   | ignored   | ignored  | required   | ignored  |
| connection_string                                       | ignored   | ignored   | ignored  | optional   | ignored  |
| url                                                     | ignored   | required  | ignored  | ignored    | ignored  |
| fqdn                                                    | ignored   | ignored   | optional | ignored    | ignored  |
| logon_domain                                            | ignored   | ignored   | optional | ignored    | ignored  |
| notes                                                   | optional  | optional  | optional | optional   | optional |
| common_name                                             | ignored   | ignored   | ignored  | ignored    | optional |
| alt_name                                                | ignored   | ignored   | ignored  | ignored    | optional |
| location                                                | ignored   | ignored   | ignored  | ignored    | optional |  
| private_key                                             | ignored   | ignored   | ignored  | ignored    | optional | 
| certificate                                             | ignored   | ignored   | ignored  | ignored    | optional |

## Examples

```yaml
- name: some acrobatics with the secret server
  hosts: your_hosts
  pre_tasks:
    - name: Load Variables from the Vault
      ansible.builtin.include_vars: "vault.yml"
      run_once: true
    - name: Set variables for the secretserver module
      ansible.builtin.set_fact:
        secretserver_base_url: "https://secretserver.example.com/SecretServer/"
  tasks:
    - name: Get a single Secret by its ID
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: get
        secret_id: 12345
      register: get_secret
      delegate_to: localhost

    - name: dump the secret we got
      debug:
        var: get_secret
        
#      RETURNS:
#        ok: [your_host] => {
#          "get_secret": {
#              "changed": false,
#              "content": {
#                  "Notes": "{'one': 'two', 'three': 'four'}",
#                  "Password": "supersecretpassword",
#                  "Username": "your_username",
#                  "folder_id": "999",
#                  "id": "12345",
#                  "name": "hello world",
#                  "type": "generic"
#              },
#              "failed": false
#          }
#        }
        
    - name: access a field from a python dict we stored in the notes field
      debug:
        msg: "{{ (get_secret['content']['Notes'] | from_yaml)['one'] }}"
        
#        RETURNS:
#          ok: [your_host] => "two"
            
    - name: Search trough all the secret names
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: search
        search_text: "login"
      register: search_secret
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: search_secret
        
#        RETURNS:
#          ok: [your_host] => {
#            "search_secret": {
#                "changed": false,
#                "content": [
#                    {
#                        "id": "001",
#                        "name": "masterloginkey"
#                    },
#                    {
#                        "id": "002",
#                        "name": "windows_login"
#                    },
#                    {
#                        "id": "003",
#                        "name": "login for that one website"
#                    },
#                    {
#                        "id": "004",
#                        "name": "Duplicate of login for that one website"
#                    },
#                    {
#                        "id": "005",
#                        "name": "Duplicate of login for that one website_final"
#                    },
#                    {
#                        "id": "006",
#                        "name": "Duplicate of login for that one website_final_final"
#                    },
#                    {
#                        "id": "007",
#                        "name": "Duplicate of login for that one website_final_final_2.0"
#                    }
#                ],
#                "failed": false
#            }
#        }


    - name: If you narrow down your search enough, so only one secretname matches your search, you get the whole secret details, as if you searched by ID
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: search
        search_text: "a really specific secret name"
      register: unique_search_secret
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: unique_search_secret

    - name: Read a .env file to demonstrate the usage of a token
      ansible.builtin.slurp:
        src: ../.env
      register: env_file_content
      delegate_to: localhost

    - name: Parse the .env file contents
      ansible.builtin.set_fact:
        env_vars: "{{ ('{' + (env_file_content.content | b64decode).split('\n') | select | map('regex_replace', '([^=]*)=(.*)', '\"\\1\": \"\\2\"') | join(',') + '}') | from_json }}"

    - name: make a search with a personal access token
      secretserver:
        secretserver_token: "{{ env_vars['SECRET_SERVER_TOKEN'] }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: get
        secret_id: 12345
      register: get_secret
      delegate_to: localhost

    - name: dump the secret we got
      debug:
        var: get_secret

    - name: Create a generic account
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: upsert
        type: "generic"
        folder_id: 999
        secret_name: "{{ 'lookup_module_test_generic' + 9999999 | random | string }}"
        user_name: "root"
        password: "{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=12') }}"
        notes:
          key1: value1
          key2: value2
      register: generic_account
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: generic_account
          
#      RETURNS:
#        ok: [your_host] => {
#          "generic_account": {
#              "changed": true,
#              "data": {
#                  "secret_id": 9876
#              },
#              "failed": false
#          }
#        }

    - name: Create a website login
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: upsert
        type: "website"
        folder_id: 999
        secret_name: "{{ 'lookup_module_test_website' + 9999999 | random | string }}"
        user_name: "root"
        password: "{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=12') }}"
        url: "https://www.example.com"
      register: website_login
      delegate_to: localhost

    - name: dump the secret result
      debug:
       var: website_login


    - name: Create a database account
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: upsert
        type: "database"
        folder_id: 999
        secret_name: "{{ 'lookup_module_test_database' + 9999999 | random | string }}"
        user_name: "root"
        password: "{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=12') }}"
        database: "jdbc:www.hostedpostgres.com:5432/mydb"
      register: database_account
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: database_account

    - name: Create a server account
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: upsert
        type: "server"
        folder_id: 999
        secret_name: "{{ 'lookup_module_test_server' + 9999999 | random | string }}"
        user_name: "root"
        password: "{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=12') }}"
        database: "jdbc:www.hostedpostgres.com:5432/mydb"
      register: server_account
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: server_account

    - name: Create a TLS certificate
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: upsert
        type: "x509"
        folder_id: 999
        secret_name: "{{ 'lookup_module_test_x509_' + 9999999 | random | string }}"
        common_name: "www.example.com"
        alt_name:
          - "example.com"
          - "mail.example.com"
          - "cms.example.com"
        password: "{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=12') }}"
        certificate: '---- BEGIN SSH2 PUBLIC KEY ---- Comment: "eddsa-key-20240412" AAAAC3NzaC1lZDI1NTE5AAAAYTBg429H1ds VUqH ---- END SSH2 PUBLIC KEY ----'
        private_key: "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAAABAAAAMwAAAAtz -----END OPENSSH PRIVATE KEY-----"
      register: x509_certificate
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: x509_certificate

    - name: Change the username and password of a Secret by searching for the secret
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: upsert
        type: "generic"
        folder_id: 999
        secret_name: "your secret name"
        user_name: "hello"
        password: "world_{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=4') }}"
      register: password_change_with_search
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: password_change_with_search

    - name: Change the password of a Secret by secret id
      secretserver:
        secretserver_password: "{{ vault_secretserver_password }}"
        secretserver_username: "{{ vault_secretserver_username }}"
        secretserver_base_url: "{{ secretserver_base_url }}"
        action: update
        secret_id: 12345
        password: "{{ lookup('password', '/dev/null chars=ascii_lowercase,digits length=20') }}"
      register: password_change_by_id
      delegate_to: localhost

    - name: dump the secret result
      debug:
        var: password_change_by_id
```
