#!/usr/bin/python

# Copyright: (c) This module was created in 2024 by the IT-Services Office of the University of Bern
# MIT License
from __future__ import (division, print_function)

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

import ansible.module_utils.secretserver_api as api

DOCUMENTATION = r'''
---
module: secretserver

short_description: Reads and writes to a Thycotic Secret Server instance

version_added: "1.0.0"

description: This module allows you to interact with an Instance of a Thycotic (formerly Delinea) Secret Server
    To execute this module, the host it is running on must be cleared to access the Secret Server by both the Firewall
    and the ACL. This is why you see `delegate_to` used extensively in the examples.
    You can test if your system can reach the Secret Server by doing 
    `curl -X POST "https://secretserver.example.com/SecretServer/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Accept: */*" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$USERNAME" \
    --data-urlencode "password=$PASSWORD`

options:
    secretserver_password:
        description: The Password you use to authenticate to the Secret Server. 
            You must specify either the secretserver_token or the secretserver_password. 
            If both are specified, the token takes precedence.
        required: false
        type: str
    secretserver_token:
        description: The Token you use to authenticate to the Secret Server. 
            You must specify either the secretserver_token or the secretserver_password. 
            If both are specified, the token takes precedence.
            You can get a Token by going to the Web UI, 
            clicking the badge on the top right and navigating to "User Preferences".
            At the bottom of the page, you have the option to "Generate API Token and Copy to Clipboard"
        required: false
        type: str
    secretserver_username: 
        description: The Username you use to authenticate to the Secret Server.
        required: true
        type: str
    secretserver_base_url: 
        description: The Base URL of your Secret Server Instance
            If your Web UI is at `https://secretserver.example.com/SecretServer/app/#/secrets/view/all`,
            your Base URL is `https://secretserver.example.com/`.
        required: true
        type: str
    action: 
        description: The Action you want to take on the secret Server.
            Must be one of "search", "get", "upsert", "update".
            "search" performs a text search over all the secret names your user has access to.
            "get" looks up a single secret by its ID.
            "upsert" will look for the secret_name and folder_id you specify. 
            If no secret exists that match those two criteria, a new secret will be created.
            If a secret already exists that matches both criteria, 
            the secret will be updated with the values you provided.
            If more than one secret matches both criteria, no secret will be changed.
            You cannot change the secret type or its name with this method.
            Any other fields you set will be overwritten with that value.
            If you do not specify a field that was previously set, it will not be overwritten.
            If you want to explicitly clear a field of any values, specify it to `set_to_none`.
            "update" updates the password of an existing secret
            "get" and "search" will run in check mode, 
            "upsert" and "update" will return after doing the input validation 
        required: true
        type: str
    search_text: 
        description: The text you want to look for. Required for the "search" action
        required: false
        type: str
    secret_id: 
        description: The ID of the Secret you want to target.
            You can get the ID of a Secret by looking at it in the Web UI.
            If the URL uf the Secret is `https://secretserver.example.com/SecretServer/app/#/secret/1234/general`,
            its ID is 1324.
            Required for the "get" and "update" actions. 
        required: false
        type: int
    folder_id: 
        description: The ID of the folder you want to target.
            You can get the ID of a folder by looking at it in the Web UI.
            If the URL uf the folder is `https://secretserver.example.com/SecretServer/app/#/secrets/view/folder/9876`,
            its ID is 9876.
            Required for the "upsert" action.
        required: false
        type: int
    type: 
        description: The type of secret you want to create.
            Different types have different fields, some of which are required fields.
            The types and their required fields are:
            "server": 
                - "secret_name"
                - "user_name"
                - "password"
            "database": 
                - "secret_name"
                - "database"
                - "user_name"
                - "password"
            "website":
                - "secret_name"
                - "url"
                - "user_name"
                - "password"
            "generic":
                - "secret_name"
                - "user_name"
                - "password"
        required: false
        type: str
    secret_name: 
        description: The name of the secret you want to create or update.
            Required for the "upsert" action with all secret types.
        required: false
        type: str
    user_name: 
        description: The value for the "Username" field of the Secret.
            Required for the "upsert" action with all secret types.
        required: false
        type: str
    password: 
        description: The value for the "Password" field.
            Required for the "upsert" action with all secret types except for "keypair".
            Required for the "update" action.
        required: false
        type: str
    database: 
        description: The value for the "Database" field.
            Required for the "upsert" action with the "database" secret type.
        required: false
        type: str
    connection_string: 
        description: The value for the "Connection string" field.
            Optional for the "upsert" action with the "database" secret type.
        required: false
        type: str
    url: 
        description: The value for the "URL" field.
            Required for the "upsert" action with the "website" secret type.
        required: false
        type: str
    fqdn: 
        description: The value for the "FQDN" field.
            Optional for the "upsert" action with the "server" secret type.
        required: false
        type: str
    logon_domain: 
        description: The value for the "Logon Domain" field.
            Optional for the "upsert" action with the "server" secret type.
        required: false
        type: str
    notes: 
        description:The value for the "Notes" field.
            Optional for the "upsert" action with any secret type.
        required: false
        type: str
    host: 
        description:The value for the "Host" field.
            Optional for the "upsert" action with the "keypair" secret type.
        required: false
        type: str
    location: 
        description:The value for the "Location" field.
            Optional for the "upsert" action with the "keypair" secret type.
        required: false
        type: str
    private_key: 
        description:The value for the "Private key" field.
            Optional for the "upsert" action with the "keypair" secret type.
        required: false
        type: str
    public_key: 
        description:The value for the "Public key" field.
            Optional for the "upsert" action with the "keypair" secret type.
        required: false
        type: str
    
        
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - id-unibe-ch.sys.secretserver

author:
    - Matthias Studer (@studerma)
'''

EXAMPLES = r'''
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

    - name: If you narrow down your search enough, so only one secretname matches your search, you get the whle secret details
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
'''

RETURN = r'''
data:
    description: The id of the secret that was targeted
    type: dict
    returned: by the "upsert" and "update" actions
    sample: "data": {"secret_id": 12345 }
content:
    description: The result of your search/lookup
    type: dict
    returned: by the "get" and "search" actions
    sample: "content": {
            "Notes": "Why did the functional programmer get thrown out of school? Because he refused to take classes.",
            "Password": "supersecretpassword",
            "Username": "my_user_name",
            "folder_id": "999",
            "id": "12345",
            "name": "Your secret's name"
        }
'''


def main():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        secretserver_password=dict(type='str', required=False, no_log=True),
        secretserver_token=dict(type='str', required=False, no_log=True),
        secretserver_username=dict(type='str', required=True),
        secretserver_base_url=dict(type='str', required=True),
        action=dict(type='str', required=True),
        search_text=dict(type='str', required=False),
        secret_id=dict(type='int', required=False),
        folder_id=dict(type='int', required=False),
        type=dict(type='str', required=False),
        secret_name=dict(type='str', required=False),
        user_name=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        database=dict(type='str', required=False),
        connection_string=dict(type='str', required=False),
        url=dict(type='str', required=False),
        fqdn=dict(type='str', required=False),
        logon_domain=dict(type='str', required=False),
        notes=dict(type='str', required=False),
        host=dict(type='str', required=False),
        location=dict(type='str', required=False),
        private_key=dict(type='str', required=False, no_log=True),
        public_key=dict(type='str', required=False)
    )

    result = {}
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # input validation
    permitted_actions = ["search", "get", "upsert", "update"]
    if module.params.get("action") not in permitted_actions:
        module.fail_json(msg=f'Action must be one of {", ".join(permitted_actions)}', **result)

    action = module.params.get("action")
    if action == "get":
        if module.params.get("secret_id") is None or not int(module.params.get("secret_id")):
            module.fail_json(msg="secret_id is mandatory for action 'get'", **result)

    elif action == "search":
        if module.params.get("search_text") is None or len(module.params.get("search_text")) < 1:
            module.fail_json(msg="You must specify a search_text to use the search function", **result)

    elif action == "upsert":
        for key in ["secret_name", "folder_id", "type"]:
            if module.params.get(key) is None:
                module.fail_json(msg=f"You must specify a {key} to use the upsert function", **result)
        if not int(module.params.get("folder_id")):
            module.fail_json(msg=f"the folder_id must be parseable to an integer", **result)

        if module.params.get("secret_type"):
            secret_type = module.params.get("secret_type")
            # Establishing what types we can handle and what their required fields are
            acceptable_types = {"server": ["secret_name", "user_name", "password"],
                                "database": ["secret_name", "database", "user_name", "password"],
                                "website": ["secret_name", "url", "user_name", "password"],
                                "generic": ["secret_name", "user_name", "password"],
                                "keypair": ["secret_name"]
                                }
            if secret_type not in acceptable_types.keys:
                module.fail_json(msg=f"the secret type must be one of {', '.join(acceptable_types)}", **result)
            for field in acceptable_types.get(secret_type):
                if module.params.get(field) is None:
                    module.fail_json(msg=f"you must specify {field} to upsert a {secret_type}", **result)

    elif action == "update":
        mandatory_fields = ["secret_id", "password"]
        for field in mandatory_fields:
            if not module.params.get(field):
                module.fail_json(msg=f"you must specify {field} to update an item", **result)

    # Authenticating with the Secret Server
    client = None
    if module.params.get("secretserver_password") is None and module.params.get('secretserver_token') is None:
        module.fail_json(msg="You must pass either secretserver_token or secretserver_password", **result)
    try:
        client = api.Auth(user_name=module.params.get("secretserver_username"),
                          password=module.params.get("secretserver_password"),
                          token=module.params.get('secretserver_token'),
                          base_url=module.params.get("secretserver_base_url")
                          )

    except Exception as e:
        if type(e) == type(TypeError) and str(e) == "unsupported operand type(s) for -: 'NoneType' and 'int'":
            module.fail_json(msg="could not log into Secret Server. "
                                 "This is most likely because you specified the wrong username/password combination",
                             **result)
        else:
            module.fail_json(msg=f"could not log into Secret Server: {e}, {type(e)}, :{str(e)}:", **result)
    if client is None or not client.get_authenticated_headers():
        module.fail_json(msg=f"error authenticating with the Secret Server", **result)

    # executing the action
    if action == "get":
        res = api.lookup_single_secret(client=client, secret_id=int(module.params.get("secret_id")))
        if res.get("success"):
            result["content"] = res.get("content")
            module.exit_json(**result)
        else:
            module.fail_json(msg=f"error getting secret {res}", **result)

    elif action == "search":
        res = api.search_by_name(client=client, search_text=module.params.get("search_text"))
        if res.get("success"):
            result["content"] = res.get("content")
            module.exit_json(**result)
        else:
            module.fail_json(msg=f"error searching for secret {res}", **result)

    elif action == "upsert":
        if module.check_mode:
            module.exit_json(skipped=True, msg="Upsert will do nothing in check mode")
        else:
            res = api.update_secret(client=client,
                                    secret_name=module.params.get("secret_name"),
                                    user_name=module.params.get("user_name"),
                                    password=module.params.get("password"),
                                    folder_id=int(module.params.get("folder_id")),
                                    connection_string=module.params.get("connection_string"),
                                    url=module.params.get("url"),
                                    database=module.params.get("database"),
                                    secret_type=module.params.get("type"),
                                    notes=module.params.get("notes"),
                                    fqdn=module.params.get("fqdn"),
                                    logon_domain=module.params.get("logon_domain"),
                                    host=module.params.get("host"),
                                    location=module.params.get("location"),
                                    private_key=module.params.get("private_key"),
                                    public_key=module.params.get("public_key")
                                    )
            if not res.get("success"):
                module.fail_json(msg=f"error upserting secret {res}", **result)

            else:
                result["data"] = res.get("data")
                result["changed"] = res.get("changed")
                module.exit_json(**result)

    elif action == "update":
        if module.check_mode:
            module.exit_json(skipped=True, msg="Update will do nothing in check mode")
        else:
            res = api.update_secret_by_id(
                client=client,
                secret_id=int(module.params.get("secret_id")),
                updated_password=module.params.get("password")
            )
            if not res.get("success"):
                module.fail_json(msg=f"error updating secret {res}", **result)

            else:
                result["data"] = res.get("text")
                result["changed"] = res.get("changed")
                module.exit_json(**result)


if __name__ == '__main__':
    main()
