#!/usr/bin/python

# Copyright: (c) This module was created in 2024 by the IT-Services Office of the University of Bern
# MIT License
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import datetime

import requests
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.basic import AnsibleModule

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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_token: "{{ env_vars['SECRET_SERVER_TOKEN'] }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
        secertserver_password: "{{ vault_secretserver_password }}"
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
message:
    content: The result of your search/lookup
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
base_url = None
authenticated_headers = None


class Auth:
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*'
    }

    def __init__(self, config):
        self._base_url = base_url
        self._user_name = config.get("user_name")
        self._password = config.get("password")
        self._token_valid_until = None
        self._access_token = None
        self._refresh_token = None

    def get_token(self):
        if self._access_token is None \
                or not isinstance(self._token_valid_until, datetime.datetime):
            return self._get_initial_token()

        if datetime.datetime.now() < self._token_valid_until:
            return self._access_token

        if self._refresh_token is not None:
            return self._refresh_access_token()

        return self._get_initial_token()

    def _get_initial_token(self):
        url = f"{self._base_url}oauth2/token"
        data = f"grant_type=password&username={self._user_name}&password={self._password}"
        response = requests.request(
            "POST",
            url,
            headers=self.headers,
            data=data
        )
        response_data = response.json()
        self._refresh_token = response_data.get("refresh_token")
        self._access_token = response_data.get("access_token")
        self._token_valid_until = datetime.datetime.now() + datetime.timedelta(
            seconds=(response_data.get("expires_in") - 10))
        return self._access_token

    def _refresh_access_token(self):
        response = requests.request(
            "POST",
            f"{self._base_url}oauth2/token",
            headers=self.headers,
            data=f"grant_type=refresh_token&refresh_token={self._refresh_token}"
        )
        response_data = response.json()
        self._refresh_token = response_data.get("refresh_token")
        self._access_token = response_data.get("access_token")
        self._token_valid_until = datetime.datetime.now() + datetime.timedelta(
            seconds=(response_data.get("expires_in") - 10))
        return self._access_token


def get_secret_body(secret_name: str,
                    secret_type: str,
                    folder_id: int,
                    logon_domain: str,
                    fqdn: str,
                    notes: str,
                    password: str,
                    user_name: str,
                    database: str,
                    connection_string: str,
                    url: str,
                    host: str,
                    location: str,
                    private_key: str,
                    public_key: str
                    ) -> dict:
    type_mapping = {"generic": {
        "template_id": 6010,
        "items": [
            {
                "fieldDescription": "",
                "fieldId": 126,
                "fieldName": "Username",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": user_name,
                "listType": "None",
                "slug": "username"
            },
            {
                "fieldDescription": "Password",
                "fieldId": 122,
                "fieldName": "Password",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": True,
                "itemValue": password,
                "slug": "password"
            },
            {
                "fieldDescription": "",
                "fieldId": 124,
                "fieldName": "Notes",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": True,
                "isPassword": False,
                "itemValue": notes,
                "listType": "None",
                "slug": "notes"
            }
        ]

    }, "website": {
        "template_id": 9,
        "items": [
            {
                "fieldDescription": "The name associated with the web password.",
                "fieldId": 39,
                "fieldName": "Username",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": user_name,
                "listType": "None",
                "slug": "username"
            },
            {
                "fieldDescription": "The password used to access the URL.",
                "fieldId": 40,
                "fieldName": "Password",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": True,
                "itemValue": password,
                "slug": "password"
            },
            {
                "fieldDescription": "",
                "fieldId": 41,
                "fieldName": "Notes",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": True,
                "isPassword": False,
                "itemValue": notes,
                "listType": "None",
                "slug": "notes"
            },
            {
                "fieldDescription": "The online address where the information is being secured.",
                "fieldId": 38,
                "fieldName": "URL",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": url,
                "listType": "None",
                "slug": "url"
            }
        ]

    }, "database": {
        "template_id": 6008,
        "items": [
            {
                "fieldDescription": "The Oracle Server Username.",
                "fieldId": 115,
                "fieldName": "Username",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": user_name,
                "listType": "None",
                "slug": "username"
            },
            {
                "fieldDescription": "The password of the Oracle user.",
                "fieldId": 113,
                "fieldName": "Password",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": True,
                "itemValue": password,
                "slug": "password"
            },
            {
                "fieldDescription": "Any additional notes.",
                "fieldId": 112,
                "fieldName": "Notes",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": True,
                "isPassword": False,
                "itemValue": notes,
                "listType": "None",
                "slug": "notes"
            },
            {
                "fieldDescription": "",
                "fieldId": 229,
                "fieldName": "Connection string",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": connection_string,
                "listType": "None",
                "slug": "connection-string"
            },
            {
                "fieldDescription": "The Database name or instance.",
                "fieldId": 138,
                "fieldName": "Database",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": database,
                "listType": "None",
                "slug": "database"
            }
        ]

    }, "server": {
        "template_id": 6026,
        "items": [
            {
                "fieldDescription": "",
                "fieldId": 187,
                "fieldName": "Username",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": user_name,
                "listType": "None",
                "slug": "username"
            },
            {
                "fieldDescription": "Password",
                "fieldId": 188,
                "fieldName": "Password",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": True,
                "itemValue": password,
                "slug": "password"
            },
            {
                "fieldDescription": "",
                "fieldId": 189,
                "fieldName": "Notes",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": True,
                "isPassword": False,
                "itemValue": notes,
                "listType": "None",
                "slug": "note"
            },
            {
                "fieldDescription": "Used by Launcher to connect",
                "fieldId": 206,
                "fieldName": "FQDN",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": fqdn,
                "listType": "None",
                "slug": "fqdn-1"
            },
            {
                "fieldDescription": "",
                "fieldId": 204,
                "fieldName": "Logon Domain",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": logon_domain,
                "listType": "None",
                "slug": "logon-domain"
            }
        ]

    }, "keypair": {
        "template_id": 6027,
        "items": [
            {
                "fieldDescription": "Where the key is used (FQDN)",
                "fieldId": 190,
                "fieldName": "Host",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": host,
                "slug": "host"
            },
            {
                "fieldDescription": "Where the key is stored",
                "fieldId": 236,
                "fieldName": "Location",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": True,
                "itemValue": location,
                "slug": "location"
            },
            {
                "fieldDescription": "As text",
                "fieldId": 194,
                "fieldName": "Private key",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": private_key,
                "listType": "None",
                "slug": "private-key-1"
            },
            {
                "fieldDescription": "Password for private key",
                "fieldId": 237,
                "fieldName": "Password",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": True,
                "itemValue": password,
                "listType": "None",
                "slug": "password"
            },
            {
                "fieldDescription": "As text",
                "fieldId": 193,
                "fieldName": "Public key",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": False,
                "isPassword": False,
                "itemValue": public_key,
                "listType": "None",
                "slug": "private-key-1"
            },
            {
                "fieldDescription": "",
                "fieldId": 195,
                "fieldName": "Notes",
                "fileAttachmentId": 0,
                "filename": "",
                "isFile": False,
                "isList": False,
                "isNotes": True,
                "isPassword": False,
                "itemValue": notes,
                "listType": "None",
                "slug": "notes"
            }
        ]

    }
    }

    return {
        "name": secret_name,
        "secretTemplateId": type_mapping.get(secret_type).get("template_id"),
        "folderId": folder_id,
        "items": type_mapping.get(secret_type).get("items"),
        "enableInheritPermissions": True,
        "enableInheritSecretPolicy": True,
        "requiresComment": False,
        "secretPolicyId": 0,
        "siteId": 1,
        "sessionRecordingEnabled": False
    }


def search_by_name(search_text: str) -> list | dict:
    url = f"{base_url}api/v2/secrets?filter.searchText={search_text}"
    response = requests.request("GET", url, headers=authenticated_headers, data={})
    if response.status_code == 200:
        json_data = json.loads(response.text)
        records_list = []
        if "records" in json_data:
            for record in json_data.get("records"):
                records_list.append({"name": to_text(record.get("name")), "id": to_text(record.get("id"))})
        return {"success": True, "content": records_list} if len(records_list) > 1 or len(records_list) == 0 \
            else lookup_single_secret(
            records_list[0].get("id"))
    else:
        return {"success": False,
                "status": response.status_code,
                "text": response.text
                }


def get_full_secret(secret_id: int) -> requests.Response:
    url = f"{base_url}api/v2/secrets/{secret_id}"
    return requests.request("GET", url, headers=authenticated_headers, data={})


def lookup_single_secret(secret_id: int) -> dict:
    type_mapping = {
        6027: "keypair",
        6010: "generic",
        9: "website",
        6008: "database",
        6026: "server",
        9041: "iam_console",
        8046: "iam_key",
        1: "credit_card",
        9044: "vault_client",
        10053: "escapeless_password",
        6013: "firewall",
        9045: "google_iam",
        8047: "ibm_mainframe",
        6033: "id_admin",
        10050: "oracle_tcps",
        10051: "oracle_ver2",
        10052: "oracle_walletless",
        2: "password",
        3: "pin",
        14: "license_key",
        9047: "sap",
        6028: "note",
        6032: "service",
        6011: "snmp",
        8045: "ssh_keyless_privileged",
        7038: "ssh_privileged",
        8044: "ssh_keyless",
        7037: "ssh",
        7041: "watchguard",
        6029: "windows_server",
        6034: "x509",
        7039: "zos_mainframe"
    }
    response = get_full_secret(secret_id)
    if response.status_code == 200:
        json_data = json.loads(response.text)
        content = {}
        if "id" in json_data:
            content["id"] = to_text(json_data.get('id'))
            content["name"] = to_text(json_data.get("name"))
            content["folder_id"] = to_text(json_data.get("folderId"))
            content["type"] = type_mapping.get(json_data.get("secretTemplateId"))
            for item in json_data.get("items"):
                content[to_text(item.get("fieldName"))] = to_text(item.get("itemValue"))
        return {"success": True, "content": content}
    else:
        return {"success": False,
                "status": response.status_code,
                "text": response.text
                }


def create_secret(
        secret_name: str,
        user_name: str,
        password: str,
        folder_id: int,
        connection_string: str,
        url: str,
        secret_type: str,
        notes: str,
        fqdn: str,
        logon_domain: str,
        database: str,
        host: str,
        location: str,
        private_key: str,
        public_key: str
) -> dict:
    response = requests.request(method="POST", url=f"{base_url}api/v1/secrets", headers={
        **authenticated_headers,
        "Content-Type": "application/json"}, data=json.dumps(get_secret_body(secret_name=secret_name,
                                                                             secret_type=secret_type,
                                                                             folder_id=folder_id,
                                                                             logon_domain=logon_domain,
                                                                             fqdn=fqdn,
                                                                             notes=notes,
                                                                             password=password,
                                                                             user_name=user_name,
                                                                             database=database,
                                                                             connection_string=connection_string,
                                                                             url=url,
                                                                             host=host,
                                                                             location=location,
                                                                             private_key=private_key,
                                                                             public_key=public_key)))

    json_data = json.loads(response.text)
    if response.status_code == 200:
        return {"success": True,
                "data": {
                    "secret_id": json_data.get("id")
                }
                }
    else:
        return {"success": False, "data": {"code": response.status_code, "payload": json_data}}


def update_secret_by_id(secret_id: int, updated_password: str) -> dict:
    full_secret_response = get_full_secret(secret_id)
    if full_secret_response.status_code == 200 and full_secret_response.json():
        previous_secret = full_secret_response.json()
        previous_items = previous_secret.get("items")
        previous_password = ""
        for item in previous_items:
            if item.get("slug") == "password":
                previous_password = item.get("itemValue")
                item["itemValue"] = updated_password
                break
        previous_secret["items"] = previous_items
        url = f"{base_url}api/v1/secrets/{secret_id}"
        response = requests.put(url, json=previous_secret, headers={
            **authenticated_headers,
            "Content-Type": "application/json"})
        if response.status_code == 200:
            return {
                "success": True,
                "code": response.status_code,
                "text": {"secret_id": response.json().get("id")},
                "changed": previous_password != updated_password
                }
        else:
            return {"success": False, "code": response.status_code, "text": response.text}
    else:
        return {"success": False, "reason": "Could not get secret to be modified",
                "code": full_secret_response.status_code, "text": full_secret_response.text}


def update_secret_by_body(secret_name: str,
                          user_name: str,
                          password: str,
                          folder_id: int,
                          connection_string: str,
                          url: str,
                          secret_type: str,
                          notes: str, fqdn: str,
                          logon_domain: str,
                          database: str,
                          secret_id: int,
                          host: str,
                          location: str,
                          private_key: str,
                          public_key: str) -> dict:
    print("running update_secret_by_body")
    full_secret_response = get_full_secret(secret_id)
    if full_secret_response.status_code == 200 and full_secret_response.json():
        # If the user has not provided a field, it would get overwritten with "none"
        # We don't want that, so we need to check each field if the user set it to the special value "set_to_none"
        # if they have done that, we set the field to "None"
        # otherwise we keep the previous value
        previous_secret = full_secret_response.json()
        updated_items = get_secret_body(secret_name=secret_name,
                                        secret_type=secret_type,
                                        folder_id=folder_id,
                                        logon_domain=logon_domain,
                                        fqdn=fqdn,
                                        notes=notes,
                                        password=password,
                                        user_name=user_name,
                                        database=database,
                                        connection_string=connection_string,
                                        url=url,
                                        host=host,
                                        location=location,
                                        private_key=private_key,
                                        public_key=public_key).get("items")
        merged_items = []
        for previous_item in previous_secret.get("items"):
            updated_item = next(item for item in updated_items
                                if item.get("fieldName") == previous_item.get("fieldName"))
            if updated_item.get("itemValue") is None:
                merged_items.append(previous_item)
            elif updated_item.get("itemValue") == "set_to_none":
                none_item = previous_item
                none_item["itemValue"] = None
                merged_items.append(none_item)
            else:
                new_item = previous_item
                new_item["itemValue"] = updated_item.get("itemValue")
                merged_items.append(new_item)
        previous_secret["items"] = merged_items
        request_url = f"{base_url}api/v1/secrets/{secret_id}"
        response = requests.put(request_url, json=previous_secret,
                                headers={
                                    **authenticated_headers,
                                    "Content-Type": "application/json"})
        if response.status_code == 200:
            return {"success": True, "code": response.status_code, "data": {"secret_id": response.json().get("id")}}
        else:
            return {"success": False, "code": response.status_code, "data": response.text}
    else:
        return {"success": False, "reason": "Could not get secret to be modified",
                "code": full_secret_response.status_code, "data": full_secret_response.text}


def update_secret(secret_name: str,
                  user_name: str,
                  password: str,
                  folder_id: int,
                  connection_string: str,
                  database: str,
                  url: str,
                  secret_type: str,
                  notes: str,
                  fqdn: str,
                  logon_domain: str,
                  host: str,
                  location: str,
                  private_key: str,
                  public_key: str
                  ) -> dict:
    search_result = search_by_name(secret_name)
    # print(f"search_result is {search_result}")
    if search_result.get('success'):
        if isinstance(search_result.get('content'), dict):
            # print("we have success and a dict")
            current_secret = search_result.get('content')
            # print(f'current user name is {current_secret.get("Username")}, looking for {user_name}, they are equal {current_secret.get("Username") == user_name}')
            # print(f'current folder {current_secret.get("folder_id")}, looking for {folder_id}, they are equal {int(current_secret.get("folder_id")) == folder_id}')
            if current_secret.get("Username") == user_name and int(current_secret.get("folder_id")) == folder_id:
                # print("must update secret")
                return update_secret_by_body(secret_name=secret_name,
                                             user_name=user_name,
                                             password=password,
                                             folder_id=folder_id,
                                             connection_string=connection_string,
                                             url=url,
                                             secret_type=secret_type,
                                             notes=notes,
                                             fqdn=fqdn,
                                             logon_domain=logon_domain,
                                             database=database,
                                             secret_id=int(current_secret["id"]),
                                             host=host,
                                             location=location,
                                             private_key=private_key,
                                             public_key=public_key)
            else:
                return {"success": False,
                        "reason": "We found a secret by that name, but not in the folder you specified. "
                                  f"Aborting to avoid overwriting the wrong secret. "
                                  f"was {current_secret.get('folder_id')}, you specified {folder_id}, "
                                  f"username was {current_secret.get('Username')}, you specified {user_name}",
                        "search_result": search_result}
        elif isinstance(search_result.get('content'), list):
            print("we have a list")
            print(f"its len is {len(search_result.get('content'))}")
            if len(search_result.get('content')) == 0:
                return create_secret(secret_name=secret_name,
                                     user_name=user_name,
                                     password=password,
                                     folder_id=folder_id,
                                     connection_string=connection_string,
                                     url=url,
                                     secret_type=secret_type,
                                     notes=notes,
                                     fqdn=fqdn,
                                     logon_domain=logon_domain,
                                     database=database,
                                     host=host,
                                     location=location,
                                     private_key=private_key,
                                     public_key=public_key
                                     )
            else:
                return {"success": False, "reason": "Secret name not unique", "search_result": search_result}
    else:
        return {"success": False, "reason": "Could not lookup if secret exists", "search_result": search_result}


def main():
    print("executing main")
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

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = {}

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

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
        for key in ["secret_name", "password", "folder_id", "type"]:
            if module.params.get(key) is None:
                module.fail_json(msg=f"You must specify a {key} to use the upsert function", **result)
        if not int(module.params.get("folder_id")):
            module.fail_json(msg=f"the folder_id must be parseable to an integer", **result)
        if module.params.get("secret_id") and not int(module.params.get("secret_id")):
            module.fail_json(msg=f"the secret_id must be parseable to an integer", **result)

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
    global base_url
    base_url = module.params.get("secretserver_base_url")
    global authenticated_headers
    if module.params.get("secretserver_token") is not None:
        authenticated_headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {module.params.get('secretserver_token')}"
        }
    else:
        if module.params.get("secretserver_password") is None:
            module.fail_json(msg="You must pass either secretserver_token or secretserver_password", **result)
        try:
            client = Auth({
                "user_name": module.params.get("secretserver_username"),
                "password": module.params.get("secretserver_password"),
            })

            authenticated_headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {client.get_token()}"
            }
        except Exception as e:
            if type(e) == type(TypeError) and str(e) == "unsupported operand type(s) for -: 'NoneType' and 'int'":
                module.fail_json(msg="could not log into Secret Server. "
                                     "This is most likely because you specified the wrong username/password combination"
                                 , **result)
            else:
                module.fail_json(msg=f"could not log into Secret Server: {e}, {type(e)}, :{str(e)}:", **result)
        if not authenticated_headers:
            module.fail_json(msg=f"error authenticating with the Secret Server", **result)

    # executing the action
    if action == "get":
        res = lookup_single_secret(int(module.params.get("secret_id")))
        if res.get("success"):
            result["content"] = res.get("content")
            module.exit_json(**result)
        else:
            module.fail_json(msg=f"error getting secret {res}", **result)

    elif action == "search":
        res = search_by_name(module.params.get("search_text"))
        if res.get("success"):
            result["content"] = res.get("content")
            module.exit_json(**result)
        else:
            module.fail_json(msg=f"error searching for secret {res}", **result)

    elif action == "upsert":
        print("executing upsert")
        if module.check_mode:
            result["comment"] = "Upsert will do nothing in check mode"
            module.exit_json(**result)
        else:
            res = update_secret(secret_name=module.params.get("secret_name"),
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
            print(f"res is {res}")
            if not res.get("success"):
                module.fail_json(msg=f"error upserting secret {res}", **result)

            else:
                result["data"] = res.get("data")
                result["changed"] = True
                module.exit_json(**result)

    elif action == "update":
        if module.check_mode:
            result["comment"] = "Upsert will do nothing in check mode"
            module.exit_json(**result)
        else:
            res = update_secret_by_id(
                secret_id=int(module.params.get("secret_id")),
                updated_password=module.params.get("password")
            )
            print(f"res is {res}")
            if not res.get("success"):
                module.fail_json(msg=f"error updating secret {res}", **result)

            else:
                result["data"] = res.get("text")
                result["changed"] = res.get("changed")
                module.exit_json(**result)


if __name__ == '__main__':
    print("entrypoint")
    main()
