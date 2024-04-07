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
module: my_test

short_description: This is my test module

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: This is my longer description explaining my test module.

options:
    name:
        description: This is the message to send to the test module.
        required: true
        type: str
    new:
        description:
            - Control to demo if the result of this module is changed or not.
            - Parameter description can be a list as well.
        required: false
        type: bool
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
# extends_documentation_fragment:
#     - my_namespace.my_collection.my_doc_fragment_name

author:
    - Your Name (@yourGitHubHandle)
'''

EXAMPLES = r'''
# Pass in a message
- name: Test with a message
  my_namespace.my_collection.my_test:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_namespace.my_collection.my_test:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_namespace.my_collection.my_test:
    name: fail me
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
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


def lookup_single_secret(secret_id: int) -> dict:
    url = f"{base_url}api/v2/secrets/{secret_id}"
    response = requests.request("GET", url, headers=authenticated_headers, data={})
    if response.status_code == 200:
        json_data = json.loads(response.text)
        content = {}
        if "id" in json_data:
            content["id"] = to_text(json_data.get('id'))
            content["name"] = to_text(json_data.get("name"))
            content["folder_id"] = to_text(json_data.get("folderId"))
            for item in json_data.get("items"):
                content[to_text(item.get("fieldName"))] = to_text(item.get("itemValue"))
        return {"success": True, "content": content}
    else:
        return {"success": False,
                "status": response.status_code,
                "text": response.text
                }


def create_secret(
        secret_name: str, user_name: str, password: str, folder_id: int, connection_string: str,
        url: str, secret_type: str, notes: str, fqdn: str, logon_domain: str, database: str
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

    }
    }

    payload = {
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

    response = requests.request(method="POST", url=f"{base_url}api/v1/secrets", headers={
        **authenticated_headers,
        "Content-Type": "application/json"}, data=json.dumps(payload))

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
    url = f"{base_url}api/v1/secrets/{secret_id}/fields/password"
    payload = json.dumps({
        "password": updated_password,
        "id": secret_id
    })
    response = requests.request("PUT", url, headers={
        **authenticated_headers,
        "Content-Type": "application/json"},
                                data=payload)
    return {"code": response.status_code, "text": response.text}


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
                  secret_id: int
                  ) -> dict:
    if secret_id is not None and secret_id > 0:
        return update_secret_by_id(
            secret_id=secret_id,
            updated_password=password
        )
    else:
        search_result = search_by_name(secret_name)
        print(f"search_result is {search_result}")
        if search_result.get('success') and len(search_result.get('content')):
            if(len(search_result.get('content'))) == 1:
                current_secret = search_result.get('content')[0]
                if current_secret.get("Username") == user_name and current_secret.get("folder_id") == folder_id:
                    update_secret_by_id(
                        secret_id=current_secret["id"],
                        updated_password=password
                    )
                else:
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
                                         database=database
                                         )
        elif len(search_result.get('content')) == 0:
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
                                 database=database
                                 )
        else:
            return {"changed": False, "reason": "Secret name not unique", "search_result": search_result}


def main():
    print("executing main")
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        secertserver_password=dict(type='str', required=False, no_log=True),
        secertserver_token=dict(type='str', required=False, no_log=True),
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
        new=dict(type='bool', required=False, default=False)
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
    permitted_actions = ["search", "get", "upsert"]
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
        for key in ["secret_name", "user_name", "password", "folder_id", "type"]:
            if module.params.get(key) is None:
                module.fail_json(msg=f"You must specify a {key} to use the upsert function", **result)
        if not int(module.params.get("folder_id")):
            module.fail_json(msg=f"the folder_id must be parseable to an integer", **result)
        if module.params.get("secret_id") and not int(module.params.get("secret_id")):
            module.fail_json(msg=f"the secret_id must be parseable to an integer", **result)

        if module.params.get("secret_type"):
            secret_type = module.params.get("secret_type")
            acceptable_types = {"server": ["secret_name", "user_name", "password"],
                                "database": ["secret_name", "database", "user_name", "password"],
                                "website": ["secret_name", "url", "user_name", "password"],
                                "generic": ["secret_name", "user_name", "password"]
                                }
            if secret_type not in acceptable_types.keys:
                module.fail_json(msg=f"the secret type must be one of {', '.join(acceptable_types)}", **result)
            for field in acceptable_types.get(secret_type):
                if module.params.get(field) is None:
                    module.fail_json(msg=f"you must specify {field} to upsert a {secret_type}", **result)

    # Authenticating with the Secret Server
    global base_url
    base_url = module.params.get("secretserver_base_url")
    global authenticated_headers
    if module.params.get("secertserver_token") is not None:
        authenticated_headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {module.params.get('secertserver_token')}"
        }
    else:
        if module.params.get("secertserver_password") is None:
            module.fail_json(msg="You must pass either secertserver_token or secertserver_password", **result)
        try:
            client = Auth({
                "user_name": module.params.get("secretserver_username"),
                "password": module.params.get("secertserver_password"),
            })

            authenticated_headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {client.get_token()}"
            }
        except Exception as e:
            module.fail_json(msg=f"could not log into Secret Server: {e}", **result)
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
                                secret_id=int(module.params.get("secret_id", -1)
                                              if module.params.get("secret_id", -1) is not None else -1)
                                )
            if not res.get("success"):
                module.fail_json(msg=f"error upserting secret {res}", **result)

            else:
                result["data"] = res.get("data")
                result["changed"] = True
                module.exit_json(**result)


if __name__ == '__main__':
    print("entrypoint")
    main()
