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
        print(f"access token is {self._access_token}")
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
        return {"success": True, "content": json_data}
    else:
        return {"success": False,
                "status": response.status_code,
                "text": response.text
                }


def create_secret(
        secret_name: str, user_name: str, password: str, folder_id: int, connection_string: str,
        url: str, secret_type: str, notes: str, fqdn: str, logon_domain: str
) -> list:
    if folder_id == -1:
        raise AnsibleError("You must specify a folder ID to create a secret")
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

    if secret_type not in type_mapping.keys():
        raise AnsibleError(f"Secret_type {secret_type} unknown")

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

    response = requests.request("POST", f"{base_url}api/v1/secrets", headers={
        **authenticated_headers,
        "Content-Type": "application/json"}, data=json.dumps(payload))

    if response.status_code == 200:
        return json.loads(response.text).get("id")
    else:
        print(f"status: {response.status_code}")
        print(response.text)


def update_secret_by_id(secret_id: str, updated_password: str) -> list:
    url = f"{base_url}api/v1/secrets/{secret_id}/fields/password"
    payload = json.dumps({
        "password": updated_password,
        "id": secret_id
    })
    response = requests.request("PUT", url, headers={
        **authenticated_headers,
        "Content-Type": "application/json"},
                                data=payload)
    print(f"status: {response.status_code}")
    print(response.text)
    if response.status_code != 200:
        raise AnsibleError(f"Error updating secret {secret_id}: {response.text}")


def update_secret(secret_name: str,
                  user_name: str,
                  password: str,
                  folder_id: int,
                  connection_string: str,
                  url: str,
                  secret_type: str,
                  notes: str,
                  fqdn: str,
                  logon_domain: str,
                  secret_id: str = None
                  ) -> list:
    display.display("updating secret")
    if secret_id is not None:
        return update_secret_by_id(
            secret_id=secret_id,
            updated_password=password
        )
    else:
        search_result = search_by_name(secret_name)
        print(search_result)
        if len(search_result) == 1:
            current_secret = search_result[0]
            if current_secret["Username"] == user_name:
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
                                     logon_domain=logon_domain
                                     )
        elif len(search_result) == 0:
            return create_secret(secret_name=secret_name,
                                 user_name=user_name,
                                 password=password,
                                 folder_id=folder_id,
                                 connection_string=connection_string,
                                 url=url,
                                 secret_type=secret_type,
                                 notes=notes,
                                 fqdn=fqdn,
                                 logon_domain=logon_domain
                                 )


def main():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        secertserver_password=dict(type='str', required=False, no_log=True, ),
        secertserver_token=dict(type='str', required=False, no_log=True, ),
        secretserver_username=dict(type='str', required=True),
        secretserver_base_url=dict(type='str', required=True),
        action=dict(type='str', required=True),
        search_text=dict(type='str', required=False),
        secret_id=dict(type='int', required=False),
        folder_id=dict(type='int', required=False),
        type=dict(type='str', required=False),
        secret_name=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True, ),
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
        if module.check_mode:
            module.exit_json(**result)


if __name__ == '__main__':
    main()
