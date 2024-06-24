import json
import datetime
import requests
from ansible.module_utils.common.text.converters import to_text
from typing import List, Dict, Union


class Auth:
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*'
    }

    def __init__(self, user_name: str, password: str, base_url: str, token: Union[str, None] = None):
        self._base_url = base_url
        self._user_name = user_name
        self._password = password
        self._token_valid_until = None
        self._access_token = token
        self._refresh_token = None

    def _get_token(self):
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

    def get_authenticated_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._get_token()}"
        }

    def get_base_url(self) -> str:
        return self._base_url


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


def search_by_name(client: Auth, search_text: str) -> Union[list, dict]:
    url = f"{client.get_base_url()}api/v2/secrets?filter.searchText={search_text}"
    response = requests.request("GET", url, headers=client.get_authenticated_headers(), data={})
    if response.status_code == 200:
        json_data = json.loads(response.text)
        records_list = []
        if "records" in json_data:
            for record in json_data.get("records"):
                records_list.append({"name": to_text(record.get("name")), "id": to_text(record.get("id"))})
        return {"success": True, "content": records_list} if len(records_list) > 1 or len(records_list) == 0 \
            else lookup_single_secret(client=client, secret_id=records_list[0].get("id"))
    else:
        return {"success": False,
                "status": response.status_code,
                "text": response.text
                }


def get_full_secret(client: Auth, secret_id: int) -> requests.Response:
    url = f"{client.get_base_url()}api/v2/secrets/{secret_id}"
    return requests.request("GET", url, headers=client.get_authenticated_headers(), data={})


def lookup_single_secret(client: Auth, secret_id: int) -> dict:
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
    response = get_full_secret(client=client, secret_id=secret_id)
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
        client: Auth,
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
    response = requests.request(method="POST", url=f"{client.get_base_url()}api/v1/secrets", headers={
        **client.get_authenticated_headers(),
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


def update_secret_by_id(client: Auth, secret_id: int, updated_password: str) -> dict:
    full_secret_response = get_full_secret(client=client, secret_id=secret_id)
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
        url = f"{client.get_base_url()}api/v1/secrets/{secret_id}"
        response = requests.put(url, json=previous_secret, headers={
            **client.get_authenticated_headers(),
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


def compare_item_lists(former: List[Dict[str, Union[str, int]]], latter: List[Dict[str, Union[str, int]]]) -> bool:
    # Made to compare lists of dicts, like the ones you have in the "items" field of a Secret
    # Returns true when both lists contain all the same dicts
    if len(former) != len(latter):
        return False

    temp_latter = latter.copy()

    for dict1 in former:
        match_found = False
        for latter_dict in temp_latter:
            if all(dict1.get(k) == v for k, v in latter_dict.items()):
                temp_latter.remove(latter_dict)
                match_found = True
                break
        if not match_found:
            return False
    return True


def update_secret_by_body(client: Auth,
                          secret_name: str,
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
    full_secret_response = get_full_secret(client=client, secret_id=secret_id)
    if full_secret_response.status_code == 200 and full_secret_response.json():
        # If the user has not provided a field, it would get overwritten with "none"
        # We don't want that, so we need to check each field if the user set it to the special value "set_to_none"
        # if they have done that, we set the field to "None"
        # otherwise we keep the previous value
        previous_secret = full_secret_response.json()
        former_items = previous_secret.get("items")
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
        print(f"updated items are {updated_items}")
        for previous_item in previous_secret.get("items", []):
            print(f"previous item is {previous_item}")
            updated_item = next(
                (item for item in updated_items if item.get("fieldId") == previous_item.get("fieldId")), None)
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
        request_url = f"{client.get_base_url()}api/v1/secrets/{secret_id}"
        response = requests.put(request_url, json=previous_secret,
                                headers={
                                    **client.get_authenticated_headers(),
                                    "Content-Type": "application/json"})
        if response.status_code == 200:
            return {"success": True,
                    "code": response.status_code,
                    "data": {"secret_id": response.json().get("id")},
                    "changed": not compare_item_lists(former_items, merged_items)}
        else:
            return {"success": False, "code": response.status_code, "data": response.text}
    else:
        return {"success": False, "reason": "Could not get secret to be modified",
                "code": full_secret_response.status_code, "data": full_secret_response.text}


def update_secret(client: Auth,
                  secret_name: str,
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
    search_result = search_by_name(client=client, search_text=secret_name)
    # print(f"search_result is {search_result}")
    if search_result.get('success'):
        if isinstance(search_result.get('content'), dict):
            # print("we have success and a dict")
            current_secret = search_result.get('content')
            # print(f'current user name is {current_secret.get("Username")}, looking for {user_name}, they are equal {current_secret.get("Username") == user_name}')
            # print(f'current folder {current_secret.get("folder_id")}, looking for {folder_id}, they are equal {int(current_secret.get("folder_id")) == folder_id}')
            if current_secret.get("Username") == user_name and int(current_secret.get("folder_id")) == folder_id:
                # print("must update secret")
                return update_secret_by_body(client=client,
                                             secret_name=secret_name,
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
            if len(search_result.get('content')) == 0:
                return create_secret(client=client,
                                     secret_name=secret_name,
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
