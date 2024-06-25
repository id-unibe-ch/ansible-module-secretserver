""" This file will look for the dummy secrets in the secret server and read their structure. it will then write out
a config file which you must copy over to secretserver.py

You must copy over the type_mapping.txt to the lookup_single_secret method as-is.

You must also copy the extended_type_mapping.txt to the get_secret_body method.
You must then replace all the 'changeme' values with the appropriate variable passed into the function.
For example: If the 'fieldName' of a dict is 'Username'
you need to change the value of the 'ItemValue' key to the name of the variable containing the Username"""
import os
from dotenv import load_dotenv
from pprint import pprint

from library.secretserver import Auth, get_full_secret, get_all_secret_ids_in_folder

ID_OF_FOLDER_WITH_DUMMY_SECRETS = 2155
IMPLEMENTED_SECRET_TYPES = ["database", "generic", "server", "website", "x509"]


def get_all_dummy_secrets():
    client = Auth(base_url=os.getenv("SECRETSERVER_BASE_URL"), token=os.getenv("SECRETSERVER_TOKEN"))
    secret_ids_in_folder = get_all_secret_ids_in_folder(client=client, folder_id=ID_OF_FOLDER_WITH_DUMMY_SECRETS)
    pprint(len(secret_ids_in_folder))

    secrets_in_folder = \
        [get_full_secret(client=client, secret_id=secret_id).json() for secret_id in secret_ids_in_folder]
    return secrets_in_folder


def create_type_mapping(secrets):
    type_mapping = {secret.get("secretTemplateId"): secret.get("name") for secret in secrets}
    extended_type_mapping = {
        secret.get("name"):
            {
                "template_id": secret.get("secretTemplateId"),
                "items": [
                    {
                        key: "changeme" if key == "itemValue" else value
                        for (key, value) in item.items() if key != "itemId"
                     }
                    for item in secret.get("items") if not item.get("isFile")
                ]
            }
        for secret in secrets if secret.get("name") in IMPLEMENTED_SECRET_TYPES
    }
    with open("type_mapping.txt", 'w') as file:
        pprint(type_mapping, stream=file)
    with open("extended_type_mapping.txt", 'w') as file:
        pprint(extended_type_mapping, stream=file)


def main():
    dummy_secrets = get_all_dummy_secrets()
    create_type_mapping(dummy_secrets)


if __name__ == '__main__':
    load_dotenv()
    main()
