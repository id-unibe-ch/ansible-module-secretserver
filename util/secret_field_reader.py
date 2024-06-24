""" This file will look for the dummy secrets in the secret server and read their structure. it will then write out
a config file which you must copy over to secretserver.py"""
import os
from dotenv import load_dotenv
from pprint import pprint

from library.secretserver import Auth, get_full_secret, get_all_secret_ids_in_folder

ID_OF_FOLDER_WITH_DUMMY_SECRETS = 2155


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
                "items": secret.get("items")
            }
        for secret in secrets
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
