#!/usr/bin/env python3
from utils import push_to_confluence, get_page_id
from requests.auth import HTTPBasicAuth
import getpass

def main():

    try:
        import config  # where we define confluence space name, list of DR and TG folders
        confluence_space_name = config.confluence_space_name
        confluence_space_home_page_name = config.confluence_space_home_page_name
        list_of_detection_rules_directories = config.list_of_detection_rules_directories # not used so far
        list_of_triggering_directories = config.list_of_triggering_directories           # not used so far
        confluence_name_of_root_directory = config.confluence_name_of_root_directory     # not used so far
        confluence_rest_api_url = config.confluence_rest_api_url
    except Exception as e:
        raise e
        pass

    mail = input("Email for access to confluence: ")
    url = confluence_rest_api_url
    password = getpass.getpass(prompt='Password: ', stream=None)
    auth = HTTPBasicAuth(mail, password)
    content=""

    data = {
        "title": confluence_name_of_root_directory,
        "spacekey": confluence_space_name,
        "parentid": str(get_page_id(url, auth, confluence_space_name, confluence_space_home_page_name)),
        "confluencecontent": content,
    }

    #print(push_to_confluence(data, url, auth))
    push_to_confluence(data, url, auth)
    
    spaces = ["Detection Rules", "Logging Policies", "Data Needed", "Triggering" ,"Response Actions", "Response Playbooks"]

    for space in spaces:
        data = {
        "title": space,
        "spacekey": confluence_space_name,
        "parentid": str(get_page_id(url, auth, confluence_space_name, confluence_name_of_root_directory)),
        "confluencecontent": content,
        }
        #print(push_to_confluence(data, url, auth))
        push_to_confluence(data, url, auth)

    print("done")

if __name__ == "__main__":
    main()