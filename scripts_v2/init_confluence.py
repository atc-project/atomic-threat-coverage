#!/usr/bin/env python3
from atcutils import ATCutils
from requests.auth import HTTPBasicAuth
import getpass


def main(c_auth=None):

    try:
        ATCconfig = ATCutils.read_yaml_file("config.yml")
        confluence_space_name = ATCconfig.get('confluence_space_name')
        confluence_space_home_page_name = ATCconfig.get(
            'confluence_space_home_page_name')
        confluence_rest_api_url = ATCconfig.get('confluence_rest_api_url')
        confluence_name_of_root_directory = ATCconfig.get(
            'confluence_name_of_root_directory')

    except Exception as e:
        raise e
        pass

    if not c_auth:
        mail = input("Email for access to confluence: ")
        password = getpass.getpass(prompt='Password: ', stream=None)
        auth = HTTPBasicAuth(mail, password)
    else:
        auth = c_auth

    url = confluence_rest_api_url
    content = ""

    print("Creating ATC page..")
    # print(str(ATCutils.confluence_get_page_id(url,
    # auth, confluence_space_name, confluence_space_home_page_name)))
    data = {
        "title": confluence_name_of_root_directory,
        "spacekey": confluence_space_name,
        "parentid": str(ATCutils.confluence_get_page_id(
            url, auth, confluence_space_name,
            confluence_space_home_page_name)),
        "confluencecontent": content,
    }

    # print(push_to_confluence(data, url, auth))
    ATCutils.push_to_confluence(data, url, auth)

    spaces = ["Detection Rules", "Logging Policies",
              "Data Needed", "Triggering", "Response Actions",
              "Response Playbooks", "Enrichments"]

    for space in spaces:
        print("Creating %s.." % space)
        data = {
            "title": space,
            "spacekey": confluence_space_name,
            "parentid": str(ATCutils.confluence_get_page_id(
                url, auth, confluence_space_name,
                confluence_name_of_root_directory)),
            "confluencecontent": content,
        }
        # print(push_to_confluence(data, url, auth))
        ATCutils.push_to_confluence(data, url, auth)
    print("Done!")


if __name__ == "__main__":
    main()
