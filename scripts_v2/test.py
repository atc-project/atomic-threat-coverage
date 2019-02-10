from atcutils import ATCutils
from requests.auth import HTTPBasicAuth
import getpass

mail = "jakob.weinzettl@gmail.com"
passwd = getpass.getpass("passwd: ")

auth = HTTPBasicAuth(mail, passwd)

space = "CLASSES"
title = "Logging Policies"
api = "https://atomicthreatcoverage.atlassian.net/wiki/rest/api/"

ATCutils.confluence_get_page_id(api, auth, space, title)
