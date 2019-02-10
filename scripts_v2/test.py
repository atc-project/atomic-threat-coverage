# from atcutils import ATCutils
from requests.auth import HTTPBasicAuth
import getpass
from detectionrule import DetectionRule

mail = "jakob.weinzettl@gmail.com"
passwd = getpass.getpass("passwd: ")

auth = HTTPBasicAuth(mail, passwd)

space = "CLASSES"
title = "Logging Policies"
api = "https://atomicthreatcoverage.atlassian.net/wiki/rest/api/"

dr = DetectionRule('../detectionrules/sysmon_exploit_cve_2017_11882.yml',
                   apipath=api, auth=auth, space=space)
dr.render_template("confluence")

print(dr.content)
