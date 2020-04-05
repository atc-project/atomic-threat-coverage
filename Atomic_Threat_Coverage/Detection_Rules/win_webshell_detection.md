| Title                    | Webshell Detection With Command Line Keywords       |
|:-------------------------|:------------------|
| **Description**          | Detects certain command line parameters often used during reconnaissance activity via web shells |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Webshell Detection With Command Line Keywords
id: bed2a484-9348-4143-8a8a-b801c979301c
description: Detects certain command line parameters often used during reconnaissance activity via web shells
author: Florian Roth
reference:
    - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
date: 2017/01/01
modified: 2019/10/26
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        CommandLine:
            - '*whoami*'
            - '*net user *'
            - '*ping -n *'
            - '*systeminfo'
            - '*&cd&echo*'
            - '*cd /d*'  # https://www.computerhope.com/cdhlp.htm
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(ParentImage.keyword:(*\\\\apache* OR *\\\\tomcat* OR *\\\\w3wp.exe OR *\\\\php\\-cgi.exe OR *\\\\nginx.exe OR *\\\\httpd.exe) AND CommandLine.keyword:(*whoami* OR *net\\ user\\ * OR *ping\\ \\-n\\ * OR *systeminfo OR *&cd&echo* OR *cd\\ \\/d*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/bed2a484-9348-4143-8a8a-b801c979301c <<EOF\n{\n  "metadata": {\n    "title": "Webshell Detection With Command Line Keywords",\n    "description": "Detects certain command line parameters often used during reconnaissance activity via web shells",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.persistence",\n      "attack.t1100"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\apache* OR *\\\\\\\\tomcat* OR *\\\\\\\\w3wp.exe OR *\\\\\\\\php\\\\-cgi.exe OR *\\\\\\\\nginx.exe OR *\\\\\\\\httpd.exe) AND CommandLine.keyword:(*whoami* OR *net\\\\ user\\\\ * OR *ping\\\\ \\\\-n\\\\ * OR *systeminfo OR *&cd&echo* OR *cd\\\\ \\\\/d*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\apache* OR *\\\\\\\\tomcat* OR *\\\\\\\\w3wp.exe OR *\\\\\\\\php\\\\-cgi.exe OR *\\\\\\\\nginx.exe OR *\\\\\\\\httpd.exe) AND CommandLine.keyword:(*whoami* OR *net\\\\ user\\\\ * OR *ping\\\\ \\\\-n\\\\ * OR *systeminfo OR *&cd&echo* OR *cd\\\\ \\\\/d*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Webshell Detection With Command Line Keywords\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage.keyword:(*\\\\apache* *\\\\tomcat* *\\\\w3wp.exe *\\\\php\\-cgi.exe *\\\\nginx.exe *\\\\httpd.exe) AND CommandLine.keyword:(*whoami* *net user * *ping \\-n * *systeminfo *&cd&echo* *cd \\/d*))
```


### splunk
    
```
((ParentImage="*\\\\apache*" OR ParentImage="*\\\\tomcat*" OR ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\php-cgi.exe" OR ParentImage="*\\\\nginx.exe" OR ParentImage="*\\\\httpd.exe") (CommandLine="*whoami*" OR CommandLine="*net user *" OR CommandLine="*ping -n *" OR CommandLine="*systeminfo" OR CommandLine="*&cd&echo*" OR CommandLine="*cd /d*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\\\apache*", "*\\\\tomcat*", "*\\\\w3wp.exe", "*\\\\php-cgi.exe", "*\\\\nginx.exe", "*\\\\httpd.exe"] CommandLine IN ["*whoami*", "*net user *", "*ping -n *", "*systeminfo", "*&cd&echo*", "*cd /d*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\apache.*|.*.*\\tomcat.*|.*.*\\w3wp\\.exe|.*.*\\php-cgi\\.exe|.*.*\\nginx\\.exe|.*.*\\httpd\\.exe))(?=.*(?:.*.*whoami.*|.*.*net user .*|.*.*ping -n .*|.*.*systeminfo|.*.*&cd&echo.*|.*.*cd /d.*)))'
```



