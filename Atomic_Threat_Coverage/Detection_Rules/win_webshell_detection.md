| Title                | Webshell Detection With Command Line Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects certain command line parameters often used during reconnaissance activity via web shells                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Webshell Detection With Command Line Keywords
description: Detects certain command line parameters often used during reconnaissance activity via web shells
author: Florian Roth
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
            - whoami
            - net user
            - ping -n
            - systeminfo
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(ParentImage.keyword:(*\\\\apache* *\\\\tomcat* *\\\\w3wp.exe *\\\\php\\-cgi.exe *\\\\nginx.exe *\\\\httpd.exe) AND CommandLine:("whoami" "net\\ user" "ping\\ \\-n" "systeminfo"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Webshell-Detection-With-Command-Line-Keywords <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(ParentImage.keyword:(*\\\\\\\\apache* *\\\\\\\\tomcat* *\\\\\\\\w3wp.exe *\\\\\\\\php\\\\-cgi.exe *\\\\\\\\nginx.exe *\\\\\\\\httpd.exe) AND CommandLine:(\\"whoami\\" \\"net\\\\ user\\" \\"ping\\\\ \\\\-n\\" \\"systeminfo\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Webshell Detection With Command Line Keywords\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:("*\\\\apache*" "*\\\\tomcat*" "*\\\\w3wp.exe" "*\\\\php\\-cgi.exe" "*\\\\nginx.exe" "*\\\\httpd.exe") AND CommandLine:("whoami" "net user" "ping \\-n" "systeminfo"))
```


### splunk
    
```
((ParentImage="*\\\\apache*" OR ParentImage="*\\\\tomcat*" OR ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\php-cgi.exe" OR ParentImage="*\\\\nginx.exe" OR ParentImage="*\\\\httpd.exe") (CommandLine="whoami" OR CommandLine="net user" OR CommandLine="ping -n" OR CommandLine="systeminfo")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage IN ["*\\\\apache*", "*\\\\tomcat*", "*\\\\w3wp.exe", "*\\\\php-cgi.exe", "*\\\\nginx.exe", "*\\\\httpd.exe"] CommandLine IN ["whoami", "net user", "ping -n", "systeminfo"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\apache.*|.*.*\\tomcat.*|.*.*\\w3wp\\.exe|.*.*\\php-cgi\\.exe|.*.*\\nginx\\.exe|.*.*\\httpd\\.exe))(?=.*(?:.*whoami|.*net user|.*ping -n|.*systeminfo)))'
```



