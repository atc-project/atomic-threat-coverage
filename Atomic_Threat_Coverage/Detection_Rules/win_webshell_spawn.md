| Title                | Shells Spawned by Web Servers                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Particular web applications may spawn a shell process legitimately</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Shells Spawned by Web Servers
status: experimental
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
falsepositives:
    - Particular web applications may spawn a shell process legitimately
level: high

```





### es-qs
    
```
(ParentImage.keyword:(*\\\\w3wp.exe *\\\\httpd.exe *\\\\nginx.exe *\\\\php\\-cgi.exe) AND Image.keyword:(*\\\\cmd.exe *\\\\sh.exe *\\\\bash.exe *\\\\powershell.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Shells-Spawned-by-Web-Servers <<EOF\n{\n  "metadata": {\n    "title": "Shells Spawned by Web Servers",\n    "description": "Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.persistence",\n      "attack.t1100"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\w3wp.exe *\\\\\\\\httpd.exe *\\\\\\\\nginx.exe *\\\\\\\\php\\\\-cgi.exe) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\powershell.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\w3wp.exe *\\\\\\\\httpd.exe *\\\\\\\\nginx.exe *\\\\\\\\php\\\\-cgi.exe) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\powershell.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Shells Spawned by Web Servers\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:("*\\\\w3wp.exe" "*\\\\httpd.exe" "*\\\\nginx.exe" "*\\\\php\\-cgi.exe") AND Image:("*\\\\cmd.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\powershell.exe"))
```


### splunk
    
```
((ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\httpd.exe" OR ParentImage="*\\\\nginx.exe" OR ParentImage="*\\\\php-cgi.exe") (Image="*\\\\cmd.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\powershell.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage IN ["*\\\\w3wp.exe", "*\\\\httpd.exe", "*\\\\nginx.exe", "*\\\\php-cgi.exe"] Image IN ["*\\\\cmd.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\powershell.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\w3wp\\.exe|.*.*\\httpd\\.exe|.*.*\\nginx\\.exe|.*.*\\php-cgi\\.exe))(?=.*(?:.*.*\\cmd\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\powershell\\.exe)))'
```



