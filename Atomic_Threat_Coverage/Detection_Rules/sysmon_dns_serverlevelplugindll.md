| Title                | DNS ServerLevelPluginDll Install                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
---
action: global
title: DNS ServerLevelPluginDll Install
status: experimental
description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
date: 2017/05/08
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1073
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
falsepositives:
    - unknown
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    dnsregmod:
        EventID: 13
        TargetObject: '*\services\DNS\Parameters\ServerLevelPluginDll'
---
logsource:
    category: process_creation
    product: windows
detection:
    dnsadmin:
        CommandLine: 'dnscmd.exe /config /serverlevelplugindll *'
```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll)\nCommandLine.keyword:dnscmd.exe\\ \\/config\\ \\/serverlevelplugindll\\ *
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/DNS-ServerLevelPluginDll-Install <<EOF\n{\n  "metadata": {\n    "title": "DNS ServerLevelPluginDll Install",\n    "description": "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\services\\\\\\\\DNS\\\\\\\\Parameters\\\\\\\\ServerLevelPluginDll)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\services\\\\\\\\DNS\\\\\\\\Parameters\\\\\\\\ServerLevelPluginDll)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DNS ServerLevelPluginDll Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n            Image = {{_source.Image}}\\n             User = {{_source.User}}\\n     TargetObject = {{_source.TargetObject}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/DNS-ServerLevelPluginDll-Install-2 <<EOF\n{\n  "metadata": {\n    "title": "DNS ServerLevelPluginDll Install",\n    "description": "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073"\n    ],\n    "query": "CommandLine.keyword:dnscmd.exe\\\\ \\\\/config\\\\ \\\\/serverlevelplugindll\\\\ *"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:dnscmd.exe\\\\ \\\\/config\\\\ \\\\/serverlevelplugindll\\\\ *",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DNS ServerLevelPluginDll Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n            Image = {{_source.Image}}\\n             User = {{_source.User}}\\n     TargetObject = {{_source.TargetObject}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:"*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll")\nCommandLine:"dnscmd.exe \\/config \\/serverlevelplugindll *"
```


### splunk
    
```
(EventID="13" TargetObject="*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll") | table EventID,CommandLine,ParentCommandLine,Image,User,TargetObject\nCommandLine="dnscmd.exe /config /serverlevelplugindll *" | table EventID,CommandLine,ParentCommandLine,Image,User,TargetObject
```


### logpoint
    
```
(EventID="13" TargetObject="*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll")\nCommandLine="dnscmd.exe /config /serverlevelplugindll *"
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll))'\ngrep -P '^dnscmd\\.exe /config /serverlevelplugindll .*'
```



