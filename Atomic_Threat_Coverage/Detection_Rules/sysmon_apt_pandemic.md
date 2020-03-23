| Title                | Pandemic Registry Key                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Pandemic Windows Implant                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Trigger              | <ul><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://wikileaks.org/vault7/#Pandemic](https://wikileaks.org/vault7/#Pandemic)</li><li>[https://twitter.com/MalwareJake/status/870349480356454401](https://twitter.com/MalwareJake/status/870349480356454401)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: Pandemic Registry Key
id: 47e0852a-cf81-4494-a8e6-31864f8c86ed
status: experimental
description: Detects Pandemic Windows Implant
references:
    - https://wikileaks.org/vault7/#Pandemic
    - https://twitter.com/MalwareJake/status/870349480356454401
tags:
    - attack.lateral_movement
    - attack.t1105
author: Florian Roth
date: 2017/06/01
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
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject:
            - 'HKLM\SYSTEM\CurrentControlSet\services\null\Instance*'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection2:
        Command: 'loaddll -a *'

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:(HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\null\\\\Instance*))\nCommand.keyword:loaddll\\ \\-a\\ *
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/47e0852a-cf81-4494-a8e6-31864f8c86ed <<EOF\n{\n  "metadata": {\n    "title": "Pandemic Registry Key",\n    "description": "Detects Pandemic Windows Implant",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1105"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\services\\\\\\\\null\\\\\\\\Instance*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\services\\\\\\\\null\\\\\\\\Instance*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Pandemic Registry Key\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n            Image = {{_source.Image}}\\n             User = {{_source.User}}\\n     TargetObject = {{_source.TargetObject}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/47e0852a-cf81-4494-a8e6-31864f8c86ed-2 <<EOF\n{\n  "metadata": {\n    "title": "Pandemic Registry Key",\n    "description": "Detects Pandemic Windows Implant",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1105"\n    ],\n    "query": "Command.keyword:loaddll\\\\ \\\\-a\\\\ *"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Command.keyword:loaddll\\\\ \\\\-a\\\\ *",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Pandemic Registry Key\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n            Image = {{_source.Image}}\\n             User = {{_source.User}}\\n     TargetObject = {{_source.TargetObject}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject.keyword:(HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\null\\\\Instance*))\nCommand.keyword:loaddll \\-a *
```


### splunk
    
```
(EventID="13" (TargetObject="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\null\\\\Instance*")) | table EventID,CommandLine,ParentCommandLine,Image,User,TargetObject\nCommand="loaddll -a *" | table EventID,CommandLine,ParentCommandLine,Image,User,TargetObject
```


### logpoint
    
```
(event_id="13" TargetObject IN ["HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\null\\\\Instance*"])\n(event_id="1" Command="loaddll -a *")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*HKLM\\SYSTEM\\CurrentControlSet\\services\\null\\Instance.*)))'\ngrep -P '^loaddll -a .*'
```



