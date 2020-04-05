| Title                    | Defrag Deactivation       |
|:-------------------------|:------------------|
| **Description**          | Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0065_4701_scheduled_task_was_disabled](../Data_Needed/DN_0065_4701_scheduled_task_was_disabled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://securelist.com/apt-slingshot/84312/](https://securelist.com/apt-slingshot/84312/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Defrag Deactivation
id: 958d81aa-8566-4cea-a565-59ccd4df27b0
author: Florian Roth
date: 2019/03/04
description: Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group
references:
    - https://securelist.com/apt-slingshot/84312/
tags:
    - attack.persistence
    - attack.t1053
    - attack.s0111
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: medium
---
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*schtasks* /delete *Defrag\ScheduledDefrag*'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Audit Other Object Access Events > Success'
detection:
    selection2:
        EventID: 4701
        TaskName: '\Microsoft\Windows\Defrag\ScheduledDefrag'

```





### es-qs
    
```
CommandLine.keyword:(*schtasks*\\ \\/delete\\ *Defrag\\\\ScheduledDefrag*)\n(EventID:"4701" AND TaskName:"\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/958d81aa-8566-4cea-a565-59ccd4df27b0 <<EOF\n{\n  "metadata": {\n    "title": "Defrag Deactivation",\n    "description": "Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group",\n    "tags": [\n      "attack.persistence",\n      "attack.t1053",\n      "attack.s0111"\n    ],\n    "query": "CommandLine.keyword:(*schtasks*\\\\ \\\\/delete\\\\ *Defrag\\\\\\\\ScheduledDefrag*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*schtasks*\\\\ \\\\/delete\\\\ *Defrag\\\\\\\\ScheduledDefrag*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Defrag Deactivation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/958d81aa-8566-4cea-a565-59ccd4df27b0-2 <<EOF\n{\n  "metadata": {\n    "title": "Defrag Deactivation",\n    "description": "Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group",\n    "tags": [\n      "attack.persistence",\n      "attack.t1053",\n      "attack.s0111"\n    ],\n    "query": "(EventID:\\"4701\\" AND TaskName:\\"\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\Defrag\\\\\\\\ScheduledDefrag\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4701\\" AND TaskName:\\"\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\Defrag\\\\\\\\ScheduledDefrag\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Defrag Deactivation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*schtasks* \\/delete *Defrag\\\\ScheduledDefrag*)\n(EventID:"4701" AND TaskName:"\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag")
```


### splunk
    
```
(CommandLine="*schtasks* /delete *Defrag\\\\ScheduledDefrag*")\n(EventID="4701" TaskName="\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*schtasks* /delete *Defrag\\\\ScheduledDefrag*"])\n(event_source="Microsoft-Windows-Security-Auditing" event_id="4701" TaskName="\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag")
```


### grep
    
```
grep -P '^(?:.*.*schtasks.* /delete .*Defrag\\ScheduledDefrag.*)'\ngrep -P '^(?:.*(?=.*4701)(?=.*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag))'
```



