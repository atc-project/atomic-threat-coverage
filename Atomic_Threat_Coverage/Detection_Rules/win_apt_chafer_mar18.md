| Title                | Chafer Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li></ul>  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/](https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/)</li></ul>  |
| Author               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>attack.g0049</li><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Chafer Activity
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
description: Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018
references:
    - https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
tags:
    - attack.persistence
    - attack.g0049
    - attack.t1053
    - attack.s0111
    - attack.defense_evasion
    - attack.t1112
date: 2018/03/23
modified: 2019/03/01
author: Florian Roth, Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: critical
---
logsource:
    product: windows
    service: system
detection:
    selection_service:
        EventID: 7045
        ServiceName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
---
logsource:
    product: windows
    service: security
detection:
    selection_service:
        EventID: 4698
        TaskName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
---
logsource:
   product: windows
   service: sysmon
detection:
    selection_reg1:
        EventID: 13 
        TargetObject: 
            - '*SOFTWARE\Microsoft\Windows\CurrentVersion\UMe'
            - '*SOFTWARE\Microsoft\Windows\CurrentVersion\UT'
        EventType: 'SetValue'
    selection_reg2:
        EventID: 13 
        TargetObject: '*\Control\SecurityProviders\WDigest\UseLogonCredential'
        EventType: 'SetValue'
        Details: 'DWORD (0x00000001)'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process1:
        CommandLine: 
            - '*\Service.exe i'
            - '*\Service.exe u'
            - '*\microsoft\Taskbar\autoit3.exe'
            - 'C:\wsc.exe*'
    selection_process2:
        Image: '*\Windows\Temp\DB\\*.exe'
    selection_process3:
        CommandLine: '*\nslookup.exe -q=TXT*'
        ParentImage: '*\Autoit*'

```





### es-qs
    
```
(EventID:"7045" AND ServiceName:("SC\\ Scheduled\\ Scan" OR "UpdatMachine"))\n(EventID:"4698" AND TaskName:("SC\\ Scheduled\\ Scan" OR "UpdatMachine"))\n(EventID:"13" AND EventType:"SetValue" AND (TargetObject.keyword:(*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UMe OR *SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UT) OR (TargetObject.keyword:*\\\\Control\\\\SecurityProviders\\\\WDigest\\\\UseLogonCredential AND Details:"DWORD\\ \\(0x00000001\\)")))\n(CommandLine.keyword:(*\\\\Service.exe\\ i OR *\\\\Service.exe\\ u OR *\\\\microsoft\\\\Taskbar\\\\autoit3.exe OR C\\:\\\\wsc.exe*) OR Image.keyword:*\\\\Windows\\\\Temp\\\\DB\\\\*.exe OR (CommandLine.keyword:*\\\\nslookup.exe\\ \\-q\\=TXT* AND ParentImage.keyword:*\\\\Autoit*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92 <<EOF\n{\n  "metadata": {\n    "title": "Chafer Activity",\n    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",\n    "tags": [\n      "attack.persistence",\n      "attack.g0049",\n      "attack.t1053",\n      "attack.s0111",\n      "attack.defense_evasion",\n      "attack.t1112"\n    ],\n    "query": "(EventID:\\"7045\\" AND ServiceName:(\\"SC\\\\ Scheduled\\\\ Scan\\" OR \\"UpdatMachine\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7045\\" AND ServiceName:(\\"SC\\\\ Scheduled\\\\ Scan\\" OR \\"UpdatMachine\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Chafer Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92-2 <<EOF\n{\n  "metadata": {\n    "title": "Chafer Activity",\n    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",\n    "tags": [\n      "attack.persistence",\n      "attack.g0049",\n      "attack.t1053",\n      "attack.s0111",\n      "attack.defense_evasion",\n      "attack.t1112"\n    ],\n    "query": "(EventID:\\"4698\\" AND TaskName:(\\"SC\\\\ Scheduled\\\\ Scan\\" OR \\"UpdatMachine\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4698\\" AND TaskName:(\\"SC\\\\ Scheduled\\\\ Scan\\" OR \\"UpdatMachine\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Chafer Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92-3 <<EOF\n{\n  "metadata": {\n    "title": "Chafer Activity",\n    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",\n    "tags": [\n      "attack.persistence",\n      "attack.g0049",\n      "attack.t1053",\n      "attack.s0111",\n      "attack.defense_evasion",\n      "attack.t1112"\n    ],\n    "query": "(EventID:\\"13\\" AND EventType:\\"SetValue\\" AND (TargetObject.keyword:(*SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\UMe OR *SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\UT) OR (TargetObject.keyword:*\\\\\\\\Control\\\\\\\\SecurityProviders\\\\\\\\WDigest\\\\\\\\UseLogonCredential AND Details:\\"DWORD\\\\ \\\\(0x00000001\\\\)\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND EventType:\\"SetValue\\" AND (TargetObject.keyword:(*SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\UMe OR *SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\UT) OR (TargetObject.keyword:*\\\\\\\\Control\\\\\\\\SecurityProviders\\\\\\\\WDigest\\\\\\\\UseLogonCredential AND Details:\\"DWORD\\\\ \\\\(0x00000001\\\\)\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Chafer Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92-4 <<EOF\n{\n  "metadata": {\n    "title": "Chafer Activity",\n    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",\n    "tags": [\n      "attack.persistence",\n      "attack.g0049",\n      "attack.t1053",\n      "attack.s0111",\n      "attack.defense_evasion",\n      "attack.t1112"\n    ],\n    "query": "(CommandLine.keyword:(*\\\\\\\\Service.exe\\\\ i OR *\\\\\\\\Service.exe\\\\ u OR *\\\\\\\\microsoft\\\\\\\\Taskbar\\\\\\\\autoit3.exe OR C\\\\:\\\\\\\\wsc.exe*) OR Image.keyword:*\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\DB\\\\\\\\*.exe OR (CommandLine.keyword:*\\\\\\\\nslookup.exe\\\\ \\\\-q\\\\=TXT* AND ParentImage.keyword:*\\\\\\\\Autoit*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:(*\\\\\\\\Service.exe\\\\ i OR *\\\\\\\\Service.exe\\\\ u OR *\\\\\\\\microsoft\\\\\\\\Taskbar\\\\\\\\autoit3.exe OR C\\\\:\\\\\\\\wsc.exe*) OR Image.keyword:*\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\DB\\\\\\\\*.exe OR (CommandLine.keyword:*\\\\\\\\nslookup.exe\\\\ \\\\-q\\\\=TXT* AND ParentImage.keyword:*\\\\\\\\Autoit*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Chafer Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND ServiceName:("SC Scheduled Scan" "UpdatMachine"))\n(EventID:"4698" AND TaskName:("SC Scheduled Scan" "UpdatMachine"))\n(EventID:"13" AND EventType:"SetValue" AND (TargetObject.keyword:(*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UMe *SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UT) OR (TargetObject.keyword:*\\\\Control\\\\SecurityProviders\\\\WDigest\\\\UseLogonCredential AND Details:"DWORD \\(0x00000001\\)")))\n(CommandLine.keyword:(*\\\\Service.exe i *\\\\Service.exe u *\\\\microsoft\\\\Taskbar\\\\autoit3.exe C\\:\\\\wsc.exe*) OR Image.keyword:*\\\\Windows\\\\Temp\\\\DB\\\\*.exe OR (CommandLine.keyword:*\\\\nslookup.exe \\-q=TXT* AND ParentImage.keyword:*\\\\Autoit*))
```


### splunk
    
```
(EventID="7045" (ServiceName="SC Scheduled Scan" OR ServiceName="UpdatMachine"))\n(EventID="4698" (TaskName="SC Scheduled Scan" OR TaskName="UpdatMachine"))\n(EventID="13" EventType="SetValue" ((TargetObject="*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UMe" OR TargetObject="*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UT") OR (TargetObject="*\\\\Control\\\\SecurityProviders\\\\WDigest\\\\UseLogonCredential" Details="DWORD (0x00000001)")))\n((CommandLine="*\\\\Service.exe i" OR CommandLine="*\\\\Service.exe u" OR CommandLine="*\\\\microsoft\\\\Taskbar\\\\autoit3.exe" OR CommandLine="C:\\\\wsc.exe*") OR Image="*\\\\Windows\\\\Temp\\\\DB\\\\*.exe" OR (CommandLine="*\\\\nslookup.exe -q=TXT*" ParentImage="*\\\\Autoit*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service IN ["SC Scheduled Scan", "UpdatMachine"])\n(event_source="Microsoft-Windows-Security-Auditing" event_id="4698" TaskName IN ["SC Scheduled Scan", "UpdatMachine"])\n(event_id="13" EventType="SetValue" (TargetObject IN ["*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UMe", "*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UT"] OR (TargetObject="*\\\\Control\\\\SecurityProviders\\\\WDigest\\\\UseLogonCredential" Details="DWORD (0x00000001)")))\n(event_id="1" (CommandLine IN ["*\\\\Service.exe i", "*\\\\Service.exe u", "*\\\\microsoft\\\\Taskbar\\\\autoit3.exe", "C:\\\\wsc.exe*"] OR Image="*\\\\Windows\\\\Temp\\\\DB\\\\*.exe" OR (CommandLine="*\\\\nslookup.exe -q=TXT*" ParentImage="*\\\\Autoit*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*SC Scheduled Scan|.*UpdatMachine)))'\ngrep -P '^(?:.*(?=.*4698)(?=.*(?:.*SC Scheduled Scan|.*UpdatMachine)))'\ngrep -P '^(?:.*(?=.*13)(?=.*SetValue)(?=.*(?:.*(?:.*(?:.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe|.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT)|.*(?:.*(?=.*.*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential)(?=.*DWORD \\(0x00000001\\)))))))'\ngrep -P '^(?:.*(?:.*(?:.*.*\\Service\\.exe i|.*.*\\Service\\.exe u|.*.*\\microsoft\\Taskbar\\autoit3\\.exe|.*C:\\wsc\\.exe.*)|.*.*\\Windows\\Temp\\DB\\\\.*\\.exe|.*(?:.*(?=.*.*\\nslookup\\.exe -q=TXT.*)(?=.*.*\\Autoit.*))))'
```



