| Title                | T1047 Wmiprvse Spawning Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects wmiprvse spawning processes                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_win32_process_create_remote.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_win32_process_create_remote.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1047 Wmiprvse Spawning Process
id: d21374ff-f574-44a7-9998-4a8c8bf33d7d
description: Detects wmiprvse spawning processes
status: experimental
date: 2019/08/15
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_win32_process_create_remote.md
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\WmiPrvSe.exe'
    filter:
        LogonId: '0x3e7'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(ParentImage.keyword:*\\\\WmiPrvSe.exe AND (NOT (LogonId:"0x3e7")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1047-Wmiprvse-Spawning-Process <<EOF\n{\n  "metadata": {\n    "title": "T1047 Wmiprvse Spawning Process",\n    "description": "Detects wmiprvse spawning processes",\n    "tags": "",\n    "query": "(ParentImage.keyword:*\\\\\\\\WmiPrvSe.exe AND (NOT (LogonId:\\"0x3e7\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:*\\\\\\\\WmiPrvSe.exe AND (NOT (LogonId:\\"0x3e7\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1047 Wmiprvse Spawning Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage.keyword:*\\\\WmiPrvSe.exe AND (NOT (LogonId:"0x3e7")))
```


### splunk
    
```
(ParentImage="*\\\\WmiPrvSe.exe" NOT (LogonId="0x3e7"))
```


### logpoint
    
```
(event_id="1" ParentImage="*\\\\WmiPrvSe.exe"  -(LogonId="0x3e7"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\WmiPrvSe\\.exe)(?=.*(?!.*(?:.*(?=.*0x3e7)))))'
```



