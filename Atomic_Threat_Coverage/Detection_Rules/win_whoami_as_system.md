| Title                    | Run Whoami as SYSTEM       |
|:-------------------------|:------------------|
| **Description**          | Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Run Whoami as SYSTEM
id: 80167ada-7a12-41ed-b8e9-aa47195c66a1
status: experimental
description: Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
author: Teymur Kheirkhabarov
date: 2019/10/23
modified: 2019/11/11
tags:
    - attack.discovery
    - attack.privilege_escalation
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: 'NT AUTHORITY\SYSTEM'
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "User.*NT AUTHORITY\\\\SYSTEM" -and $_.message -match "Image.*.*\\\\whoami.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.User:"NT\\ AUTHORITY\\\\SYSTEM" AND winlog.event_data.Image.keyword:*\\\\whoami.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/80167ada-7a12-41ed-b8e9-aa47195c66a1 <<EOF\n{\n  "metadata": {\n    "title": "Run Whoami as SYSTEM",\n    "description": "Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.",\n    "tags": [\n      "attack.discovery",\n      "attack.privilege_escalation",\n      "attack.t1033"\n    ],\n    "query": "(winlog.event_data.User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND winlog.event_data.Image.keyword:*\\\\\\\\whoami.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\" AND winlog.event_data.Image.keyword:*\\\\\\\\whoami.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Run Whoami as SYSTEM\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(User:"NT AUTHORITY\\\\SYSTEM" AND Image.keyword:*\\\\whoami.exe)
```


### splunk
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\whoami.exe")
```


### logpoint
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\whoami.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*NT AUTHORITY\\SYSTEM)(?=.*.*\\whoami\\.exe))'
```



