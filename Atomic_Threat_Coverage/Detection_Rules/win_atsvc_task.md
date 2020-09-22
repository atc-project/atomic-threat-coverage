| Title                    | Remote Task Creation via ATSVC Named Pipe       |
|:-------------------------|:------------------|
| **Description**          | Detects remote task creation via at.exe or API interacting with ATSVC namedpipe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1053.002: At (Windows)](https://attack.mitre.org/techniques/T1053.002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.002: At (Windows)](../Triggers/T1053.002.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>pentesting</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html](https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html)</li></ul>  |
| **Author**               | Samir Bousseaden |
| Other Tags           | <ul><li>car.2013-05-004</li><li>car.2015-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Remote Task Creation via ATSVC Named Pipe
id: f6de6525-4509-495a-8a82-1f8b0ed73a00
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
tags:
    - attack.lateral_movement
    - attack.persistence
    - attack.t1053          # an old one
    - car.2013-05-004
    - car.2015-04-001
    - attack.t1053.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: atsvc
        Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - pentesting
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\\\\.*\\\\IPC$" -and $_.message -match "RelativeTargetName.*atsvc" -and $_.message -match "Accesses.*.*WriteData.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName:"atsvc" AND Accesses.keyword:*WriteData*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f6de6525-4509-495a-8a82-1f8b0ed73a00 <<EOF\n{\n  "metadata": {\n    "title": "Remote Task Creation via ATSVC Named Pipe",\n    "description": "Detects remote task creation via at.exe or API interacting with ATSVC namedpipe",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.persistence",\n      "attack.t1053",\n      "car.2013-05-004",\n      "car.2015-04-001",\n      "attack.t1053.002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\IPC$ AND RelativeTargetName:\\"atsvc\\" AND Accesses.keyword:*WriteData*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\IPC$ AND RelativeTargetName:\\"atsvc\\" AND Accesses.keyword:*WriteData*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Remote Task Creation via ATSVC Named Pipe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5145" AND ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName:"atsvc" AND Accesses.keyword:*WriteData*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="atsvc" Accesses="*WriteData*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="atsvc" Accesses="*WriteData*")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*atsvc)(?=.*.*WriteData.*))'
```



