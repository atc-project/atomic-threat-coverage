| Title                    | Persistence and Execution at Scale via GPO Scheduled Task       |
|:-------------------------|:------------------|
| **Description**          | Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053.005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://twitter.com/menasec1/status/1106899890377052160](https://twitter.com/menasec1/status/1106899890377052160)</li><li>[https://www.secureworks.com/blog/ransomware-as-a-distraction](https://www.secureworks.com/blog/ransomware-as-a-distraction)</li></ul>  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Persistence and Execution at Scale via GPO Scheduled Task
id: a8f29a7b-b137-4446-80a0-b804272f3da2
description: Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://twitter.com/menasec1/status/1106899890377052160
    - https://www.secureworks.com/blog/ransomware-as-a-distraction
tags:
    - attack.persistence
    - attack.lateral_movement
    - attack.t1053          # an old one
    - attack.t1053.005
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\SYSVOL
        RelativeTargetName: '*ScheduledTasks.xml'
        Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\\\\.*\\\\SYSVOL" -and $_.message -match "RelativeTargetName.*.*ScheduledTasks.xml" -and $_.message -match "Accesses.*.*WriteData.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\\\*\\\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/a8f29a7b-b137-4446-80a0-b804272f3da2 <<EOF\n{\n  "metadata": {\n    "title": "Persistence and Execution at Scale via GPO Scheduled Task",\n    "description": "Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale",\n    "tags": [\n      "attack.persistence",\n      "attack.lateral_movement",\n      "attack.t1053",\n      "attack.t1053.005"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Persistence and Execution at Scale via GPO Scheduled Task\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5145" AND ShareName.keyword:\\\\*\\\\SYSVOL AND RelativeTargetName.keyword:*ScheduledTasks.xml AND Accesses.keyword:*WriteData*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" ShareName="\\\\*\\\\SYSVOL" RelativeTargetName="*ScheduledTasks.xml" Accesses="*WriteData*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" ShareName="\\\\*\\\\SYSVOL" RelativeTargetName="*ScheduledTasks.xml" Accesses="*WriteData*")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\\\.*\\SYSVOL)(?=.*.*ScheduledTasks\\.xml)(?=.*.*WriteData.*))'
```



