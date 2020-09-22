| Title                    | Scheduled Task Creation       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of scheduled tasks in user session |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053.005)</li><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Administrative activity</li><li>Software installation</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Scheduled Task Creation
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: experimental
description: Detects the creation of scheduled tasks in user session
author: Florian Roth
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\schtasks.exe'
        CommandLine: '* /create *'
    filter:
        User: NT AUTHORITY\SYSTEM
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053.005
    - attack.t1053     # an old one 
    - attack.s0111
    - car.2013-08-001
falsepositives:
    - Administrative activity
    - Software installation
level: low

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\schtasks.exe" -and $_.message -match "CommandLine.*.* /create .*") -and  -not ($_.message -match "User.*NT AUTHORITY\\\\SYSTEM")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\schtasks.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/create\\ *) AND (NOT (winlog.event_data.User:"NT\\ AUTHORITY\\\\SYSTEM")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/92626ddd-662c-49e3-ac59-f6535f12d189 <<EOF\n{\n  "metadata": {\n    "title": "Scheduled Task Creation",\n    "description": "Detects the creation of scheduled tasks in user session",\n    "tags": [\n      "attack.execution",\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1053.005",\n      "attack.t1053",\n      "attack.s0111",\n      "car.2013-08-001"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\schtasks.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\/create\\\\ *) AND (NOT (winlog.event_data.User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\schtasks.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\/create\\\\ *) AND (NOT (winlog.event_data.User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Scheduled Task Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\schtasks.exe AND CommandLine.keyword:* \\/create *) AND (NOT (User:"NT AUTHORITY\\\\SYSTEM")))
```


### splunk
    
```
((Image="*\\\\schtasks.exe" CommandLine="* /create *") NOT (User="NT AUTHORITY\\\\SYSTEM")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((Image="*\\\\schtasks.exe" CommandLine="* /create *")  -(User="NT AUTHORITY\\\\SYSTEM"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\schtasks\\.exe)(?=.*.* /create .*)))(?=.*(?!.*(?:.*(?=.*NT AUTHORITY\\SYSTEM)))))'
```



