| Title                    | Bypass UAC via Fodhelper.exe       |
|:-------------------------|:------------------|
| **Description**          | Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate use of fodhelper.exe utility by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html](https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community |


## Detection Rules

### Sigma rule

```
title: Bypass UAC via Fodhelper.exe
id: 7f741dcf-fc22-4759-87b4-9ae8376676a2
description: Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md
tags:
    - attack.privilege_escalation
    - attack.t1088
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\fodhelper.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate use of fodhelper.exe utility by legitimate user
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "ParentImage.*.*\\\\fodhelper.exe" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.ParentImage.keyword:*\\\\fodhelper.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7f741dcf-fc22-4759-87b4-9ae8376676a2 <<EOF\n{\n  "metadata": {\n    "title": "Bypass UAC via Fodhelper.exe",\n    "description": "Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1088"\n    ],\n    "query": "winlog.event_data.ParentImage.keyword:*\\\\\\\\fodhelper.exe"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.ParentImage.keyword:*\\\\\\\\fodhelper.exe",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Bypass UAC via Fodhelper.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
ParentImage.keyword:*\\\\fodhelper.exe
```


### splunk
    
```
ParentImage="*\\\\fodhelper.exe" | table ComputerName,User,CommandLine
```


### logpoint
    
```
ParentImage="*\\\\fodhelper.exe"
```


### grep
    
```
grep -P '^.*\\fodhelper\\.exe'
```



