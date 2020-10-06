| Title                    | Remote PowerShell Session       |
|:-------------------------|:------------------|
| **Description**          | Detects remote PowerShell sections by monitoring for wsmprovhost as a parent or child process (sign of an active ps remote session) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate usage of remote Powershell, e.g. for monitoring purposes</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Remote PowerShell Session
id: 734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8
description: Detects remote PowerShell sections by monitoring for wsmprovhost as a parent or child process (sign of an active ps remote session)
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md
tags:
    - attack.execution
    - attack.t1086 # an old one
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\wsmprovhost.exe'
        - ParentImage|endswith: '\wsmprovhost.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate usage of remote Powershell, e.g. for monitoring purposes
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\wsmprovhost.exe" -or $_.message -match "ParentImage.*.*\\\\wsmprovhost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\wsmprovhost.exe OR winlog.event_data.ParentImage.keyword:*\\\\wsmprovhost.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8 <<EOF\n{\n  "metadata": {\n    "title": "Remote PowerShell Session",\n    "description": "Detects remote PowerShell sections by monitoring for wsmprovhost as a parent or child process (sign of an active ps remote session)",\n    "tags": [\n      "attack.execution",\n      "attack.t1086",\n      "attack.t1059.001"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\wsmprovhost.exe OR winlog.event_data.ParentImage.keyword:*\\\\\\\\wsmprovhost.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\wsmprovhost.exe OR winlog.event_data.ParentImage.keyword:*\\\\\\\\wsmprovhost.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Remote PowerShell Session\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\wsmprovhost.exe OR ParentImage.keyword:*\\\\wsmprovhost.exe)
```


### splunk
    
```
(Image="*\\\\wsmprovhost.exe" OR ParentImage="*\\\\wsmprovhost.exe") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image="*\\\\wsmprovhost.exe" OR ParentImage="*\\\\wsmprovhost.exe")
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\wsmprovhost\\.exe|.*.*\\wsmprovhost\\.exe))'
```



