| Title                    | Maze Ransomware       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process characteristics of Maze ransomware word document droppers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1204.002: Malicious File](https://attack.mitre.org/techniques/T1204.002)</li><li>[T1204: User Execution](https://attack.mitre.org/techniques/T1204)</li><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li><li>[T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1204.002: Malicious File](../Triggers/T1204.002.md)</li><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li><li>[T1490: Inhibit System Recovery](../Triggers/T1490.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</li><li>[https://app.any.run/tasks/51e7185c-52d7-4efb-ac0d-e86340053473/](https://app.any.run/tasks/51e7185c-52d7-4efb-ac0d-e86340053473/)</li><li>[https://app.any.run/tasks/65a79440-373a-4725-8d74-77db9f2abda4/](https://app.any.run/tasks/65a79440-373a-4725-8d74-77db9f2abda4/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Maze Ransomware
id: 29fd07fc-9cfd-4331-b7fd-cc18dfa21052
status: experimental
description: Detects specific process characteristics of Maze ransomware word document droppers
references:
    - https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
    - https://app.any.run/tasks/51e7185c-52d7-4efb-ac0d-e86340053473/
    - https://app.any.run/tasks/65a79440-373a-4725-8d74-77db9f2abda4/
author: Florian Roth
date: 2020/05/08
modified: 2020/08/29
tags:
    - attack.execution
    - attack.t1204.002
    - attack.t1204  # an old one
    - attack.t1047
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    # Dropper
    selection1:
        ParentImage|endswith:
            - '\WINWORD.exe'
        Image|endswith:
            - '*.tmp'
    # Binary Execution
    selection2:
        Image|endswith: '\wmic.exe'
        ParentImage|contains: '\Temp\'
        CommandLine|endswith: 'shadowcopy delete'
    # Specific Pattern
    selection3: 
        CommandLine|endswith: 'shadowcopy delete'
        CommandLine|contains: '\..\..\system32'
    condition: 1 of them
fields:
    - ComputerName
    - User
    - Image
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "ParentImage.*.*\\\\WINWORD.exe") -and ($_.message -match "Image.*.*.tmp")) -or ($_.message -match "Image.*.*\\\\wmic.exe" -and $_.message -match "ParentImage.*.*\\\\Temp\\\\.*" -and $_.message -match "CommandLine.*.*shadowcopy delete") -or ($_.message -match "CommandLine.*.*shadowcopy delete" -and $_.message -match "CommandLine.*.*\\\\..\\\\..\\\\system32.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:(*\\\\WINWORD.exe) AND winlog.event_data.Image.keyword:(*.tmp)) OR (winlog.event_data.Image.keyword:*\\\\wmic.exe AND winlog.event_data.ParentImage.keyword:*\\\\Temp\\\\* AND winlog.event_data.CommandLine.keyword:*shadowcopy\\ delete) OR (winlog.event_data.CommandLine.keyword:*shadowcopy\\ delete AND winlog.event_data.CommandLine.keyword:*\\\\..\\\\..\\\\system32*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/29fd07fc-9cfd-4331-b7fd-cc18dfa21052 <<EOF\n{\n  "metadata": {\n    "title": "Maze Ransomware",\n    "description": "Detects specific process characteristics of Maze ransomware word document droppers",\n    "tags": [\n      "attack.execution",\n      "attack.t1204.002",\n      "attack.t1204",\n      "attack.t1047",\n      "attack.impact",\n      "attack.t1490"\n    ],\n    "query": "((winlog.event_data.ParentImage.keyword:(*\\\\\\\\WINWORD.exe) AND winlog.event_data.Image.keyword:(*.tmp)) OR (winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.ParentImage.keyword:*\\\\\\\\Temp\\\\\\\\* AND winlog.event_data.CommandLine.keyword:*shadowcopy\\\\ delete) OR (winlog.event_data.CommandLine.keyword:*shadowcopy\\\\ delete AND winlog.event_data.CommandLine.keyword:*\\\\\\\\..\\\\\\\\..\\\\\\\\system32*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.ParentImage.keyword:(*\\\\\\\\WINWORD.exe) AND winlog.event_data.Image.keyword:(*.tmp)) OR (winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.ParentImage.keyword:*\\\\\\\\Temp\\\\\\\\* AND winlog.event_data.CommandLine.keyword:*shadowcopy\\\\ delete) OR (winlog.event_data.CommandLine.keyword:*shadowcopy\\\\ delete AND winlog.event_data.CommandLine.keyword:*\\\\\\\\..\\\\\\\\..\\\\\\\\system32*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Maze Ransomware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n       Image = {{_source.Image}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((ParentImage.keyword:(*\\\\WINWORD.exe) AND Image.keyword:(*.tmp)) OR (Image.keyword:*\\\\wmic.exe AND ParentImage.keyword:*\\\\Temp\\\\* AND CommandLine.keyword:*shadowcopy delete) OR (CommandLine.keyword:*shadowcopy delete AND CommandLine.keyword:*\\\\..\\\\..\\\\system32*))
```


### splunk
    
```
(((ParentImage="*\\\\WINWORD.exe") (Image="*.tmp")) OR (Image="*\\\\wmic.exe" ParentImage="*\\\\Temp\\\\*" CommandLine="*shadowcopy delete") OR (CommandLine="*shadowcopy delete" CommandLine="*\\\\..\\\\..\\\\system32*")) | table ComputerName,User,Image
```


### logpoint
    
```
((ParentImage IN ["*\\\\WINWORD.exe"] Image IN ["*.tmp"]) OR (Image="*\\\\wmic.exe" ParentImage="*\\\\Temp\\\\*" CommandLine="*shadowcopy delete") OR (CommandLine="*shadowcopy delete" CommandLine="*\\\\..\\\\..\\\\system32*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*.*\\WINWORD\\.exe))(?=.*(?:.*.*\\.tmp)))|.*(?:.*(?=.*.*\\wmic\\.exe)(?=.*.*\\Temp\\\\.*)(?=.*.*shadowcopy delete))|.*(?:.*(?=.*.*shadowcopy delete)(?=.*.*\\\\.\\.\\\\.\\.\\system32.*))))'
```



