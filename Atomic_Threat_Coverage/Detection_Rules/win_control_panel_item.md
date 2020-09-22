| Title                    | Control Panel Items       |
|:-------------------------|:------------------|
| **Description**          | Detects the malicious use of a control panel item |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.002: Control Panel](https://attack.mitre.org/techniques/T1218.002)</li><li>[T1196: Control Panel Items](https://attack.mitre.org/techniques/T1196)</li><li>[T1546: Event Triggered Execution](https://attack.mitre.org/techniques/T1546)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.002: Control Panel](../Triggers/T1218.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_) |


## Detection Rules

### Sigma rule

```
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: experimental
description: Detects the malicious use of a control panel item
reference:
    - https://attack.mitre.org/techniques/T1196/
    - https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218.002
    - attack.t1196  # an old one
    - attack.persistence
    - attack.t1546
author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
date: 2020/06/22
modified: 2020/08/29
level: critical
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        CommandLine: '*.cpl'
    filter:
        CommandLine:
            - '*\System32\\*'
            - '*%System%*'
    selection2:
        CommandLine:
            - '*reg add*'
    selection3:
        CommandLine:
            - '*CurrentVersion\\Control Panel\\CPLs*'
    condition: (selection1 and not filter) or (selection2 and selection3)
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*.cpl" -and  -not (($_.message -match "CommandLine.*.*\\\\System32\\\\.*" -or $_.message -match "CommandLine.*.*%System%.*"))) -or (($_.message -match "CommandLine.*.*reg add.*") -and ($_.message -match "CommandLine.*.*CurrentVersion\\\\Control Panel\\\\CPLs.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\System32\\\\* OR *%System%*)))) OR (winlog.event_data.CommandLine.keyword:(*reg\\ add*) AND winlog.event_data.CommandLine.keyword:(*CurrentVersion\\\\Control\\ Panel\\\\CPLs*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/0ba863e6-def5-4e50-9cea-4dd8c7dc46a4 <<EOF\n{\n  "metadata": {\n    "title": "Control Panel Items",\n    "description": "Detects the malicious use of a control panel item",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1218.002",\n      "attack.t1196",\n      "attack.persistence",\n      "attack.t1546"\n    ],\n    "query": "((winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\\\\\System32\\\\\\\\* OR *%System%*)))) OR (winlog.event_data.CommandLine.keyword:(*reg\\\\ add*) AND winlog.event_data.CommandLine.keyword:(*CurrentVersion\\\\\\\\Control\\\\ Panel\\\\\\\\CPLs*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\\\\\System32\\\\\\\\* OR *%System%*)))) OR (winlog.event_data.CommandLine.keyword:(*reg\\\\ add*) AND winlog.event_data.CommandLine.keyword:(*CurrentVersion\\\\\\\\Control\\\\ Panel\\\\\\\\CPLs*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Control Panel Items\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((CommandLine.keyword:*.cpl AND (NOT (CommandLine.keyword:(*\\\\System32\\\\* *%System%*)))) OR (CommandLine.keyword:(*reg add*) AND CommandLine.keyword:(*CurrentVersion\\\\Control Panel\\\\CPLs*)))
```


### splunk
    
```
((CommandLine="*.cpl" NOT ((CommandLine="*\\\\System32\\\\*" OR CommandLine="*%System%*"))) OR ((CommandLine="*reg add*") (CommandLine="*CurrentVersion\\\\Control Panel\\\\CPLs*")))
```


### logpoint
    
```
((CommandLine="*.cpl"  -(CommandLine IN ["*\\\\System32\\\\*", "*%System%*"])) OR (CommandLine IN ["*reg add*"] CommandLine IN ["*CurrentVersion\\\\Control Panel\\\\CPLs*"]))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\.cpl)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\System32\\\\.*|.*.*%System%.*))))))|.*(?:.*(?=.*(?:.*.*reg add.*))(?=.*(?:.*.*CurrentVersion\\\\Control Panel\\\\CPLs.*)))))'
```



