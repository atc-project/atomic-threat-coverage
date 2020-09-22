| Title                    | Mshta JavaScript Execution       |
|:-------------------------|:------------------|
| **Description**          | Identifies suspicious mshta.exe commands |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li><li>[T1218.005: Mshta](https://attack.mitre.org/techniques/T1218.005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.005: Mshta](../Triggers/T1218.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html](https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.yaml)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Mshta JavaScript Execution
id: 67f113fa-e23d-4271-befa-30113b3e08b1
description: Identifies suspicious mshta.exe commands
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2020/09/01
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.yaml
tags:
    - attack.defense_evasion
    - attack.t1170          # an old one
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains: 'javascript'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - unknown
level: high
## todo — add sysmon eid 3 for this rule

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\mshta.exe" -and $_.message -match "CommandLine.*.*javascript.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\mshta.exe AND winlog.event_data.CommandLine.keyword:*javascript*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/67f113fa-e23d-4271-befa-30113b3e08b1 <<EOF\n{\n  "metadata": {\n    "title": "Mshta JavaScript Execution",\n    "description": "Identifies suspicious mshta.exe commands",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1170",\n      "attack.t1218.005"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\mshta.exe AND winlog.event_data.CommandLine.keyword:*javascript*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\mshta.exe AND winlog.event_data.CommandLine.keyword:*javascript*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mshta JavaScript Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\mshta.exe AND CommandLine.keyword:*javascript*)
```


### splunk
    
```
(Image="*\\\\mshta.exe" CommandLine="*javascript*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image="*\\\\mshta.exe" CommandLine="*javascript*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\mshta\\.exe)(?=.*.*javascript.*))'
```



