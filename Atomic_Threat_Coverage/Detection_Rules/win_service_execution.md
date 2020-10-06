| Title                    | Service Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects manual service execution (start) via system utilities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1569.002: Service Execution](https://attack.mitre.org/techniques/T1569/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1569.002: Service Execution](../Triggers/T1569.002.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrator or user executes a service for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Service Execution
id: 2a072a96-a086-49fa-bcb5-15cc5a619093
status: experimental
description: Detects manual service execution (start) via system utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: ' start ' # space character after the 'start' keyword indicates that a service name follows, in contrast to `net start` discovery expression 
    condition: selection
falsepositives:
    - Legitimate administrator or user executes a service for legitimate reason
level: low
tags:
    - attack.execution
    - attack.t1035 # an old one
    - attack.t1569.002

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\net.exe" -or $_.message -match "Image.*.*\\\\net1.exe") -and $_.message -match "CommandLine.*.* start .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*\\ start\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/2a072a96-a086-49fa-bcb5-15cc5a619093 <<EOF\n{\n  "metadata": {\n    "title": "Service Execution",\n    "description": "Detects manual service execution (start) via system utilities",\n    "tags": [\n      "attack.execution",\n      "attack.t1035",\n      "attack.t1569.002"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*\\\\ start\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*\\\\ start\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Service Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:* start *)
```


### splunk
    
```
((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="* start *")
```


### logpoint
    
```
(Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine="* start *")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*.* start .*))'
```



