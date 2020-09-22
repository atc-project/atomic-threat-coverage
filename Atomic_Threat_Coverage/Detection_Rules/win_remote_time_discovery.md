| Title                    | Discovery of a System Time       |
|:-------------------------|:------------------|
| **Description**          | Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1124: System Time Discovery](https://attack.mitre.org/techniques/T1124)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1124: System Time Discovery](../Triggers/T1124.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate use of the system utilities to discover system time for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/fcdb99c2-ac3c-4bde-b664-4b336329bed2.html](https://eqllib.readthedocs.io/en/latest/analytics/fcdb99c2-ac3c-4bde-b664-4b336329bed2.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Discovery of a System Time
id: b243b280-65fe-48df-ba07-6ddea7646427
description: "Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system."
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/fcdb99c2-ac3c-4bde-b664-4b336329bed2.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md
tags:
    - attack.discovery
    - attack.t1124
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'time'
      - Image|endswith: '\w32tm.exe'
        CommandLine|contains: 'tz'
      - Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Get-Date'
    condition: selection
falsepositives:
    - Legitimate use of the system utilities to discover system time for legitimate reason
level: low

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "Image.*.*\\\\net.exe" -or $_.message -match "Image.*.*\\\\net1.exe") -and $_.message -match "CommandLine.*.*time.*") -or ($_.message -match "Image.*.*\\\\w32tm.exe" -and $_.message -match "CommandLine.*.*tz.*") -or ($_.message -match "Image.*.*\\\\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Date.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*time*) OR (winlog.event_data.Image.keyword:*\\\\w32tm.exe AND winlog.event_data.CommandLine.keyword:*tz*) OR (winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Get\\-Date*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/b243b280-65fe-48df-ba07-6ddea7646427 <<EOF\n{\n  "metadata": {\n    "title": "Discovery of a System Time",\n    "description": "Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.",\n    "tags": [\n      "attack.discovery",\n      "attack.t1124"\n    ],\n    "query": "((winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*time*) OR (winlog.event_data.Image.keyword:*\\\\\\\\w32tm.exe AND winlog.event_data.CommandLine.keyword:*tz*) OR (winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Get\\\\-Date*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*time*) OR (winlog.event_data.Image.keyword:*\\\\\\\\w32tm.exe AND winlog.event_data.CommandLine.keyword:*tz*) OR (winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Get\\\\-Date*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Discovery of a System Time\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:*time*) OR (Image.keyword:*\\\\w32tm.exe AND CommandLine.keyword:*tz*) OR (Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:*Get\\-Date*))
```


### splunk
    
```
(((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="*time*") OR (Image="*\\\\w32tm.exe" CommandLine="*tz*") OR (Image="*\\\\powershell.exe" CommandLine="*Get-Date*"))
```


### logpoint
    
```
((Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine="*time*") OR (Image="*\\\\w32tm.exe" CommandLine="*tz*") OR (Image="*\\\\powershell.exe" CommandLine="*Get-Date*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*.*time.*))|.*(?:.*(?=.*.*\\w32tm\\.exe)(?=.*.*tz.*))|.*(?:.*(?=.*.*\\powershell\\.exe)(?=.*.*Get-Date.*))))'
```



