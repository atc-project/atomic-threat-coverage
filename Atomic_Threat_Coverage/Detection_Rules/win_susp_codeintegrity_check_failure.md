| Title                    | Failed Code Integrity Checks       |
|:-------------------------|:------------------|
| **Description**          | Code integrity failures may indicate tampered executables. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1009: Binary Padding](https://attack.mitre.org/techniques/T1009)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1009: Binary Padding](../Triggers/T1009.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Disk device errors</li></ul>  |
| **Development Status**   | stable |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Failed Code Integrity Checks
id: 470ec5fa-7b4e-4071-b200-4c753100f49b
status: stable
description: Code integrity failures may indicate tampered executables.
author: Thomas Patzke
date: 2019/12/03
tags:
    - attack.defense_evasion
    - attack.t1009
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5038
            - 6281
    condition: selection
falsepositives:
    - Disk device errors
level: low

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5038" -or $_.ID -eq "6281")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("5038" OR "6281"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/470ec5fa-7b4e-4071-b200-4c753100f49b <<EOF\n{\n  "metadata": {\n    "title": "Failed Code Integrity Checks",\n    "description": "Code integrity failures may indicate tampered executables.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1009"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:(\\"5038\\" OR \\"6281\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:(\\"5038\\" OR \\"6281\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Failed Code Integrity Checks\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:("5038" "6281")
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5038" OR EventCode="6281"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["5038", "6281"])
```


### grep
    
```
grep -P '^(?:.*5038|.*6281)'
```



