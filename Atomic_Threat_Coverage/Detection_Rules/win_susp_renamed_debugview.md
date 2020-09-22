| Title                    | Renamed SysInternals Debug View       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious renamed SysInternals DebugView execution |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.epicturla.com/blog/sysinturla](https://www.epicturla.com/blog/sysinturla)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Renamed SysInternals Debug View
id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: experimental
description: Detects suspicious renamed SysInternals DebugView execution
references:
    - https://www.epicturla.com/blog/sysinturla
author: Florian Roth
date: 2020/05/28
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 
            - 'Sysinternals DebugView'
            - 'Sysinternals Debugview'
    filter:
        OriginalFilename: 'Dbgview.exe'
        Image|endswith: '\Dbgview.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Sysinternals DebugView" -or $_.message -match "Sysinternals Debugview") -and  -not ($_.message -match "OriginalFilename.*Dbgview.exe" -and $_.message -match "Image.*.*\\\\Dbgview.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(Product:("Sysinternals\\ DebugView" OR "Sysinternals\\ Debugview") AND (NOT (OriginalFilename:"Dbgview.exe" AND winlog.event_data.Image.keyword:*\\\\Dbgview.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/cd764533-2e07-40d6-a718-cfeec7f2da7f <<EOF\n{\n  "metadata": {\n    "title": "Renamed SysInternals Debug View",\n    "description": "Detects suspicious renamed SysInternals DebugView execution",\n    "tags": "",\n    "query": "(Product:(\\"Sysinternals\\\\ DebugView\\" OR \\"Sysinternals\\\\ Debugview\\") AND (NOT (OriginalFilename:\\"Dbgview.exe\\" AND winlog.event_data.Image.keyword:*\\\\\\\\Dbgview.exe)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Product:(\\"Sysinternals\\\\ DebugView\\" OR \\"Sysinternals\\\\ Debugview\\") AND (NOT (OriginalFilename:\\"Dbgview.exe\\" AND winlog.event_data.Image.keyword:*\\\\\\\\Dbgview.exe)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed SysInternals Debug View\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Product:("Sysinternals DebugView" "Sysinternals Debugview") AND (NOT (OriginalFilename:"Dbgview.exe" AND Image.keyword:*\\\\Dbgview.exe)))
```


### splunk
    
```
((Product="Sysinternals DebugView" OR Product="Sysinternals Debugview") NOT (OriginalFilename="Dbgview.exe" Image="*\\\\Dbgview.exe"))
```


### logpoint
    
```
(Product IN ["Sysinternals DebugView", "Sysinternals Debugview"]  -(OriginalFilename="Dbgview.exe" Image="*\\\\Dbgview.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*Sysinternals DebugView|.*Sysinternals Debugview))(?=.*(?!.*(?:.*(?=.*Dbgview\\.exe)(?=.*.*\\Dbgview\\.exe)))))'
```



