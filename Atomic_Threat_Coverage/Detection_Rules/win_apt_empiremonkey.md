| Title                    | Empire Monkey       |
|:-------------------------|:------------------|
| **Description**          | Detects EmpireMonkey APT reported Activity |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Very Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b](https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
action: global
title: Empire Monkey
id: 10152a7b-b566-438f-a33c-390b607d1c8d
description: Detects EmpireMonkey APT reported Activity
references:
    - https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b
tags:
    - attack.t1086
    - attack.execution
date: 2019/04/02
author: Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Very Unlikely 
level: critical
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_cutil:
        CommandLine: 
            - '*/i:%APPDATA%\logs.txt scrobj.dll'
        Image:
            - '*\cutil.exe'
    selection_regsvr32:
        CommandLine: 
            - '*/i:%APPDATA%\logs.txt scrobj.dll'
        Description: 
            - Microsoft(C) Registerserver
        
```





### es-qs
    
```
(CommandLine.keyword:(*\\/i\\:%APPDATA%\\\\logs.txt\\ scrobj.dll) AND (Image.keyword:(*\\\\cutil.exe) OR Description:("Microsoft\\(C\\)\\ Registerserver")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/10152a7b-b566-438f-a33c-390b607d1c8d <<EOF\n{\n  "metadata": {\n    "title": "Empire Monkey",\n    "description": "Detects EmpireMonkey APT reported Activity",\n    "tags": [\n      "attack.t1086",\n      "attack.execution"\n    ],\n    "query": "(CommandLine.keyword:(*\\\\/i\\\\:%APPDATA%\\\\\\\\logs.txt\\\\ scrobj.dll) AND (Image.keyword:(*\\\\\\\\cutil.exe) OR Description:(\\"Microsoft\\\\(C\\\\)\\\\ Registerserver\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:(*\\\\/i\\\\:%APPDATA%\\\\\\\\logs.txt\\\\ scrobj.dll) AND (Image.keyword:(*\\\\\\\\cutil.exe) OR Description:(\\"Microsoft\\\\(C\\\\)\\\\ Registerserver\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Empire Monkey\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*\\/i\\:%APPDATA%\\\\logs.txt scrobj.dll) AND (Image.keyword:(*\\\\cutil.exe) OR Description:("Microsoft\\(C\\) Registerserver")))
```


### splunk
    
```
((CommandLine="*/i:%APPDATA%\\\\logs.txt scrobj.dll") ((Image="*\\\\cutil.exe") OR (Description="Microsoft(C) Registerserver")))
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*/i:%APPDATA%\\\\logs.txt scrobj.dll"] (Image IN ["*\\\\cutil.exe"] OR Description IN ["Microsoft(C) Registerserver"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*/i:%APPDATA%\\logs\\.txt scrobj\\.dll))(?=.*(?:.*(?:.*(?:.*.*\\cutil\\.exe)|.*(?:.*Microsoft\\(C\\) Registerserver)))))'
```



