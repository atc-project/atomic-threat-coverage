| Title                    | Renamed ZOHO Dctask64       |
|:-------------------------|:------------------|
| **Description**          | Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown yet</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/gN3mes1s/status/1222088214581825540](https://twitter.com/gN3mes1s/status/1222088214581825540)</li><li>[https://twitter.com/gN3mes1s/status/1222095963789111296](https://twitter.com/gN3mes1s/status/1222095963789111296)</li><li>[https://twitter.com/gN3mes1s/status/1222095371175911424](https://twitter.com/gN3mes1s/status/1222095371175911424)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Renamed ZOHO Dctask64
id: 340a090b-c4e9-412e-bb36-b4b16fe96f9b
status: experimental
description: Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation
references:
    - https://twitter.com/gN3mes1s/status/1222088214581825540
    - https://twitter.com/gN3mes1s/status/1222095963789111296
    - https://twitter.com/gN3mes1s/status/1222095371175911424
author: Florian Roth
date: 2020/01/28
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Imphash: '6834B1B94E49701D77CCB3C0895E1AFD'
    filter:
        Image|endswith: '\dctask64.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
    - ParentImage
falsepositives:
    - Unknown yet
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Imphash.*6834B1B94E49701D77CCB3C0895E1AFD" -and  -not ($_.message -match "Image.*.*\\\\dctask64.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Imphash:"6834B1B94E49701D77CCB3C0895E1AFD" AND (NOT (winlog.event_data.Image.keyword:*\\\\dctask64.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/340a090b-c4e9-412e-bb36-b4b16fe96f9b <<EOF\n{\n  "metadata": {\n    "title": "Renamed ZOHO Dctask64",\n    "description": "Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1055"\n    ],\n    "query": "(winlog.event_data.Imphash:\\"6834B1B94E49701D77CCB3C0895E1AFD\\" AND (NOT (winlog.event_data.Image.keyword:*\\\\\\\\dctask64.exe)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Imphash:\\"6834B1B94E49701D77CCB3C0895E1AFD\\" AND (NOT (winlog.event_data.Image.keyword:*\\\\\\\\dctask64.exe)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed ZOHO Dctask64\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      ParentImage = {{_source.ParentImage}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Imphash:"6834B1B94E49701D77CCB3C0895E1AFD" AND (NOT (Image.keyword:*\\\\dctask64.exe)))
```


### splunk
    
```
(Imphash="6834B1B94E49701D77CCB3C0895E1AFD" NOT (Image="*\\\\dctask64.exe")) | table CommandLine,ParentCommandLine,ParentImage
```


### logpoint
    
```
(Imphash="6834B1B94E49701D77CCB3C0895E1AFD"  -(Image="*\\\\dctask64.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*6834B1B94E49701D77CCB3C0895E1AFD)(?=.*(?!.*(?:.*(?=.*.*\\dctask64\\.exe)))))'
```



