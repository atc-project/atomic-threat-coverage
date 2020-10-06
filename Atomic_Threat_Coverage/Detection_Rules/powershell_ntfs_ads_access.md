| Title                    | NTFS Alternate Data Stream       |
|:-------------------------|:------------------|
| **Description**          | Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1564.004: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004)</li><li>[T1096: NTFS File Attributes](https://attack.mitre.org/techniques/T1096)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1564.004: NTFS File Attributes](../Triggers/T1564.004.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.powertheshell.com/ntfsstreams/](http://www.powertheshell.com/ntfsstreams/)</li></ul>  |
| **Author**               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: NTFS Alternate Data Stream
id: 8c521530-5169-495d-a199-0a3a881ad24e
status: experimental
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
references:
    - http://www.powertheshell.com/ntfsstreams/
tags:
    - attack.defense_evasion
    - attack.t1564.004
    - attack.t1096  # an old one
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
author: Sami Ruohonen
date: 2018/07/24
modified: 2020/08/24
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keyword1:
        - "set-content"
        - "add-content"
    keyword2:
        - "-stream"
    condition: keyword1 and keyword2
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "set-content" -or $_.message -match "add-content") -and $_.message -match "-stream") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(\\*.keyword:(*set\\-content* OR *add\\-content*) AND "\\-stream")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/8c521530-5169-495d-a199-0a3a881ad24e <<EOF\n{\n  "metadata": {\n    "title": "NTFS Alternate Data Stream",\n    "description": "Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1564.004",\n      "attack.t1096",\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(\\\\*.keyword:(*set\\\\-content* OR *add\\\\-content*) AND \\"\\\\-stream\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(\\\\*.keyword:(*set\\\\-content* OR *add\\\\-content*) AND \\"\\\\-stream\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'NTFS Alternate Data Stream\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(\\*.keyword:(*set\\-content* OR *add\\-content*) AND "\\-stream")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" ("set-content" OR "add-content") "-stream")
```


### logpoint
    
```
(("set-content" OR "add-content") "-stream")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*set-content|.*add-content)))(?=.*-stream))'
```



