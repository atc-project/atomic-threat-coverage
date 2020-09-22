| Title                    | Lazarus Session Highjacker       |
|:-------------------------|:------------------|
| **Description**          | Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1036.005: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036.005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf)</li></ul>  |
| **Author**               | Trent Liffick (@tliffick) |


## Detection Rules

### Sigma rule

```
title: Lazarus Session Highjacker
id: 3f7f5b0b-5b16-476c-a85f-ab477f6dd24b
description: Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)
status: experimental
references:
    - https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf
tags:
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.005
author: Trent Liffick (@tliffick)
date: 2020/06/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 
            - '*\mstdc.exe'
            - '*\gpvc.exe'
    filter:
        Image:
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWOW64\\*'
    condition: selection and not filter
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\mstdc.exe" -or $_.message -match "Image.*.*\\\\gpvc.exe") -and  -not (($_.message -match "Image.*C:\\\\Windows\\\\System32\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\SysWOW64\\\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\mstdc.exe OR *\\\\gpvc.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/3f7f5b0b-5b16-476c-a85f-ab477f6dd24b <<EOF\n{\n  "metadata": {\n    "title": "Lazarus Session Highjacker",\n    "description": "Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036",\n      "attack.t1036.005"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\mstdc.exe OR *\\\\\\\\gpvc.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\SysWOW64\\\\\\\\*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\mstdc.exe OR *\\\\\\\\gpvc.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\SysWOW64\\\\\\\\*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Lazarus Session Highjacker\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\mstdc.exe *\\\\gpvc.exe) AND (NOT (Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* C\\:\\\\Windows\\\\SysWOW64\\\\*))))
```


### splunk
    
```
((Image="*\\\\mstdc.exe" OR Image="*\\\\gpvc.exe") NOT ((Image="C:\\\\Windows\\\\System32\\\\*" OR Image="C:\\\\Windows\\\\SysWOW64\\\\*")))
```


### logpoint
    
```
(Image IN ["*\\\\mstdc.exe", "*\\\\gpvc.exe"]  -(Image IN ["C:\\\\Windows\\\\System32\\\\*", "C:\\\\Windows\\\\SysWOW64\\\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\mstdc\\.exe|.*.*\\gpvc\\.exe))(?=.*(?!.*(?:.*(?=.*(?:.*C:\\Windows\\System32\\\\.*|.*C:\\Windows\\SysWOW64\\\\.*))))))'
```



