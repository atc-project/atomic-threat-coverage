| Title                    | Clear PowerShell History       |
|:-------------------------|:------------------|
| **Description**          | Detects keywords that could indicate clearing PowerShell history |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1146: Clear Command History](https://attack.mitre.org/techniques/T1146)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1146: Clear Command History](../Triggers/T1146.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>some PS-scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a](https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Clear PowerShell History
id: dfba4ce1-e0ea-495f-986e-97140f31af2d
status: experimental
description: Detects keywords that could indicate clearing PowerShell history
date: 2019/10/25
author: Ilyas Ochkov, oscd.community
references:
    - https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a
tags:
    - attack.defense_evasion
    - attack.t1146
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        - 'del (Get-PSReadlineOption).HistorySavePath'
        - 'Set-PSReadlineOption –HistorySaveStyle SaveNothing'
        - 'Remove-Item (Get-PSReadlineOption).HistorySavePath'
        - 'rm (Get-PSReadlineOption).HistorySavePath'
    condition: keywords
falsepositives:
    - some PS-scripts
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "del (Get-PSReadlineOption).HistorySavePath" -or $_.message -match "Set-PSReadlineOption \xe2\x80\x93HistorySaveStyle SaveNothing" -or $_.message -match "Remove-Item (Get-PSReadlineOption).HistorySavePath" -or $_.message -match "rm (Get-PSReadlineOption).HistorySavePath")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
\\*.keyword:(*del\\ \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *Set\\-PSReadlineOption\\ \xe2\x80\x93HistorySaveStyle\\ SaveNothing* OR *Remove\\-Item\\ \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *rm\\ \\(Get\\-PSReadlineOption\\).HistorySavePath*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/dfba4ce1-e0ea-495f-986e-97140f31af2d <<EOF\n{\n  "metadata": {\n    "title": "Clear PowerShell History",\n    "description": "Detects keywords that could indicate clearing PowerShell history",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1146"\n    ],\n    "query": "\\\\*.keyword:(*del\\\\ \\\\(Get\\\\-PSReadlineOption\\\\).HistorySavePath* OR *Set\\\\-PSReadlineOption\\\\ \\u2013HistorySaveStyle\\\\ SaveNothing* OR *Remove\\\\-Item\\\\ \\\\(Get\\\\-PSReadlineOption\\\\).HistorySavePath* OR *rm\\\\ \\\\(Get\\\\-PSReadlineOption\\\\).HistorySavePath*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "\\\\*.keyword:(*del\\\\ \\\\(Get\\\\-PSReadlineOption\\\\).HistorySavePath* OR *Set\\\\-PSReadlineOption\\\\ \\u2013HistorySaveStyle\\\\ SaveNothing* OR *Remove\\\\-Item\\\\ \\\\(Get\\\\-PSReadlineOption\\\\).HistorySavePath* OR *rm\\\\ \\\\(Get\\\\-PSReadlineOption\\\\).HistorySavePath*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Clear PowerShell History\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
\\*.keyword:(*del \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *Set\\-PSReadlineOption \xe2\x80\x93HistorySaveStyle SaveNothing* OR *Remove\\-Item \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *rm \\(Get\\-PSReadlineOption\\).HistorySavePath*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" ("del (Get-PSReadlineOption).HistorySavePath" OR "Set-PSReadlineOption \xe2\x80\x93HistorySaveStyle SaveNothing" OR "Remove-Item (Get-PSReadlineOption).HistorySavePath" OR "rm (Get-PSReadlineOption).HistorySavePath"))
```


### logpoint
    
```
("del (Get-PSReadlineOption).HistorySavePath" OR "Set-PSReadlineOption \xe2\x80\x93HistorySaveStyle SaveNothing" OR "Remove-Item (Get-PSReadlineOption).HistorySavePath" OR "rm (Get-PSReadlineOption).HistorySavePath")
```


### grep
    
```
grep -P '^(?:.*(?:.*del \\(Get-PSReadlineOption\\)\\.HistorySavePath|.*Set-PSReadlineOption \xe2\x80\x93HistorySaveStyle SaveNothing|.*Remove-Item \\(Get-PSReadlineOption\\)\\.HistorySavePath|.*rm \\(Get-PSReadlineOption\\)\\.HistorySavePath))'
```



