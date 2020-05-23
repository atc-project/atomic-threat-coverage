| Title                    | Suspicious Use of CSharp Interactive Console       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of CSharp interactive console by PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1127: Trusted Developer Utilities](../Triggers/T1127.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Possible depending on environment. Pair with other factors such as net connections, command-line args, etc.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/](https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/)</li></ul>  |
| **Author**               | Michael R. (@nahamike01) |


## Detection Rules

### Sigma rule

```
title: Suspicious Use of CSharp Interactive Console
id: a9e416a8-e613-4f8b-88b8-a7d1d1af2f61
status: experimental
description: Detects the execution of CSharp interactive console by PowerShell
references:
    - https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/
author: Michael R. (@nahamike01)
date: 2020/03/08
tags:
    - attack.execution
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\csi.exe'
        ParentImage|endswith: '\powershell.exe'
        OriginalFileName: 'csi.exe'
    condition: selection
falsepositives:
    - Possible depending on environment. Pair with other factors such as net connections, command-line args, etc.
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\csi.exe" -and $_.message -match "ParentImage.*.*\\\\powershell.exe" -and $_.message -match "OriginalFileName.*csi.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\csi.exe AND winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND OriginalFileName:"csi.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/a9e416a8-e613-4f8b-88b8-a7d1d1af2f61 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Use of CSharp Interactive Console",\n    "description": "Detects the execution of CSharp interactive console by PowerShell",\n    "tags": [\n      "attack.execution",\n      "attack.t1127"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\csi.exe AND winlog.event_data.ParentImage.keyword:*\\\\\\\\powershell.exe AND OriginalFileName:\\"csi.exe\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\csi.exe AND winlog.event_data.ParentImage.keyword:*\\\\\\\\powershell.exe AND OriginalFileName:\\"csi.exe\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Use of CSharp Interactive Console\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\csi.exe AND ParentImage.keyword:*\\\\powershell.exe AND OriginalFileName:"csi.exe")
```


### splunk
    
```
(Image="*\\\\csi.exe" ParentImage="*\\\\powershell.exe" OriginalFileName="csi.exe")
```


### logpoint
    
```
(Image="*\\\\csi.exe" ParentImage="*\\\\powershell.exe" OriginalFileName="csi.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\csi\\.exe)(?=.*.*\\powershell\\.exe)(?=.*csi\\.exe))'
```



