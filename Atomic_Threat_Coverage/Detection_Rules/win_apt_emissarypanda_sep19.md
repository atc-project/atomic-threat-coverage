| Title                    | Emissary Panda Malware SLLauncher       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27 |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965](https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965)</li><li>[https://twitter.com/cyb3rops/status/1168863899531132929](https://twitter.com/cyb3rops/status/1168863899531132929)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Emissary Panda Malware SLLauncher
id: 9aa01d62-7667-4d3b-acb8-8cb5103e2014
status: experimental
description: Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27
references:
    - https://app.any.run/tasks/579e7587-f09d-4aae-8b07-472833262965
    - https://twitter.com/cyb3rops/status/1168863899531132929
author: Florian Roth
date: 2018/09/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\sllauncher.exe'
        Image: '*\svchost.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\\\sllauncher.exe" -and $_.message -match "Image.*.*\\\\svchost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\\\sllauncher.exe AND winlog.event_data.Image.keyword:*\\\\svchost.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9aa01d62-7667-4d3b-acb8-8cb5103e2014 <<EOF\n{\n  "metadata": {\n    "title": "Emissary Panda Malware SLLauncher",\n    "description": "Detects the execution of DLL side-loading malware used by threat group Emissary Panda aka APT27",\n    "tags": "",\n    "query": "(winlog.event_data.ParentImage.keyword:*\\\\\\\\sllauncher.exe AND winlog.event_data.Image.keyword:*\\\\\\\\svchost.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\\\\\sllauncher.exe AND winlog.event_data.Image.keyword:*\\\\\\\\svchost.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Emissary Panda Malware SLLauncher\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage.keyword:*\\\\sllauncher.exe AND Image.keyword:*\\\\svchost.exe)
```


### splunk
    
```
(ParentImage="*\\\\sllauncher.exe" Image="*\\\\svchost.exe")
```


### logpoint
    
```
(ParentImage="*\\\\sllauncher.exe" Image="*\\\\svchost.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\sllauncher\\.exe)(?=.*.*\\svchost\\.exe))'
```



