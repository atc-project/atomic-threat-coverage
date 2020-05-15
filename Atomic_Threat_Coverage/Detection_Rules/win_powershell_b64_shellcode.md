| Title                    | PowerShell Base64 Encoded Shellcode       |
|:-------------------------|:------------------|
| **Description**          | Detects Base64 encoded Shellcode |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/cyb3rops/status/1063072865992523776](https://twitter.com/cyb3rops/status/1063072865992523776)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Base64 Encoded Shellcode
id: 2d117e49-e626-4c7c-bd1f-c3c0147774c8
description: Detects Base64 encoded Shellcode
status: experimental
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
author: Florian Roth
date: 2018/11/17
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*AAAAYInlM*'
    selection2:
        CommandLine:
            - '*OiCAAAAYInlM*'
            - '*OiJAAAAYInlM*'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*AAAAYInlM.*" -and ($_.message -match "CommandLine.*.*OiCAAAAYInlM.*" -or $_.message -match "CommandLine.*.*OiJAAAAYInlM.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*AAAAYInlM* AND winlog.event_data.CommandLine.keyword:(*OiCAAAAYInlM* OR *OiJAAAAYInlM*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/2d117e49-e626-4c7c-bd1f-c3c0147774c8 <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Base64 Encoded Shellcode",\n    "description": "Detects Base64 encoded Shellcode",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*AAAAYInlM* AND winlog.event_data.CommandLine.keyword:(*OiCAAAAYInlM* OR *OiJAAAAYInlM*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*AAAAYInlM* AND winlog.event_data.CommandLine.keyword:(*OiCAAAAYInlM* OR *OiJAAAAYInlM*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Base64 Encoded Shellcode\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*AAAAYInlM* AND CommandLine.keyword:(*OiCAAAAYInlM* *OiJAAAAYInlM*))
```


### splunk
    
```
(CommandLine="*AAAAYInlM*" (CommandLine="*OiCAAAAYInlM*" OR CommandLine="*OiJAAAAYInlM*"))
```


### logpoint
    
```
(CommandLine="*AAAAYInlM*" CommandLine IN ["*OiCAAAAYInlM*", "*OiJAAAAYInlM*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*AAAAYInlM.*)(?=.*(?:.*.*OiCAAAAYInlM.*|.*.*OiJAAAAYInlM.*)))'
```



