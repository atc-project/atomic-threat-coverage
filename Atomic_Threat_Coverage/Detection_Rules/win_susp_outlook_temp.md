| Title                    | Execution in Outlook Temp Folder       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious program execution in Outlook temp folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1193: Spearphishing Attachment](../Triggers/T1193.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Execution in Outlook Temp Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: experimental
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth
date: 2019/10/01
tags:
    - attack.initial_access
    - attack.t1193
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Temporary Internet Files\Content.Outlook\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "Image.*.*\\\\Temporary Internet Files\\\\Content.Outlook\\\\.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:*\\\\Temporary\\ Internet\\ Files\\\\Content.Outlook\\\\*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/a018fdc3-46a3-44e5-9afb-2cd4af1d4b39 <<EOF\n{\n  "metadata": {\n    "title": "Execution in Outlook Temp Folder",\n    "description": "Detects a suspicious program execution in Outlook temp folder",\n    "tags": [\n      "attack.initial_access",\n      "attack.t1193"\n    ],\n    "query": "winlog.event_data.Image.keyword:*\\\\\\\\Temporary\\\\ Internet\\\\ Files\\\\\\\\Content.Outlook\\\\\\\\*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Image.keyword:*\\\\\\\\Temporary\\\\ Internet\\\\ Files\\\\\\\\Content.Outlook\\\\\\\\*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Execution in Outlook Temp Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image.keyword:*\\\\Temporary Internet Files\\\\Content.Outlook\\\\*
```


### splunk
    
```
Image="*\\\\Temporary Internet Files\\\\Content.Outlook\\\\*" | table CommandLine,ParentCommandLine
```


### logpoint
    
```
Image="*\\\\Temporary Internet Files\\\\Content.Outlook\\\\*"
```


### grep
    
```
grep -P '^.*\\Temporary Internet Files\\Content\\.Outlook\\\\.*'
```



