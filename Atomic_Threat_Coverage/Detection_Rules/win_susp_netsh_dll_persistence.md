| Title                    | Suspicious Netsh DLL Persistence       |
|:-------------------------|:------------------|
| **Description**          | Detects persitence via netsh helper |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1128: Netsh Helper DLL](https://attack.mitre.org/techniques/T1128)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1128: Netsh Helper DLL](../Triggers/T1128.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | testing |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1128/T1128.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1128/T1128.md)</li></ul>  |
| **Author**               | Victor Sergeev, oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious Netsh DLL Persistence
id: 56321594-9087-49d9-bf10-524fe8479452
description: Detects persitence via netsh helper
status: testing
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1128/T1128.md
tags:
    - attack.persistence
    - attack.t1128
date: 2019/10/25
modified: 2019/10/25
author: Victor Sergeev, oscd.community
logsource:
    category: process_creation
    product: windows   
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'add'
            - 'helper'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\netsh.exe" -and $_.message -match "CommandLine.*.*add.*" -and $_.message -match "CommandLine.*.*helper.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\netsh.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:*helper*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/56321594-9087-49d9-bf10-524fe8479452 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Netsh DLL Persistence",\n    "description": "Detects persitence via netsh helper",\n    "tags": [\n      "attack.persistence",\n      "attack.t1128"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\netsh.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:*helper*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\netsh.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:*helper*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Netsh DLL Persistence\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     ComputerName = {{_source.ComputerName}}\\n             User = {{_source.User}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\netsh.exe AND CommandLine.keyword:*add* AND CommandLine.keyword:*helper*)
```


### splunk
    
```
(Image="*\\\\netsh.exe" CommandLine="*add*" CommandLine="*helper*") | table ComputerName,User,CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\\\netsh.exe" CommandLine="*add*" CommandLine="*helper*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\netsh\\.exe)(?=.*.*add.*)(?=.*.*helper.*))'
```



