| Title                    | Java Running with Remote Debugging       |
|:-------------------------|:------------------|
| **Description**          | Detects a JAVA process running with remote debugging allowing more than just localhost to connect |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Java Running with Remote Debugging
id: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
author: Florian Roth
date: 2019/01/16
modified: 2020/08/29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*transport=dt_socket,address=*'
    exclusion:
        - CommandLine: '*address=127.0.0.1*'
        - CommandLine: '*address=localhost*'
    condition: selection and not exclusion
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*transport=dt_socket,address=.*" -and  -not ($_.message -match "CommandLine.*.*address=127.0.0.1.*" -or $_.message -match "CommandLine.*.*address=localhost.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*transport\\=dt_socket,address\\=* AND (NOT (winlog.event_data.CommandLine.keyword:*address\\=127.0.0.1* OR winlog.event_data.CommandLine.keyword:*address\\=localhost*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/8f88e3f6-2a49-48f5-a5c4-2f7eedf78710 <<EOF\n{\n  "metadata": {\n    "title": "Java Running with Remote Debugging",\n    "description": "Detects a JAVA process running with remote debugging allowing more than just localhost to connect",\n    "tags": "",\n    "query": "(winlog.event_data.CommandLine.keyword:*transport\\\\=dt_socket,address\\\\=* AND (NOT (winlog.event_data.CommandLine.keyword:*address\\\\=127.0.0.1* OR winlog.event_data.CommandLine.keyword:*address\\\\=localhost*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*transport\\\\=dt_socket,address\\\\=* AND (NOT (winlog.event_data.CommandLine.keyword:*address\\\\=127.0.0.1* OR winlog.event_data.CommandLine.keyword:*address\\\\=localhost*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Java Running with Remote Debugging\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*transport=dt_socket,address=* AND (NOT (CommandLine.keyword:*address=127.0.0.1* OR CommandLine.keyword:*address=localhost*)))
```


### splunk
    
```
(CommandLine="*transport=dt_socket,address=*" NOT (CommandLine="*address=127.0.0.1*" OR CommandLine="*address=localhost*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(CommandLine="*transport=dt_socket,address=*"  -(CommandLine="*address=127.0.0.1*" OR CommandLine="*address=localhost*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*transport=dt_socket,address=.*)(?=.*(?!.*(?:.*(?:.*(?=.*.*address=127\\.0\\.0\\.1.*)|.*(?=.*.*address=localhost.*))))))'
```



