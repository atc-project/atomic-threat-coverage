| Title                    | Suspicious Curl File Upload       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious curl process start the adds a file to a web request |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1567: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Scripts created by developers and admins</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/d1r4c/status/1279042657508081664](https://twitter.com/d1r4c/status/1279042657508081664)</li><li>[https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76](https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Curl File Upload
id: 00bca14a-df4e-4649-9054-3f2aa676bc04
status: experimental
description: Detects a suspicious curl process start the adds a file to a web request
author: Florian Roth
date: 2020/07/03
modified: 2020/09/05
references:
    - https://twitter.com/d1r4c/status/1279042657508081664
    - https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
logsource:
    category: process_creation
    product: windows
tags:
    - attack.exfiltration
    - attack.t1567
detection:
    selection:
        Image|endswith: '\curl.exe'
        CommandLine|contains: ' -F '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Scripts created by developers and admins
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\curl.exe" -and $_.message -match "CommandLine.*.* -F .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\curl.exe AND winlog.event_data.CommandLine.keyword:*\\ \\-F\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/00bca14a-df4e-4649-9054-3f2aa676bc04 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Curl File Upload",\n    "description": "Detects a suspicious curl process start the adds a file to a web request",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1567"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\curl.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-F\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\curl.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-F\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Curl File Upload\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\curl.exe AND CommandLine.keyword:* \\-F *)
```


### splunk
    
```
(Image="*\\\\curl.exe" CommandLine="* -F *") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\\\curl.exe" CommandLine="* -F *")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\curl\\.exe)(?=.*.* -F .*))'
```



