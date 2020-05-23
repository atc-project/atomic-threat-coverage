| Title                    | WMIExec VBS Script       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious file execution by wscript and cscript |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0045</li></ul> | 

## Detection Rules

### Sigma rule

```
title: WMIExec VBS Script
id: 966e4016-627f-44f7-8341-f394905c361f
description: Detects suspicious file execution by wscript and cscript
author: Florian Roth
date: 2017/04/07
references:
    - https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
tags:
    - attack.execution
    - attack.g0045
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\cscript.exe'
        CommandLine: '*.vbs /shell *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\cscript.exe" -and $_.message -match "CommandLine.*.*.vbs /shell .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\cscript.exe AND winlog.event_data.CommandLine.keyword:*.vbs\\ \\/shell\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/966e4016-627f-44f7-8341-f394905c361f <<EOF\n{\n  "metadata": {\n    "title": "WMIExec VBS Script",\n    "description": "Detects suspicious file execution by wscript and cscript",\n    "tags": [\n      "attack.execution",\n      "attack.g0045",\n      "attack.t1064"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\cscript.exe AND winlog.event_data.CommandLine.keyword:*.vbs\\\\ \\\\/shell\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\cscript.exe AND winlog.event_data.CommandLine.keyword:*.vbs\\\\ \\\\/shell\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMIExec VBS Script\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\cscript.exe AND CommandLine.keyword:*.vbs \\/shell *)
```


### splunk
    
```
(Image="*\\\\cscript.exe" CommandLine="*.vbs /shell *") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\\\cscript.exe" CommandLine="*.vbs /shell *")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\cscript\\.exe)(?=.*.*\\.vbs /shell .*))'
```



