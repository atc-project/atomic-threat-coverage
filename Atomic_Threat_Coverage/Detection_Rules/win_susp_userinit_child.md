| Title                    | Suspicious Userinit Child Process       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious child process of userinit |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrative scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1139811587760562176](https://twitter.com/SBousseaden/status/1139811587760562176)</li></ul>  |
| **Author**               | Florian Roth (rule), Samir Bousseaden (idea) |


## Detection Rules

### Sigma rule

```
title: Suspicious Userinit Child Process
id: b655a06a-31c0-477a-95c2-3726b83d649d
status: experimental
description: Detects a suspicious child process of userinit
references:
    - https://twitter.com/SBousseaden/status/1139811587760562176
author: Florian Roth (rule), Samir Bousseaden (idea)
date: 2019/06/17
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\userinit.exe'
    filter1:
        CommandLine: '*\\netlogon\\*'
    filter2:
        Image: '*\explorer.exe'
    condition: selection and not filter1 and not filter2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "ParentImage.*.*\\\\userinit.exe" -and  -not ($_.message -match "CommandLine.*.*\\\\netlogon\\\\.*")) -and  -not ($_.message -match "Image.*.*\\\\explorer.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:*\\\\userinit.exe AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\netlogon\\\\*))) AND (NOT (winlog.event_data.Image.keyword:*\\\\explorer.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/b655a06a-31c0-477a-95c2-3726b83d649d <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Userinit Child Process",\n    "description": "Detects a suspicious child process of userinit",\n    "tags": "",\n    "query": "((winlog.event_data.ParentImage.keyword:*\\\\\\\\userinit.exe AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\\\\\netlogon\\\\\\\\*))) AND (NOT (winlog.event_data.Image.keyword:*\\\\\\\\explorer.exe)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.ParentImage.keyword:*\\\\\\\\userinit.exe AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\\\\\netlogon\\\\\\\\*))) AND (NOT (winlog.event_data.Image.keyword:*\\\\\\\\explorer.exe)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Userinit Child Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((ParentImage.keyword:*\\\\userinit.exe AND (NOT (CommandLine.keyword:*\\\\netlogon\\\\*))) AND (NOT (Image.keyword:*\\\\explorer.exe)))
```


### splunk
    
```
((ParentImage="*\\\\userinit.exe" NOT (CommandLine="*\\\\netlogon\\\\*")) NOT (Image="*\\\\explorer.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((ParentImage="*\\\\userinit.exe"  -(CommandLine="*\\\\netlogon\\\\*"))  -(Image="*\\\\explorer.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\userinit\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\\\netlogon\\\\.*))))))(?=.*(?!.*(?:.*(?=.*.*\\explorer\\.exe)))))'
```



