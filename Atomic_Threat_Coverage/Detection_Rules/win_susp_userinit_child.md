| Title                | Suspicious Userinit Child Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a process from Windows task manager                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1139811587760562176](https://twitter.com/SBousseaden/status/1139811587760562176)</li></ul>  |
| Author               | Florian Roth (rule), Samir Bousseaden (idea) |


## Detection Rules

### Sigma rule

```
title: Suspicious Userinit Child Process
status: experimental
description: Detects the creation of a process from Windows task manager
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
    filter:
        CommandLine:
            - '*\explorer.exe*'
            - '*\\netlogon\\*'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```





### es-qs
    
```
(ParentImage.keyword:*\\\\userinit.exe AND (NOT (CommandLine.keyword:(*\\\\explorer.exe* *\\\\netlogon\\\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Userinit-Child-Process <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Userinit Child Process",\n    "description": "Detects the creation of a process from Windows task manager",\n    "tags": "",\n    "query": "(ParentImage.keyword:*\\\\\\\\userinit.exe AND (NOT (CommandLine.keyword:(*\\\\\\\\explorer.exe* *\\\\\\\\netlogon\\\\\\\\*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:*\\\\\\\\userinit.exe AND (NOT (CommandLine.keyword:(*\\\\\\\\explorer.exe* *\\\\\\\\netlogon\\\\\\\\*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Userinit Child Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:"*\\\\userinit.exe" AND NOT (CommandLine:("*\\\\explorer.exe*" "*\\\\netlogon\\\\*")))
```


### splunk
    
```
(ParentImage="*\\\\userinit.exe" NOT ((CommandLine="*\\\\explorer.exe*" OR CommandLine="*\\\\netlogon\\\\*"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage="*\\\\userinit.exe"  -(CommandLine IN ["*\\\\explorer.exe*", "*\\\\netlogon\\\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\userinit\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\explorer\\.exe.*|.*.*\\\\netlogon\\\\.*))))))'
```



