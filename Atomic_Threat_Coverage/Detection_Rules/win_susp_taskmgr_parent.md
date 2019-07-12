| Title                | Taskmgr as Parent                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a process from Windows task manager                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Administrative activity</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as Parent
status: experimental
description: Detects the creation of a process from Windows task manager
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\taskmgr.exe'
    filter:
        Image:
            - '*\resmon.exe'
            - '*\mmc.exe'
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low

```





### es-qs
    
```
(ParentImage.keyword:*\\\\taskmgr.exe AND (NOT (Image.keyword:(*\\\\resmon.exe *\\\\mmc.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Taskmgr-as-Parent <<EOF\n{\n  "metadata": {\n    "title": "Taskmgr as Parent",\n    "description": "Detects the creation of a process from Windows task manager",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(ParentImage.keyword:*\\\\\\\\taskmgr.exe AND (NOT (Image.keyword:(*\\\\\\\\resmon.exe *\\\\\\\\mmc.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:*\\\\\\\\taskmgr.exe AND (NOT (Image.keyword:(*\\\\\\\\resmon.exe *\\\\\\\\mmc.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Taskmgr as Parent\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:"*\\\\taskmgr.exe" AND NOT (Image:("*\\\\resmon.exe" "*\\\\mmc.exe")))
```


### splunk
    
```
(ParentImage="*\\\\taskmgr.exe" NOT ((Image="*\\\\resmon.exe" OR Image="*\\\\mmc.exe"))) | table Image,CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage="*\\\\taskmgr.exe"  -(Image IN ["*\\\\resmon.exe", "*\\\\mmc.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\taskmgr\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\resmon\\.exe|.*.*\\mmc\\.exe))))))'
```



