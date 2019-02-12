| Title                | Taskmgr as Parent                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a process from Windows task manager                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Administrative activity</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Taskmgr as Parent
status: experimental
description: Detects the creation of a process from Windows task manager
author: Florian Roth
date: 2018/03/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage: '*\taskmgr.exe'
    filter:
        Image: 
            - 'resmon.exe'
            - 'mmc.exe'
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low

```





### Kibana query

```
((EventID:"1" AND ParentImage:"*\\\\taskmgr.exe") AND NOT (Image:("resmon.exe" "mmc.exe")))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Taskmgr-as-Parent <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND ParentImage:\\"*\\\\\\\\taskmgr.exe\\") AND NOT (Image:(\\"resmon.exe\\" \\"mmc.exe\\")))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Taskmgr as Parent\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND ParentImage:"*\\\\taskmgr.exe") AND NOT (Image:("resmon.exe" "mmc.exe")))
```

