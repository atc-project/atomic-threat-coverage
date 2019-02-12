| Title                | Scheduled Task Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of scheduled tasks in user session                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privelege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053](https://attack.mitre.org/tactics/T1053)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1053](../Triggering/T1053.md)</li></ul>  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Administrative activity</li><li>Software installation</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Scheduled Task Creation
status: experimental
description: Detects the creation of scheduled tasks in user session 
author: Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: '*\schtasks.exe'
        CommandLine: '* /create *'
    filter:
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.persistence
    - attack.privelege_escalation
    - attack.t1053
    - attack.s0111
falsepositives:
    - Administrative activity
    - Software installation
level: low

```





### Kibana query

```
((EventID:"1" AND Image:"*\\\\schtasks.exe" AND CommandLine:"* \\/create *") AND NOT (User:"NT AUTHORITY\\\\SYSTEM"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Scheduled-Task-Creation <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND Image:\\"*\\\\\\\\schtasks.exe\\" AND CommandLine:\\"* \\\\/create *\\") AND NOT (User:\\"NT AUTHORITY\\\\\\\\SYSTEM\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Scheduled Task Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND Image:"*\\\\schtasks.exe" AND CommandLine:"* \\/create *") AND NOT (User:"NT AUTHORITY\\\\SYSTEM"))
```

