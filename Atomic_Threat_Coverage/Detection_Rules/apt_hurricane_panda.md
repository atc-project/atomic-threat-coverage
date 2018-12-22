| Title                | Hurricane Panda Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Hurricane Panda Activity                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1068](https://attack.mitre.org/tactics/T1068)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_windows_sysmon_process_creation_1](../Data_Needed/DN_0003_windows_sysmon_process_creation_1.md)</li><li>[DN_0002_windows_process_creation_with_commandline_4688](../Data_Needed/DN_0002_windows_process_creation_with_commandline_4688.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/](https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.g0009</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: Hurricane Panda Activity
status: experimental
description: Detects Hurricane Panda Activity 
references: 
    - https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/
tags:
    - attack.privilege_escalation
    - attack.g0009
    - attack.t1068
author: Florian Roth
date: 2018/02/25
detection:
    selection:
        CommandLine: 
            - '* localgroup administrators admin /add'
            - '*\Win64.exe*'
    condition: selection
falsepositives:
    - Unknown
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
---
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688



```





### Kibana query

```
(EventID:"1" AND CommandLine:("* localgroup administrators admin \\/add" "*\\\\Win64.exe*"))\n(EventID:"4688" AND CommandLine:("* localgroup administrators admin \\/add" "*\\\\Win64.exe*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Hurricane-Panda-Activity <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine:(\\"* localgroup administrators admin \\\\/add\\" \\"*\\\\\\\\Win64.exe*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Hurricane Panda Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Hurricane-Panda-Activity-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine:(\\"* localgroup administrators admin \\\\/add\\" \\"*\\\\\\\\Win64.exe*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Hurricane Panda Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:("* localgroup administrators admin \\/add" "*\\\\Win64.exe*"))\n(EventID:"4688" AND CommandLine:("* localgroup administrators admin \\/add" "*\\\\Win64.exe*"))
```

