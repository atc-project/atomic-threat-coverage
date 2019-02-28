| Title                | Suspicious Calculator Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/ItsReallyNick/status/1094080242686312448](https://twitter.com/ItsReallyNick/status/1094080242686312448)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Suspicious Calculator Usage
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
status: experimental
references:
    - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth
date: 2019/02/09
detection:
    condition: selection1 or ( selection2 and not filter2 )
falsepositives: 
    - Unknown
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 1
        CommandLine: '*\calc.exe *'
    selection2:
        EventID: 1
        Image: '*\calc.exe'
    filter2:
        Image: '*\Windows\Sys*'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection1:
        EventID: 4688
        ProcessCommandLine: '*\calc.exe *'
    selection2:
        EventID: 1
        Image: '*\calc.exe'
    filter2:
        Image: '*\Windows\Sys*'
```





### Kibana query

```
((EventID:"1" AND CommandLine.keyword:*\\\\calc.exe\\ *) OR ((EventID:"1" AND Image.keyword:*\\\\calc.exe) AND NOT (Image.keyword:*\\\\Windows\\\\Sys*)))\n((EventID:"4688" AND ProcessCommandLine.keyword:*\\\\calc.exe\\ *) OR ((EventID:"1" AND Image.keyword:*\\\\calc.exe) AND NOT (Image.keyword:*\\\\Windows\\\\Sys*)))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Calculator-Usage <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND CommandLine.keyword:*\\\\\\\\calc.exe\\\\ *) OR ((EventID:\\"1\\" AND Image.keyword:*\\\\\\\\calc.exe) AND NOT (Image.keyword:*\\\\\\\\Windows\\\\\\\\Sys*)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Calculator Usage\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Calculator-Usage-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"4688\\" AND ProcessCommandLine.keyword:*\\\\\\\\calc.exe\\\\ *) OR ((EventID:\\"1\\" AND Image.keyword:*\\\\\\\\calc.exe) AND NOT (Image.keyword:*\\\\\\\\Windows\\\\\\\\Sys*)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Calculator Usage\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND CommandLine:"*\\\\calc.exe *") OR ((EventID:"1" AND Image:"*\\\\calc.exe") AND NOT (Image:"*\\\\Windows\\\\Sys*")))\n((EventID:"4688" AND ProcessCommandLine:"*\\\\calc.exe *") OR ((EventID:"1" AND Image:"*\\\\calc.exe") AND NOT (Image:"*\\\\Windows\\\\Sys*")))
```

