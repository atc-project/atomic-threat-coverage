| Title                | Suspicious Encoded PowerShell Command Line                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell process starts with base64 encoded commands                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>GRR powershell hacks</li><li>PowerSponse Deployments</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e](https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Suspicious Encoded PowerShell Command Line
description: Detects suspicious powershell process starts with base64 encoded commands
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth
date: 2018/09/03
detection:
    selection:
        CommandLine:
            # Command starts with '$' symbol
            - '* -e JAB*'
            - '* -enc JAB*'
            - '* -encodedcommand JAB*'
    # Google Rapid Response
    falsepositive1:
        ImagePath: '*\GRR\*'
    # PowerSponse deployments
    falsepositive2: 
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not 1 of falsepositive*
falsepositives: 
    - GRR powershell hacks
    - PowerSponse Deployments
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
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688


```





### Kibana query

```
((EventID:"1" AND CommandLine.keyword:(*\\ \\-e\\ JAB* *\\ \\-enc\\ JAB* *\\ \\-encodedcommand\\ JAB*)) AND NOT ((ImagePath.keyword:*\\\\GRR\\*) OR (CommandLine.keyword:*\\ \\-ExecutionPolicy\\ remotesigned\\ *)))\n((EventID:"4688" AND CommandLine.keyword:(*\\ \\-e\\ JAB* *\\ \\-enc\\ JAB* *\\ \\-encodedcommand\\ JAB*)) AND NOT ((ImagePath.keyword:*\\\\GRR\\*) OR (CommandLine.keyword:*\\ \\-ExecutionPolicy\\ remotesigned\\ *)))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Encoded-PowerShell-Command-Line <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND CommandLine.keyword:(*\\\\ \\\\-e\\\\ JAB* *\\\\ \\\\-enc\\\\ JAB* *\\\\ \\\\-encodedcommand\\\\ JAB*)) AND NOT ((ImagePath.keyword:*\\\\\\\\GRR\\\\*) OR (CommandLine.keyword:*\\\\ \\\\-ExecutionPolicy\\\\ remotesigned\\\\ *)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Encoded-PowerShell-Command-Line-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"4688\\" AND CommandLine.keyword:(*\\\\ \\\\-e\\\\ JAB* *\\\\ \\\\-enc\\\\ JAB* *\\\\ \\\\-encodedcommand\\\\ JAB*)) AND NOT ((ImagePath.keyword:*\\\\\\\\GRR\\\\*) OR (CommandLine.keyword:*\\\\ \\\\-ExecutionPolicy\\\\ remotesigned\\\\ *)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND CommandLine:("* \\-e JAB*" "* \\-enc JAB*" "* \\-encodedcommand JAB*")) AND NOT ((ImagePath:"*\\\\GRR\\*") OR (CommandLine:"* \\-ExecutionPolicy remotesigned *")))\n((EventID:"4688" AND CommandLine:("* \\-e JAB*" "* \\-enc JAB*" "* \\-encodedcommand JAB*")) AND NOT ((ImagePath:"*\\\\GRR\\*") OR (CommandLine:"* \\-ExecutionPolicy remotesigned *")))
```

