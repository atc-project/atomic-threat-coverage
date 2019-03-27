| Title                | Suspicious Encoded PowerShell Command Line                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell process starts with base64 encoded commands                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>GRR powershell hacks</li><li>PowerSponse Deployments</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e](https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e)</li></ul>                                                          |
| Author               | Florian Roth, Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Encoded PowerShell Command Line
description: Detects suspicious powershell process starts with base64 encoded commands
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth, Markus Neis
date: 2018/09/03
tags:
  - attack.execution
  - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -e JAB*'
            - '* -enc JAB*'
            - '* -encodedcommand JAB*'
            - '* BA^J e-'
    falsepositive1:
        Image: '*\GRR\\*'
    falsepositive2:
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not 1 of falsepositive*
falsepositives:
    - GRR powershell hacks
    - PowerSponse Deployments
level: high

```





### es-qs
    
```
(CommandLine.keyword:(*\\ \\-e\\ JAB* *\\ \\-enc\\ JAB* *\\ \\-encodedcommand\\ JAB* *\\ BA\\^J\\ e\\-) AND NOT ((Image.keyword:*\\\\GRR\\\\*) OR (CommandLine.keyword:*\\ \\-ExecutionPolicy\\ remotesigned\\ *)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Encoded-PowerShell-Command-Line <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(CommandLine.keyword:(*\\\\ \\\\-e\\\\ JAB* *\\\\ \\\\-enc\\\\ JAB* *\\\\ \\\\-encodedcommand\\\\ JAB* *\\\\ BA\\\\^J\\\\ e\\\\-) AND NOT ((Image.keyword:*\\\\\\\\GRR\\\\\\\\*) OR (CommandLine.keyword:*\\\\ \\\\-ExecutionPolicy\\\\ remotesigned\\\\ *)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine:("* \\-e JAB*" "* \\-enc JAB*" "* \\-encodedcommand JAB*" "* BA\\^J e\\-") AND NOT ((Image:"*\\\\GRR\\\\*") OR (CommandLine:"* \\-ExecutionPolicy remotesigned *")))
```


### splunk
    
```
((CommandLine="* -e JAB*" OR CommandLine="* -enc JAB*" OR CommandLine="* -encodedcommand JAB*" OR CommandLine="* BA^J e-") NOT ((Image="*\\\\GRR\\\\*") OR (CommandLine="* -ExecutionPolicy remotesigned *")))
```


### logpoint
    
```
(CommandLine IN ["* -e JAB*", "* -enc JAB*", "* -encodedcommand JAB*", "* BA^J e-"]  -((Image="*\\\\GRR\\\\*") OR (CommandLine="* -ExecutionPolicy remotesigned *")))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -e JAB.*|.*.* -enc JAB.*|.*.* -encodedcommand JAB.*|.*.* BA\\^J e-))(?=.*(?!.*(?:.*(?:.*(?:.*(?=.*.*\\GRR\\\\.*))|.*(?:.*(?=.*.* -ExecutionPolicy remotesigned .*)))))))'
```



