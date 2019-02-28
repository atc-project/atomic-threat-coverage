| Title                | PowerShell Script Run in AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Administrative scripts</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1082851155481288706](https://twitter.com/JohnLaTwC/status/1082851155481288706)</li><li>[https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03](https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: PowerShell Script Run in AppData
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder 
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
author: Florian Roth
date: 2019/01/09
logsource:
    product: windows
    service: sysmon
detection:
    condition: selection
falsepositives:
    - Administrative scripts
level: medium
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine: 
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: 
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'

```





### Kibana query

```
(EventID:"1" AND CommandLine.keyword:(*\\ \\/c\\ powershell*\\\\AppData\\\\Local\\\\* *\\ \\/c\\ powershell*\\\\AppData\\\\Roaming\\\\*))\n(EventID:"4688" AND ProcessCommandLine.keyword:(*\\ \\/c\\ powershell*\\\\AppData\\\\Local\\\\* *\\ \\/c\\ powershell*\\\\AppData\\\\Roaming\\\\*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PowerShell-Script-Run-in-AppData <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\* *\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PowerShell Script Run in AppData\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PowerShell-Script-Run-in-AppData-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND ProcessCommandLine.keyword:(*\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\* *\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PowerShell Script Run in AppData\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:("* \\/c powershell*\\\\AppData\\\\Local\\\\*" "* \\/c powershell*\\\\AppData\\\\Roaming\\\\*"))\n(EventID:"4688" AND ProcessCommandLine:("* \\/c powershell*\\\\AppData\\\\Local\\\\*" "* \\/c powershell*\\\\AppData\\\\Roaming\\\\*"))
```

