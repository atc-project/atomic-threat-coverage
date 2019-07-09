| Title                | PowerShell Script Run in AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1082851155481288706](https://twitter.com/JohnLaTwC/status/1082851155481288706)</li><li>[https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03](https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Script Run in AppData
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth
date: 2019/01/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'
    condition: selection
falsepositives:
    - Administrative scripts
level: medium

```





### es-qs
    
```
CommandLine.keyword:(*\\ \\/c\\ powershell*\\\\AppData\\\\Local\\\\* *\\ \\/c\\ powershell*\\\\AppData\\\\Roaming\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PowerShell-Script-Run-in-AppData <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Script Run in AppData",\n    "description": "Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "CommandLine.keyword:(*\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\* *\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\* *\\\\ \\\\/c\\\\ powershell*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Script Run in AppData\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("* \\/c powershell*\\\\AppData\\\\Local\\\\*" "* \\/c powershell*\\\\AppData\\\\Roaming\\\\*")
```


### splunk
    
```
(CommandLine="* /c powershell*\\\\AppData\\\\Local\\\\*" OR CommandLine="* /c powershell*\\\\AppData\\\\Roaming\\\\*")
```


### logpoint
    
```
CommandLine IN ["* /c powershell*\\\\AppData\\\\Local\\\\*", "* /c powershell*\\\\AppData\\\\Roaming\\\\*"]
```


### grep
    
```
grep -P '^(?:.*.* /c powershell.*\\AppData\\Local\\\\.*|.*.* /c powershell.*\\AppData\\Roaming\\\\.*)'
```



