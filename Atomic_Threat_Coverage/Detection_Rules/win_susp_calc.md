| Title                | Suspicious Calculator Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/ItsReallyNick/status/1094080242686312448](https://twitter.com/ItsReallyNick/status/1094080242686312448)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Calculator Usage
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
status: experimental
references:
        - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth
date: 2019/02/09
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
        category: process_creation
        product: windows
detection:
        selection1:
                CommandLine: '*\calc.exe *'
        selection2:
                Image: '*\calc.exe'
        filter2:
                Image: '*\Windows\Sys*'
        condition: selection1 or ( selection2 and not filter2 )
falsepositives: 
        - Unknown
level: high

```





### es-qs
    
```
(CommandLine.keyword:*\\\\calc.exe\\ * OR (Image.keyword:*\\\\calc.exe AND (NOT (Image.keyword:*\\\\Windows\\\\Sys*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Calculator-Usage <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Calculator Usage",\n    "description": "Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(CommandLine.keyword:*\\\\\\\\calc.exe\\\\ * OR (Image.keyword:*\\\\\\\\calc.exe AND (NOT (Image.keyword:*\\\\\\\\Windows\\\\\\\\Sys*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:*\\\\\\\\calc.exe\\\\ * OR (Image.keyword:*\\\\\\\\calc.exe AND (NOT (Image.keyword:*\\\\\\\\Windows\\\\\\\\Sys*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Calculator Usage\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine:"*\\\\calc.exe *" OR (Image:"*\\\\calc.exe" AND NOT (Image:"*\\\\Windows\\\\Sys*")))
```


### splunk
    
```
(CommandLine="*\\\\calc.exe *" OR (Image="*\\\\calc.exe" NOT (Image="*\\\\Windows\\\\Sys*")))
```


### logpoint
    
```
(CommandLine="*\\\\calc.exe *" OR (Image="*\\\\calc.exe"  -(Image="*\\\\Windows\\\\Sys*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\calc\\.exe .*|.*(?:.*(?=.*.*\\calc\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Windows\\Sys.*)))))))'
```



