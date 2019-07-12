| Title                | Sysprep on AppData Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets](https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets)</li><li>[https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b](https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Sysprep on AppData Folder
status: experimental
description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
references:
    - https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
    - https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b
tags:
    - attack.execution
author: Florian Roth
date: 2018/06/22
modified: 2018/12/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\sysprep.exe *\AppData\\*'
            - sysprep.exe *\AppData\\*
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### es-qs
    
```
CommandLine.keyword:(*\\\\sysprep.exe\\ *\\\\AppData\\\\* sysprep.exe\\ *\\\\AppData\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Sysprep-on-AppData-Folder <<EOF\n{\n  "metadata": {\n    "title": "Sysprep on AppData Folder",\n    "description": "Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)",\n    "tags": [\n      "attack.execution"\n    ],\n    "query": "CommandLine.keyword:(*\\\\\\\\sysprep.exe\\\\ *\\\\\\\\AppData\\\\\\\\* sysprep.exe\\\\ *\\\\\\\\AppData\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\\\\\sysprep.exe\\\\ *\\\\\\\\AppData\\\\\\\\* sysprep.exe\\\\ *\\\\\\\\AppData\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Sysprep on AppData Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("*\\\\sysprep.exe *\\\\AppData\\\\*" "sysprep.exe *\\\\AppData\\\\*")
```


### splunk
    
```
(CommandLine="*\\\\sysprep.exe *\\\\AppData\\\\*" OR CommandLine="sysprep.exe *\\\\AppData\\\\*")
```


### logpoint
    
```
CommandLine IN ["*\\\\sysprep.exe *\\\\AppData\\\\*", "sysprep.exe *\\\\AppData\\\\*"]
```


### grep
    
```
grep -P '^(?:.*.*\\sysprep\\.exe .*\\AppData\\\\.*|.*sysprep\\.exe .*\\AppData\\\\.*)'
```



