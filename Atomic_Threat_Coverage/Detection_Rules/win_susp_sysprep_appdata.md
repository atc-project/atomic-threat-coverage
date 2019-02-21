| Title                | Sysprep on AppData Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets](https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets)</li><li>[https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b](https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Sysprep on AppData Folder
status: experimental
description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
references:
    - https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
    - https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b
author: Florian Roth
date: 2018/06/22
detection:
    selection:
        CommandLine: 
            - '*\sysprep.exe *\AppData\*'
            - 'sysprep.exe *\AppData\*'
    condition: selection
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
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




### es-qs
    
```
(EventID:"1" AND CommandLine.keyword:(*\\\\sysprep.exe\\ *\\\\AppData\\* sysprep.exe\\ *\\\\AppData\\*))\n(EventID:"4688" AND CommandLine.keyword:(*\\\\sysprep.exe\\ *\\\\AppData\\* sysprep.exe\\ *\\\\AppData\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Sysprep-on-AppData-Folder <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\\\\\sysprep.exe\\\\ *\\\\\\\\AppData\\\\* sysprep.exe\\\\ *\\\\\\\\AppData\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Sysprep on AppData Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Sysprep-on-AppData-Folder-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine.keyword:(*\\\\\\\\sysprep.exe\\\\ *\\\\\\\\AppData\\\\* sysprep.exe\\\\ *\\\\\\\\AppData\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Sysprep on AppData Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1" AND CommandLine:("*\\\\sysprep.exe *\\\\AppData\\*" "sysprep.exe *\\\\AppData\\*"))\n(EventID:"4688" AND CommandLine:("*\\\\sysprep.exe *\\\\AppData\\*" "sysprep.exe *\\\\AppData\\*"))
```


### splunk
    
```
(EventID="1" (CommandLine="*\\\\sysprep.exe *\\\\AppData\\*" OR CommandLine="sysprep.exe *\\\\AppData\\*"))\n(EventID="4688" (CommandLine="*\\\\sysprep.exe *\\\\AppData\\*" OR CommandLine="sysprep.exe *\\\\AppData\\*"))
```


### logpoint
    
```
(EventID="1" CommandLine IN ["*\\\\sysprep.exe *\\\\AppData\\*", "sysprep.exe *\\\\AppData\\*"])\n(EventID="4688" CommandLine IN ["*\\\\sysprep.exe *\\\\AppData\\*", "sysprep.exe *\\\\AppData\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\sysprep\\.exe .*\\AppData\\.*|.*sysprep\\.exe .*\\AppData\\.*)))'\ngrep -P '^(?:.*(?=.*4688)(?=.*(?:.*.*\\sysprep\\.exe .*\\AppData\\.*|.*sysprep\\.exe .*\\AppData\\.*)))'
```


