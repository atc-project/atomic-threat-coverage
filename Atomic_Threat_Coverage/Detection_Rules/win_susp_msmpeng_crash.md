| Title                | Microsoft Malware Protection Engine Crash                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a suspicious crash of the Microsoft Malware Protection Engine                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/tactics/T1089)</li><li>[T1211: Exploitation for Defense Evasion](https://attack.mitre.org/tactics/T1211)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[('Disabling Security Tools', 'T1089')](../Triggers/('Disabling Security Tools', 'T1089').md)</li><li>[('Exploitation for Defense Evasion', 'T1211')](../Triggers/('Exploitation for Defense Evasion', 'T1211').md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>MsMpEng.exe can crash when C:\ is full</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5](https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5)</li><li>[https://technet.microsoft.com/en-us/library/security/4022344](https://technet.microsoft.com/en-us/library/security/4022344)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Microsoft Malware Protection Engine Crash
description: This rule detects a suspicious crash of the Microsoft Malware Protection Engine
tags:
    - attack.defense_evasion
    - attack.t1089
    - attack.t1211
status: experimental
date: 2017/05/09
references:
    - https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
    - https://technet.microsoft.com/en-us/library/security/4022344
author: Florian Roth
logsource:
    product: windows
    service: application
detection:
    selection1:
        Source: 'Application Error'
        EventID: 1000
    selection2:
        Source: 'Windows Error Reporting'
        EventID: 1001
    keywords:
        - 'MsMpEng.exe'
        - 'mpengine.dll'
    condition: 1 of selection* and all of keywords
falsepositives:
    - MsMpEng.exe can crash when C:\ is full
level: high

```





### Kibana query

```
(((Source:"Application\\ Error" AND EventID:"1000") OR (Source:"Windows\\ Error\\ Reporting" AND EventID:"1001")) AND ("MsMpEng.exe" AND "mpengine.dll"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Microsoft-Malware-Protection-Engine-Crash <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(((Source:\\"Application\\\\ Error\\" AND EventID:\\"1000\\") OR (Source:\\"Windows\\\\ Error\\\\ Reporting\\" AND EventID:\\"1001\\")) AND (\\"MsMpEng.exe\\" AND \\"mpengine.dll\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Microsoft Malware Protection Engine Crash\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(((Source:"Application Error" AND EventID:"1000") OR (Source:"Windows Error Reporting" AND EventID:"1001")) AND ("MsMpEng.exe" AND "mpengine.dll"))
```

