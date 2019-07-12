| Title                | Microsoft Malware Protection Engine Crash                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a suspicious crash of the Microsoft Malware Protection Engine                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1211: Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li><li>[T1211: Exploitation for Defense Evasion](../Triggers/T1211.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>MsMpEng.exe can crash when C:\ is full</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5](https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5)</li><li>[https://technet.microsoft.com/en-us/library/security/4022344](https://technet.microsoft.com/en-us/library/security/4022344)</li></ul>  |
| Author               | Florian Roth |


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





### es-qs
    
```
(((Source:"Application\\ Error" AND EventID:"1000") OR (Source:"Windows\\ Error\\ Reporting" AND EventID:"1001")) AND ("MsMpEng.exe" AND "mpengine.dll"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Microsoft-Malware-Protection-Engine-Crash <<EOF\n{\n  "metadata": {\n    "title": "Microsoft Malware Protection Engine Crash",\n    "description": "This rule detects a suspicious crash of the Microsoft Malware Protection Engine",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1089",\n      "attack.t1211"\n    ],\n    "query": "(((Source:\\"Application\\\\ Error\\" AND EventID:\\"1000\\") OR (Source:\\"Windows\\\\ Error\\\\ Reporting\\" AND EventID:\\"1001\\")) AND (\\"MsMpEng.exe\\" AND \\"mpengine.dll\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((Source:\\"Application\\\\ Error\\" AND EventID:\\"1000\\") OR (Source:\\"Windows\\\\ Error\\\\ Reporting\\" AND EventID:\\"1001\\")) AND (\\"MsMpEng.exe\\" AND \\"mpengine.dll\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Microsoft Malware Protection Engine Crash\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((Source:"Application Error" AND EventID:"1000") OR (Source:"Windows Error Reporting" AND EventID:"1001")) AND ("MsMpEng.exe" AND "mpengine.dll"))
```


### splunk
    
```
(((Source="Application Error" EventID="1000") OR (Source="Windows Error Reporting" EventID="1001")) ("MsMpEng.exe" "mpengine.dll"))
```


### logpoint
    
```
(((Source="Application Error" EventID="1000") OR (Source="Windows Error Reporting" EventID="1001")) ("MsMpEng.exe" "mpengine.dll"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*(?:.*(?=.*Application Error)(?=.*1000))|.*(?:.*(?=.*Windows Error Reporting)(?=.*1001)))))(?=.*(?:.*(?=.*MsMpEng\\.exe)(?=.*mpengine\\.dll))))'
```



