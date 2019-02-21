| Title                | Suspicious Svchost Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious svchost process start                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Svchost Process
status: experimental
description: Detects a suspicious svchost process start 
author: Florian Roth
date: 2017/08/15
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: '*\svchost.exe'
    filter:
        ParentImage: 
            - '*\services.exe'
            - '*\MsMpEng.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
falsepositives:
    - Unknown
level: high

```




### es-qs
    
```
((EventID:"1" AND Image.keyword:*\\\\svchost.exe) AND NOT (ParentImage.keyword:(*\\\\services.exe *\\\\MsMpEng.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Svchost-Process <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND Image.keyword:*\\\\\\\\svchost.exe) AND NOT (ParentImage.keyword:(*\\\\\\\\services.exe *\\\\\\\\MsMpEng.exe)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Svchost Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"1" AND Image:"*\\\\svchost.exe") AND NOT (ParentImage:("*\\\\services.exe" "*\\\\MsMpEng.exe")))
```


### splunk
    
```
((EventID="1" Image="*\\\\svchost.exe") NOT ((ParentImage="*\\\\services.exe" OR ParentImage="*\\\\MsMpEng.exe"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((EventID="1" Image="*\\\\svchost.exe")  -(ParentImage IN ["*\\\\services.exe", "*\\\\MsMpEng.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*1)(?=.*.*\\svchost\\.exe)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\services\\.exe|.*.*\\MsMpEng\\.exe))))))'
```


