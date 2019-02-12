| Title                | PowerShell PSAttack                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of PSAttack PowerShell hack tool                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/tactics/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>                                                         |
| Trigger              | <ul><li>[('PowerShell', 'T1086')](../Triggers/('PowerShell', 'T1086').md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Pentesters</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>                                                          |
| Author               | Sean Metcalf (source), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell PSAttack 
status: experimental
description: Detects the use of PSAttack PowerShell hack tool
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
logsource:
    product: windows
    service: powershell
    definition: 'It is recommanded to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    selection:
        EventID: 4103
    keyword: 
        - 'PS ATTACK!!!'
    condition: all of them
falsepositives:
    - Pentesters
level: high

```





### Kibana query

```
(EventID:"4103" AND "PS\\ ATTACK\\!\\!\\!")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PowerShell-PSAttack <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4103\\" AND \\"PS\\\\ ATTACK\\\\!\\\\!\\\\!\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PowerShell PSAttack\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4103" AND "PS ATTACK\\!\\!\\!")
```

