| Title                | System File Execution Location Anomaly                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows program executable started in a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Exotic software</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/GelosSnake/status/934900723426439170](https://twitter.com/GelosSnake/status/934900723426439170)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: System File Execution Location Anomaly
status: experimental
description: Detects a Windows program executable started in a suspicious folder
references:
    - https://twitter.com/GelosSnake/status/934900723426439170
author: Florian Roth
date: 2017/11/27
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image:
            - '*\svchost.exe'
            - '*\rundll32.exe'
            - '*\services.exe'
            - '*\powershell.exe'
            - '*\regsvr32.exe'
            - '*\spoolsv.exe'
            - '*\lsass.exe'
            - '*\smss.exe'
            - '*\csrss.exe'
            - '*\conhost.exe'
    filter:
        Image: 
            - '*\System32\*'
            - '*\SysWow64\*'
    condition: selection and not filter
tags:
    - attack.defense_evasion
falsepositives:
    - Exotic software
level: high


```





### Kibana query

```
((EventID:"1" AND Image:("*\\\\svchost.exe" "*\\\\rundll32.exe" "*\\\\services.exe" "*\\\\powershell.exe" "*\\\\regsvr32.exe" "*\\\\spoolsv.exe" "*\\\\lsass.exe" "*\\\\smss.exe" "*\\\\csrss.exe" "*\\\\conhost.exe")) AND NOT (Image:("*\\\\System32\\*" "*\\\\SysWow64\\*")))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/System-File-Execution-Location-Anomaly <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND Image:(\\"*\\\\\\\\svchost.exe\\" \\"*\\\\\\\\rundll32.exe\\" \\"*\\\\\\\\services.exe\\" \\"*\\\\\\\\powershell.exe\\" \\"*\\\\\\\\regsvr32.exe\\" \\"*\\\\\\\\spoolsv.exe\\" \\"*\\\\\\\\lsass.exe\\" \\"*\\\\\\\\smss.exe\\" \\"*\\\\\\\\csrss.exe\\" \\"*\\\\\\\\conhost.exe\\")) AND NOT (Image:(\\"*\\\\\\\\System32\\\\*\\" \\"*\\\\\\\\SysWow64\\\\*\\")))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'System File Execution Location Anomaly\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND Image:("*\\\\svchost.exe" "*\\\\rundll32.exe" "*\\\\services.exe" "*\\\\powershell.exe" "*\\\\regsvr32.exe" "*\\\\spoolsv.exe" "*\\\\lsass.exe" "*\\\\smss.exe" "*\\\\csrss.exe" "*\\\\conhost.exe")) AND NOT (Image:("*\\\\System32\\*" "*\\\\SysWow64\\*")))
```

