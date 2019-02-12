| Title                | Executable in ADS                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of an ADS data stream that contains an executable (non-empty imphash)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1027](https://attack.mitre.org/tactics/T1027)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN_0019_15_windows_sysmon_FileCreateStreamHash.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1027](../Triggering/T1027.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/0xrawsec/status/1002478725605273600?s=21](https://twitter.com/0xrawsec/status/1002478725605273600?s=21)</li></ul>                                                          |
| Author               | Florian Roth, @0xrawsec                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0139</li><li>attack.s0139</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Executable in ADS
status: experimental
description: Detects the creation of an ADS data stream that contains an executable (non-empty imphash)
references:
    - https://twitter.com/0xrawsec/status/1002478725605273600?s=21
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.s0139
author: Florian Roth, @0xrawsec
date: 2018/06/03
logsource:
    product: windows
    service: sysmon
    definition: 'Requirements: Sysmon config with Imphash logging activated'
detection:
    selection:
        EventID: 15
    filter:
        Imphash: '00000000000000000000000000000000'
    condition: selection and not filter
fields:
    - TargetFilename
    - Image
falsepositives:
    - unknown
level: critical


```





### Kibana query

```
(EventID:"15" AND NOT (Imphash:"00000000000000000000000000000000"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Executable-in-ADS <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"15\\" AND NOT (Imphash:\\"00000000000000000000000000000000\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Executable in ADS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nTargetFilename = {{_source.TargetFilename}}\\n         Image = {{_source.Image}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"15" AND NOT (Imphash:"00000000000000000000000000000000"))
```

