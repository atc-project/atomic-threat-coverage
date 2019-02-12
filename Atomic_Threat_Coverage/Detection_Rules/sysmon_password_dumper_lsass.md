| Title                | Password Dumper Remote Thread in LSASS                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/tactics/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>                                                         |
| Trigger              | <ul><li>[('Credential Dumping', 'T1003')](../Triggers/('Credential Dumping', 'T1003').md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Password Dumper Remote Thread in LSASS 
description: Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm
status: stable
author: Thomas Patzke
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage: 'C:\Windows\System32\lsass.exe'
        StartModule: null
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
falsepositives:
    - unknown
level: high

```





### Kibana query

```
(EventID:"8" AND TargetImage:"C\\:\\\\Windows\\\\System32\\\\lsass.exe" AND NOT _exists_:StartModule)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Password-Dumper-Remote-Thread-in-LSASS <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"8\\" AND TargetImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\lsass.exe\\" AND NOT _exists_:StartModule)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Password Dumper Remote Thread in LSASS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"8" AND TargetImage:"C\\:\\\\Windows\\\\System32\\\\lsass.exe" AND NOT _exists_:StartModule)
```

