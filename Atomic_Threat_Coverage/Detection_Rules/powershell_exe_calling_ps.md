| Title                | PowerShell called from an Executable Version Mismatch                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell called from an executable by the version mismatch method                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/tactics/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0038_400_windows_powershell_engine_lifecycle](../Data_Needed/DN_0038_400_windows_powershell_engine_lifecycle.md)</li></ul>                                                         |
| Trigger              | <ul><li>[('PowerShell', 'T1086')](../Triggers/('PowerShell', 'T1086').md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration Tests</li><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>                                                          |
| Author               | Sean Metcalf (source), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell called from an Executable Version Mismatch
status: experimental
description: Detects PowerShell called from an executable by the version mismatch method
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
logsource:
    product: windows
    service: powershell-classic
detection:
    selection1:
        EventID: 400
        EngineVersion: 
            - '2.*'
            - '4.*'
            - '5.*'
        HostVersion: '3.*'
    condition: selection1
falsepositives:
    - Penetration Tests
    - Unknown
level: high

```





### Kibana query

```
(EventID:"400" AND EngineVersion.keyword:(2.* 4.* 5.*) AND HostVersion.keyword:3.*)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PowerShell-called-from-an-Executable-Version-Mismatch <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"400\\" AND EngineVersion.keyword:(2.* 4.* 5.*) AND HostVersion.keyword:3.*)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PowerShell called from an Executable Version Mismatch\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"400" AND EngineVersion:("2.*" "4.*" "5.*") AND HostVersion:"3.*")
```

