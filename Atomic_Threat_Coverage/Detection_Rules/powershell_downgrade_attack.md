| Title                | PowerShell Downgrade Attack                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0038_400_windows_powershell_engine_lifecycle](../Data_Needed/DN_0038_400_windows_powershell_engine_lifecycle.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Penetration Test</li><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)</li></ul>                                                          |
| Author               | Florian Roth (rule), Lee Holmes (idea)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell Downgrade Attack
status: experimental
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
author: Florian Roth (rule), Lee Holmes (idea)
logsource:
    product: windows
    service: powershell-classic
detection:
    selection:
        EventID: 400
        EngineVersion: '2.*'
    filter:
        HostVersion: '2.*' 
    condition: selection and not filter
falsepositives:
    - Penetration Test
    - Unknown
level: medium

```





### Kibana query

```
((EventID:"400" AND EngineVersion.keyword:2.*) AND NOT (HostVersion.keyword:2.*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PowerShell-Downgrade-Attack <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"400\\" AND EngineVersion.keyword:2.*) AND NOT (HostVersion.keyword:2.*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PowerShell Downgrade Attack\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"400" AND EngineVersion:"2.*") AND NOT (HostVersion:"2.*"))
```





### Splunk

```
((EventID="400" EngineVersion="2.*") NOT (HostVersion="2.*"))
```





### Logpoint

```
((EventID="400" EngineVersion="2.*")  -(HostVersion="2.*"))
```





### Grep

```
grep -P '^(?:.*(?=.*(?:.*(?=.*400)(?=.*2\\..*)))(?=.*(?!.*(?:.*(?=.*2\\..*)))))'
```





### Fieldlist

```
EngineVersion\nEventID\nHostVersion
```

