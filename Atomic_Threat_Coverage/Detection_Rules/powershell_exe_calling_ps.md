| Title                | PowerShell called from an Executable Version Mismatch                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell called from an executable by the version mismatch method                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0038_400_windows_powershell_engine_lifecycle](../Data_Needed/DN_0038_400_windows_powershell_engine_lifecycle.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration Tests</li><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| Author               | Sean Metcalf (source), Florian Roth (rule) |


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





### es-qs
    
```
(EventID:"400" AND EngineVersion.keyword:(2.* 4.* 5.*) AND HostVersion.keyword:3.*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PowerShell-called-from-an-Executable-Version-Mismatch <<EOF\n{\n  "metadata": {\n    "title": "PowerShell called from an Executable Version Mismatch",\n    "description": "Detects PowerShell called from an executable by the version mismatch method",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(EventID:\\"400\\" AND EngineVersion.keyword:(2.* 4.* 5.*) AND HostVersion.keyword:3.*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"400\\" AND EngineVersion.keyword:(2.* 4.* 5.*) AND HostVersion.keyword:3.*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell called from an Executable Version Mismatch\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"400" AND EngineVersion:("2.*" "4.*" "5.*") AND HostVersion:"3.*")
```


### splunk
    
```
(EventID="400" (EngineVersion="2.*" OR EngineVersion="4.*" OR EngineVersion="5.*") HostVersion="3.*")
```


### logpoint
    
```
(EventID="400" EngineVersion IN ["2.*", "4.*", "5.*"] HostVersion="3.*")
```


### grep
    
```
grep -P '^(?:.*(?=.*400)(?=.*(?:.*2\\..*|.*4\\..*|.*5\\..*))(?=.*3\\..*))'
```



