| Title                | Eventlog Cleared                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0034_104_log_file_was_cleared](../Data_Needed/DN_0034_104_log_file_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://twitter.com/deviouspolack/status/832535435960209408](https://twitter.com/deviouspolack/status/832535435960209408)</li><li>[https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100](https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Eventlog Cleared
description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
references:
    - https://twitter.com/deviouspolack/status/832535435960209408
    - https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1070
    - car.2016-04-002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 104
        Source: Microsoft-Windows-Eventlog
    condition: selection
falsepositives:
    - Unknown
level: medium


```





### es-qs
    
```
(EventID:"104" AND Source:"Microsoft\\-Windows\\-Eventlog")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Eventlog-Cleared <<EOF\n{\n  "metadata": {\n    "title": "Eventlog Cleared",\n    "description": "One of the Windows Eventlogs has been cleared. e.g. caused by \\"wevtutil cl\\" command execution",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1070",\n      "car.2016-04-002"\n    ],\n    "query": "(EventID:\\"104\\" AND Source:\\"Microsoft\\\\-Windows\\\\-Eventlog\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"104\\" AND Source:\\"Microsoft\\\\-Windows\\\\-Eventlog\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Eventlog Cleared\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"104" AND Source:"Microsoft\\-Windows\\-Eventlog")
```


### splunk
    
```
(EventID="104" Source="Microsoft-Windows-Eventlog")
```


### logpoint
    
```
(EventID="104" Source="Microsoft-Windows-Eventlog")
```


### grep
    
```
grep -P '^(?:.*(?=.*104)(?=.*Microsoft-Windows-Eventlog))'
```



