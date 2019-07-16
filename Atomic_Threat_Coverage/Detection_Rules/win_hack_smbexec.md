| Title                | smbexec.py Service Installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of smbexec.py tool by detecting a specific service installation                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)</li></ul>  |
| Author               | Omer Faruk Celik |


## Detection Rules

### Sigma rule

```
title: smbexec.py Service Installation
description: Detects the use of smbexec.py tool by detecting a specific service installation
author: Omer Faruk Celik
date: 2018/03/20
references:
    - https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1077
    - attack.t1035
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'BTOBTO'
        ServiceFileName: '*\execute.bat'
    condition: service_installation
fields:
    - ServiceName
    - ServiceFileName
falsepositives:
    - Penetration Test
    - Unknown
level: critical
```





### es-qs
    
```
(EventID:"7045" AND ServiceName:"BTOBTO" AND ServiceFileName.keyword:*\\\\execute.bat)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/smbexec.py-Service-Installation <<EOF\n{\n  "metadata": {\n    "title": "smbexec.py Service Installation",\n    "description": "Detects the use of smbexec.py tool by detecting a specific service installation",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.execution",\n      "attack.t1077",\n      "attack.t1035"\n    ],\n    "query": "(EventID:\\"7045\\" AND ServiceName:\\"BTOBTO\\" AND ServiceFileName.keyword:*\\\\\\\\execute.bat)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7045\\" AND ServiceName:\\"BTOBTO\\" AND ServiceFileName.keyword:*\\\\\\\\execute.bat)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'smbexec.py Service Installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n    ServiceName = {{_source.ServiceName}}\\nServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND ServiceName:"BTOBTO" AND ServiceFileName:"*\\\\execute.bat")
```


### splunk
    
```
(EventID="7045" ServiceName="BTOBTO" ServiceFileName="*\\\\execute.bat") | table ServiceName,ServiceFileName
```


### logpoint
    
```
(EventID="7045" ServiceName="BTOBTO" ServiceFileName="*\\\\execute.bat")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*BTOBTO)(?=.*.*\\execute\\.bat))'
```



