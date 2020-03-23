| Title                | Remote PowerShell Sessions                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0087_5156_windows_filtering_platform_has_permitted_connection](../Data_Needed/DN_0087_5156_windows_filtering_platform_has_permitted_connection.md)</li></ul>  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate use of remote PowerShell execution</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Remote PowerShell Sessions
id: 13acf386-b8c6-4fe0-9a6e-c4756b974698
description: Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986
status: experimental
date: 2019/09/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 5156
        DestPort:
            - 5985
            - 5986
        LayerRTID: 44
    condition: selection
falsepositives:
    - Legitimate use of remote PowerShell execution
level: high

```





### es-qs
    
```
(EventID:"5156" AND DestPort:("5985" OR "5986") AND LayerRTID:"44")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/13acf386-b8c6-4fe0-9a6e-c4756b974698 <<EOF\n{\n  "metadata": {\n    "title": "Remote PowerShell Sessions",\n    "description": "Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(EventID:\\"5156\\" AND DestPort:(\\"5985\\" OR \\"5986\\") AND LayerRTID:\\"44\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"5156\\" AND DestPort:(\\"5985\\" OR \\"5986\\") AND LayerRTID:\\"44\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Remote PowerShell Sessions\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5156" AND DestPort:("5985" "5986") AND LayerRTID:"44")
```


### splunk
    
```
(EventID="5156" (DestPort="5985" OR DestPort="5986") LayerRTID="44")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5156" DestPort IN ["5985", "5986"] LayerRTID="44")
```


### grep
    
```
grep -P '^(?:.*(?=.*5156)(?=.*(?:.*5985|.*5986))(?=.*44))'
```



