| Title                | Remote PowerShell Session                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote PowerShell connections by monitoring network outbount connections to ports 5985 or 5986 from not network service account                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Leigitmate usage of remote PowerShell, e.g. remote administration and monitoring.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Remote PowerShell Session
id: c539afac-c12a-46ed-b1bd-5a5567c9f045
description: Detects remote PowerShell connections by monitoring network outbount connections to ports 5985 or 5986 from not network service account
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
    service: sysmon
detection:
    selection: 
        EventID: 3
        DestinationPort:
            - 5985
            - 5986
    filter:
        User: 'NT AUTHORITY\NETWORK SERVICE'
    condition: selection and not filter
falsepositives:
    - Leigitmate usage of remote PowerShell, e.g. remote administration and monitoring.
level: high

```





### es-qs
    
```
((EventID:"3" AND DestinationPort:("5985" OR "5986")) AND (NOT (User:"NT\\ AUTHORITY\\\\NETWORK\\ SERVICE")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c539afac-c12a-46ed-b1bd-5a5567c9f045 <<EOF\n{\n  "metadata": {\n    "title": "Remote PowerShell Session",\n    "description": "Detects remote PowerShell connections by monitoring network outbount connections to ports 5985 or 5986 from not network service account",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "((EventID:\\"3\\" AND DestinationPort:(\\"5985\\" OR \\"5986\\")) AND (NOT (User:\\"NT\\\\ AUTHORITY\\\\\\\\NETWORK\\\\ SERVICE\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"3\\" AND DestinationPort:(\\"5985\\" OR \\"5986\\")) AND (NOT (User:\\"NT\\\\ AUTHORITY\\\\\\\\NETWORK\\\\ SERVICE\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Remote PowerShell Session\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"3" AND DestinationPort:("5985" "5986")) AND (NOT (User:"NT AUTHORITY\\\\NETWORK SERVICE")))
```


### splunk
    
```
((EventID="3" (DestinationPort="5985" OR DestinationPort="5986")) NOT (User="NT AUTHORITY\\\\NETWORK SERVICE"))
```


### logpoint
    
```
((event_id="3" DestinationPort IN ["5985", "5986"])  -(User="NT AUTHORITY\\\\NETWORK SERVICE"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*(?:.*5985|.*5986))))(?=.*(?!.*(?:.*(?=.*NT AUTHORITY\\NETWORK SERVICE)))))'
```



