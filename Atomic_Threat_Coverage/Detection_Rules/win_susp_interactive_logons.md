| Title                | Interactive Logon to Server Systems                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects interactive console logons to                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative activity via KVM or ILO board</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Interactive Logon to Server Systems
description: Detects interactive console logons to 
author: Florian Roth
tags:
    - attack.lateral_movement
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 529
            - 4624
            - 4625
        LogonType: 2
        ComputerName:
            - '%ServerSystems%'
            - '%DomainControllers%'
    filter:
        LogonProcessName: Advapi
        ComputerName: '%Workstations%'
    condition: selection and not filter
falsepositives:
    - Administrative activity via KVM or ILO board
level: medium



```





### es-qs
    
```
((EventID:("528" "529" "4624" "4625") AND LogonType:"2" AND ComputerName:("%ServerSystems%" "%DomainControllers%")) AND (NOT (LogonProcessName:"Advapi" AND ComputerName:"%Workstations%")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Interactive-Logon-to-Server-Systems <<EOF\n{\n  "metadata": {\n    "title": "Interactive Logon to Server Systems",\n    "description": "Detects interactive console logons to",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1078"\n    ],\n    "query": "((EventID:(\\"528\\" \\"529\\" \\"4624\\" \\"4625\\") AND LogonType:\\"2\\" AND ComputerName:(\\"%ServerSystems%\\" \\"%DomainControllers%\\")) AND (NOT (LogonProcessName:\\"Advapi\\" AND ComputerName:\\"%Workstations%\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:(\\"528\\" \\"529\\" \\"4624\\" \\"4625\\") AND LogonType:\\"2\\" AND ComputerName:(\\"%ServerSystems%\\" \\"%DomainControllers%\\")) AND (NOT (LogonProcessName:\\"Advapi\\" AND ComputerName:\\"%Workstations%\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Interactive Logon to Server Systems\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("528" "529" "4624" "4625") AND LogonType:"2" AND ComputerName:("%ServerSystems%" "%DomainControllers%")) AND NOT (LogonProcessName:"Advapi" AND ComputerName:"%Workstations%"))
```


### splunk
    
```
(((EventID="528" OR EventID="529" OR EventID="4624" OR EventID="4625") LogonType="2" (ComputerName="%ServerSystems%" OR ComputerName="%DomainControllers%")) NOT (LogonProcessName="Advapi" ComputerName="%Workstations%"))
```


### logpoint
    
```
((EventID IN ["528", "529", "4624", "4625"] LogonType="2" ComputerName IN ["%ServerSystems%", "%DomainControllers%"])  -(LogonProcessName="Advapi" ComputerName="%Workstations%"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*528|.*529|.*4624|.*4625))(?=.*2)(?=.*(?:.*%ServerSystems%|.*%DomainControllers%))))(?=.*(?!.*(?:.*(?=.*Advapi)(?=.*%Workstations%)))))'
```



