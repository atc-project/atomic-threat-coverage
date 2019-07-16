| Title                | Pass the Hash Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the attack technique pass the hash which is used to move laterally inside the network                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| Development Status   | production |
| References           | <ul><li>[https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events](https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events)</li><li>[https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis](https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis)</li><li>[https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/](https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/)</li></ul>  |
| Author               | Dave Kennedy, Jeff Warren (method) / David Vassallo (rule) |


## Detection Rules

### Sigma rule

```
title: Pass the Hash Activity
status: production
description: 'Detects the attack technique pass the hash which is used to move laterally inside the network'
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
    - https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis
    - https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/
author: Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624
detection:
    selection:
        - EventID: 4624
          SecurityID: 'NULL SID'
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          KeyLength: '0'
        - EventID: 4624
          LogonType: '9'
          LogonProcessName: 'seclogo'
    filter:
        AccountName: 'ANONYMOUS LOGON'
    condition: selection and not filter
falsepositives:
    - Administrator activity
    - Penetration tests
level: medium

```





### es-qs
    
```
((EventID:"4624" AND ((SecurityID:"NULL\\ SID" AND LogonType:"3" AND LogonProcessName:"NtLmSsp" AND KeyLength:"0") OR (LogonType:"9" AND LogonProcessName:"seclogo"))) AND (NOT (AccountName:"ANONYMOUS\\ LOGON")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Pass-the-Hash-Activity <<EOF\n{\n  "metadata": {\n    "title": "Pass the Hash Activity",\n    "description": "Detects the attack technique pass the hash which is used to move laterally inside the network",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1075"\n    ],\n    "query": "((EventID:\\"4624\\" AND ((SecurityID:\\"NULL\\\\ SID\\" AND LogonType:\\"3\\" AND LogonProcessName:\\"NtLmSsp\\" AND KeyLength:\\"0\\") OR (LogonType:\\"9\\" AND LogonProcessName:\\"seclogo\\"))) AND (NOT (AccountName:\\"ANONYMOUS\\\\ LOGON\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4624\\" AND ((SecurityID:\\"NULL\\\\ SID\\" AND LogonType:\\"3\\" AND LogonProcessName:\\"NtLmSsp\\" AND KeyLength:\\"0\\") OR (LogonType:\\"9\\" AND LogonProcessName:\\"seclogo\\"))) AND (NOT (AccountName:\\"ANONYMOUS\\\\ LOGON\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Pass the Hash Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4624" AND ((SecurityID:"NULL SID" AND LogonType:"3" AND LogonProcessName:"NtLmSsp" AND KeyLength:"0") OR (LogonType:"9" AND LogonProcessName:"seclogo"))) AND NOT (AccountName:"ANONYMOUS LOGON"))
```


### splunk
    
```
((EventID="4624" ((SecurityID="NULL SID" LogonType="3" LogonProcessName="NtLmSsp" KeyLength="0") OR (LogonType="9" LogonProcessName="seclogo"))) NOT (AccountName="ANONYMOUS LOGON"))
```


### logpoint
    
```
((EventID="4624" ((SecurityID="NULL SID" LogonType="3" LogonProcessName="NtLmSsp" KeyLength="0") OR (LogonType="9" LogonProcessName="seclogo")))  -(AccountName="ANONYMOUS LOGON"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4624)(?=.*(?:.*(?:.*(?:.*(?=.*NULL SID)(?=.*3)(?=.*NtLmSsp)(?=.*0))|.*(?:.*(?=.*9)(?=.*seclogo)))))))(?=.*(?!.*(?:.*(?=.*ANONYMOUS LOGON)))))'
```



