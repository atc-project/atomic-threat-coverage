| Title                | Successful Overpass the Hash Attempt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Runas command-line tool using /netonly parameter</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html)</li></ul>  |
| Author               | Roberto Rodriguez (source), Dominik Schaudel (rule) |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Successful Overpass the Hash Attempt
status: experimental
description: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
references: 
    - https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html
author: Roberto Rodriguez (source), Dominik Schaudel (rule)
date: 2018/02/12
tags:
    - attack.lateral_movement
    - attack.t1075
    - attack.s0002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: seclogo
        AuthenticationPackageName: Negotiate
    condition: selection
falsepositives:
    - Runas command-line tool using /netonly parameter
level: high

```





### es-qs
    
```
(EventID:"4624" AND LogonType:"9" AND LogonProcessName:"seclogo" AND AuthenticationPackageName:"Negotiate")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Successful-Overpass-the-Hash-Attempt <<EOF\n{\n  "metadata": {\n    "title": "Successful Overpass the Hash Attempt",\n    "description": "Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz\'s sekurlsa::pth module.",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1075",\n      "attack.s0002"\n    ],\n    "query": "(EventID:\\"4624\\" AND LogonType:\\"9\\" AND LogonProcessName:\\"seclogo\\" AND AuthenticationPackageName:\\"Negotiate\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4624\\" AND LogonType:\\"9\\" AND LogonProcessName:\\"seclogo\\" AND AuthenticationPackageName:\\"Negotiate\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Successful Overpass the Hash Attempt\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4624" AND LogonType:"9" AND LogonProcessName:"seclogo" AND AuthenticationPackageName:"Negotiate")
```


### splunk
    
```
(EventID="4624" LogonType="9" LogonProcessName="seclogo" AuthenticationPackageName="Negotiate")
```


### logpoint
    
```
(EventID="4624" LogonType="9" LogonProcessName="seclogo" AuthenticationPackageName="Negotiate")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*9)(?=.*seclogo)(?=.*Negotiate))'
```



