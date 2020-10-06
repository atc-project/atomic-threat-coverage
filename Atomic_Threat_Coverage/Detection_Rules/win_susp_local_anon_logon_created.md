| Title                    | Suspicious Windows ANONYMOUS LOGON Local Account Created       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of suspicious accounts simliar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li><li>[T1136.001: Local Account](https://attack.mitre.org/techniques/T1136/001)</li><li>[T1136.002: Domain Account](https://attack.mitre.org/techniques/T1136/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0086_4720_user_account_was_created](../Data_Needed/DN_0086_4720_user_account_was_created.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1136.001: Local Account](../Triggers/T1136.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1189469425482829824](https://twitter.com/SBousseaden/status/1189469425482829824)</li></ul>  |
| **Author**               | James Pemberton / @4A616D6573 |


## Detection Rules

### Sigma rule

```
title: Suspicious Windows ANONYMOUS LOGON Local Account Created
id: 1bbf25b9-8038-4154-a50b-118f2a32be27
status: experimental
description: Detects the creation of suspicious accounts simliar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.
references:
    - https://twitter.com/SBousseaden/status/1189469425482829824
author: James Pemberton / @4A616D6573
date: 2019/10/31
modified: 2020/08/23
tags:
    - attack.persistence
    - attack.t1136          # an old one
    - attack.t1136.001
    - attack.t1136.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        SAMAccountName: '*ANONYMOUS*LOGON*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4720" -and $_.message -match "SAMAccountName.*.*ANONYMOUS.*LOGON.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4720" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/1bbf25b9-8038-4154-a50b-118f2a32be27 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Windows ANONYMOUS LOGON Local Account Created",\n    "description": "Detects the creation of suspicious accounts simliar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1136",\n      "attack.t1136.001",\n      "attack.t1136.002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4720\\" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4720\\" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Windows ANONYMOUS LOGON Local Account Created\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4720" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4720" SAMAccountName="*ANONYMOUS*LOGON*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4720" SAMAccountName="*ANONYMOUS*LOGON*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4720)(?=.*.*ANONYMOUS.*LOGON.*))'
```



