| Title                    | RottenPotato Like Attack Pattern       |
|:-------------------------|:------------------|
| **Description**          | Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1171: LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1171)</li><li>[T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557.001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1195284233729777665](https://twitter.com/SBousseaden/status/1195284233729777665)</li></ul>  |
| **Author**               | @SBousseaden, Florian Roth |


## Detection Rules

### Sigma rule

```
title: RottenPotato Like Attack Pattern
id: 16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
status: experimental
description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
references:
    - https://twitter.com/SBousseaden/status/1195284233729777665
author: "@SBousseaden, Florian Roth"
date: 2019/11/15
tags:
    - attack.privilege_escalation
    - attack.credential_access
    - attack.t1171          # an old one
    - attack.t1557.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS_LOGON'
        WorkstationName: '-'
        SourceNetworkAddress: '127.0.0.1'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*3" -and $_.message -match "TargetUserName.*ANONYMOUS_LOGON" -and $_.message -match "WorkstationName.*-" -and $_.message -match "SourceNetworkAddress.*127.0.0.1") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4624" AND winlog.event_data.LogonType:"3" AND TargetUserName:"ANONYMOUS_LOGON" AND winlog.event_data.WorkstationName:"\\-" AND SourceNetworkAddress:"127.0.0.1")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/16f5d8ca-44bd-47c8-acbe-6fc95a16c12f <<EOF\n{\n  "metadata": {\n    "title": "RottenPotato Like Attack Pattern",\n    "description": "Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.credential_access",\n      "attack.t1171",\n      "attack.t1557.001"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4624\\" AND winlog.event_data.LogonType:\\"3\\" AND TargetUserName:\\"ANONYMOUS_LOGON\\" AND winlog.event_data.WorkstationName:\\"\\\\-\\" AND SourceNetworkAddress:\\"127.0.0.1\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4624\\" AND winlog.event_data.LogonType:\\"3\\" AND TargetUserName:\\"ANONYMOUS_LOGON\\" AND winlog.event_data.WorkstationName:\\"\\\\-\\" AND SourceNetworkAddress:\\"127.0.0.1\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'RottenPotato Like Attack Pattern\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4624" AND LogonType:"3" AND TargetUserName:"ANONYMOUS_LOGON" AND WorkstationName:"\\-" AND SourceNetworkAddress:"127.0.0.1")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4624" LogonType="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4624" logon_type="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*3)(?=.*ANONYMOUS_LOGON)(?=.*-)(?=.*127\\.0\\.0\\.1))'
```



