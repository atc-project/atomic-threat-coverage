| Title                    | StoneDrill Service Install       |
|:-------------------------|:------------------|
| **Description**          | This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li><li>[T1543.003: Windows Service](https://attack.mitre.org/techniques/T1543/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1543.003: Windows Service](../Triggers/T1543.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/](https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0064</li></ul> | 

## Detection Rules

### Sigma rule

```
title: StoneDrill Service Install
id: 9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6
description: This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky
author: Florian Roth
date: 2017/03/07
references:
    - https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/
tags:
    - attack.persistence
    - attack.g0064
    - attack.t1050          # an old one
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: NtsSrv
        ServiceFileName: '* LocalService'
    condition: selection
falsepositives:
    - Unlikely
level: high

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*NtsSrv" -and $_.message -match "ServiceFileName.*.* LocalService") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ServiceName:"NtsSrv" AND winlog.event_data.ServiceFileName.keyword:*\\ LocalService)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6 <<EOF\n{\n  "metadata": {\n    "title": "StoneDrill Service Install",\n    "description": "This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky",\n    "tags": [\n      "attack.persistence",\n      "attack.g0064",\n      "attack.t1050",\n      "attack.t1543.003"\n    ],\n    "query": "(winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceName:\\"NtsSrv\\" AND winlog.event_data.ServiceFileName.keyword:*\\\\ LocalService)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceName:\\"NtsSrv\\" AND winlog.event_data.ServiceFileName.keyword:*\\\\ LocalService)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'StoneDrill Service Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND ServiceName:"NtsSrv" AND ServiceFileName.keyword:* LocalService)
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" ServiceName="NtsSrv" ServiceFileName="* LocalService")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service="NtsSrv" ServiceFileName="* LocalService")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*NtsSrv)(?=.*.* LocalService))'
```



