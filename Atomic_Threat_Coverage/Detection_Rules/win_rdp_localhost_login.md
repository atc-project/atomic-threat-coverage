| Title                    | RDP Login from Localhost       |
|:-------------------------|:------------------|
| **Description**          | RDP login with localhost source address may be a tunnelled login |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li><li>[T1021.001: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.001: Remote Desktop Protocol](../Triggers/T1021.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP Login from Localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
description: RDP login with localhost source address may be a tunnelled login
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/28
modified: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1076          # an old one
    - car.2013-07-002
    - attack.t1021.001
status: experimental
author: Thomas Patzke
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        SourceNetworkAddress:
            - "::1"
            - "127.0.0.1"
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*10" -and ($_.message -match "::1" -or $_.message -match "127.0.0.1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4624" AND winlog.event_data.LogonType:"10" AND SourceNetworkAddress:("\\:\\:1" OR "127.0.0.1"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/51e33403-2a37-4d66-a574-1fda1782cc31 <<EOF\n{\n  "metadata": {\n    "title": "RDP Login from Localhost",\n    "description": "RDP login with localhost source address may be a tunnelled login",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1076",\n      "car.2013-07-002",\n      "attack.t1021.001"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4624\\" AND winlog.event_data.LogonType:\\"10\\" AND SourceNetworkAddress:(\\"\\\\:\\\\:1\\" OR \\"127.0.0.1\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4624\\" AND winlog.event_data.LogonType:\\"10\\" AND SourceNetworkAddress:(\\"\\\\:\\\\:1\\" OR \\"127.0.0.1\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'RDP Login from Localhost\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4624" AND LogonType:"10" AND SourceNetworkAddress:("\\:\\:1" "127.0.0.1"))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4624" LogonType="10" (SourceNetworkAddress="::1" OR SourceNetworkAddress="127.0.0.1"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4624" logon_type="10" SourceNetworkAddress IN ["::1", "127.0.0.1"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*10)(?=.*(?:.*::1|.*127\\.0\\.0\\.1)))'
```



