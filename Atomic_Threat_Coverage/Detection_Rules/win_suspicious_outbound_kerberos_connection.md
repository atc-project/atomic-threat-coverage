| Title                    | Suspicious Outbound Kerberos Connection       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li><li>[T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0087_5156_windows_filtering_platform_has_permitted_connection](../Data_Needed/DN_0087_5156_windows_filtering_platform_has_permitted_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1558.003: Kerberoasting](../Triggers/T1558.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other browsers</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/GhostPack/Rubeus8](https://github.com/GhostPack/Rubeus8)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious Outbound Kerberos Connection
id: eca91c7c-9214-47b9-b4c5-cb1d7e4f2350
status: experimental
description: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
references:
    - https://github.com/GhostPack/Rubeus8
author: Ilyas Ochkov, oscd.community
date: 2019/10/24
modified: 2019/11/13
tags:
    - attack.lateral_movement
    - attack.t1208           # an old one
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestinationPort: 88
    filter:
        Image|endswith:
            - '\lsass.exe'
            - '\opera.exe'
            - '\chrome.exe'
            - '\firefox.exe'
    condition: selection and not filter
falsepositives:
    - Other browsers
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5156" -and $_.message -match "DestinationPort.*88") -and  -not (($_.message -match "Image.*.*\\\\lsass.exe" -or $_.message -match "Image.*.*\\\\opera.exe" -or $_.message -match "Image.*.*\\\\chrome.exe" -or $_.message -match "Image.*.*\\\\firefox.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"5156" AND winlog.event_data.DestinationPort:"88") AND (NOT (winlog.event_data.Image.keyword:(*\\\\lsass.exe OR *\\\\opera.exe OR *\\\\chrome.exe OR *\\\\firefox.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/eca91c7c-9214-47b9-b4c5-cb1d7e4f2350 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Outbound Kerberos Connection",\n    "description": "Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1208",\n      "attack.t1558.003"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND (winlog.event_id:\\"5156\\" AND winlog.event_data.DestinationPort:\\"88\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\lsass.exe OR *\\\\\\\\opera.exe OR *\\\\\\\\chrome.exe OR *\\\\\\\\firefox.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND (winlog.event_id:\\"5156\\" AND winlog.event_data.DestinationPort:\\"88\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\lsass.exe OR *\\\\\\\\opera.exe OR *\\\\\\\\chrome.exe OR *\\\\\\\\firefox.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Outbound Kerberos Connection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"5156" AND DestinationPort:"88") AND (NOT (Image.keyword:(*\\\\lsass.exe *\\\\opera.exe *\\\\chrome.exe *\\\\firefox.exe))))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5156" DestinationPort="88") NOT ((Image="*\\\\lsass.exe" OR Image="*\\\\opera.exe" OR Image="*\\\\chrome.exe" OR Image="*\\\\firefox.exe")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="5156" DestinationPort="88")  -(Image IN ["*\\\\lsass.exe", "*\\\\opera.exe", "*\\\\chrome.exe", "*\\\\firefox.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5156)(?=.*88)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\lsass\\.exe|.*.*\\opera\\.exe|.*.*\\chrome\\.exe|.*.*\\firefox\\.exe))))))'
```



