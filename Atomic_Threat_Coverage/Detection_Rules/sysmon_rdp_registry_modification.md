| Title                    | RDP Registry Modification       |
|:-------------------------|:------------------|
| **Description**          | Detects potential malicious modification of the property value of fDenyTSConnections and UserAuthentication to enable remote desktop connections. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1112_Modify_Registry/enable_rdp_registry.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1112_Modify_Registry/enable_rdp_registry.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: RDP Registry Modification
id: 41904ebe-d56c-4904-b9ad-7a77bdf154b3
description: Detects potential malicious modification of the property value of fDenyTSConnections and UserAuthentication to enable remote desktop connections.
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1112_Modify_Registry/enable_rdp_registry.md
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|endswith:
            - '\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication'
            - '\CurrentControlSet\Control\Terminal Server\fDenyTSConnections'
        Details: 'DWORD (0x00000000)'
    condition: selection
fields:
    - ComputerName
    - Image
    - EventType
    - TargetObject
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\\UserAuthentication" -or $_.message -match "TargetObject.*.*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\fDenyTSConnections") -and $_.message -match "Details.*DWORD (0x00000000)") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\\\CurrentControlSet\\\\Control\\\\Terminal\\ Server\\\\WinStations\\\\RDP\\-Tcp\\\\UserAuthentication OR *\\\\CurrentControlSet\\\\Control\\\\Terminal\\ Server\\\\fDenyTSConnections) AND winlog.event_data.Details:"DWORD\\ \\(0x00000000\\)")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/41904ebe-d56c-4904-b9ad-7a77bdf154b3 <<EOF\n{\n  "metadata": {\n    "title": "RDP Registry Modification",\n    "description": "Detects potential malicious modification of the property value of fDenyTSConnections and UserAuthentication to enable remote desktop connections.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1112"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"13\\" AND winlog.event_data.TargetObject.keyword:(*\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Terminal\\\\ Server\\\\\\\\WinStations\\\\\\\\RDP\\\\-Tcp\\\\\\\\UserAuthentication OR *\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Terminal\\\\ Server\\\\\\\\fDenyTSConnections) AND winlog.event_data.Details:\\"DWORD\\\\ \\\\(0x00000000\\\\)\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"13\\" AND winlog.event_data.TargetObject.keyword:(*\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Terminal\\\\ Server\\\\\\\\WinStations\\\\\\\\RDP\\\\-Tcp\\\\\\\\UserAuthentication OR *\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Terminal\\\\ Server\\\\\\\\fDenyTSConnections) AND winlog.event_data.Details:\\"DWORD\\\\ \\\\(0x00000000\\\\)\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'RDP Registry Modification\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n       Image = {{_source.Image}}\\n   EventType = {{_source.EventType}}\\nTargetObject = {{_source.TargetObject}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject.keyword:(*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP\\-Tcp\\\\UserAuthentication *\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\fDenyTSConnections) AND Details:"DWORD \\(0x00000000\\)")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\\UserAuthentication" OR TargetObject="*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\fDenyTSConnections") Details="DWORD (0x00000000)") | table ComputerName,Image,EventType,TargetObject
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\\UserAuthentication", "*\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\fDenyTSConnections"] Details="DWORD (0x00000000)")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication|.*.*\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections))(?=.*DWORD \\(0x00000000\\)))'
```



