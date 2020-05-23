| Title                    | Disable Security Events Logging Adding Reg Key MiniNt       |
|:-------------------------|:------------------|
| **Description**          | Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stopped write events. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/0gtweet/status/1182516740955226112](https://twitter.com/0gtweet/status/1182516740955226112)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Disable Security Events Logging Adding Reg Key MiniNt
id: 919f2ef0-be2d-4a7a-b635-eb2b41fde044
status: experimental
description: Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stopped write events.
references:
    - https://twitter.com/0gtweet/status/1182516740955226112
tags:
    - attack.defense_evasion
    - attack.t1089
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2019/11/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
      - EventID: 12 # key create
        # Sysmon gives us HKLM\SYSTEM\CurrentControlSet\.. if ControlSetXX is the selected one
        TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
      - EventID: 14  # key rename
        NewName: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
    condition: selection
fields:
    - EventID
    - Image
    - TargetObject
    - NewName
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -and $_.message -match "TargetObject.*HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt") -or ($_.ID -eq "14" -and $_.message -match "NewName.*HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND ((winlog.event_id:"12" AND winlog.event_data.TargetObject:"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt") OR (winlog.event_id:"14" AND NewName:"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/919f2ef0-be2d-4a7a-b635-eb2b41fde044 <<EOF\n{\n  "metadata": {\n    "title": "Disable Security Events Logging Adding Reg Key MiniNt",\n    "description": "Detects the addition of a key \'MiniNt\' to the registry. Upon a reboot, Windows Event Log service will stopped write events.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1089"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND ((winlog.event_id:\\"12\\" AND winlog.event_data.TargetObject:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\MiniNt\\") OR (winlog.event_id:\\"14\\" AND NewName:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\MiniNt\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND ((winlog.event_id:\\"12\\" AND winlog.event_data.TargetObject:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\MiniNt\\") OR (winlog.event_id:\\"14\\" AND NewName:\\"HKLM\\\\\\\\SYSTEM\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\MiniNt\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Disable Security Events Logging Adding Reg Key MiniNt\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     EventID = {{_source.EventID}}\\n       Image = {{_source.Image}}\\nTargetObject = {{_source.TargetObject}}\\n     NewName = {{_source.NewName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"12" AND TargetObject:"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt") OR (EventID:"14" AND NewName:"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt"))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ((EventCode="12" TargetObject="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt") OR (EventCode="14" NewName="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt"))) | table EventCode,Image,TargetObject,NewName
```


### logpoint
    
```
((event_id="12" TargetObject="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt") OR (event_id="14" NewName="HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\MiniNt"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*12)(?=.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt))|.*(?:.*(?=.*14)(?=.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt))))'
```



