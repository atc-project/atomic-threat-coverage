| Title                    | Narrator's Feedback-Hub Persistence       |
|:-------------------------|:------------------|
| **Description**          | Detects abusing Windows 10 Narrator's Feedback-Hub |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html](https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html)</li></ul>  |
| **Author**               | Dmitriy Lifanov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Narrator's Feedback-Hub Persistence
id: f663a6d9-9d1b-49b8-b2b1-0637914d199a
description: Detects abusing Windows 10 Narrator's Feedback-Hub
references:
    - https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html
tags:
    - attack.persistence
    - attack.t1060
author: Dmitriy Lifanov, oscd.community
status: experimental
date: 2019/10/25
modified: 2019/11/10
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 12
        EventType: DeleteValue
        TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\DelegateExecute'
    selection2:
        EventID: 13
        TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\(Default)'
    condition: 1 of them
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -and $_.message -match "EventType.*DeleteValue" -and $_.message -match "TargetObject.*.*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute") -or ($_.ID -eq "13" -and $_.message -match "TargetObject.*.*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\(Default)"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND ((winlog.event_id:"12" AND winlog.event_data.EventType:"DeleteValue" AND winlog.event_data.TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute) OR (winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\\\(Default\\))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f663a6d9-9d1b-49b8-b2b1-0637914d199a <<EOF\n{\n  "metadata": {\n    "title": "Narrator\'s Feedback-Hub Persistence",\n    "description": "Detects abusing Windows 10 Narrator\'s Feedback-Hub",\n    "tags": [\n      "attack.persistence",\n      "attack.t1060"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND ((winlog.event_id:\\"12\\" AND winlog.event_data.EventType:\\"DeleteValue\\" AND winlog.event_data.TargetObject.keyword:*\\\\\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\\\\\Shell\\\\\\\\open\\\\\\\\command\\\\\\\\DelegateExecute) OR (winlog.event_id:\\"13\\" AND winlog.event_data.TargetObject.keyword:*\\\\\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\\\\\Shell\\\\\\\\open\\\\\\\\command\\\\\\\\\\\\(Default\\\\))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND ((winlog.event_id:\\"12\\" AND winlog.event_data.EventType:\\"DeleteValue\\" AND winlog.event_data.TargetObject.keyword:*\\\\\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\\\\\Shell\\\\\\\\open\\\\\\\\command\\\\\\\\DelegateExecute) OR (winlog.event_id:\\"13\\" AND winlog.event_data.TargetObject.keyword:*\\\\\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\\\\\Shell\\\\\\\\open\\\\\\\\command\\\\\\\\\\\\(Default\\\\))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Narrator\'s Feedback-Hub Persistence\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"12" AND EventType:"DeleteValue" AND TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute) OR (EventID:"13" AND TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\\\(Default\\)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ((EventCode="12" EventType="DeleteValue" TargetObject="*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute") OR (EventCode="13" TargetObject="*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\(Default)")))
```


### logpoint
    
```
((event_id="12" EventType="DeleteValue" TargetObject="*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute") OR (event_id="13" TargetObject="*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\(Default)"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*12)(?=.*DeleteValue)(?=.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute))|.*(?:.*(?=.*13)(?=.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\\\(Default\\)))))'
```



