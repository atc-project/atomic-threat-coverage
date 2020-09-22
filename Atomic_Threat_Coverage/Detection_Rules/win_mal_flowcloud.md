| Title                    | FlowCloud Malware       |
|:-------------------------|:------------------|
| **Description**          | Detects FlowCloud malware from threat group TA410. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.proofpoint.com/us/blog/threat-insight/ta410-group-behind-lookback-attacks-against-us-utilities-sector-returns-new](https://www.proofpoint.com/us/blog/threat-insight/ta410-group-behind-lookback-attacks-against-us-utilities-sector-returns-new)</li></ul>  |
| **Author**               | NVISO |


## Detection Rules

### Sigma rule

```
title: FlowCloud Malware
id: 5118765f-6657-4ddb-a487-d7bd673abbf1
status: experimental
description: Detects FlowCloud malware from threat group TA410.
references:
  - https://www.proofpoint.com/us/blog/threat-insight/ta410-group-behind-lookback-attacks-against-us-utilities-sector-returns-new
author: NVISO
tags:
  - attack.persistence
  - attack.t1112
date: 2020/06/09
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 12 # key create
      - 13 # value set
    TargetObject:
      - 'HKLM\HARDWARE\{804423C2-F490-4ac3-BFA5-13DEDE63A71A}'
      - 'HKLM\HARDWARE\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}'
      - 'HKLM\HARDWARE\{2DB80286-1784-48b5-A751-B6ED1F490303}'
      - 'HKLM\SYSTEM\Setup\PrintResponsor\\*'
  condition: selection
falsepositives:
  - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13") -and ($_.message -match "HKLM\\\\HARDWARE\\\\{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" -or $_.message -match "HKLM\\\\HARDWARE\\\\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" -or $_.message -match "HKLM\\\\HARDWARE\\\\{2DB80286-1784-48b5-A751-B6ED1F490303}" -or $_.message -match "TargetObject.*HKLM\\\\SYSTEM\\\\Setup\\\\PrintResponsor\\\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:("12" OR "13") AND winlog.event_data.TargetObject.keyword:(HKLM\\\\HARDWARE\\\\\\{804423C2\\-F490\\-4ac3\\-BFA5\\-13DEDE63A71A\\} OR HKLM\\\\HARDWARE\\\\\\{A5124AF5\\-DF23\\-49bf\\-B0ED\\-A18ED3DEA027\\} OR HKLM\\\\HARDWARE\\\\\\{2DB80286\\-1784\\-48b5\\-A751\\-B6ED1F490303\\} OR HKLM\\\\SYSTEM\\\\Setup\\\\PrintResponsor\\\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/5118765f-6657-4ddb-a487-d7bd673abbf1 <<EOF\n{\n  "metadata": {\n    "title": "FlowCloud Malware",\n    "description": "Detects FlowCloud malware from threat group TA410.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1112"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:(\\"12\\" OR \\"13\\") AND winlog.event_data.TargetObject.keyword:(HKLM\\\\\\\\HARDWARE\\\\\\\\\\\\{804423C2\\\\-F490\\\\-4ac3\\\\-BFA5\\\\-13DEDE63A71A\\\\} OR HKLM\\\\\\\\HARDWARE\\\\\\\\\\\\{A5124AF5\\\\-DF23\\\\-49bf\\\\-B0ED\\\\-A18ED3DEA027\\\\} OR HKLM\\\\\\\\HARDWARE\\\\\\\\\\\\{2DB80286\\\\-1784\\\\-48b5\\\\-A751\\\\-B6ED1F490303\\\\} OR HKLM\\\\\\\\SYSTEM\\\\\\\\Setup\\\\\\\\PrintResponsor\\\\\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:(\\"12\\" OR \\"13\\") AND winlog.event_data.TargetObject.keyword:(HKLM\\\\\\\\HARDWARE\\\\\\\\\\\\{804423C2\\\\-F490\\\\-4ac3\\\\-BFA5\\\\-13DEDE63A71A\\\\} OR HKLM\\\\\\\\HARDWARE\\\\\\\\\\\\{A5124AF5\\\\-DF23\\\\-49bf\\\\-B0ED\\\\-A18ED3DEA027\\\\} OR HKLM\\\\\\\\HARDWARE\\\\\\\\\\\\{2DB80286\\\\-1784\\\\-48b5\\\\-A751\\\\-B6ED1F490303\\\\} OR HKLM\\\\\\\\SYSTEM\\\\\\\\Setup\\\\\\\\PrintResponsor\\\\\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'FlowCloud Malware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("12" "13") AND TargetObject.keyword:(HKLM\\\\HARDWARE\\\\\\{804423C2\\-F490\\-4ac3\\-BFA5\\-13DEDE63A71A\\} HKLM\\\\HARDWARE\\\\\\{A5124AF5\\-DF23\\-49bf\\-B0ED\\-A18ED3DEA027\\} HKLM\\\\HARDWARE\\\\\\{2DB80286\\-1784\\-48b5\\-A751\\-B6ED1F490303\\} HKLM\\\\SYSTEM\\\\Setup\\\\PrintResponsor\\\\*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="12" OR EventCode="13") (TargetObject="HKLM\\\\HARDWARE\\\\{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" OR TargetObject="HKLM\\\\HARDWARE\\\\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" OR TargetObject="HKLM\\\\HARDWARE\\\\{2DB80286-1784-48b5-A751-B6ED1F490303}" OR TargetObject="HKLM\\\\SYSTEM\\\\Setup\\\\PrintResponsor\\\\*"))
```


### logpoint
    
```
(event_id IN ["12", "13"] TargetObject IN ["HKLM\\\\HARDWARE\\\\{804423C2-F490-4ac3-BFA5-13DEDE63A71A}", "HKLM\\\\HARDWARE\\\\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}", "HKLM\\\\HARDWARE\\\\{2DB80286-1784-48b5-A751-B6ED1F490303}", "HKLM\\\\SYSTEM\\\\Setup\\\\PrintResponsor\\\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*12|.*13))(?=.*(?:.*HKLM\\HARDWARE\\\\{804423C2-F490-4ac3-BFA5-13DEDE63A71A\\}|.*HKLM\\HARDWARE\\\\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027\\}|.*HKLM\\HARDWARE\\\\{2DB80286-1784-48b5-A751-B6ED1F490303\\}|.*HKLM\\SYSTEM\\Setup\\PrintResponsor\\\\.*)))'
```



