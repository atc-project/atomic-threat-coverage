| Title                    | Password Dumper Remote Thread in LSASS       |
|:-------------------------|:------------------|
| **Description**          | Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003.001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.001: LSASS Memory](../Triggers/T1003.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Password Dumper Remote Thread in LSASS
id: f239b326-2f41-4d6b-9dfa-c846a60ef505
description: Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm
status: stable
author: Thomas Patzke
date: 2017/02/19
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage: 'C:\Windows\System32\lsass.exe'
        StartModule: ''
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.s0005
    - attack.t1003.001
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "TargetImage.*C:\\\\Windows\\\\System32\\\\lsass.exe" -and $_.message -match "StartModule.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"8" AND winlog.event_data.TargetImage:"C\\:\\\\Windows\\\\System32\\\\lsass.exe" AND winlog.event_data.StartModule:"")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f239b326-2f41-4d6b-9dfa-c846a60ef505 <<EOF\n{\n  "metadata": {\n    "title": "Password Dumper Remote Thread in LSASS",\n    "description": "Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.s0005",\n      "attack.t1003.001"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"8\\" AND winlog.event_data.TargetImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\lsass.exe\\" AND winlog.event_data.StartModule:\\"\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"8\\" AND winlog.event_data.TargetImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\lsass.exe\\" AND winlog.event_data.StartModule:\\"\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Password Dumper Remote Thread in LSASS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"8" AND TargetImage:"C\\:\\\\Windows\\\\System32\\\\lsass.exe" AND StartModule:"")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="8" TargetImage="C:\\\\Windows\\\\System32\\\\lsass.exe" StartModule="")
```


### logpoint
    
```
(event_id="8" TargetImage="C:\\\\Windows\\\\System32\\\\lsass.exe" StartModule="")
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*C:\\Windows\\System32\\lsass\\.exe)(?=.*))'
```



