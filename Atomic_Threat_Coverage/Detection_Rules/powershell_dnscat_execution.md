| Title                    | Dnscat Execution       |
|:-------------------------|:------------------|
| **Description**          | Dnscat exfiltration tool execution |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1048: Exfiltration Over Alternative Protocol](../Triggers/T1048.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Dnscat Execution
id: a6d67db4-6220-436d-8afc-f3842fe05d43
description: Dnscat exfiltration tool execution
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2020/08/24
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains: "Start-Dnscat2"
    condition: selection
falsepositives:
    - Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Start-Dnscat2.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND ScriptBlockText.keyword:*Start\\-Dnscat2*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/a6d67db4-6220-436d-8afc-f3842fe05d43 <<EOF\n{\n  "metadata": {\n    "title": "Dnscat Execution",\n    "description": "Dnscat exfiltration tool execution",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1048",\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_id:\\"4104\\" AND ScriptBlockText.keyword:*Start\\\\-Dnscat2*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"4104\\" AND ScriptBlockText.keyword:*Start\\\\-Dnscat2*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Dnscat Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4104" AND ScriptBlockText.keyword:*Start\\-Dnscat2*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" ScriptBlockText="*Start-Dnscat2*")
```


### logpoint
    
```
(event_id="4104" ScriptBlockText="*Start-Dnscat2*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*.*Start-Dnscat2.*))'
```



