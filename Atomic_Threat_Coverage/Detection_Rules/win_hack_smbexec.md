| Title                    | smbexec.py Service Installation       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of smbexec.py tool by detecting a specific service installation |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1569.002: Service Execution](https://attack.mitre.org/techniques/T1569/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li><li>[T1569.002: Service Execution](../Triggers/T1569.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)</li></ul>  |
| **Author**               | Omer Faruk Celik |


## Detection Rules

### Sigma rule

```
title: smbexec.py Service Installation
id: 52a85084-6989-40c3-8f32-091e12e13f09
description: Detects the use of smbexec.py tool by detecting a specific service installation
author: Omer Faruk Celik
date: 2018/03/20
modified: 2020/08/23
references:
    - https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1077          # an old one
    - attack.t1021.002
    - attack.t1035          # an old one
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'BTOBTO'
        ServiceFileName: '*\execute.bat'
    condition: service_installation
fields:
    - ServiceName
    - ServiceFileName
falsepositives:
    - Penetration Test
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*BTOBTO" -and $_.message -match "ServiceFileName.*.*\\\\execute.bat") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ServiceName:"BTOBTO" AND winlog.event_data.ServiceFileName.keyword:*\\\\execute.bat)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/52a85084-6989-40c3-8f32-091e12e13f09 <<EOF\n{\n  "metadata": {\n    "title": "smbexec.py Service Installation",\n    "description": "Detects the use of smbexec.py tool by detecting a specific service installation",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.execution",\n      "attack.t1077",\n      "attack.t1021.002",\n      "attack.t1035",\n      "attack.t1569.002"\n    ],\n    "query": "(winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceName:\\"BTOBTO\\" AND winlog.event_data.ServiceFileName.keyword:*\\\\\\\\execute.bat)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceName:\\"BTOBTO\\" AND winlog.event_data.ServiceFileName.keyword:*\\\\\\\\execute.bat)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'smbexec.py Service Installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n    ServiceName = {{_source.ServiceName}}\\nServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND ServiceName:"BTOBTO" AND ServiceFileName.keyword:*\\\\execute.bat)
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" ServiceName="BTOBTO" ServiceFileName="*\\\\execute.bat") | table ServiceName,ServiceFileName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service="BTOBTO" ServiceFileName="*\\\\execute.bat")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*BTOBTO)(?=.*.*\\execute\\.bat))'
```



