| Title                    | Malicious Service Installations       |
|:-------------------------|:------------------|
| **Description**          | Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li><li>[T1543.003: Windows Service](https://attack.mitre.org/techniques/T1543/003)</li><li>[T1569.002: Service Execution](https://attack.mitre.org/techniques/T1569/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1543.003: Windows Service](../Triggers/T1543.003.md)</li><li>[T1569.002: Service Execution](../Triggers/T1569.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Penetration testing</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth, Daniil Yugoslavskiy, oscd.community (update) |
| Other Tags           | <ul><li>car.2013-09-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Malicious Service Installations
id: 5a105d34-05fc-401e-8553-272b45c1522d
description: Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity
author: Florian Roth, Daniil Yugoslavskiy, oscd.community (update)
date: 2017/03/27
modified: 2019/11/01
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1003
    - attack.t1035          # an old one
    - attack.t1050          # an old one
    - car.2013-09-005
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    malsvc_paexec:
        ServiceFileName|contains: '\PAExec'
    malsvc_wannacry:
        ServiceName: 'mssecsvc2.0'
    malsvc_persistence:
        ServiceFileName|contains: 'net user'
    condition: selection and 1 of malsvc_*
falsepositives:
    - Penetration testing
level: critical

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.message -match "ServiceFileName.*.*\\\\PAExec.*" -or $_.message -match "ServiceName.*mssecsvc2.0" -or $_.message -match "ServiceFileName.*.*net user.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND (winlog.event_data.ServiceFileName.keyword:*\\\\PAExec* OR winlog.event_data.ServiceName:"mssecsvc2.0" OR winlog.event_data.ServiceFileName.keyword:*net\\ user*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/5a105d34-05fc-401e-8553-272b45c1522d <<EOF\n{\n  "metadata": {\n    "title": "Malicious Service Installations",\n    "description": "Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1003",\n      "attack.t1035",\n      "attack.t1050",\n      "car.2013-09-005",\n      "attack.t1543.003",\n      "attack.t1569.002"\n    ],\n    "query": "(winlog.event_id:\\"7045\\" AND (winlog.event_data.ServiceFileName.keyword:*\\\\\\\\PAExec* OR winlog.event_data.ServiceName:\\"mssecsvc2.0\\" OR winlog.event_data.ServiceFileName.keyword:*net\\\\ user*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"7045\\" AND (winlog.event_data.ServiceFileName.keyword:*\\\\\\\\PAExec* OR winlog.event_data.ServiceName:\\"mssecsvc2.0\\" OR winlog.event_data.ServiceFileName.keyword:*net\\\\ user*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious Service Installations\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND (ServiceFileName.keyword:*\\\\PAExec* OR ServiceName:"mssecsvc2.0" OR ServiceFileName.keyword:*net user*))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" (ServiceFileName="*\\\\PAExec*" OR ServiceName="mssecsvc2.0" OR ServiceFileName="*net user*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" (ServiceFileName="*\\\\PAExec*" OR service="mssecsvc2.0" OR ServiceFileName="*net user*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*(?:.*.*\\PAExec.*|.*mssecsvc2\\.0|.*.*net user.*))))'
```



