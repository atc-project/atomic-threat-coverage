| Title                    | Login with WMI       |
|:-------------------------|:------------------|
| **Description**          | Detection of logins performed with WMI |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Monitoring tools</li><li>Legitimate system administration</li></ul>  |
| **Development Status**   | stable |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Login with WMI
id: 5af54681-df95-4c26-854f-2565e13cfab0
status: stable
description: Detection of logins performed with WMI
author: Thomas Patzke
date: 2019/12/04
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ProcessName: "*\\WmiPrvSE.exe"
    condition: selection
falsepositives:
    - Monitoring tools
    - Legitimate system administration
level: low

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "ProcessName.*.*\\\\WmiPrvSE.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4624" AND winlog.event_data.ProcessName.keyword:*\\\\WmiPrvSE.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/5af54681-df95-4c26-854f-2565e13cfab0 <<EOF\n{\n  "metadata": {\n    "title": "Login with WMI",\n    "description": "Detection of logins performed with WMI",\n    "tags": [\n      "attack.execution",\n      "attack.t1047"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4624\\" AND winlog.event_data.ProcessName.keyword:*\\\\\\\\WmiPrvSE.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4624\\" AND winlog.event_data.ProcessName.keyword:*\\\\\\\\WmiPrvSE.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Login with WMI\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4624" AND ProcessName.keyword:*\\\\WmiPrvSE.exe)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4624" ProcessName="*\\\\WmiPrvSE.exe")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4624" ProcessName="*\\\\WmiPrvSE.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*.*\\WmiPrvSE\\.exe))'
```



