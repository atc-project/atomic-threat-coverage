| Title                    | QuarksPwDump Clearing Access History       |
|:-------------------------|:------------------|
| **Description**          | Detects QuarksPwDump clearing access history in hive |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.002: Security Account Manager](https://attack.mitre.org/techniques/T1003/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.002: Security Account Manager](../Triggers/T1003.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: QuarksPwDump Clearing Access History
id: 39f919f3-980b-4e6f-a975-8af7e507ef2b
status: experimental
description: Detects QuarksPwDump clearing access history in hive
author: Florian Roth
date: 2017/05/15
modified: 2019/11/13
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.002
level: critical
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 16
        HiveName|contains: '\AppData\Local\Temp\SAM'
        HiveName|endswith: '.dmp'
    condition: selection
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "16" -and $_.message -match "HiveName.*.*\\\\AppData\\\\Local\\\\Temp\\\\SAM.*" -and $_.message -match "HiveName.*.*.dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"16" AND winlog.event_data.HiveName.keyword:*\\\\AppData\\\\Local\\\\Temp\\\\SAM* AND winlog.event_data.HiveName.keyword:*.dmp)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/39f919f3-980b-4e6f-a975-8af7e507ef2b <<EOF\n{\n  "metadata": {\n    "title": "QuarksPwDump Clearing Access History",\n    "description": "Detects QuarksPwDump clearing access history in hive",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.t1003.002"\n    ],\n    "query": "(winlog.event_id:\\"16\\" AND winlog.event_data.HiveName.keyword:*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\SAM* AND winlog.event_data.HiveName.keyword:*.dmp)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"16\\" AND winlog.event_data.HiveName.keyword:*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\SAM* AND winlog.event_data.HiveName.keyword:*.dmp)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'QuarksPwDump Clearing Access History\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"16" AND HiveName.keyword:*\\\\AppData\\\\Local\\\\Temp\\\\SAM* AND HiveName.keyword:*.dmp)
```


### splunk
    
```
(source="WinEventLog:System" EventCode="16" HiveName="*\\\\AppData\\\\Local\\\\Temp\\\\SAM*" HiveName="*.dmp")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="16" HiveName="*\\\\AppData\\\\Local\\\\Temp\\\\SAM*" HiveName="*.dmp")
```


### grep
    
```
grep -P '^(?:.*(?=.*16)(?=.*.*\\AppData\\Local\\Temp\\SAM.*)(?=.*.*\\.dmp))'
```



