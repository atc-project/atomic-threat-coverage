| Title                    | SAM Dump to AppData       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.002: Security Account Manager](https://attack.mitre.org/techniques/T1003.002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.002: Security Account Manager](../Triggers/T1003.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration testing</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: SAM Dump to AppData
id: 839dd1e8-eda8-4834-8145-01beeee33acd
status: experimental
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.002
author: Florian Roth
date: 2018/01/27
logsource:
    product: windows
    service: system
    definition: The source of this type of event is Kernel-General
detection:
    selection:
        EventID: 16
        Message:
            - '*\AppData\Local\Temp\SAM-*.dmp *'
    condition: selection
falsepositives:
    - Penetration testing
level: high

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "16" -and ($_.message -match ".*\\\\AppData\\\\Local\\\\Temp\\\\SAM-.*.dmp .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"16" AND Message.keyword:(*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/839dd1e8-eda8-4834-8145-01beeee33acd <<EOF\n{\n  "metadata": {\n    "title": "SAM Dump to AppData",\n    "description": "Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.t1003.002"\n    ],\n    "query": "(winlog.event_id:\\"16\\" AND Message.keyword:(*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\SAM\\\\-*.dmp\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"16\\" AND Message.keyword:(*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\SAM\\\\-*.dmp\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'SAM Dump to AppData\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"16" AND Message.keyword:(*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp *))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="16" (Message="*\\\\AppData\\\\Local\\\\Temp\\\\SAM-*.dmp *"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="16" Message IN ["*\\\\AppData\\\\Local\\\\Temp\\\\SAM-*.dmp *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*16)(?=.*(?:.*.*\\AppData\\Local\\Temp\\SAM-.*\\.dmp .*)))'
```



