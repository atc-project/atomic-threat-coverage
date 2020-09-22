| Title                    | MSHTA Spwaned by SVCHOST       |
|:-------------------------|:------------------|
| **Description**          | Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.005: Mshta](https://attack.mitre.org/techniques/T1218.005)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.005: Mshta](../Triggers/T1218.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://codewhitesec.blogspot.com/2018/07/lethalhta.html](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: MSHTA Spwaned by SVCHOST
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: experimental
description: Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
tags:
    - attack.defense_evasion
    - attack.t1218.005
    - attack.execution  # an old one
    - attack.t1170  # an old one
author: Markus Neis
date: 2018/06/07
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\svchost.exe'
        Image: '*\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\\\svchost.exe" -and $_.message -match "Image.*.*\\\\mshta.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\mshta.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/ed5d72a6-f8f4-479d-ba79-02f6a80d7471 <<EOF\n{\n  "metadata": {\n    "title": "MSHTA Spwaned by SVCHOST",\n    "description": "Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1218.005",\n      "attack.execution",\n      "attack.t1170"\n    ],\n    "query": "(winlog.event_data.ParentImage.keyword:*\\\\\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\\\\\mshta.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\\\\\mshta.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'MSHTA Spwaned by SVCHOST\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage.keyword:*\\\\svchost.exe AND Image.keyword:*\\\\mshta.exe)
```


### splunk
    
```
(ParentImage="*\\\\svchost.exe" Image="*\\\\mshta.exe")
```


### logpoint
    
```
(ParentImage="*\\\\svchost.exe" Image="*\\\\mshta.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\svchost\\.exe)(?=.*.*\\mshta\\.exe))'
```



