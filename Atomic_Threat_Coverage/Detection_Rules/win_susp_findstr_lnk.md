| Title                    | Findstr Launching .lnk File       |
|:-------------------------|:------------------|
| **Description**          | Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li><li>[T1027.003: Steganography](https://attack.mitre.org/techniques/T1027.003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/](https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/)</li></ul>  |
| **Author**               | Trent Liffick |


## Detection Rules

### Sigma rule

```
title: Findstr Launching .lnk File
id: 33339be3-148b-4e16-af56-ad16ec6c7e7b
description: Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack
status: experimental
references:
    - https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.t1202
    - attack.t1027.003
author: Trent Liffick
date: 2020/05/01
modified: 2020/08/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\findstr.exe'
        CommandLine: '*.lnk'
    condition: selection
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\findstr.exe" -and $_.message -match "CommandLine.*.*.lnk") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\findstr.exe AND winlog.event_data.CommandLine.keyword:*.lnk)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/33339be3-148b-4e16-af56-ad16ec6c7e7b <<EOF\n{\n  "metadata": {\n    "title": "Findstr Launching .lnk File",\n    "description": "Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036",\n      "attack.t1202",\n      "attack.t1027.003"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\findstr.exe AND winlog.event_data.CommandLine.keyword:*.lnk)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\findstr.exe AND winlog.event_data.CommandLine.keyword:*.lnk)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Findstr Launching .lnk File\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\findstr.exe AND CommandLine.keyword:*.lnk)
```


### splunk
    
```
(Image="*\\\\findstr.exe" CommandLine="*.lnk") | table Image,CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\\\findstr.exe" CommandLine="*.lnk")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\findstr\\.exe)(?=.*.*\\.lnk))'
```



