| Title                    | Application Whitelisting Bypass via Dnx.exe       |
|:-------------------------|:------------------|
| **Description**          | Execute C# code located in the consoleapp folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li><li>[T1027.004: Compile After Delivery](https://attack.mitre.org/techniques/T1027.004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li><li>[T1027.004: Compile After Delivery](../Triggers/T1027.004.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate use of dnx.exe by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml)</li><li>[https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting Bypass via Dnx.exe
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: experimental
description: Execute C# code located in the consoleapp folder
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
    - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2020/08/30
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.t1027.004
    - attack.execution      # an old one
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnx.exe'
    condition: selection
falsepositives:
    - Legitimate use of dnx.exe by legitimate user

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "Image.*.*\\\\dnx.exe" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:*\\\\dnx.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/81ebd28b-9607-4478-bf06-974ed9d53ed7 <<EOF\n{\n  "metadata": {\n    "title": "Application Whitelisting Bypass via Dnx.exe",\n    "description": "Execute C# code located in the consoleapp folder",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1218",\n      "attack.t1027.004",\n      "attack.execution"\n    ],\n    "query": "winlog.event_data.Image.keyword:*\\\\\\\\dnx.exe"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Image.keyword:*\\\\\\\\dnx.exe",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Application Whitelisting Bypass via Dnx.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image.keyword:*\\\\dnx.exe
```


### splunk
    
```
Image="*\\\\dnx.exe"
```


### logpoint
    
```
Image="*\\\\dnx.exe"
```


### grep
    
```
grep -P '^.*\\dnx\\.exe'
```



