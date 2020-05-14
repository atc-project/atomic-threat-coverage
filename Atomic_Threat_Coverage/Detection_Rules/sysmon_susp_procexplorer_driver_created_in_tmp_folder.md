| Title                    | Suspicious PROCEXP152.sys File Created In TMP       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)</li></ul>  |
| **Author**               | xknow (@xknow_infosec), xorxes (@xor_xes) |


## Detection Rules

### Sigma rule

```
title: Suspicious PROCEXP152.sys File Created In TMP
id: 3da70954-0f2c-4103-adff-b7440368f50e
description: Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.
status: experimental
date: 2019/04/08
author: xknow (@xknow_infosec), xorxes (@xor_xes)
references:
    - https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
tags:
    - attack.t1089
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 11
        TargetFilename: '*\AppData\Local\Temp\*\PROCEXP152.sys'
    selection_2:
        Image|contains:
            - '*\procexp64.exe'
            - '*\procexp.exe'
            - '*\procmon64.exe'
            - '*\procmon.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.
level: medium

```





### es-qs
    
```
((EventID:"11" AND TargetFilename.keyword:*\\\\AppData\\\\Local\\\\Temp\\*\\\\PROCEXP152.sys) AND (NOT (Image.keyword:(*\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/3da70954-0f2c-4103-adff-b7440368f50e <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PROCEXP152.sys File Created In TMP",\n    "description": "Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.",\n    "tags": [\n      "attack.t1089",\n      "attack.defense_evasion"\n    ],\n    "query": "((EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\*\\\\\\\\PROCEXP152.sys) AND (NOT (Image.keyword:(*\\\\\\\\procexp64.exe* OR *\\\\\\\\procexp.exe* OR *\\\\\\\\procmon64.exe* OR *\\\\\\\\procmon.exe*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\*\\\\\\\\PROCEXP152.sys) AND (NOT (Image.keyword:(*\\\\\\\\procexp64.exe* OR *\\\\\\\\procexp.exe* OR *\\\\\\\\procmon64.exe* OR *\\\\\\\\procmon.exe*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PROCEXP152.sys File Created In TMP\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"11" AND TargetFilename.keyword:*\\\\AppData\\\\Local\\\\Temp\\*\\\\PROCEXP152.sys) AND (NOT (Image.keyword:(*\\\\procexp64.exe* *\\\\procexp.exe* *\\\\procmon64.exe* *\\\\procmon.exe*))))
```


### splunk
    
```
((EventID="11" TargetFilename="*\\\\AppData\\\\Local\\\\Temp\\*\\\\PROCEXP152.sys") NOT ((Image="*\\\\procexp64.exe*" OR Image="*\\\\procexp.exe*" OR Image="*\\\\procmon64.exe*" OR Image="*\\\\procmon.exe*")))
```


### logpoint
    
```
((event_id="11" TargetFilename="*\\\\AppData\\\\Local\\\\Temp\\*\\\\PROCEXP152.sys")  -(Image IN ["*\\\\procexp64.exe*", "*\\\\procexp.exe*", "*\\\\procmon64.exe*", "*\\\\procmon.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*11)(?=.*.*\\AppData\\Local\\Temp\\.*\\PROCEXP152\\.sys)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\procexp64\\.exe.*|.*.*\\procexp\\.exe.*|.*.*\\procmon64\\.exe.*|.*.*\\procmon\\.exe.*))))))'
```



