| Title                    | Suspicious Service Installed       |
|:-------------------------|:------------------|
| **Description**          | Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)</li></ul>  |
| **Author**               | xknow (@xknow_infosec), xorxes (@xor_xes) |


## Detection Rules

### Sigma rule

```
title: Suspicious Service Installed
id: f2485272-a156-4773-82d7-1d178bc4905b
description: Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)
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
        EventID: 13
        TargetObject:
            - 'HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath'
            - 'HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath'
    selection_2:
        Image|contains:
            - '*\procexp64.exe'
            - '*\procexp.exe'
            - '*\procmon64.exe'
            - '*\procmon.exe'
    selection_3:
        Details|contains:
            - '*\WINDOWS\system32\Drivers\PROCEXP152.SYS'
    condition: selection_1 and not selection_2 and not selection_3
falsepositives:
    - Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.
level: medium

```





### es-qs
    
```
(((EventID:"13" AND TargetObject:("HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NalDrv\\\\ImagePath" OR "HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\PROCEXP152\\\\ImagePath")) AND (NOT (Image.keyword:(*\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*)))) AND (NOT (Details.keyword:(*\\\\WINDOWS\\\\system32\\\\Drivers\\\\PROCEXP152.SYS*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f2485272-a156-4773-82d7-1d178bc4905b <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Service Installed",\n    "description": "Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)",\n    "tags": [\n      "attack.t1089",\n      "attack.defense_evasion"\n    ],\n    "query": "(((EventID:\\"13\\" AND TargetObject:(\\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\NalDrv\\\\\\\\ImagePath\\" OR \\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\PROCEXP152\\\\\\\\ImagePath\\")) AND (NOT (Image.keyword:(*\\\\\\\\procexp64.exe* OR *\\\\\\\\procexp.exe* OR *\\\\\\\\procmon64.exe* OR *\\\\\\\\procmon.exe*)))) AND (NOT (Details.keyword:(*\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\Drivers\\\\\\\\PROCEXP152.SYS*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((EventID:\\"13\\" AND TargetObject:(\\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\NalDrv\\\\\\\\ImagePath\\" OR \\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\PROCEXP152\\\\\\\\ImagePath\\")) AND (NOT (Image.keyword:(*\\\\\\\\procexp64.exe* OR *\\\\\\\\procexp.exe* OR *\\\\\\\\procmon64.exe* OR *\\\\\\\\procmon.exe*)))) AND (NOT (Details.keyword:(*\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\Drivers\\\\\\\\PROCEXP152.SYS*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Service Installed\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((EventID:"13" AND TargetObject:("HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NalDrv\\\\ImagePath" "HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\PROCEXP152\\\\ImagePath")) AND (NOT (Image.keyword:(*\\\\procexp64.exe* *\\\\procexp.exe* *\\\\procmon64.exe* *\\\\procmon.exe*)))) AND (NOT (Details.keyword:(*\\\\WINDOWS\\\\system32\\\\Drivers\\\\PROCEXP152.SYS*))))
```


### splunk
    
```
(((EventID="13" (TargetObject="HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NalDrv\\\\ImagePath" OR TargetObject="HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\PROCEXP152\\\\ImagePath")) NOT ((Image="*\\\\procexp64.exe*" OR Image="*\\\\procexp.exe*" OR Image="*\\\\procmon64.exe*" OR Image="*\\\\procmon.exe*"))) NOT ((Details="*\\\\WINDOWS\\\\system32\\\\Drivers\\\\PROCEXP152.SYS*")))
```


### logpoint
    
```
(((event_id="13" TargetObject IN ["HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NalDrv\\\\ImagePath", "HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\PROCEXP152\\\\ImagePath"])  -(Image IN ["*\\\\procexp64.exe*", "*\\\\procexp.exe*", "*\\\\procmon64.exe*", "*\\\\procmon.exe*"]))  -(Details IN ["*\\\\WINDOWS\\\\system32\\\\Drivers\\\\PROCEXP152.SYS*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*(?=.*13)(?=.*(?:.*HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath|.*HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\procexp64\\.exe.*|.*.*\\procexp\\.exe.*|.*.*\\procmon64\\.exe.*|.*.*\\procmon\\.exe.*)))))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\WINDOWS\\system32\\Drivers\\PROCEXP152\\.SYS.*))))))'
```



