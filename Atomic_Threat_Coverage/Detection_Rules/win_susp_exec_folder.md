| Title                    | Executables Started in Suspicious Folder       |
|:-------------------------|:------------------|
| **Description**          | Detects process starts of binaries from a suspicious folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt](https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt)</li><li>[https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses](https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses)</li><li>[https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/](https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/)</li><li>[https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/suspicious_process_creation_via_windows_event_logs.md](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/suspicious_process_creation_via_windows_event_logs.md)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Executables Started in Suspicious Folder
id: 7a38aa19-86a9-4af7-ac51-6bfe4e59f254
status: experimental
description: Detects process starts of binaries from a suspicious folder
author: Florian Roth
date: 2017/10/14
modified: 2019/02/21
references:
    - https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt
    - https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
    - https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/suspicious_process_creation_via_windows_event_logs.md
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - C:\PerfLogs\\*
            - C:\$Recycle.bin\\*
            - C:\Intel\Logs\\*
            - C:\Users\Default\\*
            - C:\Users\Public\\*
            - C:\Users\NetworkService\\*
            - C:\Windows\Fonts\\*
            - C:\Windows\Debug\\*
            - C:\Windows\Media\\*
            - C:\Windows\Help\\*
            - C:\Windows\addins\\*
            - C:\Windows\repair\\*
            - C:\Windows\security\\*
            - '*\RSA\MachineKeys\\*'
            - C:\Windows\system32\config\systemprofile\\*
            - C:\Windows\Tasks\\*
            - C:\Windows\System32\Tasks\\*
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*C:\\\\PerfLogs\\\\.*" -or $_.message -match "Image.*C:\\\\$Recycle.bin\\\\.*" -or $_.message -match "Image.*C:\\\\Intel\\\\Logs\\\\.*" -or $_.message -match "Image.*C:\\\\Users\\\\Default\\\\.*" -or $_.message -match "Image.*C:\\\\Users\\\\Public\\\\.*" -or $_.message -match "Image.*C:\\\\Users\\\\NetworkService\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\Fonts\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\Debug\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\Media\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\Help\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\addins\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\repair\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\security\\\\.*" -or $_.message -match "Image.*.*\\\\RSA\\\\MachineKeys\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\Tasks\\\\.*" -or $_.message -match "Image.*C:\\\\Windows\\\\System32\\\\Tasks\\\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(C\\:\\\\PerfLogs\\\\* OR C\\:\\\\$Recycle.bin\\\\* OR C\\:\\\\Intel\\\\Logs\\\\* OR C\\:\\\\Users\\\\Default\\\\* OR C\\:\\\\Users\\\\Public\\\\* OR C\\:\\\\Users\\\\NetworkService\\\\* OR C\\:\\\\Windows\\\\Fonts\\\\* OR C\\:\\\\Windows\\\\Debug\\\\* OR C\\:\\\\Windows\\\\Media\\\\* OR C\\:\\\\Windows\\\\Help\\\\* OR C\\:\\\\Windows\\\\addins\\\\* OR C\\:\\\\Windows\\\\repair\\\\* OR C\\:\\\\Windows\\\\security\\\\* OR *\\\\RSA\\\\MachineKeys\\\\* OR C\\:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\\\* OR C\\:\\\\Windows\\\\Tasks\\\\* OR C\\:\\\\Windows\\\\System32\\\\Tasks\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7a38aa19-86a9-4af7-ac51-6bfe4e59f254 <<EOF\n{\n  "metadata": {\n    "title": "Executables Started in Suspicious Folder",\n    "description": "Detects process starts of binaries from a suspicious folder",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "winlog.event_data.Image.keyword:(C\\\\:\\\\\\\\PerfLogs\\\\\\\\* OR C\\\\:\\\\\\\\$Recycle.bin\\\\\\\\* OR C\\\\:\\\\\\\\Intel\\\\\\\\Logs\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\NetworkService\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Debug\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Media\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Help\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\repair\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\security\\\\\\\\* OR *\\\\\\\\RSA\\\\\\\\MachineKeys\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Tasks\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\Tasks\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Image.keyword:(C\\\\:\\\\\\\\PerfLogs\\\\\\\\* OR C\\\\:\\\\\\\\$Recycle.bin\\\\\\\\* OR C\\\\:\\\\\\\\Intel\\\\\\\\Logs\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\NetworkService\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Debug\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Media\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Help\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\repair\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\security\\\\\\\\* OR *\\\\\\\\RSA\\\\\\\\MachineKeys\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\Tasks\\\\\\\\* OR C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\Tasks\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Executables Started in Suspicious Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image.keyword:(C\\:\\\\PerfLogs\\\\* C\\:\\\\$Recycle.bin\\\\* C\\:\\\\Intel\\\\Logs\\\\* C\\:\\\\Users\\\\Default\\\\* C\\:\\\\Users\\\\Public\\\\* C\\:\\\\Users\\\\NetworkService\\\\* C\\:\\\\Windows\\\\Fonts\\\\* C\\:\\\\Windows\\\\Debug\\\\* C\\:\\\\Windows\\\\Media\\\\* C\\:\\\\Windows\\\\Help\\\\* C\\:\\\\Windows\\\\addins\\\\* C\\:\\\\Windows\\\\repair\\\\* C\\:\\\\Windows\\\\security\\\\* *\\\\RSA\\\\MachineKeys\\\\* C\\:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\\\* C\\:\\\\Windows\\\\Tasks\\\\* C\\:\\\\Windows\\\\System32\\\\Tasks\\\\*)
```


### splunk
    
```
(Image="C:\\\\PerfLogs\\\\*" OR Image="C:\\\\$Recycle.bin\\\\*" OR Image="C:\\\\Intel\\\\Logs\\\\*" OR Image="C:\\\\Users\\\\Default\\\\*" OR Image="C:\\\\Users\\\\Public\\\\*" OR Image="C:\\\\Users\\\\NetworkService\\\\*" OR Image="C:\\\\Windows\\\\Fonts\\\\*" OR Image="C:\\\\Windows\\\\Debug\\\\*" OR Image="C:\\\\Windows\\\\Media\\\\*" OR Image="C:\\\\Windows\\\\Help\\\\*" OR Image="C:\\\\Windows\\\\addins\\\\*" OR Image="C:\\\\Windows\\\\repair\\\\*" OR Image="C:\\\\Windows\\\\security\\\\*" OR Image="*\\\\RSA\\\\MachineKeys\\\\*" OR Image="C:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\\\*" OR Image="C:\\\\Windows\\\\Tasks\\\\*" OR Image="C:\\\\Windows\\\\System32\\\\Tasks\\\\*")
```


### logpoint
    
```
Image IN ["C:\\\\PerfLogs\\\\*", "C:\\\\$Recycle.bin\\\\*", "C:\\\\Intel\\\\Logs\\\\*", "C:\\\\Users\\\\Default\\\\*", "C:\\\\Users\\\\Public\\\\*", "C:\\\\Users\\\\NetworkService\\\\*", "C:\\\\Windows\\\\Fonts\\\\*", "C:\\\\Windows\\\\Debug\\\\*", "C:\\\\Windows\\\\Media\\\\*", "C:\\\\Windows\\\\Help\\\\*", "C:\\\\Windows\\\\addins\\\\*", "C:\\\\Windows\\\\repair\\\\*", "C:\\\\Windows\\\\security\\\\*", "*\\\\RSA\\\\MachineKeys\\\\*", "C:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\\\*", "C:\\\\Windows\\\\Tasks\\\\*", "C:\\\\Windows\\\\System32\\\\Tasks\\\\*"]
```


### grep
    
```
grep -P '^(?:.*C:\\PerfLogs\\\\.*|.*C:\\\\$Recycle\\.bin\\\\.*|.*C:\\Intel\\Logs\\\\.*|.*C:\\Users\\Default\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\NetworkService\\\\.*|.*C:\\Windows\\Fonts\\\\.*|.*C:\\Windows\\Debug\\\\.*|.*C:\\Windows\\Media\\\\.*|.*C:\\Windows\\Help\\\\.*|.*C:\\Windows\\addins\\\\.*|.*C:\\Windows\\repair\\\\.*|.*C:\\Windows\\security\\\\.*|.*.*\\RSA\\MachineKeys\\\\.*|.*C:\\Windows\\system32\\config\\systemprofile\\\\.*|.*C:\\Windows\\Tasks\\\\.*|.*C:\\Windows\\System32\\Tasks\\\\.*)'
```



