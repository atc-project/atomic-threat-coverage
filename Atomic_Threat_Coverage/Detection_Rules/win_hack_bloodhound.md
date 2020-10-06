| Title                    | Bloodhound and Sharphound Hack Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects command line parameters used by Bloodhound and Sharphound hack tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087.001: Local Account](https://attack.mitre.org/techniques/T1087/001)</li><li>[T1087.002: Domain Account](https://attack.mitre.org/techniques/T1087/002)</li><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)</li><li>[T1069.001: Local Groups](https://attack.mitre.org/techniques/T1069/001)</li><li>[T1069.002: Domain Groups](https://attack.mitre.org/techniques/T1069/002)</li><li>[T1069: Permission Groups Discovery](https://attack.mitre.org/techniques/T1069)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1087.001: Local Account](../Triggers/T1087.001.md)</li><li>[T1087.002: Domain Account](../Triggers/T1087.002.md)</li><li>[T1482: Domain Trust Discovery](../Triggers/T1482.md)</li><li>[T1069.001: Local Groups](../Triggers/T1069.001.md)</li><li>[T1069.002: Domain Groups](../Triggers/T1069.002.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other programs that use these command line option and accepts an 'All' parameter</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)</li><li>[https://github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Bloodhound and Sharphound Hack Tool
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
author: Florian Roth
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
date: 2019/12/20
modified: 2019/12/21
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1087  # an old one
    - attack.t1482
    - attack.t1069.001
    - attack.t1069.002
    - attack.t1069  # an old one
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        Image|contains: 
            - '\Bloodhound.exe'
            - '\SharpHound.exe'
    selection2:
        CommandLine|contains: 
            - ' -CollectionMethod All '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection3:
        CommandLine|contains|all: 
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection4:
        CommandLine|contains|all: 
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of them
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high


```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\Bloodhound.exe.*" -or $_.message -match "Image.*.*\\\\SharpHound.exe.*") -or ($_.message -match "CommandLine.*.* -CollectionMethod All .*" -or $_.message -match "CommandLine.*.*.exe -c All -d .*" -or $_.message -match "CommandLine.*.*Invoke-Bloodhound.*" -or $_.message -match "CommandLine.*.*Get-BloodHoundData.*") -or ($_.message -match "CommandLine.*.* -JsonFolder .*" -and $_.message -match "CommandLine.*.* -ZipFileName .*") -or ($_.message -match "CommandLine.*.* DCOnly .*" -and $_.message -match "CommandLine.*.* --NoSaveCache .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\Bloodhound.exe* OR *\\\\SharpHound.exe*) OR winlog.event_data.CommandLine.keyword:(*\\ \\-CollectionMethod\\ All\\ * OR *.exe\\ \\-c\\ All\\ \\-d\\ * OR *Invoke\\-Bloodhound* OR *Get\\-BloodHoundData*) OR (winlog.event_data.CommandLine.keyword:*\\ \\-JsonFolder\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-ZipFileName\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ DCOnly\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-\\-NoSaveCache\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f376c8a7-a2d0-4ddc-aa0c-16c17236d962 <<EOF\n{\n  "metadata": {\n    "title": "Bloodhound and Sharphound Hack Tool",\n    "description": "Detects command line parameters used by Bloodhound and Sharphound hack tools",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087.001",\n      "attack.t1087.002",\n      "attack.t1087",\n      "attack.t1482",\n      "attack.t1069.001",\n      "attack.t1069.002",\n      "attack.t1069",\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\Bloodhound.exe* OR *\\\\\\\\SharpHound.exe*) OR winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-CollectionMethod\\\\ All\\\\ * OR *.exe\\\\ \\\\-c\\\\ All\\\\ \\\\-d\\\\ * OR *Invoke\\\\-Bloodhound* OR *Get\\\\-BloodHoundData*) OR (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-JsonFolder\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-ZipFileName\\\\ *) OR (winlog.event_data.CommandLine.keyword:*\\\\ DCOnly\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-\\\\-NoSaveCache\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\Bloodhound.exe* OR *\\\\\\\\SharpHound.exe*) OR winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-CollectionMethod\\\\ All\\\\ * OR *.exe\\\\ \\\\-c\\\\ All\\\\ \\\\-d\\\\ * OR *Invoke\\\\-Bloodhound* OR *Get\\\\-BloodHoundData*) OR (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-JsonFolder\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-ZipFileName\\\\ *) OR (winlog.event_data.CommandLine.keyword:*\\\\ DCOnly\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-\\\\-NoSaveCache\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Bloodhound and Sharphound Hack Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\Bloodhound.exe* *\\\\SharpHound.exe*) OR CommandLine.keyword:(* \\-CollectionMethod All * *.exe \\-c All \\-d * *Invoke\\-Bloodhound* *Get\\-BloodHoundData*) OR (CommandLine.keyword:* \\-JsonFolder * AND CommandLine.keyword:* \\-ZipFileName *) OR (CommandLine.keyword:* DCOnly * AND CommandLine.keyword:* \\-\\-NoSaveCache *))
```


### splunk
    
```
((Image="*\\\\Bloodhound.exe*" OR Image="*\\\\SharpHound.exe*") OR (CommandLine="* -CollectionMethod All *" OR CommandLine="*.exe -c All -d *" OR CommandLine="*Invoke-Bloodhound*" OR CommandLine="*Get-BloodHoundData*") OR (CommandLine="* -JsonFolder *" CommandLine="* -ZipFileName *") OR (CommandLine="* DCOnly *" CommandLine="* --NoSaveCache *"))
```


### logpoint
    
```
(Image IN ["*\\\\Bloodhound.exe*", "*\\\\SharpHound.exe*"] OR CommandLine IN ["* -CollectionMethod All *", "*.exe -c All -d *", "*Invoke-Bloodhound*", "*Get-BloodHoundData*"] OR (CommandLine="* -JsonFolder *" CommandLine="* -ZipFileName *") OR (CommandLine="* DCOnly *" CommandLine="* --NoSaveCache *"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*\\Bloodhound\\.exe.*|.*.*\\SharpHound\\.exe.*)|.*(?:.*.* -CollectionMethod All .*|.*.*\\.exe -c All -d .*|.*.*Invoke-Bloodhound.*|.*.*Get-BloodHoundData.*)|.*(?:.*(?=.*.* -JsonFolder .*)(?=.*.* -ZipFileName .*))|.*(?:.*(?=.*.* DCOnly .*)(?=.*.* --NoSaveCache .*))))'
```



