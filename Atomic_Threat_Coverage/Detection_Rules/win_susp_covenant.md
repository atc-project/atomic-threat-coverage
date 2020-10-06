| Title                    | Covenant Launcher Indicators       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious command lines used in Covenant luanchers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1564.003: Hidden Window](https://attack.mitre.org/techniques/T1564/003)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1564.003: Hidden Window](../Triggers/T1564.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/covenant-v0-5-eee0507b85ba](https://posts.specterops.io/covenant-v0-5-eee0507b85ba)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Covenant Launcher Indicators
id: c260b6db-48ba-4b4a-a76f-2f67644e99d2
description: Detects suspicious command lines used in Covenant luanchers
status: experimental
references:
    - https://posts.specterops.io/covenant-v0-5-eee0507b85ba
author: Florian Roth
date: 2020/06/04
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    - attack.t1564.003
    - attack.t1086        # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -Sta -Nop -Window Hidden -Command '
            - ' -Sta -Nop -Window Hidden -EncodedCommand '
            - 'sv o (New-Object IO.MemorySteam);sv d '
            - 'mshta file.hta'
            - 'GruntHTTP'
            - '-EncodedCommand cwB2ACAAbwAgA'
    condition: selection
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* -Sta -Nop -Window Hidden -Command .*" -or $_.message -match "CommandLine.*.* -Sta -Nop -Window Hidden -EncodedCommand .*" -or $_.message -match "CommandLine.*.*sv o (New-Object IO.MemorySteam);sv d .*" -or $_.message -match "CommandLine.*.*mshta file.hta.*" -or $_.message -match "CommandLine.*.*GruntHTTP.*" -or $_.message -match "CommandLine.*.*-EncodedCommand cwB2ACAAbwAgA.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\ \\-Sta\\ \\-Nop\\ \\-Window\\ Hidden\\ \\-Command\\ * OR *\\ \\-Sta\\ \\-Nop\\ \\-Window\\ Hidden\\ \\-EncodedCommand\\ * OR *sv\\ o\\ \\(New\\-Object\\ IO.MemorySteam\\);sv\\ d\\ * OR *mshta\\ file.hta* OR *GruntHTTP* OR *\\-EncodedCommand\\ cwB2ACAAbwAgA*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c260b6db-48ba-4b4a-a76f-2f67644e99d2 <<EOF\n{\n  "metadata": {\n    "title": "Covenant Launcher Indicators",\n    "description": "Detects suspicious command lines used in Covenant luanchers",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1059.001",\n      "attack.t1564.003",\n      "attack.t1086"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-Sta\\\\ \\\\-Nop\\\\ \\\\-Window\\\\ Hidden\\\\ \\\\-Command\\\\ * OR *\\\\ \\\\-Sta\\\\ \\\\-Nop\\\\ \\\\-Window\\\\ Hidden\\\\ \\\\-EncodedCommand\\\\ * OR *sv\\\\ o\\\\ \\\\(New\\\\-Object\\\\ IO.MemorySteam\\\\);sv\\\\ d\\\\ * OR *mshta\\\\ file.hta* OR *GruntHTTP* OR *\\\\-EncodedCommand\\\\ cwB2ACAAbwAgA*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-Sta\\\\ \\\\-Nop\\\\ \\\\-Window\\\\ Hidden\\\\ \\\\-Command\\\\ * OR *\\\\ \\\\-Sta\\\\ \\\\-Nop\\\\ \\\\-Window\\\\ Hidden\\\\ \\\\-EncodedCommand\\\\ * OR *sv\\\\ o\\\\ \\\\(New\\\\-Object\\\\ IO.MemorySteam\\\\);sv\\\\ d\\\\ * OR *mshta\\\\ file.hta* OR *GruntHTTP* OR *\\\\-EncodedCommand\\\\ cwB2ACAAbwAgA*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Covenant Launcher Indicators\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(* \\-Sta \\-Nop \\-Window Hidden \\-Command * * \\-Sta \\-Nop \\-Window Hidden \\-EncodedCommand * *sv o \\(New\\-Object IO.MemorySteam\\);sv d * *mshta file.hta* *GruntHTTP* *\\-EncodedCommand cwB2ACAAbwAgA*)
```


### splunk
    
```
(CommandLine="* -Sta -Nop -Window Hidden -Command *" OR CommandLine="* -Sta -Nop -Window Hidden -EncodedCommand *" OR CommandLine="*sv o (New-Object IO.MemorySteam);sv d *" OR CommandLine="*mshta file.hta*" OR CommandLine="*GruntHTTP*" OR CommandLine="*-EncodedCommand cwB2ACAAbwAgA*")
```


### logpoint
    
```
CommandLine IN ["* -Sta -Nop -Window Hidden -Command *", "* -Sta -Nop -Window Hidden -EncodedCommand *", "*sv o (New-Object IO.MemorySteam);sv d *", "*mshta file.hta*", "*GruntHTTP*", "*-EncodedCommand cwB2ACAAbwAgA*"]
```


### grep
    
```
grep -P '^(?:.*.* -Sta -Nop -Window Hidden -Command .*|.*.* -Sta -Nop -Window Hidden -EncodedCommand .*|.*.*sv o \\(New-Object IO\\.MemorySteam\\);sv d .*|.*.*mshta file\\.hta.*|.*.*GruntHTTP.*|.*.*-EncodedCommand cwB2ACAAbwAgA.*)'
```



