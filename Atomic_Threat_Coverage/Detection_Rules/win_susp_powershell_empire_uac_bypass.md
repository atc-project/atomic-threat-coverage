| Title                    | Empire PowerShell UAC Bypass       |
|:-------------------------|:------------------|
| **Description**          | Detects some Empire PowerShell UAC bypass methods |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64)</li><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64)</li></ul>  |
| **Author**               | Ecco |
| Other Tags           | <ul><li>car.2019-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Empire PowerShell UAC Bypass
id: 3268b746-88d8-4cd3-bffc-30077d02c787
status: experimental
description: Detects some Empire PowerShell UAC bypass methods
references:
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64
author: Ecco
date: 2019/08/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)*'
            - '* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
    - car.2019-04-001
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\\\Microsoft\\\\Windows Update).Update).*" -or $_.message -match "CommandLine.*.* -NoP -NonI -c $x=$((gp HKCU:Software\\\\Microsoft\\\\Windows Update).Update);.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\ \\-NoP\\ \\-NonI\\ \\-w\\ Hidden\\ \\-c\\ $x\\=$\\(\\(gp\\ HKCU\\:Software\\\\Microsoft\\\\Windows\\ Update\\).Update\\)* OR *\\ \\-NoP\\ \\-NonI\\ \\-c\\ $x\\=$\\(\\(gp\\ HKCU\\:Software\\\\Microsoft\\\\Windows\\ Update\\).Update\\);*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/3268b746-88d8-4cd3-bffc-30077d02c787 <<EOF\n{\n  "metadata": {\n    "title": "Empire PowerShell UAC Bypass",\n    "description": "Detects some Empire PowerShell UAC bypass methods",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.privilege_escalation",\n      "attack.t1088",\n      "car.2019-04-001"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-NoP\\\\ \\\\-NonI\\\\ \\\\-w\\\\ Hidden\\\\ \\\\-c\\\\ $x\\\\=$\\\\(\\\\(gp\\\\ HKCU\\\\:Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ Update\\\\).Update\\\\)* OR *\\\\ \\\\-NoP\\\\ \\\\-NonI\\\\ \\\\-c\\\\ $x\\\\=$\\\\(\\\\(gp\\\\ HKCU\\\\:Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ Update\\\\).Update\\\\);*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-NoP\\\\ \\\\-NonI\\\\ \\\\-w\\\\ Hidden\\\\ \\\\-c\\\\ $x\\\\=$\\\\(\\\\(gp\\\\ HKCU\\\\:Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ Update\\\\).Update\\\\)* OR *\\\\ \\\\-NoP\\\\ \\\\-NonI\\\\ \\\\-c\\\\ $x\\\\=$\\\\(\\\\(gp\\\\ HKCU\\\\:Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ Update\\\\).Update\\\\);*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Empire PowerShell UAC Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(* \\-NoP \\-NonI \\-w Hidden \\-c $x=$\\(\\(gp HKCU\\:Software\\\\Microsoft\\\\Windows Update\\).Update\\)* * \\-NoP \\-NonI \\-c $x=$\\(\\(gp HKCU\\:Software\\\\Microsoft\\\\Windows Update\\).Update\\);*)
```


### splunk
    
```
(CommandLine="* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\\\Microsoft\\\\Windows Update).Update)*" OR CommandLine="* -NoP -NonI -c $x=$((gp HKCU:Software\\\\Microsoft\\\\Windows Update).Update);*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\\\Microsoft\\\\Windows Update).Update)*", "* -NoP -NonI -c $x=$((gp HKCU:Software\\\\Microsoft\\\\Windows Update).Update);*"]
```


### grep
    
```
grep -P '^(?:.*.* -NoP -NonI -w Hidden -c \\$x=\\$\\(\\(gp HKCU:Software\\\\Microsoft\\\\Windows Update\\)\\.Update\\).*|.*.* -NoP -NonI -c \\$x=\\$\\(\\(gp HKCU:Software\\\\Microsoft\\\\Windows Update\\)\\.Update\\);.*)'
```



