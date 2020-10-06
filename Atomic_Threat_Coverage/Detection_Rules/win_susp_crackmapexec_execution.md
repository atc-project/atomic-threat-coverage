| Title                    | CrackMapExec Command Execution       |
|:-------------------------|:------------------|
| **Description**          | Detect various execution methods of the CrackMapExec pentesting framework |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0106</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CrackMapExec Command Execution
id: 058f4380-962d-40a5-afce-50207d36d7e2
status: experimental
description: Detect various execution methods of the CrackMapExec pentesting framework
references:
    - https://github.com/byt3bl33d3r/CrackMapExec
tags:
    - attack.execution
    - attack.t1047
    - attack.t1053
    - attack.t1059.003  
    - attack.t1059.001
    - attack.s0106
    - attack.t1086      # an old one
author: Thomas Patzke
date: 2020/05/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            # cme/protocols/smb/wmiexec.py (generalized execute_remote and execute_fileless)
            - '*cmd.exe /Q /c * 1> \\\\*\\*\\* 2>&1'
            # cme/protocols/smb/atexec.py:109 (fileless output via share)
            - '*cmd.exe /C * > \\\\*\\*\\* 2>&1'
            # cme/protocols/smb/atexec.py:111 (fileless output via share)
            - '*cmd.exe /C * > *\\Temp\\* 2>&1'
            # cme/helpers/powershell.py:139 (PowerShell execution with obfuscation)
            - '*powershell.exe -exec bypass -noni -nop -w 1 -C "*'
            # cme/helpers/powershell.py:149 (PowerShell execution without obfuscation)
            - '*powershell.exe -noni -nop -w 1 -enc *'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*cmd.exe /Q /c .* 1> \\\\\\\\.*\\\\.*\\\\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > \\\\\\\\.*\\\\.*\\\\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > .*\\\\Temp\\\\.* 2>&1" -or $_.message -match "CommandLine.*.*powershell.exe -exec bypass -noni -nop -w 1 -C \\".*" -or $_.message -match "CommandLine.*.*powershell.exe -noni -nop -w 1 -enc .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*cmd.exe\\ \\/Q\\ \\/c\\ *\\ 1>\\ \\\\\\\\*\\\\*\\\\*\\ 2>&1 OR *cmd.exe\\ \\/C\\ *\\ >\\ \\\\\\\\*\\\\*\\\\*\\ 2>&1 OR *cmd.exe\\ \\/C\\ *\\ >\\ *\\\\Temp\\\\*\\ 2>&1 OR *powershell.exe\\ \\-exec\\ bypass\\ \\-noni\\ \\-nop\\ \\-w\\ 1\\ \\-C\\ \\"* OR *powershell.exe\\ \\-noni\\ \\-nop\\ \\-w\\ 1\\ \\-enc\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/058f4380-962d-40a5-afce-50207d36d7e2 <<EOF\n{\n  "metadata": {\n    "title": "CrackMapExec Command Execution",\n    "description": "Detect various execution methods of the CrackMapExec pentesting framework",\n    "tags": [\n      "attack.execution",\n      "attack.t1047",\n      "attack.t1053",\n      "attack.t1059.003",\n      "attack.t1059.001",\n      "attack.s0106",\n      "attack.t1086"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*cmd.exe\\\\ \\\\/Q\\\\ \\\\/c\\\\ *\\\\ 1>\\\\ \\\\\\\\\\\\\\\\*\\\\\\\\*\\\\\\\\*\\\\ 2>&1 OR *cmd.exe\\\\ \\\\/C\\\\ *\\\\ >\\\\ \\\\\\\\\\\\\\\\*\\\\\\\\*\\\\\\\\*\\\\ 2>&1 OR *cmd.exe\\\\ \\\\/C\\\\ *\\\\ >\\\\ *\\\\\\\\Temp\\\\\\\\*\\\\ 2>&1 OR *powershell.exe\\\\ \\\\-exec\\\\ bypass\\\\ \\\\-noni\\\\ \\\\-nop\\\\ \\\\-w\\\\ 1\\\\ \\\\-C\\\\ \\\\\\"* OR *powershell.exe\\\\ \\\\-noni\\\\ \\\\-nop\\\\ \\\\-w\\\\ 1\\\\ \\\\-enc\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*cmd.exe\\\\ \\\\/Q\\\\ \\\\/c\\\\ *\\\\ 1>\\\\ \\\\\\\\\\\\\\\\*\\\\\\\\*\\\\\\\\*\\\\ 2>&1 OR *cmd.exe\\\\ \\\\/C\\\\ *\\\\ >\\\\ \\\\\\\\\\\\\\\\*\\\\\\\\*\\\\\\\\*\\\\ 2>&1 OR *cmd.exe\\\\ \\\\/C\\\\ *\\\\ >\\\\ *\\\\\\\\Temp\\\\\\\\*\\\\ 2>&1 OR *powershell.exe\\\\ \\\\-exec\\\\ bypass\\\\ \\\\-noni\\\\ \\\\-nop\\\\ \\\\-w\\\\ 1\\\\ \\\\-C\\\\ \\\\\\"* OR *powershell.exe\\\\ \\\\-noni\\\\ \\\\-nop\\\\ \\\\-w\\\\ 1\\\\ \\\\-enc\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CrackMapExec Command Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*cmd.exe \\/Q \\/c * 1> \\\\\\\\*\\\\*\\\\* 2>&1 *cmd.exe \\/C * > \\\\\\\\*\\\\*\\\\* 2>&1 *cmd.exe \\/C * > *\\\\Temp\\\\* 2>&1 *powershell.exe \\-exec bypass \\-noni \\-nop \\-w 1 \\-C \\"* *powershell.exe \\-noni \\-nop \\-w 1 \\-enc *)
```


### splunk
    
```
(CommandLine="*cmd.exe /Q /c * 1> \\\\\\\\*\\\\*\\\\* 2>&1" OR CommandLine="*cmd.exe /C * > \\\\\\\\*\\\\*\\\\* 2>&1" OR CommandLine="*cmd.exe /C * > *\\\\Temp\\\\* 2>&1" OR CommandLine="*powershell.exe -exec bypass -noni -nop -w 1 -C \\"*" OR CommandLine="*powershell.exe -noni -nop -w 1 -enc *") | table ComputerName,User,CommandLine
```


### logpoint
    
```
CommandLine IN ["*cmd.exe /Q /c * 1> \\\\\\\\*\\\\*\\\\* 2>&1", "*cmd.exe /C * > \\\\\\\\*\\\\*\\\\* 2>&1", "*cmd.exe /C * > *\\\\Temp\\\\* 2>&1", "*powershell.exe -exec bypass -noni -nop -w 1 -C \\"*", "*powershell.exe -noni -nop -w 1 -enc *"]
```


### grep
    
```
grep -P \'^(?:.*.*cmd\\.exe /Q /c .* 1> \\\\\\\\.*\\\\.*\\\\.* 2>&1|.*.*cmd\\.exe /C .* > \\\\\\\\.*\\\\.*\\\\.* 2>&1|.*.*cmd\\.exe /C .* > .*\\\\Temp\\\\.* 2>&1|.*.*powershell\\.exe -exec bypass -noni -nop -w 1 -C ".*|.*.*powershell\\.exe -noni -nop -w 1 -enc .*)\'
```



