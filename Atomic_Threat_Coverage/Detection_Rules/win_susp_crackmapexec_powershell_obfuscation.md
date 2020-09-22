| Title                    | CrackMapExec PowerShell Obfuscation       |
|:-------------------------|:------------------|
| **Description**          | The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1027.005: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027.005)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)</li><li>[https://github.com/byt3bl33d3r/CrackMapExec/blob/0a49f75347b625e81ee6aa8c33d3970b5515ea9e/cme/helpers/powershell.py#L242](https://github.com/byt3bl33d3r/CrackMapExec/blob/0a49f75347b625e81ee6aa8c33d3970b5515ea9e/cme/helpers/powershell.py#L242)</li></ul>  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: CrackMapExec PowerShell Obfuscation
id: 6f8b3439-a203-45dc-a88b-abf57ea15ccf
status: experimental
description: The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.
references:
    - https://github.com/byt3bl33d3r/CrackMapExec
    - https://github.com/byt3bl33d3r/CrackMapExec/blob/0a49f75347b625e81ee6aa8c33d3970b5515ea9e/cme/helpers/powershell.py#L242
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027.005
    - attack.t1027      # an old one
    - attack.t1086      # an old one
author: Thomas Patzke
date: 2020/05/22
logsource:
    category: process_creation
    product: windows
detection:
    powershell_execution:
        CommandLine|contains: 'powershell.exe'
    snippets:
        CommandLine|contains:
            - 'join*split'
            # Line 343ff
            - "( $ShellId[1]+$ShellId[13]+'x')"
            - '( $PSHome[*]+$PSHOME[*]+'
            - "( $env:Public[13]+$env:Public[5]+'x')"
            - "( $env:ComSpec[4,*,25]-Join'')"
            - "[1,3]+'x'-Join'')"
    condition: powershell_execution and snippets
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
Get-WinEvent | where {($_.message -match "CommandLine.*.*powershell.exe.*" -and ($_.message -match "CommandLine.*.*join.*split.*" -or $_.message -match "CommandLine.*.*( $ShellId[1]\\+$ShellId[13]\\+\'x\').*" -or $_.message -match "CommandLine.*.*( $PSHome[.*]\\+$PSHOME[.*]\\+.*" -or $_.message -match "CommandLine.*.*( $env:Public[13]\\+$env:Public[5]\\+\'x\').*" -or $_.message -match "CommandLine.*.*( $env:ComSpec[4,.*,25]-Join\'\').*" -or $_.message -match "CommandLine.*.*[1,3]\\+\'x\'-Join\'\').*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*powershell.exe* AND winlog.event_data.CommandLine.keyword:(*join*split* OR *\\(\\ $ShellId\\[1\\]\\+$ShellId\\[13\\]\\+'x'\\)* OR *\\(\\ $PSHome\\[*\\]\\+$PSHOME\\[*\\]\\+* OR *\\(\\ $env\\:Public\\[13\\]\\+$env\\:Public\\[5\\]\\+'x'\\)* OR *\\(\\ $env\\:ComSpec\\[4,*,25\\]\\-Join''\\)* OR *\\[1,3\\]\\+'x'\\-Join''\\)*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/6f8b3439-a203-45dc-a88b-abf57ea15ccf <<EOF\n{\n  "metadata": {\n    "title": "CrackMapExec PowerShell Obfuscation",\n    "description": "The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.defense_evasion",\n      "attack.t1027.005",\n      "attack.t1027",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*powershell.exe* AND winlog.event_data.CommandLine.keyword:(*join*split* OR *\\\\(\\\\ $ShellId\\\\[1\\\\]\\\\+$ShellId\\\\[13\\\\]\\\\+\'x\'\\\\)* OR *\\\\(\\\\ $PSHome\\\\[*\\\\]\\\\+$PSHOME\\\\[*\\\\]\\\\+* OR *\\\\(\\\\ $env\\\\:Public\\\\[13\\\\]\\\\+$env\\\\:Public\\\\[5\\\\]\\\\+\'x\'\\\\)* OR *\\\\(\\\\ $env\\\\:ComSpec\\\\[4,*,25\\\\]\\\\-Join\'\'\\\\)* OR *\\\\[1,3\\\\]\\\\+\'x\'\\\\-Join\'\'\\\\)*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*powershell.exe* AND winlog.event_data.CommandLine.keyword:(*join*split* OR *\\\\(\\\\ $ShellId\\\\[1\\\\]\\\\+$ShellId\\\\[13\\\\]\\\\+\'x\'\\\\)* OR *\\\\(\\\\ $PSHome\\\\[*\\\\]\\\\+$PSHOME\\\\[*\\\\]\\\\+* OR *\\\\(\\\\ $env\\\\:Public\\\\[13\\\\]\\\\+$env\\\\:Public\\\\[5\\\\]\\\\+\'x\'\\\\)* OR *\\\\(\\\\ $env\\\\:ComSpec\\\\[4,*,25\\\\]\\\\-Join\'\'\\\\)* OR *\\\\[1,3\\\\]\\\\+\'x\'\\\\-Join\'\'\\\\)*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CrackMapExec PowerShell Obfuscation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*powershell.exe* AND CommandLine.keyword:(*join*split* *\\( $ShellId\\[1\\]\\+$ShellId\\[13\\]\\+'x'\\)* *\\( $PSHome\\[*\\]\\+$PSHOME\\[*\\]\\+* *\\( $env\\:Public\\[13\\]\\+$env\\:Public\\[5\\]\\+'x'\\)* *\\( $env\\:ComSpec\\[4,*,25\\]\\-Join''\\)* *\\[1,3\\]\\+'x'\\-Join''\\)*))
```


### splunk
    
```
(CommandLine="*powershell.exe*" (CommandLine="*join*split*" OR CommandLine="*( $ShellId[1]+$ShellId[13]+\'x\')*" OR CommandLine="*( $PSHome[*]+$PSHOME[*]+*" OR CommandLine="*( $env:Public[13]+$env:Public[5]+\'x\')*" OR CommandLine="*( $env:ComSpec[4,*,25]-Join\'\')*" OR CommandLine="*[1,3]+\'x\'-Join\'\')*")) | table ComputerName,User,CommandLine
```


### logpoint
    
```
(CommandLine="*powershell.exe*" CommandLine IN ["*join*split*", "*( $ShellId[1]+$ShellId[13]+\'x\')*", "*( $PSHome[*]+$PSHOME[*]+*", "*( $env:Public[13]+$env:Public[5]+\'x\')*", "*( $env:ComSpec[4,*,25]-Join\'\')*", "*[1,3]+\'x\'-Join\'\')*"])
```


### grep
    
```
grep -P \'^(?:.*(?=.*.*powershell\\.exe.*)(?=.*(?:.*.*join.*split.*|.*.*\\( \\$ShellId\\[1\\]\\+\\$ShellId\\[13\\]\\+\'"\'"\'x\'"\'"\'\\).*|.*.*\\( \\$PSHome\\[.*\\]\\+\\$PSHOME\\[.*\\]\\+.*|.*.*\\( \\$env:Public\\[13\\]\\+\\$env:Public\\[5\\]\\+\'"\'"\'x\'"\'"\'\\).*|.*.*\\( \\$env:ComSpec\\[4,.*,25\\]-Join\'"\'"\'\'"\'"\'\\).*|.*.*\\[1,3\\]\\+\'"\'"\'x\'"\'"\'-Join\'"\'"\'\'"\'"\'\\).*)))\'
```



