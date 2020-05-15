| Title                    | Meterpreter or Cobalt Strike Getsystem Service Start       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Commandlines containing components like cmd accidentally</li><li>Jobs and services started with cmd</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/](https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Meterpreter or Cobalt Strike Getsystem Service Start
id: 15619216-e993-4721-b590-4c520615a67d
description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2019/11/11
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
tags:
    - attack.privilege_escalation
    - attack.t1134
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        ParentImage|endswith: '\services.exe'
    selection_2:    
        - CommandLine|contains:
            - 'cmd'
            - 'comspec'
        # meterpreter getsystem technique 1: cmd.exe /c echo 559891bb017 > \\.\pipe\5e120a
        - CommandLine|contains|all:
            - 'cmd'
            - '/c'
            - 'echo'
            - '\pipe\'
        # cobaltstrike getsystem technique 1: %COMSPEC% /c echo 559891bb017 > \\.\pipe\5e120a
        - CommandLine|contains|all:
            - '%COMSPEC%'
            - '/c'
            - 'echo'
            - '\pipe\'
        # meterpreter getsystem technique 2: rundll32.exe C:\Users\test\AppData\Local\Temp\tmexsn.dll,a /p:tmexsn
        - CommandLine|contains|all:
            - 'rundll32'
            - '.dll,a'
            - '/p:'
    filter1:
        CommandLine|contains: 'MpCmdRun'
    condition: selection_1 and selection_2 and not filter1
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Commandlines containing components like cmd accidentally
    - Jobs and services started with cmd
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "ParentImage.*.*\\\\services.exe" -and (($_.message -match "CommandLine.*.*cmd.*" -or $_.message -match "CommandLine.*.*comspec.*") -or ($_.message -match "CommandLine.*.*cmd.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\\\\pipe\\\\.*") -or ($_.message -match "CommandLine.*.*%COMSPEC%.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\\\\pipe\\\\.*") -or ($_.message -match "CommandLine.*.*rundll32.*" -and $_.message -match "CommandLine.*.*.dll,a.*" -and $_.message -match "CommandLine.*.*/p:.*"))) -and  -not ($_.message -match "CommandLine.*.*MpCmdRun.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:*\\\\services.exe AND (winlog.event_data.CommandLine.keyword:(*cmd* OR *comspec*) OR (winlog.event_data.CommandLine.keyword:*cmd* AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.CommandLine.keyword:*%COMSPEC%* AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.CommandLine.keyword:*rundll32* AND winlog.event_data.CommandLine.keyword:*.dll,a* AND winlog.event_data.CommandLine.keyword:*\\/p\\:*))) AND (NOT (winlog.event_data.CommandLine.keyword:*MpCmdRun*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/15619216-e993-4721-b590-4c520615a67d <<EOF\n{\n  "metadata": {\n    "title": "Meterpreter or Cobalt Strike Getsystem Service Start",\n    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1134"\n    ],\n    "query": "((winlog.event_data.ParentImage.keyword:*\\\\\\\\services.exe AND (winlog.event_data.CommandLine.keyword:(*cmd* OR *comspec*) OR (winlog.event_data.CommandLine.keyword:*cmd* AND winlog.event_data.CommandLine.keyword:*\\\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\\\\\pipe\\\\\\\\*) OR (winlog.event_data.CommandLine.keyword:*%COMSPEC%* AND winlog.event_data.CommandLine.keyword:*\\\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\\\\\pipe\\\\\\\\*) OR (winlog.event_data.CommandLine.keyword:*rundll32* AND winlog.event_data.CommandLine.keyword:*.dll,a* AND winlog.event_data.CommandLine.keyword:*\\\\/p\\\\:*))) AND (NOT (winlog.event_data.CommandLine.keyword:*MpCmdRun*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.ParentImage.keyword:*\\\\\\\\services.exe AND (winlog.event_data.CommandLine.keyword:(*cmd* OR *comspec*) OR (winlog.event_data.CommandLine.keyword:*cmd* AND winlog.event_data.CommandLine.keyword:*\\\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\\\\\pipe\\\\\\\\*) OR (winlog.event_data.CommandLine.keyword:*%COMSPEC%* AND winlog.event_data.CommandLine.keyword:*\\\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\\\\\pipe\\\\\\\\*) OR (winlog.event_data.CommandLine.keyword:*rundll32* AND winlog.event_data.CommandLine.keyword:*.dll,a* AND winlog.event_data.CommandLine.keyword:*\\\\/p\\\\:*))) AND (NOT (winlog.event_data.CommandLine.keyword:*MpCmdRun*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Meterpreter or Cobalt Strike Getsystem Service Start\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((ParentImage.keyword:*\\\\services.exe AND (CommandLine.keyword:(*cmd* *comspec*) OR (CommandLine.keyword:*cmd* AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*echo* AND CommandLine.keyword:*\\\\pipe\\\\*) OR (CommandLine.keyword:*%COMSPEC%* AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*echo* AND CommandLine.keyword:*\\\\pipe\\\\*) OR (CommandLine.keyword:*rundll32* AND CommandLine.keyword:*.dll,a* AND CommandLine.keyword:*\\/p\\:*))) AND (NOT (CommandLine.keyword:*MpCmdRun*)))
```


### splunk
    
```
((ParentImage="*\\\\services.exe" ((CommandLine="*cmd*" OR CommandLine="*comspec*") OR (CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\\\pipe\\\\*") OR (CommandLine="*%COMSPEC%*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\\\pipe\\\\*") OR (CommandLine="*rundll32*" CommandLine="*.dll,a*" CommandLine="*/p:*"))) NOT (CommandLine="*MpCmdRun*")) | table ComputerName,User,CommandLine
```


### logpoint
    
```
((ParentImage="*\\\\services.exe" (CommandLine IN ["*cmd*", "*comspec*"] OR (CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\\\pipe\\\\*") OR (CommandLine="*%COMSPEC%*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\\\pipe\\\\*") OR (CommandLine="*rundll32*" CommandLine="*.dll,a*" CommandLine="*/p:*")))  -(CommandLine="*MpCmdRun*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\services\\.exe)(?=.*(?:.*(?:.*(?:.*.*cmd.*|.*.*comspec.*)|.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\\.dll,a.*)(?=.*.*/p:.*)))))))(?=.*(?!.*(?:.*(?=.*.*MpCmdRun.*)))))'
```



