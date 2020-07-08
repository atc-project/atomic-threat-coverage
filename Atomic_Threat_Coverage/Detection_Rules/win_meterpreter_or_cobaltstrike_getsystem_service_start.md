| Title                    | Meterpreter or Cobalt Strike Getsystem Service Start       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Commandlines containing components like cmd accidentally</li><li>Jobs and services started with cmd</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/](https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, Ecco |


## Detection Rules

### Sigma rule

```
title: Meterpreter or Cobalt Strike Getsystem Service Start
id: 15619216-e993-4721-b590-4c520615a67d
description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
author: Teymur Kheirkhabarov, Ecco
date: 2019/10/26
modified: 2020/05/15
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
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\services.exe" -and (($_.message -match "CommandLine.*.*cmd.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\\pipe\\.*") -or ($_.message -match "CommandLine.*.*%COMSPEC%.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\\pipe\\.*") -or ($_.message -match "CommandLine.*.*rundll32.*" -and $_.message -match "CommandLine.*.*.dll,a.*" -and $_.message -match "CommandLine.*.*/p:.*"))) -and  -not ($_.message -match "CommandLine.*.*MpCmdRun.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:*\\services.exe AND ((winlog.event_data.CommandLine.keyword:*cmd* AND winlog.event_data.CommandLine.keyword:*\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\pipe\\*) OR (winlog.event_data.CommandLine.keyword:*%COMSPEC%* AND winlog.event_data.CommandLine.keyword:*\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\pipe\\*) OR (winlog.event_data.CommandLine.keyword:*rundll32* AND winlog.event_data.CommandLine.keyword:*.dll,a* AND winlog.event_data.CommandLine.keyword:*\/p\:*))) AND (NOT (winlog.event_data.CommandLine.keyword:*MpCmdRun*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/15619216-e993-4721-b590-4c520615a67d <<EOF
{
  "metadata": {
    "title": "Meterpreter or Cobalt Strike Getsystem Service Start",
    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1134"
    ],
    "query": "((winlog.event_data.ParentImage.keyword:*\\\\services.exe AND ((winlog.event_data.CommandLine.keyword:*cmd* AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.CommandLine.keyword:*%COMSPEC%* AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.CommandLine.keyword:*rundll32* AND winlog.event_data.CommandLine.keyword:*.dll,a* AND winlog.event_data.CommandLine.keyword:*\\/p\\:*))) AND (NOT (winlog.event_data.CommandLine.keyword:*MpCmdRun*)))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "((winlog.event_data.ParentImage.keyword:*\\\\services.exe AND ((winlog.event_data.CommandLine.keyword:*cmd* AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.CommandLine.keyword:*%COMSPEC%* AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*echo* AND winlog.event_data.CommandLine.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.CommandLine.keyword:*rundll32* AND winlog.event_data.CommandLine.keyword:*.dll,a* AND winlog.event_data.CommandLine.keyword:*\\/p\\:*))) AND (NOT (winlog.event_data.CommandLine.keyword:*MpCmdRun*)))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Meterpreter or Cobalt Strike Getsystem Service Start'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
((ParentImage.keyword:*\\services.exe AND ((CommandLine.keyword:*cmd* AND CommandLine.keyword:*\/c* AND CommandLine.keyword:*echo* AND CommandLine.keyword:*\\pipe\\*) OR (CommandLine.keyword:*%COMSPEC%* AND CommandLine.keyword:*\/c* AND CommandLine.keyword:*echo* AND CommandLine.keyword:*\\pipe\\*) OR (CommandLine.keyword:*rundll32* AND CommandLine.keyword:*.dll,a* AND CommandLine.keyword:*\/p\:*))) AND (NOT (CommandLine.keyword:*MpCmdRun*)))
```


### splunk
    
```
((ParentImage="*\\services.exe" ((CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\pipe\\*") OR (CommandLine="*%COMSPEC%*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\pipe\\*") OR (CommandLine="*rundll32*" CommandLine="*.dll,a*" CommandLine="*/p:*"))) NOT (CommandLine="*MpCmdRun*")) | table ComputerName,User,CommandLine
```


### logpoint
    
```
(event_id="1" (ParentImage="*\\services.exe" ((CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\pipe\\*") OR (CommandLine="*%COMSPEC%*" CommandLine="*/c*" CommandLine="*echo*" CommandLine="*\\pipe\\*") OR (CommandLine="*rundll32*" CommandLine="*.dll,a*" CommandLine="*/p:*")))  -(CommandLine="*MpCmdRun*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\services\.exe)(?=.*(?:.*(?:.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\.dll,a.*)(?=.*.*/p:.*)))))))(?=.*(?!.*(?:.*(?=.*.*MpCmdRun.*)))))'
```



