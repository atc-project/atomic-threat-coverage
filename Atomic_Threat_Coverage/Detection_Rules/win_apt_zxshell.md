| Title                    | ZxShell Malware       |
|:-------------------------|:------------------|
| **Description**          | Detects a ZxShell start by the called and well-known function name |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)</li><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218/011)</li><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.hybrid-analysis.com/sample/5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16?environmentId=100](https://www.hybrid-analysis.com/sample/5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16?environmentId=100)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0412</li><li>attack.g0001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: ZxShell Malware
id: f0b70adb-0075-43b0-9745-e82a1c608fcc
description: Detects a ZxShell start by the called and well-known function name
author: Florian Roth
date: 2017/07/20
modified: 2020/08/26
references:
    - https://www.hybrid-analysis.com/sample/5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16?environmentId=100
tags:
    - attack.execution
    - attack.t1059.003
    - attack.t1059  # an old one
    - attack.defense_evasion
    - attack.t1218.011
    - attack.t1085  # an old one
    - attack.s0412
    - attack.g0001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'rundll32.exe *,zxFunction*'
            - 'rundll32.exe *,RemoteDiskXXXXX'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*rundll32.exe .*,zxFunction.*" -or $_.message -match "CommandLine.*.*rundll32.exe .*,RemoteDiskXXXXX.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*rundll32.exe\ *,zxFunction* OR *rundll32.exe\ *,RemoteDiskXXXXX*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f0b70adb-0075-43b0-9745-e82a1c608fcc <<EOF
{
  "metadata": {
    "title": "ZxShell Malware",
    "description": "Detects a ZxShell start by the called and well-known function name",
    "tags": [
      "attack.execution",
      "attack.t1059.003",
      "attack.t1059",
      "attack.defense_evasion",
      "attack.t1218.011",
      "attack.t1085",
      "attack.s0412",
      "attack.g0001"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*rundll32.exe\\ *,zxFunction* OR *rundll32.exe\\ *,RemoteDiskXXXXX*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*rundll32.exe\\ *,zxFunction* OR *rundll32.exe\\ *,RemoteDiskXXXXX*)",
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
        "subject": "Sigma Rule 'ZxShell Malware'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
CommandLine.keyword:(*rundll32.exe *,zxFunction* *rundll32.exe *,RemoteDiskXXXXX*)
```


### splunk
    
```
(CommandLine="*rundll32.exe *,zxFunction*" OR CommandLine="*rundll32.exe *,RemoteDiskXXXXX*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*rundll32.exe *,zxFunction*", "*rundll32.exe *,RemoteDiskXXXXX*"]
```


### grep
    
```
grep -P '^(?:.*.*rundll32\.exe .*,zxFunction.*|.*.*rundll32\.exe .*,RemoteDiskXXXXX.*)'
```



