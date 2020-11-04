| Title                    | PowerShell Download from URL       |
|:-------------------------|:------------------|
| **Description**          | Detects a Powershell process that contains download commands in its command line string |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Download from URL
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth
date: 2019/01/16
tags:
    - attack.t1086
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\powershell.exe" -and ($_.message -match "CommandLine.*.*new-object system.net.webclient).downloadstring(.*" -or $_.message -match "CommandLine.*.*new-object system.net.webclient).downloadfile(.*" -or $_.message -match "CommandLine.*.*new-object net.webclient).downloadstring(.*" -or $_.message -match "CommandLine.*.*new-object net.webclient).downloadfile(.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\powershell.exe AND winlog.event_data.CommandLine.keyword:(*new\-object\ system.net.webclient\).downloadstring\(* OR *new\-object\ system.net.webclient\).downloadfile\(* OR *new\-object\ net.webclient\).downloadstring\(* OR *new\-object\ net.webclient\).downloadfile\(*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3b6ab547-8ec2-4991-b9d2-2b06702a48d7 <<EOF
{
  "metadata": {
    "title": "PowerShell Download from URL",
    "description": "Detects a Powershell process that contains download commands in its command line string",
    "tags": [
      "attack.t1086",
      "attack.execution"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:(*new\\-object\\ system.net.webclient\\).downloadstring\\(* OR *new\\-object\\ system.net.webclient\\).downloadfile\\(* OR *new\\-object\\ net.webclient\\).downloadstring\\(* OR *new\\-object\\ net.webclient\\).downloadfile\\(*))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:(*new\\-object\\ system.net.webclient\\).downloadstring\\(* OR *new\\-object\\ system.net.webclient\\).downloadfile\\(* OR *new\\-object\\ net.webclient\\).downloadstring\\(* OR *new\\-object\\ net.webclient\\).downloadfile\\(*))",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'PowerShell Download from URL'",
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
(Image.keyword:*\\powershell.exe AND CommandLine.keyword:(*new\-object system.net.webclient\).downloadstring\(* *new\-object system.net.webclient\).downloadfile\(* *new\-object net.webclient\).downloadstring\(* *new\-object net.webclient\).downloadfile\(*))
```


### splunk
    
```
(Image="*\\powershell.exe" (CommandLine="*new-object system.net.webclient).downloadstring(*" OR CommandLine="*new-object system.net.webclient).downloadfile(*" OR CommandLine="*new-object net.webclient).downloadstring(*" OR CommandLine="*new-object net.webclient).downloadfile(*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\powershell.exe" CommandLine IN ["*new-object system.net.webclient).downloadstring(*", "*new-object system.net.webclient).downloadfile(*", "*new-object net.webclient).downloadstring(*", "*new-object net.webclient).downloadfile(*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\powershell\.exe)(?=.*(?:.*.*new-object system\.net\.webclient\)\.downloadstring\(.*|.*.*new-object system\.net\.webclient\)\.downloadfile\(.*|.*.*new-object net\.webclient\)\.downloadstring\(.*|.*.*new-object net\.webclient\)\.downloadfile\(.*)))'
```



