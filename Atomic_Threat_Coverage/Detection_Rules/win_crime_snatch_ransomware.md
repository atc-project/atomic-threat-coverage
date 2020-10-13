| Title                    | Snatch Ransomware       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process characteristics of Snatch ransomware word document droppers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1204: User Execution](https://attack.mitre.org/techniques/T1204)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Scripts that shutdown the system immediatly and reboot them in safe mode are unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/](https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Snatch Ransomware
id: 5325945e-f1f0-406e-97b8-65104d393fff
status: experimental
description: Detects specific process characteristics of Snatch ransomware word document droppers
references:
    - https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/
author: Florian Roth
date: 2020/08/26
tags:
    - attack.execution
    - attack.t1204
logsource:
    category: process_creation
    product: windows
detection:
    # Shutdown in safe mode immediately 
    selection:
        CommandLine|contains: 
            - 'shutdown /r /f /t 00'
            - 'net stop SuperBackupMan'
    condition: selection
fields:
    - ComputerName
    - User
    - Image
falsepositives:
    - Scripts that shutdown the system immediatly and reboot them in safe mode are unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*shutdown /r /f /t 00.*" -or $_.message -match "CommandLine.*.*net stop SuperBackupMan.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*shutdown\ \/r\ \/f\ \/t\ 00* OR *net\ stop\ SuperBackupMan*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/5325945e-f1f0-406e-97b8-65104d393fff <<EOF
{
  "metadata": {
    "title": "Snatch Ransomware",
    "description": "Detects specific process characteristics of Snatch ransomware word document droppers",
    "tags": [
      "attack.execution",
      "attack.t1204"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*shutdown\\ \\/r\\ \\/f\\ \\/t\\ 00* OR *net\\ stop\\ SuperBackupMan*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*shutdown\\ \\/r\\ \\/f\\ \\/t\\ 00* OR *net\\ stop\\ SuperBackupMan*)",
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
        "subject": "Sigma Rule 'Snatch Ransomware'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n       Image = {{_source.Image}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
CommandLine.keyword:(*shutdown \/r \/f \/t 00* *net stop SuperBackupMan*)
```


### splunk
    
```
(CommandLine="*shutdown /r /f /t 00*" OR CommandLine="*net stop SuperBackupMan*") | table ComputerName,User,Image
```


### logpoint
    
```
CommandLine IN ["*shutdown /r /f /t 00*", "*net stop SuperBackupMan*"]
```


### grep
    
```
grep -P '^(?:.*.*shutdown /r /f /t 00.*|.*.*net stop SuperBackupMan.*)'
```



