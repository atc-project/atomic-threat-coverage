| Title                    | Meterpreter or Cobalt Strike Getsystem Service Installation       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li><li>[T1134.001: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001)</li><li>[T1134.002: Create Process with Token](https://attack.mitre.org/techniques/T1134/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Highly unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/](https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, Ecco |


## Detection Rules

### Sigma rule

```
action: global
title: Meterpreter or Cobalt Strike Getsystem Service Installation
id: 843544a7-56e0-4dcc-a44f-5cc266dd97d6
description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation
author: Teymur Kheirkhabarov, Ecco
date: 2019/10/26
modified: 2020/08/23
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
tags:
    - attack.privilege_escalation
    - attack.t1134          # an old one
    - attack.t1134.001
    - attack.t1134.002
detection:
    selection_1:
        # meterpreter getsystem technique 1: cmd.exe /c echo 559891bb017 > \\.\pipe\5e120a
        - ServiceFileName|contains|all:
            - 'cmd'
            - '/c'
            - 'echo'
            - '\pipe\'
        # cobaltstrike getsystem technique 1: %COMSPEC% /c echo 559891bb017 > \\.\pipe\5e120a
        - ServiceFileName|contains|all:
            - '%COMSPEC%'
            - '/c'
            - 'echo'
            - '\pipe\'
        # meterpreter getsystem technique 2: rundll32.exe C:\Users\test\AppData\Local\Temp\tmexsn.dll,a /p:tmexsn
        - ServiceFileName|contains|all:
            - 'rundll32'
            - '.dll,a'
            - '/p:'
    condition: selection and selection_1
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - ServiceFileName
falsepositives:
    - Highly unlikely
level: critical
---
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
---
 logsource:
     product: windows
     service: security
 detection:
     selection:
         EventID: 4697

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and (($_.message -match "ServiceFileName.*.*cmd.*" -and $_.message -match "ServiceFileName.*.*/c.*" -and $_.message -match "ServiceFileName.*.*echo.*" -and $_.message -match "ServiceFileName.*.*\\pipe\\.*") -or ($_.message -match "ServiceFileName.*.*%COMSPEC%.*" -and $_.message -match "ServiceFileName.*.*/c.*" -and $_.message -match "ServiceFileName.*.*echo.*" -and $_.message -match "ServiceFileName.*.*\\pipe\\.*") -or ($_.message -match "ServiceFileName.*.*rundll32.*" -and $_.message -match "ServiceFileName.*.*.dll,a.*" -and $_.message -match "ServiceFileName.*.*/p:.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "6" -and (($_.message -match "ServiceFileName.*.*cmd.*" -and $_.message -match "ServiceFileName.*.*/c.*" -and $_.message -match "ServiceFileName.*.*echo.*" -and $_.message -match "ServiceFileName.*.*\\pipe\\.*") -or ($_.message -match "ServiceFileName.*.*%COMSPEC%.*" -and $_.message -match "ServiceFileName.*.*/c.*" -and $_.message -match "ServiceFileName.*.*echo.*" -and $_.message -match "ServiceFileName.*.*\\pipe\\.*") -or ($_.message -match "ServiceFileName.*.*rundll32.*" -and $_.message -match "ServiceFileName.*.*.dll,a.*" -and $_.message -match "ServiceFileName.*.*/p:.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and (($_.message -match "ServiceFileName.*.*cmd.*" -and $_.message -match "ServiceFileName.*.*/c.*" -and $_.message -match "ServiceFileName.*.*echo.*" -and $_.message -match "ServiceFileName.*.*\\pipe\\.*") -or ($_.message -match "ServiceFileName.*.*%COMSPEC%.*" -and $_.message -match "ServiceFileName.*.*/c.*" -and $_.message -match "ServiceFileName.*.*echo.*" -and $_.message -match "ServiceFileName.*.*\\pipe\\.*") -or ($_.message -match "ServiceFileName.*.*rundll32.*" -and $_.message -match "ServiceFileName.*.*.dll,a.*" -and $_.message -match "ServiceFileName.*.*/p:.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\pipe\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\pipe\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\/p\:*)))
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"6" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\pipe\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\pipe\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\/p\:*)))
(winlog.channel:"Security" AND winlog.event_id:"4697" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\pipe\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\pipe\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\/p\:*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/843544a7-56e0-4dcc-a44f-5cc266dd97d6 <<EOF
{
  "metadata": {
    "title": "Meterpreter or Cobalt Strike Getsystem Service Installation",
    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1134",
      "attack.t1134.001",
      "attack.t1134.002"
    ],
    "query": "(winlog.event_id:\"7045\" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\\/p\\:*)))"
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
                    "query": "(winlog.event_id:\"7045\" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\\/p\\:*)))",
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
        "subject": "Sigma Rule 'Meterpreter or Cobalt Strike Getsystem Service Installation'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\nSubjectDomainName = {{_source.SubjectDomainName}}\n  SubjectUserName = {{_source.SubjectUserName}}\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/843544a7-56e0-4dcc-a44f-5cc266dd97d6-2 <<EOF
{
  "metadata": {
    "title": "Meterpreter or Cobalt Strike Getsystem Service Installation",
    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1134",
      "attack.t1134.001",
      "attack.t1134.002"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"6\" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\\/p\\:*)))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"6\" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\\/p\\:*)))",
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
        "subject": "Sigma Rule 'Meterpreter or Cobalt Strike Getsystem Service Installation'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\nSubjectDomainName = {{_source.SubjectDomainName}}\n  SubjectUserName = {{_source.SubjectUserName}}\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/843544a7-56e0-4dcc-a44f-5cc266dd97d6-3 <<EOF
{
  "metadata": {
    "title": "Meterpreter or Cobalt Strike Getsystem Service Installation",
    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1134",
      "attack.t1134.001",
      "attack.t1134.002"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4697\" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\\/p\\:*)))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4697\" AND ((winlog.event_data.ServiceFileName.keyword:*cmd* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*%COMSPEC%* AND winlog.event_data.ServiceFileName.keyword:*\\/c* AND winlog.event_data.ServiceFileName.keyword:*echo* AND winlog.event_data.ServiceFileName.keyword:*\\\\pipe\\\\*) OR (winlog.event_data.ServiceFileName.keyword:*rundll32* AND winlog.event_data.ServiceFileName.keyword:*.dll,a* AND winlog.event_data.ServiceFileName.keyword:*\\/p\\:*)))",
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
        "subject": "Sigma Rule 'Meterpreter or Cobalt Strike Getsystem Service Installation'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\nSubjectDomainName = {{_source.SubjectDomainName}}\n  SubjectUserName = {{_source.SubjectUserName}}\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"7045" AND ((ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\/p\:*)))
(EventID:"6" AND ((ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\/p\:*)))
(EventID:"4697" AND ((ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\/p\:*)))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" ((ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*"))) | table ComputerName,SubjectDomainName,SubjectUserName,ServiceFileName
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="6" ((ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*"))) | table ComputerName,SubjectDomainName,SubjectUserName,ServiceFileName
(source="WinEventLog:Security" EventCode="4697" ((ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*"))) | table ComputerName,SubjectDomainName,SubjectUserName,ServiceFileName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" ((ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")))
(event_id="6" ((ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")))
(event_source="Microsoft-Windows-Security-Auditing" event_id="4697" ((ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*(?:.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\.dll,a.*)(?=.*.*/p:.*))))))'
grep -P '^(?:.*(?=.*6)(?=.*(?:.*(?:.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\.dll,a.*)(?=.*.*/p:.*))))))'
grep -P '^(?:.*(?=.*4697)(?=.*(?:.*(?:.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\.dll,a.*)(?=.*.*/p:.*))))))'
```



