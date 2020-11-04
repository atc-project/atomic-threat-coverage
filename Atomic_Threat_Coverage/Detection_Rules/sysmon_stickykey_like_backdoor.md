| Title                    | Sticky Key Like Backdoor Usage       |
|:-------------------------|:------------------|
| **Description**          | Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1015: Accessibility Features](https://attack.mitre.org/techniques/T1015)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1015: Accessibility Features](../Triggers/T1015.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/](https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/)</li></ul>  |
| **Author**               | Florian Roth, @twjackomo |
| Other Tags           | <ul><li>car.2014-11-003</li><li>car.2014-11-008</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Sticky Key Like Backdoor Usage
id: baca5663-583c-45f9-b5dc-ea96a22ce542
description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login
    screen
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1015
    - car.2014-11-003
    - car.2014-11-008
author: Florian Roth, @twjackomo
date: 2018/03/15
detection:
    condition: 1 of them
falsepositives:
    - Unlikely
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger'
        EventType: 'SetValue'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        ParentImage:
            - '*\winlogon.exe'
        CommandLine:
            - '*cmd.exe sethc.exe *'
            - '*cmd.exe utilman.exe *'
            - '*cmd.exe osk.exe *'
            - '*cmd.exe Magnify.exe *'
            - '*cmd.exe Narrator.exe *'
            - '*cmd.exe DisplaySwitch.exe *'

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger") -and $_.message -match "EventType.*SetValue") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.message -match "ParentImage.*.*\\winlogon.exe") -and ($_.message -match "CommandLine.*.*cmd.exe sethc.exe .*" -or $_.message -match "CommandLine.*.*cmd.exe utilman.exe .*" -or $_.message -match "CommandLine.*.*cmd.exe osk.exe .*" -or $_.message -match "CommandLine.*.*cmd.exe Magnify.exe .*" -or $_.message -match "CommandLine.*.*cmd.exe Narrator.exe .*" -or $_.message -match "CommandLine.*.*cmd.exe DisplaySwitch.exe .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\sethc.exe\\Debugger OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\utilman.exe\\Debugger OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\osk.exe\\Debugger OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\Magnify.exe\\Debugger OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\Narrator.exe\\Debugger OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\DisplaySwitch.exe\\Debugger) AND winlog.event_data.EventType:"SetValue")
(winlog.event_data.ParentImage.keyword:(*\\winlogon.exe) AND winlog.event_data.CommandLine.keyword:(*cmd.exe\ sethc.exe\ * OR *cmd.exe\ utilman.exe\ * OR *cmd.exe\ osk.exe\ * OR *cmd.exe\ Magnify.exe\ * OR *cmd.exe\ Narrator.exe\ * OR *cmd.exe\ DisplaySwitch.exe\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/baca5663-583c-45f9-b5dc-ea96a22ce542 <<EOF
{
  "metadata": {
    "title": "Sticky Key Like Backdoor Usage",
    "description": "Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen",
    "tags": [
      "attack.privilege_escalation",
      "attack.persistence",
      "attack.t1015",
      "car.2014-11-003",
      "car.2014-11-008"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\sethc.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\utilman.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\osk.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\Magnify.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\Narrator.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\DisplaySwitch.exe\\\\Debugger) AND winlog.event_data.EventType:\"SetValue\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\sethc.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\utilman.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\osk.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\Magnify.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\Narrator.exe\\\\Debugger OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\DisplaySwitch.exe\\\\Debugger) AND winlog.event_data.EventType:\"SetValue\")",
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
        "subject": "Sigma Rule 'Sticky Key Like Backdoor Usage'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/baca5663-583c-45f9-b5dc-ea96a22ce542-2 <<EOF
{
  "metadata": {
    "title": "Sticky Key Like Backdoor Usage",
    "description": "Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen",
    "tags": [
      "attack.privilege_escalation",
      "attack.persistence",
      "attack.t1015",
      "car.2014-11-003",
      "car.2014-11-008"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\winlogon.exe) AND winlog.event_data.CommandLine.keyword:(*cmd.exe\\ sethc.exe\\ * OR *cmd.exe\\ utilman.exe\\ * OR *cmd.exe\\ osk.exe\\ * OR *cmd.exe\\ Magnify.exe\\ * OR *cmd.exe\\ Narrator.exe\\ * OR *cmd.exe\\ DisplaySwitch.exe\\ *))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\winlogon.exe) AND winlog.event_data.CommandLine.keyword:(*cmd.exe\\ sethc.exe\\ * OR *cmd.exe\\ utilman.exe\\ * OR *cmd.exe\\ osk.exe\\ * OR *cmd.exe\\ Magnify.exe\\ * OR *cmd.exe\\ Narrator.exe\\ * OR *cmd.exe\\ DisplaySwitch.exe\\ *))",
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
        "subject": "Sigma Rule 'Sticky Key Like Backdoor Usage'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"13" AND TargetObject.keyword:(*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger) AND EventType:"SetValue")
(ParentImage.keyword:(*\\winlogon.exe) AND CommandLine.keyword:(*cmd.exe sethc.exe * *cmd.exe utilman.exe * *cmd.exe osk.exe * *cmd.exe Magnify.exe * *cmd.exe Narrator.exe * *cmd.exe DisplaySwitch.exe *))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger") EventType="SetValue")
((ParentImage="*\\winlogon.exe") (CommandLine="*cmd.exe sethc.exe *" OR CommandLine="*cmd.exe utilman.exe *" OR CommandLine="*cmd.exe osk.exe *" OR CommandLine="*cmd.exe Magnify.exe *" OR CommandLine="*cmd.exe Narrator.exe *" OR CommandLine="*cmd.exe DisplaySwitch.exe *"))
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger"] EventType="SetValue")
(ParentImage IN ["*\\winlogon.exe"] CommandLine IN ["*cmd.exe sethc.exe *", "*cmd.exe utilman.exe *", "*cmd.exe osk.exe *", "*cmd.exe Magnify.exe *", "*cmd.exe Narrator.exe *", "*cmd.exe DisplaySwitch.exe *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc\.exe\Debugger|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman\.exe\Debugger|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk\.exe\Debugger|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify\.exe\Debugger|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator\.exe\Debugger|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch\.exe\Debugger))(?=.*SetValue))'
grep -P '^(?:.*(?=.*(?:.*.*\winlogon\.exe))(?=.*(?:.*.*cmd\.exe sethc\.exe .*|.*.*cmd\.exe utilman\.exe .*|.*.*cmd\.exe osk\.exe .*|.*.*cmd\.exe Magnify\.exe .*|.*.*cmd\.exe Narrator\.exe .*|.*.*cmd\.exe DisplaySwitch\.exe .*)))'
```



