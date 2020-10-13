| Title                    | Chafer Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005)</li><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li><li>[T1543.003: Windows Service](https://attack.mitre.org/techniques/T1543/003)</li><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li><li>[T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071)</li><li>[T1071.004: DNS](https://attack.mitre.org/techniques/T1071/004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li><li>[T1543.003: Windows Service](../Triggers/T1543.003.md)</li><li>[T1112: Modify Registry](../Triggers/T1112.md)</li><li>[T1071.004: DNS](../Triggers/T1071.004.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/](https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>attack.g0049</li><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Chafer Activity
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
description: Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018
references:
    - https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
tags:
    - attack.persistence
    - attack.g0049
    - attack.t1053 # an old one
    - attack.t1053.005
    - attack.s0111
    - attack.t1050 # an old one
    - attack.t1543.003
    - attack.defense_evasion
    - attack.t1112
    - attack.command_and_control
    - attack.t1071 # an old one
    - attack.t1071.004
date: 2018/03/23
modified: 2020/08/26
author: Florian Roth, Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: critical
---
logsource:
    product: windows
    service: system
detection:
    selection_service:
        EventID: 7045
        ServiceName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
---
logsource:
    product: windows
    service: security
detection:
    selection_service:
        EventID: 4698
        TaskName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
---
logsource:
   product: windows
   service: sysmon
detection:
    selection_reg1:
        EventID: 13 
        TargetObject: 
            - '*SOFTWARE\Microsoft\Windows\CurrentVersion\UMe'
            - '*SOFTWARE\Microsoft\Windows\CurrentVersion\UT'
        EventType: 'SetValue'
    selection_reg2:
        EventID: 13 
        TargetObject: '*\Control\SecurityProviders\WDigest\UseLogonCredential'
        EventType: 'SetValue'
        Details: 'DWORD (0x00000001)'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process1:
        CommandLine: 
            - '*\Service.exe i'
            - '*\Service.exe u'
            - '*\microsoft\Taskbar\autoit3.exe'
            - 'C:\wsc.exe*'
    selection_process2:
        Image: '*\Windows\Temp\DB\\*.exe'
    selection_process3:
        CommandLine: '*\nslookup.exe -q=TXT*'
        ParentImage: '*\Autoit*'

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.message -match "SC Scheduled Scan" -or $_.message -match "UpdatMachine")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Security | where {($_.ID -eq "4698" -and ($_.message -match "SC Scheduled Scan" -or $_.message -match "UpdatMachine")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "EventType.*SetValue" -and (($_.message -match "TargetObject.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe" -or $_.message -match "TargetObject.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT") -or ($_.message -match "TargetObject.*.*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" -and $_.message -match "Details.*DWORD (0x00000001)"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.message -match "CommandLine.*.*\\Service.exe i" -or $_.message -match "CommandLine.*.*\\Service.exe u" -or $_.message -match "CommandLine.*.*\\microsoft\\Taskbar\\autoit3.exe" -or $_.message -match "CommandLine.*C:\\wsc.exe.*") -or $_.message -match "Image.*.*\\Windows\\Temp\\DB\\.*.exe" -or ($_.message -match "CommandLine.*.*\\nslookup.exe -q=TXT.*" -and $_.message -match "ParentImage.*.*\\Autoit.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ServiceName:("SC\ Scheduled\ Scan" OR "UpdatMachine"))
(winlog.channel:"Security" AND winlog.event_id:"4698" AND TaskName:("SC\ Scheduled\ Scan" OR "UpdatMachine"))
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.EventType:"SetValue" AND (winlog.event_data.TargetObject.keyword:(*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe OR *SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT) OR (winlog.event_data.TargetObject.keyword:*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential AND winlog.event_data.Details:"DWORD\ \(0x00000001\)")))
(winlog.event_data.CommandLine.keyword:(*\\Service.exe\ i OR *\\Service.exe\ u OR *\\microsoft\\Taskbar\\autoit3.exe OR C\:\\wsc.exe*) OR winlog.event_data.Image.keyword:*\\Windows\\Temp\\DB\\*.exe OR (winlog.event_data.CommandLine.keyword:*\\nslookup.exe\ \-q\=TXT* AND winlog.event_data.ParentImage.keyword:*\\Autoit*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92 <<EOF
{
  "metadata": {
    "title": "Chafer Activity",
    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",
    "tags": [
      "attack.persistence",
      "attack.g0049",
      "attack.t1053",
      "attack.t1053.005",
      "attack.s0111",
      "attack.t1050",
      "attack.t1543.003",
      "attack.defense_evasion",
      "attack.t1112",
      "attack.command_and_control",
      "attack.t1071",
      "attack.t1071.004"
    ],
    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:(\"SC\\ Scheduled\\ Scan\" OR \"UpdatMachine\"))"
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
                    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:(\"SC\\ Scheduled\\ Scan\" OR \"UpdatMachine\"))",
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
        "subject": "Sigma Rule 'Chafer Activity'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92-2 <<EOF
{
  "metadata": {
    "title": "Chafer Activity",
    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",
    "tags": [
      "attack.persistence",
      "attack.g0049",
      "attack.t1053",
      "attack.t1053.005",
      "attack.s0111",
      "attack.t1050",
      "attack.t1543.003",
      "attack.defense_evasion",
      "attack.t1112",
      "attack.command_and_control",
      "attack.t1071",
      "attack.t1071.004"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4698\" AND TaskName:(\"SC\\ Scheduled\\ Scan\" OR \"UpdatMachine\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4698\" AND TaskName:(\"SC\\ Scheduled\\ Scan\" OR \"UpdatMachine\"))",
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
        "subject": "Sigma Rule 'Chafer Activity'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92-3 <<EOF
{
  "metadata": {
    "title": "Chafer Activity",
    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",
    "tags": [
      "attack.persistence",
      "attack.g0049",
      "attack.t1053",
      "attack.t1053.005",
      "attack.s0111",
      "attack.t1050",
      "attack.t1543.003",
      "attack.defense_evasion",
      "attack.t1112",
      "attack.command_and_control",
      "attack.t1071",
      "attack.t1071.004"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.EventType:\"SetValue\" AND (winlog.event_data.TargetObject.keyword:(*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UMe OR *SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UT) OR (winlog.event_data.TargetObject.keyword:*\\\\Control\\\\SecurityProviders\\\\WDigest\\\\UseLogonCredential AND winlog.event_data.Details:\"DWORD\\ \\(0x00000001\\)\")))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.EventType:\"SetValue\" AND (winlog.event_data.TargetObject.keyword:(*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UMe OR *SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UT) OR (winlog.event_data.TargetObject.keyword:*\\\\Control\\\\SecurityProviders\\\\WDigest\\\\UseLogonCredential AND winlog.event_data.Details:\"DWORD\\ \\(0x00000001\\)\")))",
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
        "subject": "Sigma Rule 'Chafer Activity'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/53ba33fd-3a50-4468-a5ef-c583635cfa92-4 <<EOF
{
  "metadata": {
    "title": "Chafer Activity",
    "description": "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018",
    "tags": [
      "attack.persistence",
      "attack.g0049",
      "attack.t1053",
      "attack.t1053.005",
      "attack.s0111",
      "attack.t1050",
      "attack.t1543.003",
      "attack.defense_evasion",
      "attack.t1112",
      "attack.command_and_control",
      "attack.t1071",
      "attack.t1071.004"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*\\\\Service.exe\\ i OR *\\\\Service.exe\\ u OR *\\\\microsoft\\\\Taskbar\\\\autoit3.exe OR C\\:\\\\wsc.exe*) OR winlog.event_data.Image.keyword:*\\\\Windows\\\\Temp\\\\DB\\\\*.exe OR (winlog.event_data.CommandLine.keyword:*\\\\nslookup.exe\\ \\-q\\=TXT* AND winlog.event_data.ParentImage.keyword:*\\\\Autoit*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*\\\\Service.exe\\ i OR *\\\\Service.exe\\ u OR *\\\\microsoft\\\\Taskbar\\\\autoit3.exe OR C\\:\\\\wsc.exe*) OR winlog.event_data.Image.keyword:*\\\\Windows\\\\Temp\\\\DB\\\\*.exe OR (winlog.event_data.CommandLine.keyword:*\\\\nslookup.exe\\ \\-q\\=TXT* AND winlog.event_data.ParentImage.keyword:*\\\\Autoit*))",
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
        "subject": "Sigma Rule 'Chafer Activity'",
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
(EventID:"7045" AND ServiceName:("SC Scheduled Scan" "UpdatMachine"))
(EventID:"4698" AND TaskName:("SC Scheduled Scan" "UpdatMachine"))
(EventID:"13" AND EventType:"SetValue" AND (TargetObject.keyword:(*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe *SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT) OR (TargetObject.keyword:*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential AND Details:"DWORD \(0x00000001\)")))
(CommandLine.keyword:(*\\Service.exe i *\\Service.exe u *\\microsoft\\Taskbar\\autoit3.exe C\:\\wsc.exe*) OR Image.keyword:*\\Windows\\Temp\\DB\\*.exe OR (CommandLine.keyword:*\\nslookup.exe \-q=TXT* AND ParentImage.keyword:*\\Autoit*))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" (ServiceName="SC Scheduled Scan" OR ServiceName="UpdatMachine"))
(source="WinEventLog:Security" EventCode="4698" (TaskName="SC Scheduled Scan" OR TaskName="UpdatMachine"))
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" EventType="SetValue" ((TargetObject="*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe" OR TargetObject="*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT") OR (TargetObject="*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" Details="DWORD (0x00000001)")))
((CommandLine="*\\Service.exe i" OR CommandLine="*\\Service.exe u" OR CommandLine="*\\microsoft\\Taskbar\\autoit3.exe" OR CommandLine="C:\\wsc.exe*") OR Image="*\\Windows\\Temp\\DB\\*.exe" OR (CommandLine="*\\nslookup.exe -q=TXT*" ParentImage="*\\Autoit*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service IN ["SC Scheduled Scan", "UpdatMachine"])
(event_source="Microsoft-Windows-Security-Auditing" event_id="4698" TaskName IN ["SC Scheduled Scan", "UpdatMachine"])
(event_id="13" EventType="SetValue" (TargetObject IN ["*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe", "*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT"] OR (TargetObject="*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" Details="DWORD (0x00000001)")))
(CommandLine IN ["*\\Service.exe i", "*\\Service.exe u", "*\\microsoft\\Taskbar\\autoit3.exe", "C:\\wsc.exe*"] OR Image="*\\Windows\\Temp\\DB\\*.exe" OR (CommandLine="*\\nslookup.exe -q=TXT*" ParentImage="*\\Autoit*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*SC Scheduled Scan|.*UpdatMachine)))'
grep -P '^(?:.*(?=.*4698)(?=.*(?:.*SC Scheduled Scan|.*UpdatMachine)))'
grep -P '^(?:.*(?=.*13)(?=.*SetValue)(?=.*(?:.*(?:.*(?:.*.*SOFTWARE\Microsoft\Windows\CurrentVersion\UMe|.*.*SOFTWARE\Microsoft\Windows\CurrentVersion\UT)|.*(?:.*(?=.*.*\Control\SecurityProviders\WDigest\UseLogonCredential)(?=.*DWORD \(0x00000001\)))))))'
grep -P '^(?:.*(?:.*(?:.*.*\Service\.exe i|.*.*\Service\.exe u|.*.*\microsoft\Taskbar\autoit3\.exe|.*C:\wsc\.exe.*)|.*.*\Windows\Temp\DB\\.*\.exe|.*(?:.*(?=.*.*\nslookup\.exe -q=TXT.*)(?=.*.*\Autoit.*))))'
```



