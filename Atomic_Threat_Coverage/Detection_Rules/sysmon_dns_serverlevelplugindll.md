| Title                    | DNS ServerLevelPluginDll Install       |
|:-------------------------|:------------------|
| **Description**          | Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: DNS ServerLevelPluginDll Install
id: e61e8a88-59a9-451c-874e-70fcc9740d67
status: experimental
description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server
    (restart required)
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
date: 2017/05/08
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1073
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
falsepositives:
    - unknown
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    dnsregmod:
        EventID: 13
        TargetObject: '*\services\DNS\Parameters\ServerLevelPluginDll'
---
logsource:
    category: process_creation
    product: windows
detection:
    dnsadmin:
        CommandLine: 'dnscmd.exe /config /serverlevelplugindll *'
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "TargetObject.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {$_.message -match "CommandLine.*dnscmd.exe /config /serverlevelplugindll .*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:*\\services\\DNS\\Parameters\\ServerLevelPluginDll)
winlog.event_data.CommandLine.keyword:dnscmd.exe\ \/config\ \/serverlevelplugindll\ *
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e61e8a88-59a9-451c-874e-70fcc9740d67 <<EOF
{
  "metadata": {
    "title": "DNS ServerLevelPluginDll Install",
    "description": "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll)",
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
        "subject": "Sigma Rule 'DNS ServerLevelPluginDll Install'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n          EventID = {{_source.EventID}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n            Image = {{_source.Image}}\n             User = {{_source.User}}\n     TargetObject = {{_source.TargetObject}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e61e8a88-59a9-451c-874e-70fcc9740d67-2 <<EOF
{
  "metadata": {
    "title": "DNS ServerLevelPluginDll Install",
    "description": "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073"
    ],
    "query": "winlog.event_data.CommandLine.keyword:dnscmd.exe\\ \\/config\\ \\/serverlevelplugindll\\ *"
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
                    "query": "winlog.event_data.CommandLine.keyword:dnscmd.exe\\ \\/config\\ \\/serverlevelplugindll\\ *",
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
        "subject": "Sigma Rule 'DNS ServerLevelPluginDll Install'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n          EventID = {{_source.EventID}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n            Image = {{_source.Image}}\n             User = {{_source.User}}\n     TargetObject = {{_source.TargetObject}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"13" AND TargetObject.keyword:*\\services\\DNS\\Parameters\\ServerLevelPluginDll)
CommandLine.keyword:dnscmd.exe \/config \/serverlevelplugindll *
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" TargetObject="*\\services\\DNS\\Parameters\\ServerLevelPluginDll") | table EventCode,CommandLine,ParentCommandLine,Image,User,TargetObject
CommandLine="dnscmd.exe /config /serverlevelplugindll *" | table EventCode,CommandLine,ParentCommandLine,Image,User,TargetObject
```


### logpoint
    
```
(event_id="13" TargetObject="*\\services\\DNS\\Parameters\\ServerLevelPluginDll")
CommandLine="dnscmd.exe /config /serverlevelplugindll *"
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\services\DNS\Parameters\ServerLevelPluginDll))'
grep -P '^dnscmd\.exe /config /serverlevelplugindll .*'
```



