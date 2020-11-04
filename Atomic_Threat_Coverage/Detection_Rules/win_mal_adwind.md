| Title                    | Adwind RAT / JRAT       |
|:-------------------------|:------------------|
| **Description**          | Detects javaw.exe in AppData folder as used by Adwind / JRAT |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100](https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100)</li><li>[https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf](https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf)</li></ul>  |
| **Author**               | Florian Roth, Tom Ueltschi |


## Detection Rules

### Sigma rule

```
action: global
title: Adwind RAT / JRAT
id: 1fac1481-2dbc-48b2-9096-753c49b4ec71
status: experimental
description: Detects javaw.exe in AppData folder as used by Adwind / JRAT
references:
    - https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
    - https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf
author: Florian Roth, Tom Ueltschi
date: 2017/11/10
modified: 2018/12/11
tags:
    - attack.execution
    - attack.t1064
detection:
    condition: selection
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\AppData\Roaming\Oracle*\java*.exe *'
            - '*cscript.exe *Retrive*.vbs *'
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename:
            - '*\AppData\Roaming\Oracle\bin\java*.exe'
            - '*\Retrive*.vbs'
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*
        Details: '%AppData%\Roaming\Oracle\bin\\*'

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\AppData\\Roaming\\Oracle.*\\java.*.exe .*" -or $_.message -match "CommandLine.*.*cscript.exe .*Retrive.*.vbs .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*\\AppData\\Roaming\\Oracle\\bin\\java.*.exe" -or $_.message -match "TargetFilename.*.*\\Retrive.*.vbs")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "TargetObject.*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run.*" -and $_.message -match "Details.*%AppData%\\Roaming\\Oracle\\bin\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\AppData\\Roaming\\Oracle*\\java*.exe\ * OR *cscript.exe\ *Retrive*.vbs\ *)
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:(*\\AppData\\Roaming\\Oracle\\bin\\java*.exe OR *\\Retrive*.vbs))
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run* AND winlog.event_data.Details.keyword:%AppData%\\Roaming\\Oracle\\bin\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1fac1481-2dbc-48b2-9096-753c49b4ec71 <<EOF
{
  "metadata": {
    "title": "Adwind RAT / JRAT",
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "tags": [
      "attack.execution",
      "attack.t1064"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\AppData\\\\Roaming\\\\Oracle*\\\\java*.exe\\ * OR *cscript.exe\\ *Retrive*.vbs\\ *)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\AppData\\\\Roaming\\\\Oracle*\\\\java*.exe\\ * OR *cscript.exe\\ *Retrive*.vbs\\ *)",
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
        "subject": "Sigma Rule 'Adwind RAT / JRAT'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1fac1481-2dbc-48b2-9096-753c49b4ec71-2 <<EOF
{
  "metadata": {
    "title": "Adwind RAT / JRAT",
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "tags": [
      "attack.execution",
      "attack.t1064"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:(*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe OR *\\\\Retrive*.vbs))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:(*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe OR *\\\\Retrive*.vbs))",
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
        "subject": "Sigma Rule 'Adwind RAT / JRAT'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1fac1481-2dbc-48b2-9096-753c49b4ec71-3 <<EOF
{
  "metadata": {
    "title": "Adwind RAT / JRAT",
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "tags": [
      "attack.execution",
      "attack.t1064"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* AND winlog.event_data.Details.keyword:%AppData%\\\\Roaming\\\\Oracle\\\\bin\\\\*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* AND winlog.event_data.Details.keyword:%AppData%\\\\Roaming\\\\Oracle\\\\bin\\\\*)",
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
        "subject": "Sigma Rule 'Adwind RAT / JRAT'",
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
CommandLine.keyword:(*\\AppData\\Roaming\\Oracle*\\java*.exe * *cscript.exe *Retrive*.vbs *)
(EventID:"11" AND TargetFilename.keyword:(*\\AppData\\Roaming\\Oracle\\bin\\java*.exe *\\Retrive*.vbs))
(EventID:"13" AND TargetObject.keyword:HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run* AND Details.keyword:%AppData%\\Roaming\\Oracle\\bin\\*)
```


### splunk
    
```
(CommandLine="*\\AppData\\Roaming\\Oracle*\\java*.exe *" OR CommandLine="*cscript.exe *Retrive*.vbs *")
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" (TargetFilename="*\\AppData\\Roaming\\Oracle\\bin\\java*.exe" OR TargetFilename="*\\Retrive*.vbs"))
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" Details="%AppData%\\Roaming\\Oracle\\bin\\*")
```


### logpoint
    
```
CommandLine IN ["*\\AppData\\Roaming\\Oracle*\\java*.exe *", "*cscript.exe *Retrive*.vbs *"]
(event_id="11" TargetFilename IN ["*\\AppData\\Roaming\\Oracle\\bin\\java*.exe", "*\\Retrive*.vbs"])
(event_id="13" TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" Details="%AppData%\\Roaming\\Oracle\\bin\\*")
```


### grep
    
```
grep -P '^(?:.*.*\AppData\Roaming\Oracle.*\java.*\.exe .*|.*.*cscript\.exe .*Retrive.*\.vbs .*)'
grep -P '^(?:.*(?=.*11)(?=.*(?:.*.*\AppData\Roaming\Oracle\bin\java.*\.exe|.*.*\Retrive.*\.vbs)))'
grep -P '^(?:.*(?=.*13)(?=.*HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run.*)(?=.*%AppData%\Roaming\Oracle\bin\\.*))'
```



