| Title                    | Unidentified Attacker November 2018       |
|:-------------------------|:------------------|
| **Description**          | A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://twitter.com/DrunkBinary/status/1063075530180886529](https://twitter.com/DrunkBinary/status/1063075530180886529)</li></ul>  |
| **Author**               | @41thexplorer, Microsoft Defender ATP |


## Detection Rules

### Sigma rule

```
action: global
title: Unidentified Attacker November 2018
id: 7453575c-a747-40b9-839b-125a0aae324b
status: stable
description: A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with
    YYTRIUM/APT29 campaign in 2016.
references:
    - https://twitter.com/DrunkBinary/status/1063075530180886529
author: '@41thexplorer, Microsoft Defender ATP'
date: 2018/11/20
modified: 2018/12/11
tags:
    - attack.execution
    - attack.t1085
detection:
    condition: 1 of them
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*cyzfc.dat, PointFunctionCall'
---
# Sysmon: File Creation (ID 11)
logsource:
    product: windows
    service: sysmon
detection:
    selection2:
        EventID: 11
        TargetFilename: 
            - '*ds7002.lnk*' 
```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*cyzfc.dat, PointFunctionCall" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*ds7002.lnk.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*cyzfc.dat,\ PointFunctionCall
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:(*ds7002.lnk*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7453575c-a747-40b9-839b-125a0aae324b <<EOF
{
  "metadata": {
    "title": "Unidentified Attacker November 2018",
    "description": "A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016.",
    "tags": [
      "attack.execution",
      "attack.t1085"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*cyzfc.dat,\\ PointFunctionCall"
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
                    "query": "winlog.event_data.CommandLine.keyword:*cyzfc.dat,\\ PointFunctionCall",
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
        "subject": "Sigma Rule 'Unidentified Attacker November 2018'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7453575c-a747-40b9-839b-125a0aae324b-2 <<EOF
{
  "metadata": {
    "title": "Unidentified Attacker November 2018",
    "description": "A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016.",
    "tags": [
      "attack.execution",
      "attack.t1085"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:(*ds7002.lnk*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:(*ds7002.lnk*))",
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
        "subject": "Sigma Rule 'Unidentified Attacker November 2018'",
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
CommandLine.keyword:*cyzfc.dat, PointFunctionCall
(EventID:"11" AND TargetFilename.keyword:(*ds7002.lnk*))
```


### splunk
    
```
CommandLine="*cyzfc.dat, PointFunctionCall"
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" (TargetFilename="*ds7002.lnk*"))
```


### logpoint
    
```
CommandLine="*cyzfc.dat, PointFunctionCall"
(event_id="11" TargetFilename IN ["*ds7002.lnk*"])
```


### grep
    
```
grep -P '^.*cyzfc\.dat, PointFunctionCall'
grep -P '^(?:.*(?=.*11)(?=.*(?:.*.*ds7002\.lnk.*)))'
```



