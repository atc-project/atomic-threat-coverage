| Title                    | Fireball Archer Install       |
|:-------------------------|:------------------|
| **Description**          | Detects Archer malware invocation via rundll32 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218/011)</li><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.virustotal.com/en/file/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022/analysis/](https://www.virustotal.com/en/file/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022/analysis/)</li><li>[https://www.hybrid-analysis.com/sample/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022?environmentId=100](https://www.hybrid-analysis.com/sample/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022?environmentId=100)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Fireball Archer Install
id: 3d4aebe0-6d29-45b2-a8a4-3dfde586a26d
status: experimental
description: Detects Archer malware invocation via rundll32
author: Florian Roth
date: 2017/06/03
modified: 2020/08/29
references:
    - https://www.virustotal.com/en/file/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022/analysis/
    - https://www.hybrid-analysis.com/sample/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022?environmentId=100
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218.011
    - attack.t1085  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\rundll32.exe *,InstallArcherSvc'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*\\rundll32.exe .*,InstallArcherSvc" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\rundll32.exe\ *,InstallArcherSvc
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3d4aebe0-6d29-45b2-a8a4-3dfde586a26d <<EOF
{
  "metadata": {
    "title": "Fireball Archer Install",
    "description": "Detects Archer malware invocation via rundll32",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.t1218.011",
      "attack.t1085"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\\\rundll32.exe\\ *,InstallArcherSvc"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\\\rundll32.exe\\ *,InstallArcherSvc",
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
        "subject": "Sigma Rule 'Fireball Archer Install'",
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
CommandLine.keyword:*\\rundll32.exe *,InstallArcherSvc
```


### splunk
    
```
CommandLine="*\\rundll32.exe *,InstallArcherSvc" | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine="*\\rundll32.exe *,InstallArcherSvc"
```


### grep
    
```
grep -P '^.*\rundll32\.exe .*,InstallArcherSvc'
```



