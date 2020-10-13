| Title                    | Hurricane Panda Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects Hurricane Panda Activity |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/](https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Hurricane Panda Activity
id: 0eb2107b-a596-422e-b123-b389d5594ed7
author: Florian Roth
date: 2019/03/04
status: experimental
description: Detects Hurricane Panda Activity
references:
    - https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/
tags:
    - attack.privilege_escalation
    - attack.g0009
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* localgroup administrators admin /add'
            - '*\Win64.exe*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* localgroup administrators admin /add" -or $_.message -match "CommandLine.*.*\\Win64.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ localgroup\ administrators\ admin\ \/add OR *\\Win64.exe*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0eb2107b-a596-422e-b123-b389d5594ed7 <<EOF
{
  "metadata": {
    "title": "Hurricane Panda Activity",
    "description": "Detects Hurricane Panda Activity",
    "tags": [
      "attack.privilege_escalation",
      "attack.g0009",
      "attack.t1068"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ localgroup\\ administrators\\ admin\\ \\/add OR *\\\\Win64.exe*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ localgroup\\ administrators\\ admin\\ \\/add OR *\\\\Win64.exe*)",
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
        "subject": "Sigma Rule 'Hurricane Panda Activity'",
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
CommandLine.keyword:(* localgroup administrators admin \/add *\\Win64.exe*)
```


### splunk
    
```
(CommandLine="* localgroup administrators admin /add" OR CommandLine="*\\Win64.exe*")
```


### logpoint
    
```
CommandLine IN ["* localgroup administrators admin /add", "*\\Win64.exe*"]
```


### grep
    
```
grep -P '^(?:.*.* localgroup administrators admin /add|.*.*\Win64\.exe.*)'
```



