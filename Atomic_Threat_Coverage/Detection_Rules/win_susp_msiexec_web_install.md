| Title                    | MsiExec Web Install       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious msiexec process starts with web addreses as parameter |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.007: Msiexec](https://attack.mitre.org/techniques/T1218/007)</li><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.007: Msiexec](../Triggers/T1218.007.md)</li><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/](https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: MsiExec Web Install
id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
status: experimental
description: Detects suspicious msiexec process starts with web addreses as parameter
references:
    - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
tags:
    - attack.defense_evasion
    - attack.t1218.007
    - attack.command_and_control
    - attack.t1105
author: Florian Roth
date: 2018/02/09
modified: 2020/08/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* msiexec*://*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* msiexec.*://.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ msiexec*\:\/\/*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f7b5f842-a6af-4da5-9e95-e32478f3cd2f <<EOF
{
  "metadata": {
    "title": "MsiExec Web Install",
    "description": "Detects suspicious msiexec process starts with web addreses as parameter",
    "tags": [
      "attack.defense_evasion",
      "attack.t1218.007",
      "attack.command_and_control",
      "attack.t1105"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ msiexec*\\:\\/\\/*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ msiexec*\\:\\/\\/*)",
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
        "subject": "Sigma Rule 'MsiExec Web Install'",
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
CommandLine.keyword:(* msiexec*\:\/\/*)
```


### splunk
    
```
(CommandLine="* msiexec*://*")
```


### logpoint
    
```
CommandLine IN ["* msiexec*://*"]
```


### grep
    
```
grep -P '^(?:.*.* msiexec.*://.*)'
```



