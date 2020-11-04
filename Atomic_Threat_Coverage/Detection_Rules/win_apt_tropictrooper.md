| Title                    | TropicTrooper Campaign November 2018       |
|:-------------------------|:------------------|
| **Description**          | Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/](https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/)</li></ul>  |
| **Author**               | @41thexplorer, Microsoft Defender ATP |


## Detection Rules

### Sigma rule

```
title: TropicTrooper Campaign November 2018
id: 8c7090c3-e0a0-4944-bd08-08c3a0cecf79
author: '@41thexplorer, Microsoft Defender ATP'
status: stable
date: 2019/11/12
description: Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia
references:
    - https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/
tags:
    - attack.execution
    - attack.t1085
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*'
    condition: selection
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8c7090c3-e0a0-4944-bd08-08c3a0cecf79 <<EOF
{
  "metadata": {
    "title": "TropicTrooper Campaign November 2018",
    "description": "Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia",
    "tags": [
      "attack.execution",
      "attack.t1085"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*",
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
        "subject": "Sigma Rule 'TropicTrooper Campaign November 2018'",
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
CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*
```


### splunk
    
```
CommandLine="*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*"
```


### logpoint
    
```
CommandLine="*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*"
```


### grep
    
```
grep -P '^.*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc.*'
```



