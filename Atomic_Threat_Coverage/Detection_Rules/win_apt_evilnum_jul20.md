| Title                    | EvilNum Golden Chickens Deployment via OCX Files       |
|:-------------------------|:------------------|
| **Description**          | Detects Golden Chickens deployment method as used by Evilnum in report published in July 2020 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218/011)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/2020/07/09/more-evil-deep-look-evilnum-toolset/](https://www.welivesecurity.com/2020/07/09/more-evil-deep-look-evilnum-toolset/)</li><li>[https://app.any.run/tasks/33d37fdf-158d-4930-aa68-813e1d5eb8ba/](https://app.any.run/tasks/33d37fdf-158d-4930-aa68-813e1d5eb8ba/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: EvilNum Golden Chickens Deployment via OCX Files
id: 8acf3cfa-1e8c-4099-83de-a0c4038e18f0
status: experimental
description: Detects Golden Chickens deployment method as used by Evilnum in report published in July 2020
references:
    - https://www.welivesecurity.com/2020/07/09/more-evil-deep-look-evilnum-toolset/
    - https://app.any.run/tasks/33d37fdf-158d-4930-aa68-813e1d5eb8ba/
author: Florian Roth
date: 2020/07/10
modified: 2020/08/27
tags:
    - attack.defense_evasion
    - attack.t1085 # an old one
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'regsvr32'
            - ' /s /i '
            - '\AppData\Roaming\'
            - '.ocx'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*regsvr32.*" -and $_.message -match "CommandLine.*.* /s /i .*" -and $_.message -match "CommandLine.*.*\\AppData\\Roaming\\.*" -and $_.message -match "CommandLine.*.*.ocx.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*regsvr32* AND winlog.event_data.CommandLine.keyword:*\ \/s\ \/i\ * AND winlog.event_data.CommandLine.keyword:*\\AppData\\Roaming\\* AND winlog.event_data.CommandLine.keyword:*.ocx*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8acf3cfa-1e8c-4099-83de-a0c4038e18f0 <<EOF
{
  "metadata": {
    "title": "EvilNum Golden Chickens Deployment via OCX Files",
    "description": "Detects Golden Chickens deployment method as used by Evilnum in report published in July 2020",
    "tags": [
      "attack.defense_evasion",
      "attack.t1085",
      "attack.t1218.011"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*regsvr32* AND winlog.event_data.CommandLine.keyword:*\\ \\/s\\ \\/i\\ * AND winlog.event_data.CommandLine.keyword:*\\\\AppData\\\\Roaming\\\\* AND winlog.event_data.CommandLine.keyword:*.ocx*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*regsvr32* AND winlog.event_data.CommandLine.keyword:*\\ \\/s\\ \\/i\\ * AND winlog.event_data.CommandLine.keyword:*\\\\AppData\\\\Roaming\\\\* AND winlog.event_data.CommandLine.keyword:*.ocx*)",
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
        "subject": "Sigma Rule 'EvilNum Golden Chickens Deployment via OCX Files'",
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
(CommandLine.keyword:*regsvr32* AND CommandLine.keyword:* \/s \/i * AND CommandLine.keyword:*\\AppData\\Roaming\\* AND CommandLine.keyword:*.ocx*)
```


### splunk
    
```
(CommandLine="*regsvr32*" CommandLine="* /s /i *" CommandLine="*\\AppData\\Roaming\\*" CommandLine="*.ocx*")
```


### logpoint
    
```
(CommandLine="*regsvr32*" CommandLine="* /s /i *" CommandLine="*\\AppData\\Roaming\\*" CommandLine="*.ocx*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*regsvr32.*)(?=.*.* /s /i .*)(?=.*.*\AppData\Roaming\\.*)(?=.*.*\.ocx.*))'
```



