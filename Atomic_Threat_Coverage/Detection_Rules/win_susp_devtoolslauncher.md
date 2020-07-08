| Title                    | Devtoolslauncher.exe Executes Specified Binary       |
|:-------------------------|:------------------|
| **Description**          | The Devtoolslauncher.exe executes other binary |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate use of devtoolslauncher.exe by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml)</li><li>[https://twitter.com/_felamos/status/1179811992841797632](https://twitter.com/_felamos/status/1179811992841797632)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community (rule), @_felamos (idea) |


## Detection Rules

### Sigma rule

```
title: Devtoolslauncher.exe Executes Specified Binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: experimental
description: The Devtoolslauncher.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\devtoolslauncher.exe" -and $_.message -match "CommandLine.*.*LaunchForDeploy.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\devtoolslauncher.exe AND winlog.event_data.CommandLine.keyword:*LaunchForDeploy*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6 <<EOF
{
  "metadata": {
    "title": "Devtoolslauncher.exe Executes Specified Binary",
    "description": "The Devtoolslauncher.exe executes other binary",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1218"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\devtoolslauncher.exe AND winlog.event_data.CommandLine.keyword:*LaunchForDeploy*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\devtoolslauncher.exe AND winlog.event_data.CommandLine.keyword:*LaunchForDeploy*)",
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
        "subject": "Sigma Rule 'Devtoolslauncher.exe Executes Specified Binary'",
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
(Image.keyword:*\\devtoolslauncher.exe AND CommandLine.keyword:*LaunchForDeploy*)
```


### splunk
    
```
(Image="*\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*")
```


### logpoint
    
```
(event_id="1" Image="*\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\devtoolslauncher\.exe)(?=.*.*LaunchForDeploy.*))'
```



