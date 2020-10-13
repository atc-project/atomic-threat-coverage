| Title                    | HH.exe Execution       |
|:-------------------------|:------------------|
| **Description**          | Identifies usage of hh.exe executing recently modified .chm files. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.001: Compiled HTML File](https://attack.mitre.org/techniques/T1218/001)</li><li>[T1223: Compiled HTML File](https://attack.mitre.org/techniques/T1223)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.001: Compiled HTML File](../Triggers/T1218.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unlike</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1223/T1223.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1223/T1223.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/b25aa548-7937-11e9-8f5c-d46d6d62a49e.html](https://eqllib.readthedocs.io/en/latest/analytics/b25aa548-7937-11e9-8f5c-d46d6d62a49e.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Dan Beavin), oscd.community |


## Detection Rules

### Sigma rule

```
title: HH.exe Execution
id: 68c8acb4-1b60-4890-8e82-3ddf7a6dba84
description: Identifies usage of hh.exe executing recently modified .chm files.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Dan Beavin), oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1223/T1223.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/b25aa548-7937-11e9-8f5c-d46d6d62a49e.html
date: 2019/10/24
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.t1218.001
    - attack.execution  # an old one
    - attack.t1223  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\hh.exe'
        CommandLine|contains: '.chm'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - unlike
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\hh.exe" -and $_.message -match "CommandLine.*.*.chm.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\hh.exe AND winlog.event_data.CommandLine.keyword:*.chm*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/68c8acb4-1b60-4890-8e82-3ddf7a6dba84 <<EOF
{
  "metadata": {
    "title": "HH.exe Execution",
    "description": "Identifies usage of hh.exe executing recently modified .chm files.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1218.001",
      "attack.execution",
      "attack.t1223"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\hh.exe AND winlog.event_data.CommandLine.keyword:*.chm*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\hh.exe AND winlog.event_data.CommandLine.keyword:*.chm*)",
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
        "subject": "Sigma Rule 'HH.exe Execution'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\hh.exe AND CommandLine.keyword:*.chm*)
```


### splunk
    
```
(Image="*\\hh.exe" CommandLine="*.chm*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image="*\\hh.exe" CommandLine="*.chm*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\hh\.exe)(?=.*.*\.chm.*))'
```



