| Title                    | Stop Windows Service       |
|:-------------------------|:------------------|
| **Description**          | Detects a windows service to be stopped |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1489: Service Stop](https://attack.mitre.org/techniques/T1489)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1489: Service Stop](../Triggers/T1489.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Administrator shutting down the service due to upgrade or removal purposes</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Jakob Weinzettl, oscd.community |


## Detection Rules

### Sigma rule

```
title: Stop Windows Service
id: eb87818d-db5d-49cc-a987-d5da331fbd90
description: Detects a windows service to be stopped
status: experimental
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2019/11/08
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith:
            - '\sc.exe'
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'stop'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Administrator shutting down the service due to upgrade or removal purposes
level: low

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\sc.exe" -or $_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*stop.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\sc.exe OR *\\net.exe OR *\\net1.exe) AND winlog.event_data.CommandLine.keyword:*stop*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/eb87818d-db5d-49cc-a987-d5da331fbd90 <<EOF
{
  "metadata": {
    "title": "Stop Windows Service",
    "description": "Detects a windows service to be stopped",
    "tags": [
      "attack.impact",
      "attack.t1489"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\sc.exe OR *\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*stop*)"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\sc.exe OR *\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*stop*)",
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
        "subject": "Sigma Rule 'Stop Windows Service'",
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
(Image.keyword:(*\\sc.exe *\\net.exe *\\net1.exe) AND CommandLine.keyword:*stop*)
```


### splunk
    
```
((Image="*\\sc.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*stop*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image IN ["*\\sc.exe", "*\\net.exe", "*\\net1.exe"] CommandLine="*stop*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\sc\.exe|.*.*\net\.exe|.*.*\net1\.exe))(?=.*.*stop.*))'
```



