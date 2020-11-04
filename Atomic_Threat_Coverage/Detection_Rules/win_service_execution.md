| Title                    | Service Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects manual service execution (start) via system utilities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrator or user executes a service for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Service Execution
id: 2a072a96-a086-49fa-bcb5-15cc5a619093
status: experimental
description: Detects manual service execution (start) via system utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: ' start ' # space character after the 'start' keyword indicates that a service name follows, in contrast to `net start` discovery expression 
    condition: selection
falsepositives:
    - Legitimate administrator or user executes a service for legitimate reason
level: low
tags:
    - attack.execution
    - attack.t1035

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.* start .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\net.exe OR *\\net1.exe) AND winlog.event_data.CommandLine.keyword:*\ start\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2a072a96-a086-49fa-bcb5-15cc5a619093 <<EOF
{
  "metadata": {
    "title": "Service Execution",
    "description": "Detects manual service execution (start) via system utilities",
    "tags": [
      "attack.execution",
      "attack.t1035"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*\\ start\\ *)"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*\\ start\\ *)",
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
        "subject": "Sigma Rule 'Service Execution'",
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
(Image.keyword:(*\\net.exe *\\net1.exe) AND CommandLine.keyword:* start *)
```


### splunk
    
```
((Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="* start *")
```


### logpoint
    
```
(Image IN ["*\\net.exe", "*\\net1.exe"] CommandLine="* start *")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\net\.exe|.*.*\net1\.exe))(?=.*.* start .*))'
```



