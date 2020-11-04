| Title                    | Data Compressed - rar.exe       |
|:-------------------------|:------------------|
| **Description**          | An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>highly likely if rar is default archiver in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html](https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html)</li></ul>  |
| **Author**               | Timur Zinniatullin, E.M. Anhaus, oscd.community |


## Detection Rules

### Sigma rule

```
title: Data Compressed - rar.exe
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network
author: Timur Zinniatullin, E.M. Anhaus, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rar.exe'
        CommandLine|contains: ' a '
    condition: selection
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
falsepositives:
    - highly likely if rar is default archiver in the monitored environment
level: low
tags:
    - attack.exfiltration
    - attack.t1002
```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\rar.exe" -and $_.message -match "CommandLine.*.* a .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\rar.exe AND winlog.event_data.CommandLine.keyword:*\ a\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6f3e2987-db24-4c78-a860-b4f4095a7095 <<EOF
{
  "metadata": {
    "title": "Data Compressed - rar.exe",
    "description": "An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network",
    "tags": [
      "attack.exfiltration",
      "attack.t1002"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\rar.exe AND winlog.event_data.CommandLine.keyword:*\\ a\\ *)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\rar.exe AND winlog.event_data.CommandLine.keyword:*\\ a\\ *)",
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
        "subject": "Sigma Rule 'Data Compressed - rar.exe'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n            Image = {{_source.Image}}\n      CommandLine = {{_source.CommandLine}}\n             User = {{_source.User}}\n        LogonGuid = {{_source.LogonGuid}}\n           Hashes = {{_source.Hashes}}\nParentProcessGuid = {{_source.ParentProcessGuid}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\rar.exe AND CommandLine.keyword:* a *)
```


### splunk
    
```
(Image="*\\rar.exe" CommandLine="* a *") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(Image="*\\rar.exe" CommandLine="* a *")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\rar\.exe)(?=.*.* a .*))'
```



