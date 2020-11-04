| Title                    | Windows Network Enumeration       |
|:-------------------------|:------------------|
| **Description**          | Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1018: Remote System Discovery](https://attack.mitre.org/techniques/T1018)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1018: Remote System Discovery](../Triggers/T1018.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate use of net.exe utility by legitimate user</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html](https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.yaml)</li></ul>  |
| **Author**               | Endgame, JHasenbusch (ported for oscd.community) |


## Detection Rules

### Sigma rule

```
title: Windows Network Enumeration
id: 62510e69-616b-4078-b371-847da438cc03
status: stable
description: Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.yaml
author: Endgame, JHasenbusch (ported for oscd.community)
date: 2018/10/30
modified: 2019/11/11
tags:
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'view'
    filter:
        CommandLine|contains: '\\'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate use of net.exe utility by legitimate user
level: low 

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*view.*") -and  -not ($_.message -match "CommandLine.*.*\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:(*\\net.exe OR *\\net1.exe) AND winlog.event_data.CommandLine.keyword:*view*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/62510e69-616b-4078-b371-847da438cc03 <<EOF
{
  "metadata": {
    "title": "Windows Network Enumeration",
    "description": "Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.",
    "tags": [
      "attack.discovery",
      "attack.t1018"
    ],
    "query": "((winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*view*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\*)))"
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
                    "query": "((winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*view*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\*)))",
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
        "subject": "Sigma Rule 'Windows Network Enumeration'",
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
((Image.keyword:(*\\net.exe *\\net1.exe) AND CommandLine.keyword:*view*) AND (NOT (CommandLine.keyword:*\\*)))
```


### splunk
    
```
(((Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*view*") NOT (CommandLine="*\\*")) | table ComputerName,User,CommandLine
```


### logpoint
    
```
((Image IN ["*\\net.exe", "*\\net1.exe"] CommandLine="*view*")  -(CommandLine="*\\*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*.*\net\.exe|.*.*\net1\.exe))(?=.*.*view.*)))(?=.*(?!.*(?:.*(?=.*.*\\.*)))))'
```



