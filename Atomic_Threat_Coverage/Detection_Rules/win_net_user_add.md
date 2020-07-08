| Title                    | Net.exe User Account Creation       |
|:-------------------------|:------------------|
| **Description**          | Identifies creation of local users via the net.exe command |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legit user creation</li><li>Better use event ids for user creation rather than command line rules</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html](https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.yaml)</li></ul>  |
| **Author**               | Endgame, JHasenbusch (adapted to sigma for oscd.community) |


## Detection Rules

### Sigma rule

```
title: Net.exe User Account Creation
id: cd219ff3-fa99-45d4-8380-a7d15116c6dc
status: experimental
description: Identifies creation of local users via the net.exe command
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.yaml
author: Endgame, JHasenbusch (adapted to sigma for oscd.community)
date: 2018/10/30
modified: 2019/11/11
tags:
    - attack.persistence
    - attack.credential_access
    - attack.t1136
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains|all: 
            - 'user'
            - 'add'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legit user creation
    - Better use event ids for user creation rather than command line rules
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*user.*" -and $_.message -match "CommandLine.*.*add.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\net.exe OR *\\net1.exe) AND winlog.event_data.CommandLine.keyword:*user* AND winlog.event_data.CommandLine.keyword:*add*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cd219ff3-fa99-45d4-8380-a7d15116c6dc <<EOF
{
  "metadata": {
    "title": "Net.exe User Account Creation",
    "description": "Identifies creation of local users via the net.exe command",
    "tags": [
      "attack.persistence",
      "attack.credential_access",
      "attack.t1136"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*user* AND winlog.event_data.CommandLine.keyword:*add*)"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*user* AND winlog.event_data.CommandLine.keyword:*add*)",
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
        "subject": "Sigma Rule 'Net.exe User Account Creation'",
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
(Image.keyword:(*\\net.exe *\\net1.exe) AND CommandLine.keyword:*user* AND CommandLine.keyword:*add*)
```


### splunk
    
```
((Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*user*" CommandLine="*add*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(event_id="1" Image IN ["*\\net.exe", "*\\net1.exe"] CommandLine="*user*" CommandLine="*add*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\net\.exe|.*.*\net1\.exe))(?=.*.*user.*)(?=.*.*add.*))'
```



