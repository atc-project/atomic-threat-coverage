| Title                    | Modification of Boot Configuration       |
|:-------------------------|:------------------|
| **Description**          | Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1490: Inhibit System Recovery](../Triggers/T1490.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/c4732632-9c1d-4980-9fa8-1d98c93f918e.html](https://eqllib.readthedocs.io/en/latest/analytics/c4732632-9c1d-4980-9fa8-1d98c93f918e.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Modification of Boot Configuration
id: 1444443e-6757-43e4-9ea4-c8fc705f79a2
description: Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive
    technique.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/c4732632-9c1d-4980-9fa8-1d98c93f918e.html
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: \bcdedit.exe
        CommandLine|contains: set
    selection2:
        - CommandLine|contains|all:
            - bootstatuspolicy
            - ignoreallfailures
        - CommandLine|contains|all:
            - recoveryenabled
            - 'no'
    condition: selection1 and selection2
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unlikely
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\bcdedit.exe" -and $_.message -match "CommandLine.*.*set.*") -and (($_.message -match "CommandLine.*.*bootstatuspolicy.*" -and $_.message -match "CommandLine.*.*ignoreallfailures.*") -or ($_.message -match "CommandLine.*.*recoveryenabled.*" -and $_.message -match "CommandLine.*.*no.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\bcdedit.exe AND winlog.event_data.CommandLine.keyword:*set*) AND ((winlog.event_data.CommandLine.keyword:*bootstatuspolicy* AND winlog.event_data.CommandLine.keyword:*ignoreallfailures*) OR (winlog.event_data.CommandLine.keyword:*recoveryenabled* AND winlog.event_data.CommandLine.keyword:*no*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1444443e-6757-43e4-9ea4-c8fc705f79a2 <<EOF
{
  "metadata": {
    "title": "Modification of Boot Configuration",
    "description": "Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique.",
    "tags": [
      "attack.impact",
      "attack.t1490"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\bcdedit.exe AND winlog.event_data.CommandLine.keyword:*set*) AND ((winlog.event_data.CommandLine.keyword:*bootstatuspolicy* AND winlog.event_data.CommandLine.keyword:*ignoreallfailures*) OR (winlog.event_data.CommandLine.keyword:*recoveryenabled* AND winlog.event_data.CommandLine.keyword:*no*)))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\bcdedit.exe AND winlog.event_data.CommandLine.keyword:*set*) AND ((winlog.event_data.CommandLine.keyword:*bootstatuspolicy* AND winlog.event_data.CommandLine.keyword:*ignoreallfailures*) OR (winlog.event_data.CommandLine.keyword:*recoveryenabled* AND winlog.event_data.CommandLine.keyword:*no*)))",
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
        "subject": "Sigma Rule 'Modification of Boot Configuration'",
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
((Image.keyword:*\\bcdedit.exe AND CommandLine.keyword:*set*) AND ((CommandLine.keyword:*bootstatuspolicy* AND CommandLine.keyword:*ignoreallfailures*) OR (CommandLine.keyword:*recoveryenabled* AND CommandLine.keyword:*no*)))
```


### splunk
    
```
((Image="*\\bcdedit.exe" CommandLine="*set*") ((CommandLine="*bootstatuspolicy*" CommandLine="*ignoreallfailures*") OR (CommandLine="*recoveryenabled*" CommandLine="*no*"))) | table ComputerName,User,CommandLine
```


### logpoint
    
```
((Image="*\\bcdedit.exe" CommandLine="*set*") ((CommandLine="*bootstatuspolicy*" CommandLine="*ignoreallfailures*") OR (CommandLine="*recoveryenabled*" CommandLine="*no*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\bcdedit\.exe)(?=.*.*set.*)))(?=.*(?:.*(?:.*(?:.*(?=.*.*bootstatuspolicy.*)(?=.*.*ignoreallfailures.*))|.*(?:.*(?=.*.*recoveryenabled.*)(?=.*.*no.*))))))'
```



