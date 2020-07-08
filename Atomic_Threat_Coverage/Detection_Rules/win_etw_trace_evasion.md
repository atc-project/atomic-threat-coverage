| Title                    | Disable of ETW Trace       |
|:-------------------------|:------------------|
| **Description**          | Detects a command that clears or disables any ETW trace log which could indicate a logging evasion. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1551: None](https://attack.mitre.org/techniques/T1551)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1551: None](../Triggers/T1551.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)</li><li>[https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml)</li><li>[https://abuse.io/lockergoga.txt](https://abuse.io/lockergoga.txt)</li></ul>  |
| **Author**               | @neu5ron, Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Disable of ETW Trace
id: a238b5d0-ce2d-4414-a676-7a531b3d13d6
description: Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml
    - https://abuse.io/lockergoga.txt
author: '@neu5ron, Florian Roth'
date: 2019/03/22
tags:
    - attack.execution
    - attack.t1070
    - car.2016-04-002
    - attack.t1551
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_clear_1:
        CommandLine: '* cl */Trace*'
    selection_clear_2:
        CommandLine: '* clear-log */Trace*'
    selection_disable_1:
        CommandLine: '* sl* /e:false*'
    selection_disable_2:
        CommandLine: '* set-log* /e:false*'
    condition: selection_clear_1 or selection_clear_2 or selection_disable_1 or selection_disable_2
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.* cl .*/Trace.*" -or $_.message -match "CommandLine.*.* clear-log .*/Trace.*" -or $_.message -match "CommandLine.*.* sl.* /e:false.*" -or $_.message -match "CommandLine.*.* set-log.* /e:false.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*\ cl\ *\/Trace* OR winlog.event_data.CommandLine.keyword:*\ clear\-log\ *\/Trace* OR winlog.event_data.CommandLine.keyword:*\ sl*\ \/e\:false* OR winlog.event_data.CommandLine.keyword:*\ set\-log*\ \/e\:false*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a238b5d0-ce2d-4414-a676-7a531b3d13d6 <<EOF
{
  "metadata": {
    "title": "Disable of ETW Trace",
    "description": "Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.",
    "tags": [
      "attack.execution",
      "attack.t1070",
      "car.2016-04-002",
      "attack.t1551"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*\\ cl\\ *\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\ clear\\-log\\ *\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\ sl*\\ \\/e\\:false* OR winlog.event_data.CommandLine.keyword:*\\ set\\-log*\\ \\/e\\:false*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*\\ cl\\ *\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\ clear\\-log\\ *\\/Trace* OR winlog.event_data.CommandLine.keyword:*\\ sl*\\ \\/e\\:false* OR winlog.event_data.CommandLine.keyword:*\\ set\\-log*\\ \\/e\\:false*)",
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
        "subject": "Sigma Rule 'Disable of ETW Trace'",
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
(CommandLine.keyword:* cl *\/Trace* OR CommandLine.keyword:* clear\-log *\/Trace* OR CommandLine.keyword:* sl* \/e\:false* OR CommandLine.keyword:* set\-log* \/e\:false*)
```


### splunk
    
```
(CommandLine="* cl */Trace*" OR CommandLine="* clear-log */Trace*" OR CommandLine="* sl* /e:false*" OR CommandLine="* set-log* /e:false*")
```


### logpoint
    
```
(event_id="1" (CommandLine="* cl */Trace*" OR CommandLine="* clear-log */Trace*" OR CommandLine="* sl* /e:false*" OR CommandLine="* set-log* /e:false*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*.* cl .*/Trace.*|.*.* clear-log .*/Trace.*|.*.* sl.* /e:false.*|.*.* set-log.* /e:false.*))'
```



