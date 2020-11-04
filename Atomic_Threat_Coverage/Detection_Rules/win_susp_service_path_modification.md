| Title                    | Suspicious Service Path Modification       |
|:-------------------------|:------------------|
| **Description**          | Detects service path modification to powershell/cmd |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1031: Modify Existing Service](https://attack.mitre.org/techniques/T1031)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1031: Modify Existing Service](../Triggers/T1031.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml)</li></ul>  |
| **Author**               | Victor Sergeev, oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious Service Path Modification
id: 138d3531-8793-4f50-a2cd-f291b2863d78
description: Detects service path modification to powershell/cmd
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml
tags:
    - attack.persistence
    - attack.t1031
date: 2019/10/21
modified: 2019/11/10
author: Victor Sergeev, oscd.community
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'config'
            - 'binpath'
    selection_2:
        CommandLine|contains:
            - 'powershell'
            - 'cmd'
    condition: selection_1 and selection_2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\sc.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*binpath.*" -and ($_.message -match "CommandLine.*.*powershell.*" -or $_.message -match "CommandLine.*.*cmd.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\sc.exe AND winlog.event_data.CommandLine.keyword:*config* AND winlog.event_data.CommandLine.keyword:*binpath* AND winlog.event_data.CommandLine.keyword:(*powershell* OR *cmd*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/138d3531-8793-4f50-a2cd-f291b2863d78 <<EOF
{
  "metadata": {
    "title": "Suspicious Service Path Modification",
    "description": "Detects service path modification to powershell/cmd",
    "tags": [
      "attack.persistence",
      "attack.t1031"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*config* AND winlog.event_data.CommandLine.keyword:*binpath* AND winlog.event_data.CommandLine.keyword:(*powershell* OR *cmd*))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*config* AND winlog.event_data.CommandLine.keyword:*binpath* AND winlog.event_data.CommandLine.keyword:(*powershell* OR *cmd*))",
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
        "subject": "Sigma Rule 'Suspicious Service Path Modification'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\sc.exe AND CommandLine.keyword:*config* AND CommandLine.keyword:*binpath* AND CommandLine.keyword:(*powershell* *cmd*))
```


### splunk
    
```
(Image="*\\sc.exe" CommandLine="*config*" CommandLine="*binpath*" (CommandLine="*powershell*" OR CommandLine="*cmd*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\sc.exe" CommandLine="*config*" CommandLine="*binpath*" CommandLine IN ["*powershell*", "*cmd*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\sc\.exe)(?=.*.*config.*)(?=.*.*binpath.*)(?=.*(?:.*.*powershell.*|.*.*cmd.*)))'
```



