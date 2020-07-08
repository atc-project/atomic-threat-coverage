| Title                    | Suspicious Netsh DLL Persistence       |
|:-------------------------|:------------------|
| **Description**          | Detects persitence via netsh helper |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1128: Netsh Helper DLL](https://attack.mitre.org/techniques/T1128)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | testing |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1128/T1128.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1128/T1128.md)</li></ul>  |
| **Author**               | Victor Sergeev, oscd.community |
| Other Tags           | <ul><li>attack.t1546.007</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Netsh DLL Persistence
id: 56321594-9087-49d9-bf10-524fe8479452
description: Detects persitence via netsh helper
status: testing
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1128/T1128.md
tags:
    - attack.persistence
    - attack.t1128
    - attack.t1546.007
date: 2019/10/25
modified: 2019/10/25
author: Victor Sergeev, oscd.community
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'add'
            - 'helper'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and $_.message -match "CommandLine.*.*add.*" -and $_.message -match "CommandLine.*.*helper.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\netsh.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:*helper*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/56321594-9087-49d9-bf10-524fe8479452 <<EOF
{
  "metadata": {
    "title": "Suspicious Netsh DLL Persistence",
    "description": "Detects persitence via netsh helper",
    "tags": [
      "attack.persistence",
      "attack.t1128",
      "attack.t1546.007"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\netsh.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:*helper*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\netsh.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:*helper*)",
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
        "subject": "Sigma Rule 'Suspicious Netsh DLL Persistence'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     ComputerName = {{_source.ComputerName}}\n             User = {{_source.User}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\netsh.exe AND CommandLine.keyword:*add* AND CommandLine.keyword:*helper*)
```


### splunk
    
```
(Image="*\\netsh.exe" CommandLine="*add*" CommandLine="*helper*") | table ComputerName,User,CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\netsh.exe" CommandLine="*add*" CommandLine="*helper*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\netsh\.exe)(?=.*.*add.*)(?=.*.*helper.*))'
```



