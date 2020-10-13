| Title                    | Suspicious Copy From or To System32       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious copy command that copies a system program from System32 to another directory on disk - sometimes used to use LOLBINs like certutil or desktopimgdownldr to a different location with a different name |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036.003: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036.003: Rename System Utilities](../Triggers/T1036.003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Admin scripts like https://www.itexperience.net/sccm-batch-files-and-32-bits-processes-on-64-bits-os/</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120](https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious Copy From or To System32
id: fff9d2b7-e11c-4a69-93d3-40ef66189767
status: experimental
description: Detects a suspicious copy command that copies a system program from System32 to another directory on disk - sometimes used to use LOLBINs like certutil or desktopimgdownldr to a different location with a different name
author: Florian Roth, Markus Neis
date: 2020/07/03
modified: 2020/09/05
references:
    - https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120
logsource:
    category: process_creation
    product: windows
tags:
    - attack.defense_evasion
    - attack.t1036.003
detection:
    selection:
        CommandLine|contains: 
            - ' /c copy *\System32\'
            - 'xcopy*\System32\'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Admin scripts like https://www.itexperience.net/sccm-batch-files-and-32-bits-processes-on-64-bits-os/
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* /c copy .*\\System32\\.*" -or $_.message -match "CommandLine.*.*xcopy.*\\System32\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ \/c\ copy\ *\\System32\\* OR *xcopy*\\System32\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fff9d2b7-e11c-4a69-93d3-40ef66189767 <<EOF
{
  "metadata": {
    "title": "Suspicious Copy From or To System32",
    "description": "Detects a suspicious copy command that copies a system program from System32 to another directory on disk - sometimes used to use LOLBINs like certutil or desktopimgdownldr to a different location with a different name",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036.003"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\/c\\ copy\\ *\\\\System32\\\\* OR *xcopy*\\\\System32\\\\*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\/c\\ copy\\ *\\\\System32\\\\* OR *xcopy*\\\\System32\\\\*)",
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
        "subject": "Sigma Rule 'Suspicious Copy From or To System32'",
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
CommandLine.keyword:(* \/c copy *\\System32\\* *xcopy*\\System32\\*)
```


### splunk
    
```
(CommandLine="* /c copy *\\System32\\*" OR CommandLine="*xcopy*\\System32\\*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["* /c copy *\\System32\\*", "*xcopy*\\System32\\*"]
```


### grep
    
```
grep -P '^(?:.*.* /c copy .*\System32\\.*|.*.*xcopy.*\System32\\.*)'
```



