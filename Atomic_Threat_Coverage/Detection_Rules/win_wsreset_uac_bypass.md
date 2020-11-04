| Title                    | Wsreset UAC Bypass       |
|:-------------------------|:------------------|
| **Description**          | Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown sub processes of Wsreset.exe</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://lolbas-project.github.io/lolbas/Binaries/Wsreset/](https://lolbas-project.github.io/lolbas/Binaries/Wsreset/)</li><li>[https://www.activecyber.us/activelabs/windows-uac-bypass](https://www.activecyber.us/activelabs/windows-uac-bypass)</li><li>[https://twitter.com/ReaQta/status/1222548288731217921](https://twitter.com/ReaQta/status/1222548288731217921)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Wsreset UAC Bypass
id: bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae
status: experimental
description: Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC 
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
    - https://www.activecyber.us/activelabs/windows-uac-bypass
    - https://twitter.com/ReaQta/status/1222548288731217921
author: Florian Roth
date: 2020/01/30
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1088
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WSreset.exe'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unknown sub processes of Wsreset.exe
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\WSreset.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.ParentImage.keyword:(*\\WSreset.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae <<EOF
{
  "metadata": {
    "title": "Wsreset UAC Bypass",
    "description": "Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1088"
    ],
    "query": "winlog.event_data.ParentImage.keyword:(*\\\\WSreset.exe)"
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
                    "query": "winlog.event_data.ParentImage.keyword:(*\\\\WSreset.exe)",
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
        "subject": "Sigma Rule 'Wsreset UAC Bypass'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nCommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
ParentImage.keyword:(*\\WSreset.exe)
```


### splunk
    
```
(ParentImage="*\\WSreset.exe") | table CommandLine
```


### logpoint
    
```
ParentImage IN ["*\\WSreset.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\WSreset\.exe)'
```



