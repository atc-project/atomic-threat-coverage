| Title                    | Sysprep on AppData Folder       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets](https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets)</li><li>[https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b](https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Sysprep on AppData Folder
id: d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e
status: experimental
description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
references:
    - https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
    - https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b
tags:
    - attack.execution
author: Florian Roth
date: 2018/06/22
modified: 2018/12/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\sysprep.exe *\AppData\\*'
            - sysprep.exe *\AppData\\*
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\sysprep.exe .*\\AppData\\.*" -or $_.message -match "CommandLine.*sysprep.exe .*\\AppData\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\sysprep.exe\ *\\AppData\\* OR sysprep.exe\ *\\AppData\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e <<EOF
{
  "metadata": {
    "title": "Sysprep on AppData Folder",
    "description": "Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)",
    "tags": [
      "attack.execution"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\sysprep.exe\\ *\\\\AppData\\\\* OR sysprep.exe\\ *\\\\AppData\\\\*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\sysprep.exe\\ *\\\\AppData\\\\* OR sysprep.exe\\ *\\\\AppData\\\\*)",
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
        "subject": "Sigma Rule 'Sysprep on AppData Folder'",
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
CommandLine.keyword:(*\\sysprep.exe *\\AppData\\* sysprep.exe *\\AppData\\*)
```


### splunk
    
```
(CommandLine="*\\sysprep.exe *\\AppData\\*" OR CommandLine="sysprep.exe *\\AppData\\*")
```


### logpoint
    
```
CommandLine IN ["*\\sysprep.exe *\\AppData\\*", "sysprep.exe *\\AppData\\*"]
```


### grep
    
```
grep -P '^(?:.*.*\sysprep\.exe .*\AppData\\.*|.*sysprep\.exe .*\AppData\\.*)'
```



