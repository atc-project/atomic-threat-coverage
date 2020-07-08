| Title                    | Equation Group DLL_U Load       |
|:-------------------------|:------------------|
| **Description**          | Detects a specific tool and export used by EquationGroup |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=](https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=)</li><li>[https://securelist.com/apt-slingshot/84312/](https://securelist.com/apt-slingshot/84312/)</li><li>[https://twitter.com/cyb3rops/status/972186477512839170](https://twitter.com/cyb3rops/status/972186477512839170)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0020</li><li>attack.t1218.011</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Equation Group DLL_U Load
id: d465d1d8-27a2-4cca-9621-a800f37cf72e
author: Florian Roth
date: 2019/03/04
description: Detects a specific tool and export used by EquationGroup
references:
    - https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=
    - https://securelist.com/apt-slingshot/84312/
    - https://twitter.com/cyb3rops/status/972186477512839170
tags:
    - attack.execution
    - attack.g0020
    - attack.t1059
    - attack.defense_evasion
    - attack.t1085
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\rundll32.exe'
        CommandLine: '*,dll_u'
    selection2:
        CommandLine: '* -export dll_u *'
    condition: 1 of them
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*,dll_u") -or $_.message -match "CommandLine.*.* -export dll_u .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*,dll_u) OR winlog.event_data.CommandLine.keyword:*\ \-export\ dll_u\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d465d1d8-27a2-4cca-9621-a800f37cf72e <<EOF
{
  "metadata": {
    "title": "Equation Group DLL_U Load",
    "description": "Detects a specific tool and export used by EquationGroup",
    "tags": [
      "attack.execution",
      "attack.g0020",
      "attack.t1059",
      "attack.defense_evasion",
      "attack.t1085",
      "attack.t1218.011"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*,dll_u) OR winlog.event_data.CommandLine.keyword:*\\ \\-export\\ dll_u\\ *)"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*,dll_u) OR winlog.event_data.CommandLine.keyword:*\\ \\-export\\ dll_u\\ *)",
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
        "subject": "Sigma Rule 'Equation Group DLL_U Load'",
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
((Image.keyword:*\\rundll32.exe AND CommandLine.keyword:*,dll_u) OR CommandLine.keyword:* \-export dll_u *)
```


### splunk
    
```
((Image="*\\rundll32.exe" CommandLine="*,dll_u") OR CommandLine="* -export dll_u *")
```


### logpoint
    
```
(event_id="1" ((Image="*\\rundll32.exe" CommandLine="*,dll_u") OR CommandLine="* -export dll_u *"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\rundll32\.exe)(?=.*.*,dll_u))|.*.* -export dll_u .*))'
```



