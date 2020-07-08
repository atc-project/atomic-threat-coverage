| Title                    | Suspicious Call by Ordinal       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious calls of DLLs in rundll32.dll exports by ordinal |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Windows contol panel elements have been identified as source (mmc)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/](https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/)</li><li>[https://github.com/Neo23x0/DLLRunner](https://github.com/Neo23x0/DLLRunner)</li><li>[https://twitter.com/cyb3rops/status/1186631731543236608](https://twitter.com/cyb3rops/status/1186631731543236608)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1218.011</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Call by Ordinal
id: e79a9e79-eb72-4e78-a628-0e7e8f59e89c
description: Detects suspicious calls of DLLs in rundll32.dll exports by ordinal
status: experimental
references:
    - https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
    - https://github.com/Neo23x0/DLLRunner
    - https://twitter.com/cyb3rops/status/1186631731543236608
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
    - attack.t1218.011
author: Florian Roth
date: 2019/10/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\rundll32.exe *,#*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Windows contol panel elements have been identified as source (mmc)
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\rundll32.exe .*,#.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\rundll32.exe\ *,#*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e79a9e79-eb72-4e78-a628-0e7e8f59e89c <<EOF
{
  "metadata": {
    "title": "Suspicious Call by Ordinal",
    "description": "Detects suspicious calls of DLLs in rundll32.dll exports by ordinal",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1085",
      "attack.t1218.011"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\\\rundll32.exe\\ *,#*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\\\rundll32.exe\\ *,#*",
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
        "subject": "Sigma Rule 'Suspicious Call by Ordinal'",
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
CommandLine.keyword:*\\rundll32.exe *,#*
```


### splunk
    
```
CommandLine="*\\rundll32.exe *,#*"
```


### logpoint
    
```
(event_id="1" CommandLine="*\\rundll32.exe *,#*")
```


### grep
    
```
grep -P '^.*\rundll32\.exe .*,#.*'
```



