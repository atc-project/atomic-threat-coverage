| Title                    | WMI Spawning Windows PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects WMI spawning PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>AppvClient</li><li>CCM</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml)</li><li>[https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e](https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e)</li></ul>  |
| **Author**               | Markus Neis / @Karneades |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: WMI Spawning Windows PowerShell
id: 692f0bec-83ba-4d04-af7e-e884a96059b6
status: experimental
description: Detects WMI spawning PowerShell
references:
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml
    - https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e
author: Markus Neis / @Karneades
date: 2019/04/03
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1064
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wmiprvse.exe'
        Image:
            - '*\powershell.exe'
    condition: selection
falsepositives:
    - AppvClient
    - CCM
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\wmiprvse.exe") -and ($_.message -match "Image.*.*\\powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\wmiprvse.exe) AND winlog.event_data.Image.keyword:(*\\powershell.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/692f0bec-83ba-4d04-af7e-e884a96059b6 <<EOF
{
  "metadata": {
    "title": "WMI Spawning Windows PowerShell",
    "description": "Detects WMI spawning PowerShell",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.t1064",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\wmiprvse.exe) AND winlog.event_data.Image.keyword:(*\\\\powershell.exe))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\wmiprvse.exe) AND winlog.event_data.Image.keyword:(*\\\\powershell.exe))",
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
        "subject": "Sigma Rule 'WMI Spawning Windows PowerShell'",
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
(ParentImage.keyword:(*\\wmiprvse.exe) AND Image.keyword:(*\\powershell.exe))
```


### splunk
    
```
((ParentImage="*\\wmiprvse.exe") (Image="*\\powershell.exe"))
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\wmiprvse.exe"] Image IN ["*\\powershell.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\wmiprvse\.exe))(?=.*(?:.*.*\powershell\.exe)))'
```



