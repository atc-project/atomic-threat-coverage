| Title                    | Encoded IEX       |
|:-------------------------|:------------------|
| **Description**          | Detects a base64 encoded IEX command string in a process command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1059.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Encoded IEX
id: 88f680b8-070e-402c-ae11-d2914f2257f1
status: experimental
description: Detects a base64 encoded IEX command string in a process command line
author: Florian Roth
date: 2019/08/23
tags:
    - attack.t1086
    - attack.t1140
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains:
            - 'IEX (['
            - 'iex (['
            - 'iex (New'
            - 'IEX (New'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*SUVYIChb.*" -or $_.message -match "CommandLine.*.*lFWCAoW.*" -or $_.message -match "CommandLine.*.*JRVggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChb.*" -or $_.message -match "CommandLine.*.*lleCAoW.*" -or $_.message -match "CommandLine.*.*pZXggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChOZX.*" -or $_.message -match "CommandLine.*.*lleCAoTmV3.*" -or $_.message -match "CommandLine.*.*pZXggKE5ld.*" -or $_.message -match "CommandLine.*.*SUVYIChOZX.*" -or $_.message -match "CommandLine.*.*lFWCAoTmV3.*" -or $_.message -match "CommandLine.*.*JRVggKE5ld.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*SUVYIChb* OR *lFWCAoW* OR *JRVggKF* OR *aWV4IChb* OR *lleCAoW* OR *pZXggKF* OR *aWV4IChOZX* OR *lleCAoTmV3* OR *pZXggKE5ld* OR *SUVYIChOZX* OR *lFWCAoTmV3* OR *JRVggKE5ld*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/88f680b8-070e-402c-ae11-d2914f2257f1 <<EOF
{
  "metadata": {
    "title": "Encoded IEX",
    "description": "Detects a base64 encoded IEX command string in a process command line",
    "tags": [
      "attack.t1086",
      "attack.t1140",
      "attack.execution",
      "attack.t1059.003"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*SUVYIChb* OR *lFWCAoW* OR *JRVggKF* OR *aWV4IChb* OR *lleCAoW* OR *pZXggKF* OR *aWV4IChOZX* OR *lleCAoTmV3* OR *pZXggKE5ld* OR *SUVYIChOZX* OR *lFWCAoTmV3* OR *JRVggKE5ld*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*SUVYIChb* OR *lFWCAoW* OR *JRVggKF* OR *aWV4IChb* OR *lleCAoW* OR *pZXggKF* OR *aWV4IChOZX* OR *lleCAoTmV3* OR *pZXggKE5ld* OR *SUVYIChOZX* OR *lFWCAoTmV3* OR *JRVggKE5ld*)",
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
        "subject": "Sigma Rule 'Encoded IEX'",
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
CommandLine.keyword:(*SUVYIChb* *lFWCAoW* *JRVggKF* *aWV4IChb* *lleCAoW* *pZXggKF* *aWV4IChOZX* *lleCAoTmV3* *pZXggKE5ld* *SUVYIChOZX* *lFWCAoTmV3* *JRVggKE5ld*)
```


### splunk
    
```
(CommandLine="*SUVYIChb*" OR CommandLine="*lFWCAoW*" OR CommandLine="*JRVggKF*" OR CommandLine="*aWV4IChb*" OR CommandLine="*lleCAoW*" OR CommandLine="*pZXggKF*" OR CommandLine="*aWV4IChOZX*" OR CommandLine="*lleCAoTmV3*" OR CommandLine="*pZXggKE5ld*" OR CommandLine="*SUVYIChOZX*" OR CommandLine="*lFWCAoTmV3*" OR CommandLine="*JRVggKE5ld*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*SUVYIChb*", "*lFWCAoW*", "*JRVggKF*", "*aWV4IChb*", "*lleCAoW*", "*pZXggKF*", "*aWV4IChOZX*", "*lleCAoTmV3*", "*pZXggKE5ld*", "*SUVYIChOZX*", "*lFWCAoTmV3*", "*JRVggKE5ld*"])
```


### grep
    
```
grep -P '^(?:.*.*SUVYIChb.*|.*.*lFWCAoW.*|.*.*JRVggKF.*|.*.*aWV4IChb.*|.*.*lleCAoW.*|.*.*pZXggKF.*|.*.*aWV4IChOZX.*|.*.*lleCAoTmV3.*|.*.*pZXggKE5ld.*|.*.*SUVYIChOZX.*|.*.*lFWCAoTmV3.*|.*.*JRVggKE5ld.*)'
```



