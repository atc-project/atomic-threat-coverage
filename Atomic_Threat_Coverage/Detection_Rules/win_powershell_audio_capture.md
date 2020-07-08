| Title                    | Audio Capture via PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects audio capture via PowerShell Cmdlet |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1123: Audio Capture](https://attack.mitre.org/techniques/T1123)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1123: Audio Capture](../Triggers/T1123.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate audio capture by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html](https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Audio Capture via PowerShell
id: 932fb0d8-692b-4b0f-a26e-5643a50fe7d6
description: Detects audio capture via PowerShell Cmdlet
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html
tags:
    - attack.collection
    - attack.t1123
detection:
    selection:
        CommandLine|contains: 'WindowsAudioDevice-Powershell-Cmdlet'
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user
level: medium
logsource:
    category: process_creation
    product: windows

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*WindowsAudioDevice-Powershell-Cmdlet.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*WindowsAudioDevice\-Powershell\-Cmdlet*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/932fb0d8-692b-4b0f-a26e-5643a50fe7d6 <<EOF
{
  "metadata": {
    "title": "Audio Capture via PowerShell",
    "description": "Detects audio capture via PowerShell Cmdlet",
    "tags": [
      "attack.collection",
      "attack.t1123"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*WindowsAudioDevice\\-Powershell\\-Cmdlet*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*WindowsAudioDevice\\-Powershell\\-Cmdlet*",
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
        "subject": "Sigma Rule 'Audio Capture via PowerShell'",
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
CommandLine.keyword:*WindowsAudioDevice\-Powershell\-Cmdlet*
```


### splunk
    
```
CommandLine="*WindowsAudioDevice-Powershell-Cmdlet*"
```


### logpoint
    
```
(event_id="1" CommandLine="*WindowsAudioDevice-Powershell-Cmdlet*")
```


### grep
    
```
grep -P '^.*WindowsAudioDevice-Powershell-Cmdlet.*'
```



