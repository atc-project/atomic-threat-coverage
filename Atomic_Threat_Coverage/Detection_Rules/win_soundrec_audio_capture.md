| Title                    | Audio Capture via SoundRecorder       |
|:-------------------------|:------------------|
| **Description**          | Detect attacker collecting audio via SoundRecorder application |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1123: Audio Capture](https://attack.mitre.org/techniques/T1123)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1123: Audio Capture](../Triggers/T1123.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate audio capture by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html](https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Audio Capture via SoundRecorder
id: 83865853-59aa-449e-9600-74b9d89a6d6e
description: Detect attacker collecting audio via SoundRecorder application
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html
tags:
    - attack.collection
    - attack.t1123
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\SoundRecorder.exe'
        CommandLine|contains: '/FILE'
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\SoundRecorder.exe" -and $_.message -match "CommandLine.*.*/FILE.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\SoundRecorder.exe AND winlog.event_data.CommandLine.keyword:*\/FILE*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/83865853-59aa-449e-9600-74b9d89a6d6e <<EOF
{
  "metadata": {
    "title": "Audio Capture via SoundRecorder",
    "description": "Detect attacker collecting audio via SoundRecorder application",
    "tags": [
      "attack.collection",
      "attack.t1123"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\SoundRecorder.exe AND winlog.event_data.CommandLine.keyword:*\\/FILE*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\SoundRecorder.exe AND winlog.event_data.CommandLine.keyword:*\\/FILE*)",
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
        "subject": "Sigma Rule 'Audio Capture via SoundRecorder'",
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
(Image.keyword:*\\SoundRecorder.exe AND CommandLine.keyword:*\/FILE*)
```


### splunk
    
```
(Image="*\\SoundRecorder.exe" CommandLine="*/FILE*")
```


### logpoint
    
```
(event_id="1" Image="*\\SoundRecorder.exe" CommandLine="*/FILE*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\SoundRecorder\.exe)(?=.*.*/FILE.*))'
```



