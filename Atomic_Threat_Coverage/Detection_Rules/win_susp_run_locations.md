| Title                    | Suspicious Process Start Locations       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious process run from unusual locations |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-05-002](https://car.mitre.org/wiki/CAR-2013-05-002)</li></ul>  |
| **Author**               | juju4 |
| Other Tags           | <ul><li>car.2013-05-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Process Start Locations
id: 15b75071-74cc-47e0-b4c6-b43744a62a2b
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
date: 2019/01/16
tags:
    - attack.defense_evasion
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*:\RECYCLER\\*'
            - '*:\SystemVolumeInformation\\*'
            - 'C:\\Windows\\Tasks\\*'
            - 'C:\\Windows\\debug\\*'
            - 'C:\\Windows\\fonts\\*'
            - 'C:\\Windows\\help\\*'
            - 'C:\\Windows\\drivers\\*'
            - 'C:\\Windows\\addins\\*'
            - 'C:\\Windows\\cursors\\*'
            - 'C:\\Windows\\system32\tasks\\*'

    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*:\\RECYCLER\\.*" -or $_.message -match "Image.*.*:\\SystemVolumeInformation\\.*" -or $_.message -match "Image.*C:\\Windows\\Tasks\\.*" -or $_.message -match "Image.*C:\\Windows\\debug\\.*" -or $_.message -match "Image.*C:\\Windows\\fonts\\.*" -or $_.message -match "Image.*C:\\Windows\\help\\.*" -or $_.message -match "Image.*C:\\Windows\\drivers\\.*" -or $_.message -match "Image.*C:\\Windows\\addins\\.*" -or $_.message -match "Image.*C:\\Windows\\cursors\\.*" -or $_.message -match "Image.*C:\\Windows\\system32\\tasks\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\:\\RECYCLER\\* OR *\:\\SystemVolumeInformation\\* OR C\:\\Windows\\Tasks\\* OR C\:\\Windows\\debug\\* OR C\:\\Windows\\fonts\\* OR C\:\\Windows\\help\\* OR C\:\\Windows\\drivers\\* OR C\:\\Windows\\addins\\* OR C\:\\Windows\\cursors\\* OR C\:\\Windows\\system32\\tasks\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/15b75071-74cc-47e0-b4c6-b43744a62a2b <<EOF
{
  "metadata": {
    "title": "Suspicious Process Start Locations",
    "description": "Detects suspicious process run from unusual locations",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036",
      "car.2013-05-002"
    ],
    "query": "winlog.event_data.Image.keyword:(*\\:\\\\RECYCLER\\\\* OR *\\:\\\\SystemVolumeInformation\\\\* OR C\\:\\\\Windows\\\\Tasks\\\\* OR C\\:\\\\Windows\\\\debug\\\\* OR C\\:\\\\Windows\\\\fonts\\\\* OR C\\:\\\\Windows\\\\help\\\\* OR C\\:\\\\Windows\\\\drivers\\\\* OR C\\:\\\\Windows\\\\addins\\\\* OR C\\:\\\\Windows\\\\cursors\\\\* OR C\\:\\\\Windows\\\\system32\\\\tasks\\\\*)"
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
                    "query": "winlog.event_data.Image.keyword:(*\\:\\\\RECYCLER\\\\* OR *\\:\\\\SystemVolumeInformation\\\\* OR C\\:\\\\Windows\\\\Tasks\\\\* OR C\\:\\\\Windows\\\\debug\\\\* OR C\\:\\\\Windows\\\\fonts\\\\* OR C\\:\\\\Windows\\\\help\\\\* OR C\\:\\\\Windows\\\\drivers\\\\* OR C\\:\\\\Windows\\\\addins\\\\* OR C\\:\\\\Windows\\\\cursors\\\\* OR C\\:\\\\Windows\\\\system32\\\\tasks\\\\*)",
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
        "subject": "Sigma Rule 'Suspicious Process Start Locations'",
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
Image.keyword:(*\:\\RECYCLER\\* *\:\\SystemVolumeInformation\\* C\:\\Windows\\Tasks\\* C\:\\Windows\\debug\\* C\:\\Windows\\fonts\\* C\:\\Windows\\help\\* C\:\\Windows\\drivers\\* C\:\\Windows\\addins\\* C\:\\Windows\\cursors\\* C\:\\Windows\\system32\\tasks\\*)
```


### splunk
    
```
(Image="*:\\RECYCLER\\*" OR Image="*:\\SystemVolumeInformation\\*" OR Image="C:\\Windows\\Tasks\\*" OR Image="C:\\Windows\\debug\\*" OR Image="C:\\Windows\\fonts\\*" OR Image="C:\\Windows\\help\\*" OR Image="C:\\Windows\\drivers\\*" OR Image="C:\\Windows\\addins\\*" OR Image="C:\\Windows\\cursors\\*" OR Image="C:\\Windows\\system32\\tasks\\*")
```


### logpoint
    
```
Image IN ["*:\\RECYCLER\\*", "*:\\SystemVolumeInformation\\*", "C:\\Windows\\Tasks\\*", "C:\\Windows\\debug\\*", "C:\\Windows\\fonts\\*", "C:\\Windows\\help\\*", "C:\\Windows\\drivers\\*", "C:\\Windows\\addins\\*", "C:\\Windows\\cursors\\*", "C:\\Windows\\system32\\tasks\\*"]
```


### grep
    
```
grep -P '^(?:.*.*:\RECYCLER\\.*|.*.*:\SystemVolumeInformation\\.*|.*C:\\Windows\\Tasks\\.*|.*C:\\Windows\\debug\\.*|.*C:\\Windows\\fonts\\.*|.*C:\\Windows\\help\\.*|.*C:\\Windows\\drivers\\.*|.*C:\\Windows\\addins\\.*|.*C:\\Windows\\cursors\\.*|.*C:\\Windows\\system32\tasks\\.*)'
```



