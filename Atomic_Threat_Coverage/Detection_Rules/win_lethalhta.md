| Title                    | MSHTA Spwaned by SVCHOST       |
|:-------------------------|:------------------|
| **Description**          | Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.005: Mshta](https://attack.mitre.org/techniques/T1218/005)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.005: Mshta](../Triggers/T1218.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://codewhitesec.blogspot.com/2018/07/lethalhta.html](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: MSHTA Spwaned by SVCHOST
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: experimental
description: Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
tags:
    - attack.defense_evasion
    - attack.t1218.005
    - attack.execution  # an old one
    - attack.t1170  # an old one
author: Markus Neis
date: 2018/06/07
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\svchost.exe'
        Image: '*\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\svchost.exe" -and $_.message -match "Image.*.*\\mshta.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\svchost.exe AND winlog.event_data.Image.keyword:*\\mshta.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ed5d72a6-f8f4-479d-ba79-02f6a80d7471 <<EOF
{
  "metadata": {
    "title": "MSHTA Spwaned by SVCHOST",
    "description": "Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report",
    "tags": [
      "attack.defense_evasion",
      "attack.t1218.005",
      "attack.execution",
      "attack.t1170"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\mshta.exe)"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\mshta.exe)",
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
        "subject": "Sigma Rule 'MSHTA Spwaned by SVCHOST'",
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
(ParentImage.keyword:*\\svchost.exe AND Image.keyword:*\\mshta.exe)
```


### splunk
    
```
(ParentImage="*\\svchost.exe" Image="*\\mshta.exe")
```


### logpoint
    
```
(ParentImage="*\\svchost.exe" Image="*\\mshta.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\svchost\.exe)(?=.*.*\mshta\.exe))'
```



