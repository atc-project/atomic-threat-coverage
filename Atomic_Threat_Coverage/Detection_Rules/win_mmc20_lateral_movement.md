| Title                    | MMC20 Lateral Movement       |
|:-------------------------|:------------------|
| **Description**          | Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1175: Component Object Model and Distributed COM](https://attack.mitre.org/techniques/T1175)</li><li>[T1021.003: Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.003: Distributed Component Object Model](../Triggers/T1021.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)</li><li>[https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing](https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing)</li></ul>  |
| **Author**               | @2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea) |


## Detection Rules

### Sigma rule

```
title: MMC20 Lateral Movement
id: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
author: '@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)'
date: 2020/03/04
modified: 2020/08/23
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing
tags:
    - attack.execution
    - attack.t1175          # an old one
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\svchost.exe'
        Image: '*\mmc.exe'
        CommandLine: '*-Embedding*'
    condition: selection
falsepositives:
    - Unlikely
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\svchost.exe" -and $_.message -match "Image.*.*\\mmc.exe" -and $_.message -match "CommandLine.*.*-Embedding.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\svchost.exe AND winlog.event_data.Image.keyword:*\\mmc.exe AND winlog.event_data.CommandLine.keyword:*\-Embedding*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f1f3bf22-deb2-418d-8cce-e1a45e46a5bd <<EOF
{
  "metadata": {
    "title": "MMC20 Lateral Movement",
    "description": "Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of \"-Embedding\" as a child of svchost.exe",
    "tags": [
      "attack.execution",
      "attack.t1175",
      "attack.t1021.003"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\mmc.exe AND winlog.event_data.CommandLine.keyword:*\\-Embedding*)"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\svchost.exe AND winlog.event_data.Image.keyword:*\\\\mmc.exe AND winlog.event_data.CommandLine.keyword:*\\-Embedding*)",
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
        "subject": "Sigma Rule 'MMC20 Lateral Movement'",
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
(ParentImage.keyword:*\\svchost.exe AND Image.keyword:*\\mmc.exe AND CommandLine.keyword:*\-Embedding*)
```


### splunk
    
```
(ParentImage="*\\svchost.exe" Image="*\\mmc.exe" CommandLine="*-Embedding*")
```


### logpoint
    
```
(ParentImage="*\\svchost.exe" Image="*\\mmc.exe" CommandLine="*-Embedding*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\svchost\.exe)(?=.*.*\mmc\.exe)(?=.*.*-Embedding.*))'
```



