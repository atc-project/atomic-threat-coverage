| Title                    | Run PowerShell Script from ADS       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell script execution from Alternate Data Stream (ADS) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1096: NTFS File Attributes](https://attack.mitre.org/techniques/T1096)</li><li>[T1564.004: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1564.004: NTFS File Attributes](../Triggers/T1564.004.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1](https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1)</li></ul>  |
| **Author**               | Sergey Soldatov, Kaspersky Lab, oscd.community |


## Detection Rules

### Sigma rule

```
title: Run PowerShell Script from ADS
id: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
status: experimental
description: Detects PowerShell script execution from Alternate Data Stream (ADS)
references:
    - https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1
author: Sergey Soldatov, Kaspersky Lab, oscd.community
date: 2019/10/30
tags:
    - attack.defense_evasion
    - attack.t1096 # an old one
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\powershell.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'Get-Content'
            - '-Stream'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Content.*" -and $_.message -match "CommandLine.*.*-Stream.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\powershell.exe AND winlog.event_data.Image.keyword:*\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Get\-Content* AND winlog.event_data.CommandLine.keyword:*\-Stream*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/45a594aa-1fbd-4972-a809-ff5a99dd81b8 <<EOF
{
  "metadata": {
    "title": "Run PowerShell Script from ADS",
    "description": "Detects PowerShell script execution from Alternate Data Stream (ADS)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1096",
      "attack.t1564.004"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Get\\-Content* AND winlog.event_data.CommandLine.keyword:*\\-Stream*)"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*Get\\-Content* AND winlog.event_data.CommandLine.keyword:*\\-Stream*)",
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
        "subject": "Sigma Rule 'Run PowerShell Script from ADS'",
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
(ParentImage.keyword:*\\powershell.exe AND Image.keyword:*\\powershell.exe AND CommandLine.keyword:*Get\-Content* AND CommandLine.keyword:*\-Stream*)
```


### splunk
    
```
(ParentImage="*\\powershell.exe" Image="*\\powershell.exe" CommandLine="*Get-Content*" CommandLine="*-Stream*")
```


### logpoint
    
```
(ParentImage="*\\powershell.exe" Image="*\\powershell.exe" CommandLine="*Get-Content*" CommandLine="*-Stream*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\powershell\.exe)(?=.*.*\powershell\.exe)(?=.*.*Get-Content.*)(?=.*.*-Stream.*))'
```



