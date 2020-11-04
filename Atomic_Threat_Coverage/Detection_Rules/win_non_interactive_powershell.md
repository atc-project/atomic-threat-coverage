| Title                    | Non Interactive PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate programs executing PowerShell scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements) |


## Detection Rules

### Sigma rule

```
title: Non Interactive PowerShell
id: f4bbd493-b796-416e-bbf2-121235348529
description: Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md
tags:
    - attack.execution
    - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection: 
        Image|endswith: '\powershell.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate programs executing PowerShell scripts
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\powershell.exe" -and  -not ($_.message -match "ParentImage.*.*\\explorer.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\powershell.exe AND (NOT (winlog.event_data.ParentImage.keyword:*\\explorer.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f4bbd493-b796-416e-bbf2-121235348529 <<EOF
{
  "metadata": {
    "title": "Non Interactive PowerShell",
    "description": "Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\powershell.exe AND (NOT (winlog.event_data.ParentImage.keyword:*\\\\explorer.exe)))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\powershell.exe AND (NOT (winlog.event_data.ParentImage.keyword:*\\\\explorer.exe)))",
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
        "subject": "Sigma Rule 'Non Interactive PowerShell'",
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
(Image.keyword:*\\powershell.exe AND (NOT (ParentImage.keyword:*\\explorer.exe)))
```


### splunk
    
```
(Image="*\\powershell.exe" NOT (ParentImage="*\\explorer.exe"))
```


### logpoint
    
```
(Image="*\\powershell.exe"  -(ParentImage="*\\explorer.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\powershell\.exe)(?=.*(?!.*(?:.*(?=.*.*\explorer\.exe)))))'
```



