| Title                    | Clear PowerShell History       |
|:-------------------------|:------------------|
| **Description**          | Detects keywords that could indicate clearing PowerShell history |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1146: Clear Command History](https://attack.mitre.org/techniques/T1146)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1146: Clear Command History](../Triggers/T1146.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>some PS-scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a](https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Clear PowerShell History
id: dfba4ce1-e0ea-495f-986e-97140f31af2d
status: experimental
description: Detects keywords that could indicate clearing PowerShell history
date: 2019/10/25
author: Ilyas Ochkov, oscd.community
references:
    - https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a
tags:
    - attack.defense_evasion
    - attack.t1146
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        - 'del (Get-PSReadlineOption).HistorySavePath'
        - 'Set-PSReadlineOption –HistorySaveStyle SaveNothing'
        - 'Remove-Item (Get-PSReadlineOption).HistorySavePath'
        - 'rm (Get-PSReadlineOption).HistorySavePath'
    condition: keywords
falsepositives:
    - some PS-scripts
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "del (Get-PSReadlineOption).HistorySavePath" -or $_.message -match "Set-PSReadlineOption –HistorySaveStyle SaveNothing" -or $_.message -match "Remove-Item (Get-PSReadlineOption).HistorySavePath" -or $_.message -match "rm (Get-PSReadlineOption).HistorySavePath")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
\*.keyword:(*del\ \(Get\-PSReadlineOption\).HistorySavePath* OR *Set\-PSReadlineOption\ –HistorySaveStyle\ SaveNothing* OR *Remove\-Item\ \(Get\-PSReadlineOption\).HistorySavePath* OR *rm\ \(Get\-PSReadlineOption\).HistorySavePath*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/dfba4ce1-e0ea-495f-986e-97140f31af2d <<EOF
{
  "metadata": {
    "title": "Clear PowerShell History",
    "description": "Detects keywords that could indicate clearing PowerShell history",
    "tags": [
      "attack.defense_evasion",
      "attack.t1146"
    ],
    "query": "\\*.keyword:(*del\\ \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *Set\\-PSReadlineOption\\ \u2013HistorySaveStyle\\ SaveNothing* OR *Remove\\-Item\\ \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *rm\\ \\(Get\\-PSReadlineOption\\).HistorySavePath*)"
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
                    "query": "\\*.keyword:(*del\\ \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *Set\\-PSReadlineOption\\ \u2013HistorySaveStyle\\ SaveNothing* OR *Remove\\-Item\\ \\(Get\\-PSReadlineOption\\).HistorySavePath* OR *rm\\ \\(Get\\-PSReadlineOption\\).HistorySavePath*)",
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
        "subject": "Sigma Rule 'Clear PowerShell History'",
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
\*.keyword:(*del \(Get\-PSReadlineOption\).HistorySavePath* OR *Set\-PSReadlineOption –HistorySaveStyle SaveNothing* OR *Remove\-Item \(Get\-PSReadlineOption\).HistorySavePath* OR *rm \(Get\-PSReadlineOption\).HistorySavePath*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" ("del (Get-PSReadlineOption).HistorySavePath" OR "Set-PSReadlineOption –HistorySaveStyle SaveNothing" OR "Remove-Item (Get-PSReadlineOption).HistorySavePath" OR "rm (Get-PSReadlineOption).HistorySavePath"))
```


### logpoint
    
```
("del (Get-PSReadlineOption).HistorySavePath" OR "Set-PSReadlineOption –HistorySaveStyle SaveNothing" OR "Remove-Item (Get-PSReadlineOption).HistorySavePath" OR "rm (Get-PSReadlineOption).HistorySavePath")
```


### grep
    
```
grep -P '^(?:.*(?:.*del \(Get-PSReadlineOption\)\.HistorySavePath|.*Set-PSReadlineOption –HistorySaveStyle SaveNothing|.*Remove-Item \(Get-PSReadlineOption\)\.HistorySavePath|.*rm \(Get-PSReadlineOption\)\.HistorySavePath))'
```



