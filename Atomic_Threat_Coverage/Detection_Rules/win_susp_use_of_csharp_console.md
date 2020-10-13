| Title                    | Suspicious Use of CSharp Interactive Console       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of CSharp interactive console by PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1127: Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Possible depending on environment. Pair with other factors such as net connections, command-line args, etc.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/](https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/)</li></ul>  |
| **Author**               | Michael R. (@nahamike01) |


## Detection Rules

### Sigma rule

```
title: Suspicious Use of CSharp Interactive Console
id: a9e416a8-e613-4f8b-88b8-a7d1d1af2f61
status: experimental
description: Detects the execution of CSharp interactive console by PowerShell
references:
    - https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/
author: Michael R. (@nahamike01)
date: 2020/03/08
tags:
    - attack.execution
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\csi.exe'
        ParentImage|endswith: '\powershell.exe'
        OriginalFileName: 'csi.exe'
    condition: selection
falsepositives:
    - Possible depending on environment. Pair with other factors such as net connections, command-line args, etc.
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\csi.exe" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "OriginalFileName.*csi.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\csi.exe AND winlog.event_data.ParentImage.keyword:*\\powershell.exe AND OriginalFileName:"csi.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a9e416a8-e613-4f8b-88b8-a7d1d1af2f61 <<EOF
{
  "metadata": {
    "title": "Suspicious Use of CSharp Interactive Console",
    "description": "Detects the execution of CSharp interactive console by PowerShell",
    "tags": [
      "attack.execution",
      "attack.t1127"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\csi.exe AND winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND OriginalFileName:\"csi.exe\")"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\csi.exe AND winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND OriginalFileName:\"csi.exe\")",
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
        "subject": "Sigma Rule 'Suspicious Use of CSharp Interactive Console'",
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
(Image.keyword:*\\csi.exe AND ParentImage.keyword:*\\powershell.exe AND OriginalFileName:"csi.exe")
```


### splunk
    
```
(Image="*\\csi.exe" ParentImage="*\\powershell.exe" OriginalFileName="csi.exe")
```


### logpoint
    
```
(Image="*\\csi.exe" ParentImage="*\\powershell.exe" OriginalFileName="csi.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\csi\.exe)(?=.*.*\powershell\.exe)(?=.*csi\.exe))'
```



