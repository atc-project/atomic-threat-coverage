| Title                    | Empire Monkey       |
|:-------------------------|:------------------|
| **Description**          | Detects EmpireMonkey APT reported Activity |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Very Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b](https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
action: global
title: Empire Monkey
id: 10152a7b-b566-438f-a33c-390b607d1c8d
description: Detects EmpireMonkey APT reported Activity
references:
    - https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b
tags:
    - attack.t1086
    - attack.execution
date: 2019/04/02
author: Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Very Unlikely 
level: critical
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_cutil:
        CommandLine: 
            - '*/i:%APPDATA%\logs.txt scrobj.dll'
        Image:
            - '*\cutil.exe'
    selection_regsvr32:
        CommandLine: 
            - '*/i:%APPDATA%\logs.txt scrobj.dll'
        Description: 
            - Microsoft(C) Registerserver
        
```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*/i:%APPDATA%\\logs.txt scrobj.dll") -and (($_.message -match "Image.*.*\\cutil.exe") -or ($_.message -match "Microsoft(C) Registerserver"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*\/i\:%APPDATA%\\logs.txt\ scrobj.dll) AND (winlog.event_data.Image.keyword:(*\\cutil.exe) OR winlog.event_data.Description:("Microsoft\(C\)\ Registerserver")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/10152a7b-b566-438f-a33c-390b607d1c8d <<EOF
{
  "metadata": {
    "title": "Empire Monkey",
    "description": "Detects EmpireMonkey APT reported Activity",
    "tags": [
      "attack.t1086",
      "attack.execution"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*\\/i\\:%APPDATA%\\\\logs.txt\\ scrobj.dll) AND (winlog.event_data.Image.keyword:(*\\\\cutil.exe) OR winlog.event_data.Description:(\"Microsoft\\(C\\)\\ Registerserver\")))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*\\/i\\:%APPDATA%\\\\logs.txt\\ scrobj.dll) AND (winlog.event_data.Image.keyword:(*\\\\cutil.exe) OR winlog.event_data.Description:(\"Microsoft\\(C\\)\\ Registerserver\")))",
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
        "subject": "Sigma Rule 'Empire Monkey'",
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
(CommandLine.keyword:(*\/i\:%APPDATA%\\logs.txt scrobj.dll) AND (Image.keyword:(*\\cutil.exe) OR Description:("Microsoft\(C\) Registerserver")))
```


### splunk
    
```
((CommandLine="*/i:%APPDATA%\\logs.txt scrobj.dll") ((Image="*\\cutil.exe") OR (Description="Microsoft(C) Registerserver")))
```


### logpoint
    
```
(CommandLine IN ["*/i:%APPDATA%\\logs.txt scrobj.dll"] (Image IN ["*\\cutil.exe"] OR Description IN ["Microsoft(C) Registerserver"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*/i:%APPDATA%\logs\.txt scrobj\.dll))(?=.*(?:.*(?:.*(?:.*.*\cutil\.exe)|.*(?:.*Microsoft\(C\) Registerserver)))))'
```



