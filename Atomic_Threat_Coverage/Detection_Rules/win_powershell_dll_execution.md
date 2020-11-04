| Title                    | Detection of PowerShell Execution via DLL       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/p3nt4/PowerShdll/blob/master/README.md](https://github.com/p3nt4/PowerShdll/blob/master/README.md)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Detection of PowerShell Execution via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: experimental
description: Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll
references:
    - https://github.com/p3nt4/PowerShdll/blob/master/README.md
tags:
    - attack.execution
    - attack.t1086
    - car.2014-04-003
author: Markus Neis
date: 2018/08/25
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\rundll32.exe'
    selection2:
        Description:
            - '*Windows-Hostprozess (Rundll32)*'
    selection3:
        CommandLine:
            - '*Default.GetString*'
            - '*FromBase64String*'
    condition: (selection1 or selection2) and selection3
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "Image.*.*\\rundll32.exe") -or ($_.message -match "Description.*.*Windows-Hostprozess (Rundll32).*")) -and ($_.message -match "CommandLine.*.*Default.GetString.*" -or $_.message -match "CommandLine.*.*FromBase64String.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:(*\\rundll32.exe) OR winlog.event_data.Description.keyword:(*Windows\-Hostprozess\ \(Rundll32\)*)) AND winlog.event_data.CommandLine.keyword:(*Default.GetString* OR *FromBase64String*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6812a10b-60ea-420c-832f-dfcc33b646ba <<EOF
{
  "metadata": {
    "title": "Detection of PowerShell Execution via DLL",
    "description": "Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "car.2014-04-003"
    ],
    "query": "((winlog.event_data.Image.keyword:(*\\\\rundll32.exe) OR winlog.event_data.Description.keyword:(*Windows\\-Hostprozess\\ \\(Rundll32\\)*)) AND winlog.event_data.CommandLine.keyword:(*Default.GetString* OR *FromBase64String*))"
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
                    "query": "((winlog.event_data.Image.keyword:(*\\\\rundll32.exe) OR winlog.event_data.Description.keyword:(*Windows\\-Hostprozess\\ \\(Rundll32\\)*)) AND winlog.event_data.CommandLine.keyword:(*Default.GetString* OR *FromBase64String*))",
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
        "subject": "Sigma Rule 'Detection of PowerShell Execution via DLL'",
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
((Image.keyword:(*\\rundll32.exe) OR Description.keyword:(*Windows\-Hostprozess \(Rundll32\)*)) AND CommandLine.keyword:(*Default.GetString* *FromBase64String*))
```


### splunk
    
```
(((Image="*\\rundll32.exe") OR (Description="*Windows-Hostprozess (Rundll32)*")) (CommandLine="*Default.GetString*" OR CommandLine="*FromBase64String*"))
```


### logpoint
    
```
((Image IN ["*\\rundll32.exe"] OR Description IN ["*Windows-Hostprozess (Rundll32)*"]) CommandLine IN ["*Default.GetString*", "*FromBase64String*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*(?:.*.*\rundll32\.exe)|.*(?:.*.*Windows-Hostprozess \(Rundll32\).*))))(?=.*(?:.*.*Default\.GetString.*|.*.*FromBase64String.*)))'
```



