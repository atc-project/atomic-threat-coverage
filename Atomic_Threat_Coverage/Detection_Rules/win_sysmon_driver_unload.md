| Title                    | Sysmon Driver Unload       |
|:-------------------------|:------------------|
| **Description**          | Detect possible Sysmon driver unload |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon](https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon)</li></ul>  |
| **Author**               | Kirill Kiryanov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Sysmon Driver Unload
id: 4d7cda18-1b12-4e52-b45c-d28653210df8
status: experimental
author: Kirill Kiryanov, oscd.community
description: Detect possible Sysmon driver unload
date: 2019/10/23
modified: 2019/11/07
references:
    - https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\fltmc.exe'
        CommandLine|contains|all:
            - 'unload'
            - 'sys'
    condition: selection
falsepositives: 
    - Unknown
level: high
fields:
    - CommandLine
    - Details

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\fltmc.exe" -and $_.message -match "CommandLine.*.*unload.*" -and $_.message -match "CommandLine.*.*sys.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\fltmc.exe AND winlog.event_data.CommandLine.keyword:*unload* AND winlog.event_data.CommandLine.keyword:*sys*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4d7cda18-1b12-4e52-b45c-d28653210df8 <<EOF
{
  "metadata": {
    "title": "Sysmon Driver Unload",
    "description": "Detect possible Sysmon driver unload",
    "tags": "",
    "query": "(winlog.event_data.Image.keyword:*\\\\fltmc.exe AND winlog.event_data.CommandLine.keyword:*unload* AND winlog.event_data.CommandLine.keyword:*sys*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\fltmc.exe AND winlog.event_data.CommandLine.keyword:*unload* AND winlog.event_data.CommandLine.keyword:*sys*)",
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
        "subject": "Sigma Rule 'Sysmon Driver Unload'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nCommandLine = {{_source.CommandLine}}\n    Details = {{_source.Details}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\fltmc.exe AND CommandLine.keyword:*unload* AND CommandLine.keyword:*sys*)
```


### splunk
    
```
(Image="*\\fltmc.exe" CommandLine="*unload*" CommandLine="*sys*") | table CommandLine,Details
```


### logpoint
    
```
(event_id="1" Image="*\\fltmc.exe" CommandLine="*unload*" CommandLine="*sys*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\fltmc\.exe)(?=.*.*unload.*)(?=.*.*sys.*))'
```



