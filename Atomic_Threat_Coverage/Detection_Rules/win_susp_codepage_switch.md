| Title                    | Suspicious Code Page Switch       |
|:-------------------------|:------------------|
| **Description**          | Detects a code page switch in command line or batch scripts to a rare language |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrative activity (adjust code pages according to your organisation's region)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers](https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers)</li><li>[https://twitter.com/cglyer/status/1183756892952248325](https://twitter.com/cglyer/status/1183756892952248325)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Code Page Switch
id: c7942406-33dd-4377-a564-0f62db0593a3
status: experimental
description: Detects a code page switch in command line or batch scripts to a rare language
author: Florian Roth
date: 2019/10/14
references:
    - https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
    - https://twitter.com/cglyer/status/1183756892952248325
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 
            - 'chcp* 936'  # Chinese
            # - 'chcp* 1256' # Arabic
            - 'chcp* 1258' # Vietnamese
            # - 'chcp* 855'  # Russian
            # - 'chcp* 866'  # Russian
            # - 'chcp* 864'  # Arabic
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - "Administrative activity (adjust code pages according to your organisation's region)"
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*chcp.* 936" -or $_.message -match "CommandLine.*chcp.* 1258")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(chcp*\ 936 OR chcp*\ 1258)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c7942406-33dd-4377-a564-0f62db0593a3 <<EOF
{
  "metadata": {
    "title": "Suspicious Code Page Switch",
    "description": "Detects a code page switch in command line or batch scripts to a rare language",
    "tags": "",
    "query": "winlog.event_data.CommandLine.keyword:(chcp*\\ 936 OR chcp*\\ 1258)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(chcp*\\ 936 OR chcp*\\ 1258)",
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
        "subject": "Sigma Rule 'Suspicious Code Page Switch'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
CommandLine.keyword:(chcp* 936 chcp* 1258)
```


### splunk
    
```
(CommandLine="chcp* 936" OR CommandLine="chcp* 1258") | table ParentCommandLine
```


### logpoint
    
```
(event_id="1" CommandLine IN ["chcp* 936", "chcp* 1258"])
```


### grep
    
```
grep -P '^(?:.*chcp.* 936|.*chcp.* 1258)'
```



