| Title                    | MSTSC Shadowing       |
|:-------------------------|:------------------|
| **Description**          | Detects RDP session hijacking by using MSTSC shadowing |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/kmkz_security/status/1220694202301976576](https://twitter.com/kmkz_security/status/1220694202301976576)</li><li>[https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet](https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: MSTSC Shadowing
id: 6ba5a05f-b095-4f0a-8654-b825f4f16334
description: Detects RDP session hijacking by using MSTSC shadowing
status: experimental
author: Florian Roth
date: 2020/01/24
references:
    - https://twitter.com/kmkz_security/status/1220694202301976576
    - https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'noconsentprompt'
            - 'shadow:'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*noconsentprompt.*" -and $_.message -match "CommandLine.*.*shadow:.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6ba5a05f-b095-4f0a-8654-b825f4f16334 <<EOF
{
  "metadata": {
    "title": "MSTSC Shadowing",
    "description": "Detects RDP session hijacking by using MSTSC shadowing",
    "tags": "",
    "query": "(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\:*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*noconsentprompt* AND winlog.event_data.CommandLine.keyword:*shadow\\:*)",
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
        "subject": "Sigma Rule 'MSTSC Shadowing'",
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
(CommandLine.keyword:*noconsentprompt* AND CommandLine.keyword:*shadow\:*)
```


### splunk
    
```
(CommandLine="*noconsentprompt*" CommandLine="*shadow:*")
```


### logpoint
    
```
(event_id="1" CommandLine="*noconsentprompt*" CommandLine="*shadow:*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*noconsentprompt.*)(?=.*.*shadow:.*))'
```



