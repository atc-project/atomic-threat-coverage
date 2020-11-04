| Title                    | FromBase64String Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious FromBase64String expressions in command line arguments |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrative script libraries</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639](https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: FromBase64String Command Line
id: e32d4572-9826-4738-b651-95fa63747e8a
status: experimental
description: Detects suspicious FromBase64String expressions in command line arguments
references:
    - https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639
author: Florian Roth
date: 2020/01/29
tags: 
    - attack.t1027
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '::FromBase64String('
    condition: selection
falsepositives:
    - Administrative script libraries
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*::FromBase64String(.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\:\:FromBase64String\(*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e32d4572-9826-4738-b651-95fa63747e8a <<EOF
{
  "metadata": {
    "title": "FromBase64String Command Line",
    "description": "Detects suspicious FromBase64String expressions in command line arguments",
    "tags": [
      "attack.t1027",
      "attack.defense_evasion"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\:\\:FromBase64String\\(*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\:\\:FromBase64String\\(*",
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
        "subject": "Sigma Rule 'FromBase64String Command Line'",
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
CommandLine.keyword:*\:\:FromBase64String\(*
```


### splunk
    
```
CommandLine="*::FromBase64String(*"
```


### logpoint
    
```
CommandLine="*::FromBase64String(*"
```


### grep
    
```
grep -P '^.*::FromBase64String\(.*'
```



