| Title                    | Suspicious Curl Usage on Windows       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious curl process start on Windows and outputs the requested document to a local file |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Scripts created by developers and admins</li><li>Administrative activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/reegun21/status/1222093798009790464](https://twitter.com/reegun21/status/1222093798009790464)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Curl Usage on Windows
id: e218595b-bbe7-4ee5-8a96-f32a24ad3468
status: experimental
description: Detects a suspicious curl process start on Windows and outputs the requested document to a local file
author: Florian Roth
date: 2020/07/03
modified: 2020/09/05
references:
    - https://twitter.com/reegun21/status/1222093798009790464
logsource:
    category: process_creation
    product: windows
tags:
    - attack.command_and_control
    - attack.t1105
detection:
    selection1:
        Image|endswith: '\curl.exe'
    selection2:
        Product: 'The curl executable'
    selection3: 
        CommandLine|contains: ' -O '
    condition: ( selection1 or selection2 ) and selection3
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\curl.exe" -or $_.message -match "Product.*The curl executable") -and $_.message -match "CommandLine.*.* -O .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\curl.exe OR Product:"The\ curl\ executable") AND winlog.event_data.CommandLine.keyword:*\ \-O\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e218595b-bbe7-4ee5-8a96-f32a24ad3468 <<EOF
{
  "metadata": {
    "title": "Suspicious Curl Usage on Windows",
    "description": "Detects a suspicious curl process start on Windows and outputs the requested document to a local file",
    "tags": [
      "attack.command_and_control",
      "attack.t1105"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\curl.exe OR Product:\"The\\ curl\\ executable\") AND winlog.event_data.CommandLine.keyword:*\\ \\-O\\ *)"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\curl.exe OR Product:\"The\\ curl\\ executable\") AND winlog.event_data.CommandLine.keyword:*\\ \\-O\\ *)",
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
        "subject": "Sigma Rule 'Suspicious Curl Usage on Windows'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((Image.keyword:*\\curl.exe OR Product:"The curl executable") AND CommandLine.keyword:* \-O *)
```


### splunk
    
```
((Image="*\\curl.exe" OR Product="The curl executable") CommandLine="* -O *") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((Image="*\\curl.exe" OR Product="The curl executable") CommandLine="* -O *")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\curl\.exe|.*The curl executable)))(?=.*.* -O .*))'
```



