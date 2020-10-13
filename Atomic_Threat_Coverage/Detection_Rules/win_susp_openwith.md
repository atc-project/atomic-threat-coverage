| Title                    | OpenWith.exe Executes Specified Binary       |
|:-------------------------|:------------------|
| **Description**          | The OpenWith.exe executes other binary |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate use of OpenWith.exe by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml)</li><li>[https://twitter.com/harr0ey/status/991670870384021504](https://twitter.com/harr0ey/status/991670870384021504)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community (rule), @harr0ey (idea) |


## Detection Rules

### Sigma rule

```
title: OpenWith.exe Executes Specified Binary
id: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f
status: experimental
description: The OpenWith.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
    - https://twitter.com/harr0ey/status/991670870384021504
author: Beyu Denis, oscd.community (rule), @harr0ey (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution      # an old one
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\OpenWith.exe'
        CommandLine|contains: '/c'
    condition: selection
falsepositives:
    - Legitimate use of OpenWith.exe by legitimate user

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\OpenWith.exe" -and $_.message -match "CommandLine.*.*/c.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\OpenWith.exe AND winlog.event_data.CommandLine.keyword:*\/c*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cec8e918-30f7-4e2d-9bfa-a59cc97ae60f <<EOF
{
  "metadata": {
    "title": "OpenWith.exe Executes Specified Binary",
    "description": "The OpenWith.exe executes other binary",
    "tags": [
      "attack.defense_evasion",
      "attack.t1218",
      "attack.execution"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\OpenWith.exe AND winlog.event_data.CommandLine.keyword:*\\/c*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\OpenWith.exe AND winlog.event_data.CommandLine.keyword:*\\/c*)",
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
        "subject": "Sigma Rule 'OpenWith.exe Executes Specified Binary'",
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
(Image.keyword:*\\OpenWith.exe AND CommandLine.keyword:*\/c*)
```


### splunk
    
```
(Image="*\\OpenWith.exe" CommandLine="*/c*")
```


### logpoint
    
```
(Image="*\\OpenWith.exe" CommandLine="*/c*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\OpenWith\.exe)(?=.*.*/c.*))'
```



