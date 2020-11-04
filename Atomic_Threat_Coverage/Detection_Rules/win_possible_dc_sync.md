| Title                    | Possible DC Sync       |
|:-------------------------|:------------------|
| **Description**          | Detects DC sync via create new SPN |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Neo23x0/sigma/blob/ec5bb710499caae6667c7f7311ca9e92c03b9039/rules/windows/builtin/win_dcsync.yml](https://github.com/Neo23x0/sigma/blob/ec5bb710499caae6667c7f7311ca9e92c03b9039/rules/windows/builtin/win_dcsync.yml)</li><li>[https://twitter.com/gentilkiwi/status/1003236624925413376](https://twitter.com/gentilkiwi/status/1003236624925413376)</li><li>[https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)</li><li>[https://jsecurity101.com/2019/Syncing-into-the-Shadows/](https://jsecurity101.com/2019/Syncing-into-the-Shadows/)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Possible DC Sync
id: 32e19d25-4aed-4860-a55a-be99cb0bf7ed
description: Detects DC sync via create new SPN
status: experimental
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
references:
    - https://github.com/Neo23x0/sigma/blob/ec5bb710499caae6667c7f7311ca9e92c03b9039/rules/windows/builtin/win_dcsync.yml
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
    - https://jsecurity101.com/2019/Syncing-into-the-Shadows/
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4742
        ServicePrincipalNames: '*GC/*'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4742" -and $_.message -match "ServicePrincipalNames.*.*GC/.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4742" AND ServicePrincipalNames.keyword:*GC\/*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/32e19d25-4aed-4860-a55a-be99cb0bf7ed <<EOF
{
  "metadata": {
    "title": "Possible DC Sync",
    "description": "Detects DC sync via create new SPN",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4742\" AND ServicePrincipalNames.keyword:*GC\\/*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4742\" AND ServicePrincipalNames.keyword:*GC\\/*)",
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
        "subject": "Sigma Rule 'Possible DC Sync'",
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
(EventID:"4742" AND ServicePrincipalNames.keyword:*GC\/*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4742" ServicePrincipalNames="*GC/*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4742" ServicePrincipalNames="*GC/*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4742)(?=.*.*GC/.*))'
```



