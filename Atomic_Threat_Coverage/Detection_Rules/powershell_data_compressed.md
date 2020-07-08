| Title                    | Data Compressed - Powershell       |
|:-------------------------|:------------------|
| **Description**          | An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li><li>[T1560: Archive Collected Data](https://attack.mitre.org/techniques/T1560)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1560: Archive Collected Data](../Triggers/T1560.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>highly likely if archive ops are done via PS</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Data Compressed - Powershell
id: 6dc5d284-69ea-42cf-9311-fb1c3932a69a
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
        keywords|contains|all:
            - '-Recurse'
            - '|'
            - 'Compress-Archive'
    condition: selection
falsepositives:
    - highly likely if archive ops are done via PS
level: low
tags:
    - attack.exfiltration
    - attack.t1002
    - attack.t1560

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "keywords.*.*-Recurse.*" -and $_.message -match "keywords.*.*|.*" -and $_.message -match "keywords.*.*Compress-Archive.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND keywords.keyword:*\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\-Archive*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6dc5d284-69ea-42cf-9311-fb1c3932a69a <<EOF
{
  "metadata": {
    "title": "Data Compressed - Powershell",
    "description": "An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network",
    "tags": [
      "attack.exfiltration",
      "attack.t1002",
      "attack.t1560"
    ],
    "query": "(winlog.event_id:\"4104\" AND keywords.keyword:*\\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\\-Archive*)"
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
                    "query": "(winlog.event_id:\"4104\" AND keywords.keyword:*\\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\\-Archive*)",
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
        "subject": "Sigma Rule 'Data Compressed - Powershell'",
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
(EventID:"4104" AND keywords.keyword:*\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\-Archive*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" keywords="*-Recurse*" keywords="*|*" keywords="*Compress-Archive*")
```


### logpoint
    
```
(event_id="4104" keywords="*-Recurse*" keywords="*|*" keywords="*Compress-Archive*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*.*-Recurse.*)(?=.*.*\|.*)(?=.*.*Compress-Archive.*))'
```



