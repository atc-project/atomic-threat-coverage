| Title                    | Windows Defender AMSI Trigger Detected       |
|:-------------------------|:------------------|
| **Description**          | Detects triggering of AMSI by Windows Defender. |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unlikely</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps](https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps)</li></ul>  |
| **Author**               | Bhabesh Raj |


## Detection Rules

### Sigma rule

```
title: Windows Defender AMSI Trigger Detected
id: ea9bf0fa-edec-4fb8-8b78-b119f2528186
description: Detects triggering of AMSI by Windows Defender.
date: 2020/09/14
author: Bhabesh Raj
references:
    - https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps
status: stable
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 1116
        DetectionSource: 'AMSI'
    condition: selection
falsepositives:
    - unlikely
level: high
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {($_.ID -eq "1116" -and $_.message -match "DetectionSource.*AMSI") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Windows\ Defender\/Operational" AND winlog.event_id:"1116" AND DetectionSource:"AMSI")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ea9bf0fa-edec-4fb8-8b78-b119f2528186 <<EOF
{
  "metadata": {
    "title": "Windows Defender AMSI Trigger Detected",
    "description": "Detects triggering of AMSI by Windows Defender.",
    "tags": "",
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND winlog.event_id:\"1116\" AND DetectionSource:\"AMSI\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational\" AND winlog.event_id:\"1116\" AND DetectionSource:\"AMSI\")",
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
        "subject": "Sigma Rule 'Windows Defender AMSI Trigger Detected'",
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
(EventID:"1116" AND DetectionSource:"AMSI")
```


### splunk
    
```
(EventCode="1116" DetectionSource="AMSI")
```


### logpoint
    
```
(event_id="1116" DetectionSource="AMSI")
```


### grep
    
```
grep -P '^(?:.*(?=.*1116)(?=.*AMSI))'
```



