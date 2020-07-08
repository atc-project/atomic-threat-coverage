| Title                    | Kerberos Manipulation       |
|:-------------------------|:------------------|
| **Description**          | This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1212: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Faulty legacy applications</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Kerberos Manipulation
id: f7644214-0eb0-4ace-9455-331ec4c09253
description: This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages
author: Florian Roth
date: 2017/02/10
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
          - 675
          - 4768
          - 4769
          - 4771
        FailureCode:
          - '0x9'
          - '0xA'
          - '0xB'
          - '0xF'
          - '0x10'
          - '0x11'
          - '0x13'
          - '0x14'
          - '0x1A'
          - '0x1F'
          - '0x21'
          - '0x22'
          - '0x23'
          - '0x24'
          - '0x26'
          - '0x27'
          - '0x28'
          - '0x29'
          - '0x2C'
          - '0x2D'
          - '0x2E'
          - '0x2F'
          - '0x31'
          - '0x32'
          - '0x3E'
          - '0x3F'
          - '0x40'
          - '0x41'
          - '0x43'
          - '0x44'
    condition: selection
falsepositives:
    - Faulty legacy applications
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "675" -or $_.ID -eq "4768" -or $_.ID -eq "4769" -or $_.ID -eq "4771") -and ($_.message -match "0x9" -or $_.message -match "0xA" -or $_.message -match "0xB" -or $_.message -match "0xF" -or $_.message -match "0x10" -or $_.message -match "0x11" -or $_.message -match "0x13" -or $_.message -match "0x14" -or $_.message -match "0x1A" -or $_.message -match "0x1F" -or $_.message -match "0x21" -or $_.message -match "0x22" -or $_.message -match "0x23" -or $_.message -match "0x24" -or $_.message -match "0x26" -or $_.message -match "0x27" -or $_.message -match "0x28" -or $_.message -match "0x29" -or $_.message -match "0x2C" -or $_.message -match "0x2D" -or $_.message -match "0x2E" -or $_.message -match "0x2F" -or $_.message -match "0x31" -or $_.message -match "0x32" -or $_.message -match "0x3E" -or $_.message -match "0x3F" -or $_.message -match "0x40" -or $_.message -match "0x41" -or $_.message -match "0x43" -or $_.message -match "0x44")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("675" OR "4768" OR "4769" OR "4771") AND winlog.event_data.FailureCode:("0x9" OR "0xA" OR "0xB" OR "0xF" OR "0x10" OR "0x11" OR "0x13" OR "0x14" OR "0x1A" OR "0x1F" OR "0x21" OR "0x22" OR "0x23" OR "0x24" OR "0x26" OR "0x27" OR "0x28" OR "0x29" OR "0x2C" OR "0x2D" OR "0x2E" OR "0x2F" OR "0x31" OR "0x32" OR "0x3E" OR "0x3F" OR "0x40" OR "0x41" OR "0x43" OR "0x44"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f7644214-0eb0-4ace-9455-331ec4c09253 <<EOF
{
  "metadata": {
    "title": "Kerberos Manipulation",
    "description": "This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages",
    "tags": [
      "attack.credential_access",
      "attack.t1212"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"675\" OR \"4768\" OR \"4769\" OR \"4771\") AND winlog.event_data.FailureCode:(\"0x9\" OR \"0xA\" OR \"0xB\" OR \"0xF\" OR \"0x10\" OR \"0x11\" OR \"0x13\" OR \"0x14\" OR \"0x1A\" OR \"0x1F\" OR \"0x21\" OR \"0x22\" OR \"0x23\" OR \"0x24\" OR \"0x26\" OR \"0x27\" OR \"0x28\" OR \"0x29\" OR \"0x2C\" OR \"0x2D\" OR \"0x2E\" OR \"0x2F\" OR \"0x31\" OR \"0x32\" OR \"0x3E\" OR \"0x3F\" OR \"0x40\" OR \"0x41\" OR \"0x43\" OR \"0x44\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"675\" OR \"4768\" OR \"4769\" OR \"4771\") AND winlog.event_data.FailureCode:(\"0x9\" OR \"0xA\" OR \"0xB\" OR \"0xF\" OR \"0x10\" OR \"0x11\" OR \"0x13\" OR \"0x14\" OR \"0x1A\" OR \"0x1F\" OR \"0x21\" OR \"0x22\" OR \"0x23\" OR \"0x24\" OR \"0x26\" OR \"0x27\" OR \"0x28\" OR \"0x29\" OR \"0x2C\" OR \"0x2D\" OR \"0x2E\" OR \"0x2F\" OR \"0x31\" OR \"0x32\" OR \"0x3E\" OR \"0x3F\" OR \"0x40\" OR \"0x41\" OR \"0x43\" OR \"0x44\"))",
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
        "subject": "Sigma Rule 'Kerberos Manipulation'",
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
(EventID:("675" "4768" "4769" "4771") AND FailureCode:("0x9" "0xA" "0xB" "0xF" "0x10" "0x11" "0x13" "0x14" "0x1A" "0x1F" "0x21" "0x22" "0x23" "0x24" "0x26" "0x27" "0x28" "0x29" "0x2C" "0x2D" "0x2E" "0x2F" "0x31" "0x32" "0x3E" "0x3F" "0x40" "0x41" "0x43" "0x44"))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="675" OR EventCode="4768" OR EventCode="4769" OR EventCode="4771") (FailureCode="0x9" OR FailureCode="0xA" OR FailureCode="0xB" OR FailureCode="0xF" OR FailureCode="0x10" OR FailureCode="0x11" OR FailureCode="0x13" OR FailureCode="0x14" OR FailureCode="0x1A" OR FailureCode="0x1F" OR FailureCode="0x21" OR FailureCode="0x22" OR FailureCode="0x23" OR FailureCode="0x24" OR FailureCode="0x26" OR FailureCode="0x27" OR FailureCode="0x28" OR FailureCode="0x29" OR FailureCode="0x2C" OR FailureCode="0x2D" OR FailureCode="0x2E" OR FailureCode="0x2F" OR FailureCode="0x31" OR FailureCode="0x32" OR FailureCode="0x3E" OR FailureCode="0x3F" OR FailureCode="0x40" OR FailureCode="0x41" OR FailureCode="0x43" OR FailureCode="0x44"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["675", "4768", "4769", "4771"] result_code IN ["0x9", "0xA", "0xB", "0xF", "0x10", "0x11", "0x13", "0x14", "0x1A", "0x1F", "0x21", "0x22", "0x23", "0x24", "0x26", "0x27", "0x28", "0x29", "0x2C", "0x2D", "0x2E", "0x2F", "0x31", "0x32", "0x3E", "0x3F", "0x40", "0x41", "0x43", "0x44"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*675|.*4768|.*4769|.*4771))(?=.*(?:.*0x9|.*0xA|.*0xB|.*0xF|.*0x10|.*0x11|.*0x13|.*0x14|.*0x1A|.*0x1F|.*0x21|.*0x22|.*0x23|.*0x24|.*0x26|.*0x27|.*0x28|.*0x29|.*0x2C|.*0x2D|.*0x2E|.*0x2F|.*0x31|.*0x32|.*0x3E|.*0x3F|.*0x40|.*0x41|.*0x43|.*0x44)))'
```



