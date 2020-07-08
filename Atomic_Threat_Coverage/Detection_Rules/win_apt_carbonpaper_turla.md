| Title                    | Turla Service Install       |
|:-------------------------|:------------------|
| **Description**          | This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0010</li><li>attack.t1543.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Turla Service Install
id: 1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4
description: This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET
references:
    - https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
tags:
    - attack.persistence
    - attack.g0010
    - attack.t1050
    - attack.t1543.003
date: 2017/03/31
author: Florian Roth
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName:
            - 'srservice'
            - 'ipvpn'
            - 'hkmsvc'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.message -match "srservice" -or $_.message -match "ipvpn" -or $_.message -match "hkmsvc")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ServiceName:("srservice" OR "ipvpn" OR "hkmsvc"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4 <<EOF
{
  "metadata": {
    "title": "Turla Service Install",
    "description": "This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET",
    "tags": [
      "attack.persistence",
      "attack.g0010",
      "attack.t1050",
      "attack.t1543.003"
    ],
    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:(\"srservice\" OR \"ipvpn\" OR \"hkmsvc\"))"
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
                    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:(\"srservice\" OR \"ipvpn\" OR \"hkmsvc\"))",
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
        "subject": "Sigma Rule 'Turla Service Install'",
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
(EventID:"7045" AND ServiceName:("srservice" "ipvpn" "hkmsvc"))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" (ServiceName="srservice" OR ServiceName="ipvpn" OR ServiceName="hkmsvc"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service IN ["srservice", "ipvpn", "hkmsvc"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*srservice|.*ipvpn|.*hkmsvc)))'
```



