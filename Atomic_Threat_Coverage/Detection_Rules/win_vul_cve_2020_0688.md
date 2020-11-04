| Title                    | CVE-2020-0688 Exploitation via Eventlog       |
|:-------------------------|:------------------|
| **Description**          | Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.trustedsec.com/blog/detecting-cve-20200688-remote-code-execution-vulnerability-on-microsoft-exchange-server/](https://www.trustedsec.com/blog/detecting-cve-20200688-remote-code-execution-vulnerability-on-microsoft-exchange-server/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: CVE-2020-0688 Exploitation via Eventlog
id: d6266bf5-935e-4661-b477-78772735a7cb
status: experimental
description: Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688 
references:
    - https://www.trustedsec.com/blog/detecting-cve-20200688-remote-code-execution-vulnerability-on-microsoft-exchange-server/
author: Florian Roth
date: 2020/02/29
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    product: windows
    service: application
detection:
    selection1:
        EventID: 4
        Source: MSExchange Control Panel
        Level: Error
    selection2:
        - '*&__VIEWSTATE=*'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Application | where {(($_.ID -eq "4" -and $_.message -match "Source.*MSExchange Control Panel" -and $_.message -match "Level.*Error") -and $_.message -match "*&__VIEWSTATE=*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Application" AND (winlog.event_id:"4" AND winlog.event_data.Source:"MSExchange\ Control\ Panel" AND Level:"Error") AND "*&__VIEWSTATE\=*")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d6266bf5-935e-4661-b477-78772735a7cb <<EOF
{
  "metadata": {
    "title": "CVE-2020-0688 Exploitation via Eventlog",
    "description": "Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688",
    "tags": [
      "attack.initial_access",
      "attack.t1190"
    ],
    "query": "(winlog.channel:\"Application\" AND (winlog.event_id:\"4\" AND winlog.event_data.Source:\"MSExchange\\ Control\\ Panel\" AND Level:\"Error\") AND \"*&__VIEWSTATE\\=*\")"
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
                    "query": "(winlog.channel:\"Application\" AND (winlog.event_id:\"4\" AND winlog.event_data.Source:\"MSExchange\\ Control\\ Panel\" AND Level:\"Error\") AND \"*&__VIEWSTATE\\=*\")",
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
        "subject": "Sigma Rule 'CVE-2020-0688 Exploitation via Eventlog'",
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
((EventID:"4" AND Source:"MSExchange Control Panel" AND Level:"Error") AND "*&__VIEWSTATE=*")
```


### splunk
    
```
(source="WinEventLog:Application" (EventCode="4" Source="MSExchange Control Panel" Level="Error") "*&__VIEWSTATE=*")
```


### logpoint
    
```
((event_id="4" Source="MSExchange Control Panel" Level="Error") "*&__VIEWSTATE=*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4)(?=.*MSExchange Control Panel)(?=.*Error)))(?=.*.*&__VIEWSTATE=.*))'
```



