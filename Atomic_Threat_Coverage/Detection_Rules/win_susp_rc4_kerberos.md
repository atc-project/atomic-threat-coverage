| Title                    | Suspicious Kerberos RC4 Ticket Encryption       |
|:-------------------------|:------------------|
| **Description**          | Detects service ticket requests using RC4 encryption type |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Service accounts used on legacy systems (e.g. NetApp)</li><li>Windows Domains with DFL 2003 and legacy systems</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=3458](https://adsecurity.org/?p=3458)</li><li>[https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity](https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1558.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Kerberos RC4 Ticket Encryption
id: 496a0e47-0a33-4dca-b009-9e6ca3591f39
status: experimental
references:
    - https://adsecurity.org/?p=3458
    - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
tags:
    - attack.credential_access
    - attack.t1208
    - attack.t1558.003
description: Detects service ticket requests using RC4 encryption type
author: Florian Roth
date: 2017/02/06
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    reduction:
        - ServiceName: '$*'
    condition: selection and not reduction
falsepositives:
    - Service accounts used on legacy systems (e.g. NetApp)
    - Windows Domains with DFL 2003 and legacy systems
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4769" -and $_.message -match "TicketOptions.*0x40810000" -and $_.message -match "TicketEncryptionType.*0x17") -and  -not ($_.message -match "ServiceName.*$.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:"0x40810000" AND winlog.event_data.TicketEncryptionType:"0x17") AND (NOT (winlog.event_data.ServiceName.keyword:$*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/496a0e47-0a33-4dca-b009-9e6ca3591f39 <<EOF
{
  "metadata": {
    "title": "Suspicious Kerberos RC4 Ticket Encryption",
    "description": "Detects service ticket requests using RC4 encryption type",
    "tags": [
      "attack.credential_access",
      "attack.t1208",
      "attack.t1558.003"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4769\" AND winlog.event_data.TicketOptions:\"0x40810000\" AND winlog.event_data.TicketEncryptionType:\"0x17\") AND (NOT (winlog.event_data.ServiceName.keyword:$*)))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4769\" AND winlog.event_data.TicketOptions:\"0x40810000\" AND winlog.event_data.TicketEncryptionType:\"0x17\") AND (NOT (winlog.event_data.ServiceName.keyword:$*)))",
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
        "subject": "Sigma Rule 'Suspicious Kerberos RC4 Ticket Encryption'",
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
((EventID:"4769" AND TicketOptions:"0x40810000" AND TicketEncryptionType:"0x17") AND (NOT (ServiceName.keyword:$*)))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4769" TicketOptions="0x40810000" TicketEncryptionType="0x17") NOT (ServiceName="$*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4769" ticket_options="0x40810000" TicketEncryptionType="0x17")  -(service="$*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4769)(?=.*0x40810000)(?=.*0x17)))(?=.*(?!.*(?:.*(?:.*(?=.*\$.*))))))'
```



