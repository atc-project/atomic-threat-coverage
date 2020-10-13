| Title                    | Potential Remote Desktop Connection to Non-Domain Host       |
|:-------------------------|:------------------|
| **Description**          | Detects logons using NTLM to hosts that are potentially not part of the domain. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1219: Remote Access Software](../Triggers/T1219.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Host connections to valid domains, exclude these.</li><li>Host connections not using host FQDN.</li><li>Host connections to external legitimate domains.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[n/a](n/a)</li></ul>  |
| **Author**               | James Pemberton |


## Detection Rules

### Sigma rule

```
title: Potential Remote Desktop Connection to Non-Domain Host
id: ce5678bb-b9aa-4fb5-be4b-e57f686256ad
status: experimental
description: Detects logons using NTLM to hosts that are potentially not part of the domain.
references:
    - n/a
author: James Pemberton
date: 2020/05/22
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8001
        TargetName: TERMSRV*
    condition: selection
fields:
    - Computer
    - UserName
    - DomainName
    - TargetName
falsepositives:
    - Host connections to valid domains, exclude these.
    - Host connections not using host FQDN.
    - Host connections to external legitimate domains.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8001" -and $_.message -match "TargetName.*TERMSRV.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-NTLM\/Operational" AND winlog.event_id:"8001" AND TargetName.keyword:TERMSRV*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ce5678bb-b9aa-4fb5-be4b-e57f686256ad <<EOF
{
  "metadata": {
    "title": "Potential Remote Desktop Connection to Non-Domain Host",
    "description": "Detects logons using NTLM to hosts that are potentially not part of the domain.",
    "tags": [
      "attack.command_and_control",
      "attack.t1219"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-NTLM\\/Operational\" AND winlog.event_id:\"8001\" AND TargetName.keyword:TERMSRV*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-NTLM\\/Operational\" AND winlog.event_id:\"8001\" AND TargetName.keyword:TERMSRV*)",
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
        "subject": "Sigma Rule 'Potential Remote Desktop Connection to Non-Domain Host'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n  Computer = {{_source.Computer}}\n  UserName = {{_source.UserName}}\nDomainName = {{_source.DomainName}}\nTargetName = {{_source.TargetName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"8001" AND TargetName.keyword:TERMSRV*)
```


### splunk
    
```
(source="Microsoft-Windows-NTLM/Operational" EventCode="8001" TargetName="TERMSRV*") | table Computer,UserName,DomainName,TargetName
```


### logpoint
    
```
(event_source="Microsoft-Windows-NTLM/Operational" event_id="8001" TargetName="TERMSRV*")
```


### grep
    
```
grep -P '^(?:.*(?=.*8001)(?=.*TERMSRV.*))'
```



