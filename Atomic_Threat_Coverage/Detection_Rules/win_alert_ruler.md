| Title                    | Hacktool Ruler       |
|:-------------------------|:------------------|
| **Description**          | This events that are generated when using the hacktool Ruler by Sensepost |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li><li>[T1114: Email Collection](https://attack.mitre.org/techniques/T1114)</li><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Go utilities that use staaldraad awesome NTLM library</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/sensepost/ruler](https://github.com/sensepost/ruler)</li><li>[https://github.com/sensepost/ruler/issues/47](https://github.com/sensepost/ruler/issues/47)</li><li>[https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427](https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1550.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Hacktool Ruler
id: 24549159-ac1b-479c-8175-d42aea947cae
description: This events that are generated when using the hacktool Ruler by Sensepost
author: Florian Roth
date: 2017/05/31
modified: 2019/07/26
references:
    - https://github.com/sensepost/ruler
    - https://github.com/sensepost/ruler/issues/47
    - https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
tags:
    - attack.discovery
    - attack.execution
    - attack.t1087
    - attack.t1075
    - attack.t1114
    - attack.t1059
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 4776
        Workstation: 'RULER'
    selection2:
        EventID:
            - 4624
            - 4625
        WorkstationName: 'RULER'
    condition: (1 of selection*)
falsepositives:
    - Go utilities that use staaldraad awesome NTLM library
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(((($_.ID -eq "4776") -and $_.message -match "Workstation.*RULER") -or (($_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "WorkstationName.*RULER"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:("4776") AND Workstation:"RULER") OR (winlog.event_id:("4624" OR "4625") AND winlog.event_data.WorkstationName:"RULER")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/24549159-ac1b-479c-8175-d42aea947cae <<EOF
{
  "metadata": {
    "title": "Hacktool Ruler",
    "description": "This events that are generated when using the hacktool Ruler by Sensepost",
    "tags": [
      "attack.discovery",
      "attack.execution",
      "attack.t1087",
      "attack.t1075",
      "attack.t1114",
      "attack.t1059",
      "attack.t1550.002"
    ],
    "query": "(winlog.channel:\"Security\" AND ((winlog.event_id:(\"4776\") AND Workstation:\"RULER\") OR (winlog.event_id:(\"4624\" OR \"4625\") AND winlog.event_data.WorkstationName:\"RULER\")))"
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
                    "query": "(winlog.channel:\"Security\" AND ((winlog.event_id:(\"4776\") AND Workstation:\"RULER\") OR (winlog.event_id:(\"4624\" OR \"4625\") AND winlog.event_data.WorkstationName:\"RULER\")))",
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
        "subject": "Sigma Rule 'Hacktool Ruler'",
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
((EventID:("4776") AND Workstation:"RULER") OR (EventID:("4624" "4625") AND WorkstationName:"RULER"))
```


### splunk
    
```
(source="WinEventLog:Security" (((EventCode="4776") Workstation="RULER") OR ((EventCode="4624" OR EventCode="4625") WorkstationName="RULER")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((event_id IN ["4776"] Workstation="RULER") OR (event_id IN ["4624", "4625"] WorkstationName="RULER")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*4776))(?=.*RULER))|.*(?:.*(?=.*(?:.*4624|.*4625))(?=.*RULER))))'
```



