| Title                    | Mouse Lock Credential Gathering       |
|:-------------------------|:------------------|
| **Description**          | In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1056.002: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1056.002: GUI Input Capture](../Triggers/T1056.002.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate uses of Mouse Lock software</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Cian Heasley |


## Detection Rules

### Sigma rule

```
title: Mouse Lock Credential Gathering
id: c9192ad9-75e5-43eb-8647-82a0a5b493e3
status: experimental
description: In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.
author: Cian Heasley
reference:
    - https://github.com/klsecservices/Publications/blob/master/Incident-Response-Analyst-Report-2020.pdf
    - https://sourceforge.net/projects/mouselock/
date: 2020/08/13
tags:
    - attack.credential_access
    - attack.collection
    - attack.t1056.002
logsource:
    category: process_creation
detection:
    selection:
        - Product|contains: 'Mouse Lock'
        - Company|contains: 'Misc314'
        - CommandLine|contains: 'Mouse Lock_'
    condition: selection
fields:
    - Product
    - Company
    - CommandLine
falsepositives:
    - Legitimate uses of Mouse Lock software
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Product.*.*Mouse Lock.*" -or $_.message -match "Company.*.*Misc314.*" -or $_.message -match "CommandLine.*.*Mouse Lock_.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(Product.keyword:*Mouse\ Lock* OR Company.keyword:*Misc314* OR winlog.event_data.CommandLine.keyword:*Mouse\ Lock_*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c9192ad9-75e5-43eb-8647-82a0a5b493e3 <<EOF
{
  "metadata": {
    "title": "Mouse Lock Credential Gathering",
    "description": "In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool \"Mouse Lock\" as being used for both credential access and collection in security incidents.",
    "tags": [
      "attack.credential_access",
      "attack.collection",
      "attack.t1056.002"
    ],
    "query": "(Product.keyword:*Mouse\\ Lock* OR Company.keyword:*Misc314* OR winlog.event_data.CommandLine.keyword:*Mouse\\ Lock_*)"
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
                    "query": "(Product.keyword:*Mouse\\ Lock* OR Company.keyword:*Misc314* OR winlog.event_data.CommandLine.keyword:*Mouse\\ Lock_*)",
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
        "subject": "Sigma Rule 'Mouse Lock Credential Gathering'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n    Product = {{_source.Product}}\n    Company = {{_source.Company}}\nCommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Product.keyword:*Mouse Lock* OR Company.keyword:*Misc314* OR CommandLine.keyword:*Mouse Lock_*)
```


### splunk
    
```
(Product="*Mouse Lock*" OR Company="*Misc314*" OR CommandLine="*Mouse Lock_*") | table Product,Company,CommandLine
```


### logpoint
    
```
(Product="*Mouse Lock*" OR Company="*Misc314*" OR CommandLine="*Mouse Lock_*")
```


### grep
    
```
grep -P '^(?:.*(?:.*.*Mouse Lock.*|.*.*Misc314.*|.*.*Mouse Lock_.*))'
```



