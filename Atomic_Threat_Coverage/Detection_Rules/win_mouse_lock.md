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
(Product.keyword:*Mouse\\ Lock* OR Company.keyword:*Misc314* OR winlog.event_data.CommandLine.keyword:*Mouse\\ Lock_*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c9192ad9-75e5-43eb-8647-82a0a5b493e3 <<EOF\n{\n  "metadata": {\n    "title": "Mouse Lock Credential Gathering",\n    "description": "In Kaspersky\'s 2020 Incident Response Analyst Report they listed legitimate tool \\"Mouse Lock\\" as being used for both credential access and collection in security incidents.",\n    "tags": [\n      "attack.credential_access",\n      "attack.collection",\n      "attack.t1056.002"\n    ],\n    "query": "(Product.keyword:*Mouse\\\\ Lock* OR Company.keyword:*Misc314* OR winlog.event_data.CommandLine.keyword:*Mouse\\\\ Lock_*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Product.keyword:*Mouse\\\\ Lock* OR Company.keyword:*Misc314* OR winlog.event_data.CommandLine.keyword:*Mouse\\\\ Lock_*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mouse Lock Credential Gathering\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n    Product = {{_source.Product}}\\n    Company = {{_source.Company}}\\nCommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
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



