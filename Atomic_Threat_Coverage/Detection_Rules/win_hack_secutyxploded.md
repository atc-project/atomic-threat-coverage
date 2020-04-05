| Title                    | SecurityXploded Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of SecurityXploded Tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://securityxploded.com/](https://securityxploded.com/)</li><li>[https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/](https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: SecurityXploded Tool
id: 7679d464-4f74-45e2-9e01-ac66c5eb041a
description: Detects the execution of SecurityXploded Tools
author: Florian Roth
references:
    - https://securityxploded.com/
    - https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/
date: 2018/12/19
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Company: SecurityXploded
    selection2:
        Image|endswith: 'PasswordDump.exe'
    selection3:
        OriginalFilename|endswith: 'PasswordDump.exe'
    condition: 1 of them
falsepositives:
    - unlikely
level: critical

```





### es-qs
    
```
(Company:"SecurityXploded" OR Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7679d464-4f74-45e2-9e01-ac66c5eb041a <<EOF\n{\n  "metadata": {\n    "title": "SecurityXploded Tool",\n    "description": "Detects the execution of SecurityXploded Tools",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.s0005"\n    ],\n    "query": "(Company:\\"SecurityXploded\\" OR Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Company:\\"SecurityXploded\\" OR Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'SecurityXploded Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Company:"SecurityXploded" OR Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)
```


### splunk
    
```
(Company="SecurityXploded" OR Image="*PasswordDump.exe" OR OriginalFilename="*PasswordDump.exe")
```


### logpoint
    
```
(event_id="1" (Company="SecurityXploded" OR Image="*PasswordDump.exe" OR OriginalFilename="*PasswordDump.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*SecurityXploded|.*.*PasswordDump\\.exe|.*.*PasswordDump\\.exe))'
```



