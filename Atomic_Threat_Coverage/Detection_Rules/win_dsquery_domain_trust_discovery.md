| Title                | Domain Trust Discovery                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a discovery of domain trusts                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1482: Domain Trust Discovery](../Triggers/T1482.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrators script of some sort</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.yaml)</li></ul>  |
| Author               | Jakob Weinzettl, oscd.community |


## Detection Rules

### Sigma rule

```
title: Domain Trust Discovery
id: 77815820-246c-47b8-9741-e0def3f57308
status: experimental
description: Detects a discovery of domain trusts
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.yaml
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2019/11/08
tags:
    - attack.discovery
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\dsquery.exe'
        CommandLine|contains|all:
            - '-filter'
            - 'trustedDomain'
      - Image|endswith: '\nltest.exe'
        CommandLine|contains: 'domain_trusts'
    condition: selection
falsepositives:
    - Administrators script of some sort
level: medium

```





### es-qs
    
```
((Image.keyword:*\\\\dsquery.exe AND CommandLine.keyword:*\\-filter* AND CommandLine.keyword:*trustedDomain*) OR (Image.keyword:*\\\\nltest.exe AND CommandLine.keyword:*domain_trusts*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Domain-Trust-Discovery <<EOF\n{\n  "metadata": {\n    "title": "Domain Trust Discovery",\n    "description": "Detects a discovery of domain trusts",\n    "tags": [\n      "attack.discovery",\n      "attack.t1482"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\dsquery.exe AND CommandLine.keyword:*\\\\-filter* AND CommandLine.keyword:*trustedDomain*) OR (Image.keyword:*\\\\\\\\nltest.exe AND CommandLine.keyword:*domain_trusts*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\dsquery.exe AND CommandLine.keyword:*\\\\-filter* AND CommandLine.keyword:*trustedDomain*) OR (Image.keyword:*\\\\\\\\nltest.exe AND CommandLine.keyword:*domain_trusts*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Domain Trust Discovery\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\dsquery.exe AND CommandLine.keyword:*\\-filter* AND CommandLine.keyword:*trustedDomain*) OR (Image.keyword:*\\\\nltest.exe AND CommandLine.keyword:*domain_trusts*))
```


### splunk
    
```
((Image="*\\\\dsquery.exe" CommandLine="*-filter*" CommandLine="*trustedDomain*") OR (Image="*\\\\nltest.exe" CommandLine="*domain_trusts*"))
```


### logpoint
    
```
(event_id="1" ((Image="*\\\\dsquery.exe" CommandLine="*-filter*" CommandLine="*trustedDomain*") OR (Image="*\\\\nltest.exe" CommandLine="*domain_trusts*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\dsquery\\.exe)(?=.*.*-filter.*)(?=.*.*trustedDomain.*))|.*(?:.*(?=.*.*\\nltest\\.exe)(?=.*.*domain_trusts.*))))'
```



