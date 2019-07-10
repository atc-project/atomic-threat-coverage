| Title                | Possible SPN Enumeration                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Service Principal Name Enumeration used for Kerberoasting                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrator Activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation](https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation)</li></ul>  |
| Author               | Markus Neis, keepwatch |


## Detection Rules

### Sigma rule

```
title: Possible SPN Enumeration
description: Detects Service Principal Name Enumeration used for Kerberoasting
status: experimental
references:
    - https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
author: Markus Neis, keepwatch
date: 2018/11/14
tags:
    - attack.credential_access
    - attack.t1208
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image: '*\setspn.exe'
    selection_desc:
        Description: '*Query or reset the computer* SPN attribute*'
    cmd:
        CommandLine: '*-q*'
    condition: (selection_image or selection_desc) and cmd
falsepositives:
    - Administrator Activity
level: medium

```





### es-qs
    
```
((Image.keyword:*\\\\setspn.exe OR Description.keyword:*Query\\ or\\ reset\\ the\\ computer*\\ SPN\\ attribute*) AND CommandLine.keyword:*\\-q*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Possible-SPN-Enumeration <<EOF\n{\n  "metadata": {\n    "title": "Possible SPN Enumeration",\n    "description": "Detects Service Principal Name Enumeration used for Kerberoasting",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1208"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\setspn.exe OR Description.keyword:*Query\\\\ or\\\\ reset\\\\ the\\\\ computer*\\\\ SPN\\\\ attribute*) AND CommandLine.keyword:*\\\\-q*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\setspn.exe OR Description.keyword:*Query\\\\ or\\\\ reset\\\\ the\\\\ computer*\\\\ SPN\\\\ attribute*) AND CommandLine.keyword:*\\\\-q*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible SPN Enumeration\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image:"*\\\\setspn.exe" OR Description:"*Query or reset the computer* SPN attribute*") AND CommandLine:"*\\-q*")
```


### splunk
    
```
((Image="*\\\\setspn.exe" OR Description="*Query or reset the computer* SPN attribute*") CommandLine="*-q*")
```


### logpoint
    
```
((Image="*\\\\setspn.exe" OR Description="*Query or reset the computer* SPN attribute*") CommandLine="*-q*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\\setspn\\.exe|.*.*Query or reset the computer.* SPN attribute.*)))(?=.*.*-q.*))'
```



