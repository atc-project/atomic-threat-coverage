| Title                | psr.exe capture screenshots                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The psr.exe captures desktop screenshots and saves them on the local machine                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml)</li><li>[https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf](https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: psr.exe capture screenshots
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: experimental
description: The psr.exe captures desktop screenshots and saves them on the local machine
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml
    - https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf
author: Beyu Denis, oscd.community
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.persistence
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Psr.exe'
        CommandLine|contains: '/start'
    condition: selection 
falsepositives:
    - Unknown

```





### es-qs
    
```
(Image.keyword:*\\\\Psr.exe AND CommandLine.keyword:*\\/start*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/psr.exe-capture-screenshots <<EOF\n{\n  "metadata": {\n    "title": "psr.exe capture screenshots",\n    "description": "The psr.exe captures desktop screenshots and saves them on the local machine",\n    "tags": [\n      "attack.persistence",\n      "attack.t1218"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\Psr.exe AND CommandLine.keyword:*\\\\/start*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\Psr.exe AND CommandLine.keyword:*\\\\/start*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'psr.exe capture screenshots\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\Psr.exe AND CommandLine.keyword:*\\/start*)
```


### splunk
    
```
(Image="*\\\\Psr.exe" CommandLine="*/start*")
```


### logpoint
    
```
(event_id="1" Image="*\\\\Psr.exe" CommandLine="*/start*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\Psr\\.exe)(?=.*.*/start.*))'
```



