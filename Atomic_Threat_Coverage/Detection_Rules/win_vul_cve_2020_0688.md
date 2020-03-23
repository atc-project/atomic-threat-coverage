| Title                | CVE-2020-0688 Exploitation via Eventlog                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Trigger              | <ul><li>[T1190: Exploit Public-Facing Application](../Triggers/T1190.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.trustedsec.com/blog/detecting-cve-20200688-remote-code-execution-vulnerability-on-microsoft-exchange-server/](https://www.trustedsec.com/blog/detecting-cve-20200688-remote-code-execution-vulnerability-on-microsoft-exchange-server/)</li></ul>  |
| Author               | Florian Roth |


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





### es-qs
    
```
((EventID:"4" AND Source:"MSExchange\\ Control\\ Panel" AND Level:"Error") AND "*&__VIEWSTATE\\=*")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d6266bf5-935e-4661-b477-78772735a7cb <<EOF\n{\n  "metadata": {\n    "title": "CVE-2020-0688 Exploitation via Eventlog",\n    "description": "Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688",\n    "tags": [\n      "attack.initial_access",\n      "attack.t1190"\n    ],\n    "query": "((EventID:\\"4\\" AND Source:\\"MSExchange\\\\ Control\\\\ Panel\\" AND Level:\\"Error\\") AND \\"*&__VIEWSTATE\\\\=*\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4\\" AND Source:\\"MSExchange\\\\ Control\\\\ Panel\\" AND Level:\\"Error\\") AND \\"*&__VIEWSTATE\\\\=*\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CVE-2020-0688 Exploitation via Eventlog\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4" AND Source:"MSExchange Control Panel" AND Level:"Error") AND "*&__VIEWSTATE=*")
```


### splunk
    
```
((EventID="4" Source="MSExchange Control Panel" Level="Error") "*&__VIEWSTATE=*")
```


### logpoint
    
```
((event_id="4" Source="MSExchange Control Panel" Level="Error") "*&__VIEWSTATE=*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4)(?=.*MSExchange Control Panel)(?=.*Error)))(?=.*.*&__VIEWSTATE=.*))'
```



