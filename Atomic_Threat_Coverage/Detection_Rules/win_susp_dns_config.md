| Title                | DNS Server Error Failed Loading the ServerLevelPluginDLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0036_150_dns_server_could_not_load_dll](../Data_Needed/DN_0036_150_dns_server_could_not_load_dll.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li><li>[https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx)</li><li>[https://twitter.com/gentilkiwi/status/861641945944391680](https://twitter.com/gentilkiwi/status/861641945944391680)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: DNS Server Error Failed Loading the ServerLevelPluginDLL
description: This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded
status: experimental
date: 2017/05/08
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
    - https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx
    - https://twitter.com/gentilkiwi/status/861641945944391680
author: Florian Roth
logsource:
    product: windows
    service: dns-server
detection:
    selection:
        EventID: 
            - 150
            - 770
    condition: selection
falsepositives: 
    - Unknown
level: critical



```





### Kibana query

```
EventID:("150" "770")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/DNS-Server-Error-Failed-Loading-the-ServerLevelPluginDLL <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "EventID:(\\"150\\" \\"770\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'DNS Server Error Failed Loading the ServerLevelPluginDLL\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
EventID:("150" "770")
```





### Splunk

```
(EventID="150" OR EventID="770")
```





### Logpoint

```
EventID IN ["150", "770"]
```





### Grep

```
grep -P '^(?:.*150|.*770)'
```





### Fieldlist

```
EventID
```

