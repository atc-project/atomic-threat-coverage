| Title                | Rundll32 Internet Connection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a rundll32 that communicates with public IP addresses                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Communication to other corporate systems that use IP addresses from public address spaces</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100](https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Rundll32 Internet Connection
status: experimental
description: Detects a rundll32 that communicates with public IP addresses
references:
    - https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100
author: Florian Roth
date: 2017/11/04
tags:
    - attack.t1085
    - attack.defense_evasion
    - attack.execution
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image: '*\rundll32.exe'
    filter:
        DestinationIp: 
            - '10.*'
            - '192.168.*'
            - '172.16.*'
            - '172.17.*'
            - '172.18.*'
            - '172.19.*'
            - '172.20.*'
            - '172.21.*'
            - '172.22.*'
            - '172.23.*'
            - '172.24.*'
            - '172.25.*'
            - '172.26.*'
            - '172.27.*'
            - '172.28.*'
            - '172.29.*'
            - '172.30.*'
            - '172.31.*'
            - '127.*'
    condition: selection and not filter
falsepositives:
    - Communication to other corporate systems that use IP addresses from public address spaces
level: medium

```





### es-qs
    
```
((EventID:"3" AND Image.keyword:*\\\\rundll32.exe) AND (NOT (DestinationIp.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Rundll32-Internet-Connection <<EOF\n{\n  "metadata": {\n    "title": "Rundll32 Internet Connection",\n    "description": "Detects a rundll32 that communicates with public IP addresses",\n    "tags": [\n      "attack.t1085",\n      "attack.defense_evasion",\n      "attack.execution"\n    ],\n    "query": "((EventID:\\"3\\" AND Image.keyword:*\\\\\\\\rundll32.exe) AND (NOT (DestinationIp.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"3\\" AND Image.keyword:*\\\\\\\\rundll32.exe) AND (NOT (DestinationIp.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Rundll32 Internet Connection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"3" AND Image:"*\\\\rundll32.exe") AND NOT (DestinationIp:("10.*" "192.168.*" "172.16.*" "172.17.*" "172.18.*" "172.19.*" "172.20.*" "172.21.*" "172.22.*" "172.23.*" "172.24.*" "172.25.*" "172.26.*" "172.27.*" "172.28.*" "172.29.*" "172.30.*" "172.31.*" "127.*")))
```


### splunk
    
```
((EventID="3" Image="*\\\\rundll32.exe") NOT ((DestinationIp="10.*" OR DestinationIp="192.168.*" OR DestinationIp="172.16.*" OR DestinationIp="172.17.*" OR DestinationIp="172.18.*" OR DestinationIp="172.19.*" OR DestinationIp="172.20.*" OR DestinationIp="172.21.*" OR DestinationIp="172.22.*" OR DestinationIp="172.23.*" OR DestinationIp="172.24.*" OR DestinationIp="172.25.*" OR DestinationIp="172.26.*" OR DestinationIp="172.27.*" OR DestinationIp="172.28.*" OR DestinationIp="172.29.*" OR DestinationIp="172.30.*" OR DestinationIp="172.31.*" OR DestinationIp="127.*")))
```


### logpoint
    
```
((EventID="3" Image="*\\\\rundll32.exe")  -(DestinationIp IN ["10.*", "192.168.*", "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*", "172.22.*", "172.23.*", "172.24.*", "172.25.*", "172.26.*", "172.27.*", "172.28.*", "172.29.*", "172.30.*", "172.31.*", "127.*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*.*\\rundll32\\.exe)))(?=.*(?!.*(?:.*(?=.*(?:.*10\\..*|.*192\\.168\\..*|.*172\\.16\\..*|.*172\\.17\\..*|.*172\\.18\\..*|.*172\\.19\\..*|.*172\\.20\\..*|.*172\\.21\\..*|.*172\\.22\\..*|.*172\\.23\\..*|.*172\\.24\\..*|.*172\\.25\\..*|.*172\\.26\\..*|.*172\\.27\\..*|.*172\\.28\\..*|.*172\\.29\\..*|.*172\\.30\\..*|.*172\\.31\\..*|.*127\\..*))))))'
```



