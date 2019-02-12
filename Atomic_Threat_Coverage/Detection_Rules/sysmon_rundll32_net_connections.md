| Title                | Rundll32 Internet Connection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a rundll32 that communicates with public IP addresses                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1085: Rundll32](https://attack.mitre.org/tactics/T1085)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              | <ul><li>[('Rundll32', 'T1085')](../Triggers/('Rundll32', 'T1085').md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Communication to other corporate systems that use IP addresses from public address spaces</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100](https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


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
            - '172.*'
    condition: selection and not filter
falsepositives:
    - Communication to other corporate systems that use IP addresses from public address spaces
level: medium

```





### Kibana query

```
((EventID:"3" AND Image.keyword:*\\\\rundll32.exe) AND NOT (DestinationIp.keyword:(10.* 192.168.* 172.*)))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Rundll32-Internet-Connection <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"3\\" AND Image.keyword:*\\\\\\\\rundll32.exe) AND NOT (DestinationIp.keyword:(10.* 192.168.* 172.*)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Rundll32 Internet Connection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"3" AND Image:"*\\\\rundll32.exe") AND NOT (DestinationIp:("10.*" "192.168.*" "172.*")))
```

