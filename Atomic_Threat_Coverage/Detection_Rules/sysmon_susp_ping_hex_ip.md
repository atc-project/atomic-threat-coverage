| Title                | Ping Hex IP                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a ping command that uses a hex encoded IP address                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unlikely, because no sane admin pings IP addresses in a hexadecimal form</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna](https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna)</li><li>[https://twitter.com/vysecurity/status/977198418354491392](https://twitter.com/vysecurity/status/977198418354491392)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Ping Hex IP
description: Detects a ping command that uses a hex encoded IP address
references:
    - https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna
    - https://twitter.com/vysecurity/status/977198418354491392
author: Florian Roth
date: 2018/03/23
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine:
            - '*\ping.exe 0x*'
            - '*\ping 0x*'
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high


```





### Kibana query

```
(EventID:"1" AND CommandLine.keyword:(*\\\\ping.exe\\ 0x* *\\\\ping\\ 0x*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Ping-Hex-IP <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\\\\\ping.exe\\\\ 0x* *\\\\\\\\ping\\\\ 0x*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Ping Hex IP\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:("*\\\\ping.exe 0x*" "*\\\\ping 0x*"))
```





### Splunk

```
(EventID="1" (CommandLine="*\\\\ping.exe 0x*" OR CommandLine="*\\\\ping 0x*")) | table ParentCommandLine
```





### Logpoint

```
(EventID="1" CommandLine IN ["*\\\\ping.exe 0x*", "*\\\\ping 0x*"])
```





### Grep

```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\ping\\.exe 0x.*|.*.*\\ping 0x.*)))'
```





### Fieldlist

```
CommandLine\nEventID
```

