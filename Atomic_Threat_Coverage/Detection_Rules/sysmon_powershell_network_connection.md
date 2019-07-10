| Title                | PowerShell Network Connections                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company's ip range')                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.youtube.com/watch?v=DLtJTxMWZ2o](https://www.youtube.com/watch?v=DLtJTxMWZ2o)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Network Connections
status: experimental
description: "Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company's ip range')"  
author: Florian Roth
references:
    - https://www.youtube.com/watch?v=DLtJTxMWZ2o
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image: '*\powershell.exe'
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
            - '127.0.0.1'
        DestinationIsIpv6: 'false'
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: low

```





### es-qs
    
```
((EventID:"3" AND Image.keyword:*\\\\powershell.exe) AND (NOT (DestinationIp.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.0.0.1) AND DestinationIsIpv6:"false" AND User:"NT\\ AUTHORITY\\\\SYSTEM")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PowerShell-Network-Connections <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Network Connections",\n    "description": "Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company\'s ip range\')",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "((EventID:\\"3\\" AND Image.keyword:*\\\\\\\\powershell.exe) AND (NOT (DestinationIp.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.0.0.1) AND DestinationIsIpv6:\\"false\\" AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"3\\" AND Image.keyword:*\\\\\\\\powershell.exe) AND (NOT (DestinationIp.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.0.0.1) AND DestinationIsIpv6:\\"false\\" AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Network Connections\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"3" AND Image:"*\\\\powershell.exe") AND NOT (DestinationIp:("10.*" "192.168.*" "172.16.*" "172.17.*" "172.18.*" "172.19.*" "172.20.*" "172.21.*" "172.22.*" "172.23.*" "172.24.*" "172.25.*" "172.26.*" "172.27.*" "172.28.*" "172.29.*" "172.30.*" "172.31.*" "127.0.0.1") AND DestinationIsIpv6:"false" AND User:"NT AUTHORITY\\\\SYSTEM"))
```


### splunk
    
```
((EventID="3" Image="*\\\\powershell.exe") NOT ((DestinationIp="10.*" OR DestinationIp="192.168.*" OR DestinationIp="172.16.*" OR DestinationIp="172.17.*" OR DestinationIp="172.18.*" OR DestinationIp="172.19.*" OR DestinationIp="172.20.*" OR DestinationIp="172.21.*" OR DestinationIp="172.22.*" OR DestinationIp="172.23.*" OR DestinationIp="172.24.*" OR DestinationIp="172.25.*" OR DestinationIp="172.26.*" OR DestinationIp="172.27.*" OR DestinationIp="172.28.*" OR DestinationIp="172.29.*" OR DestinationIp="172.30.*" OR DestinationIp="172.31.*" OR DestinationIp="127.0.0.1") DestinationIsIpv6="false" User="NT AUTHORITY\\\\SYSTEM"))
```


### logpoint
    
```
((EventID="3" Image="*\\\\powershell.exe")  -(DestinationIp IN ["10.*", "192.168.*", "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*", "172.22.*", "172.23.*", "172.24.*", "172.25.*", "172.26.*", "172.27.*", "172.28.*", "172.29.*", "172.30.*", "172.31.*", "127.0.0.1"] DestinationIsIpv6="false" User="NT AUTHORITY\\\\SYSTEM"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*.*\\powershell\\.exe)))(?=.*(?!.*(?:.*(?=.*(?:.*10\\..*|.*192\\.168\\..*|.*172\\.16\\..*|.*172\\.17\\..*|.*172\\.18\\..*|.*172\\.19\\..*|.*172\\.20\\..*|.*172\\.21\\..*|.*172\\.22\\..*|.*172\\.23\\..*|.*172\\.24\\..*|.*172\\.25\\..*|.*172\\.26\\..*|.*172\\.27\\..*|.*172\\.28\\..*|.*172\\.29\\..*|.*172\\.30\\..*|.*172\\.31\\..*|.*127\\.0\\.0\\.1))(?=.*false)(?=.*NT AUTHORITY\\SYSTEM)))))'
```



