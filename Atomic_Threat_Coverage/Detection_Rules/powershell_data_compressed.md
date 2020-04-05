| Title                    | Data Compressed - Powershell       |
|:-------------------------|:------------------|
| **Description**          | An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>highly likely if archive ops are done via PS</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Data Compressed - Powershell
id: 6dc5d284-69ea-42cf-9311-fb1c3932a69a
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount
    of data sent over the network
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
        keywords|contains|all: 
            - '-Recurse'
            - '|'
            - 'Compress-Archive'
    condition: selection
falsepositives:
    - highly likely if archive ops are done via PS
level: low
tags:
    - attack.exfiltration
    - attack.t1002

```





### es-qs
    
```
(EventID:"4104" AND keywords.keyword:*\\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\\-Archive*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/6dc5d284-69ea-42cf-9311-fb1c3932a69a <<EOF\n{\n  "metadata": {\n    "title": "Data Compressed - Powershell",\n    "description": "An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1002"\n    ],\n    "query": "(EventID:\\"4104\\" AND keywords.keyword:*\\\\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\\\\-Archive*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4104\\" AND keywords.keyword:*\\\\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\\\\-Archive*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Data Compressed - Powershell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4104" AND keywords.keyword:*\\-Recurse* AND keywords.keyword:*|* AND keywords.keyword:*Compress\\-Archive*)
```


### splunk
    
```
(EventID="4104" keywords="*-Recurse*" keywords="*|*" keywords="*Compress-Archive*")
```


### logpoint
    
```
(event_id="4104" keywords="*-Recurse*" keywords="*|*" keywords="*Compress-Archive*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*.*-Recurse.*)(?=.*.*\\|.*)(?=.*.*Compress-Archive.*))'
```



