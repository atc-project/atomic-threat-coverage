| Title                | Execution of Renamed PaExec                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of renamed paexec via imphash and executable product string                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown imphashes</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[sha256=01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc](sha256=01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc)</li><li>[https://summit.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf](https://summit.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf)</li></ul>  |
| Author               | Jason Lynch |
| Other Tags           | <ul><li>FIN7</li><li>FIN7</li><li>car.2013-05-009</li><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Execution of Renamed PaExec 
status: experimental
description: Detects execution of renamed paexec via imphash and executable product string 
references:
    - sha256=01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc 
    - https://summit.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf
tags:
    - attack.defense_evasion
    - attack.t1036
    - FIN7
    - car.2013-05-009
date: 2019/04/17
author: Jason Lynch 
falsepositives:
    - Unknown imphashes
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Product:
            - '*PAExec*'
    selection2:
        Imphash:
            - 11D40A7B7876288F919AB819CC2D9802
            - 6444f8a34e99b8f7d9647de66aabe516
            - dfd6aa3f7b2b1035b76b718f1ddc689f
            - 1a6cca4d5460b1710a12dea39e4a592c
    filter1:
        Image: '*paexec*'
    condition: (selection1 and selection2) and not filter1

```





### es-qs
    
```
((Product.keyword:(*PAExec*) AND Imphash:("11D40A7B7876288F919AB819CC2D9802" "6444f8a34e99b8f7d9647de66aabe516" "dfd6aa3f7b2b1035b76b718f1ddc689f" "1a6cca4d5460b1710a12dea39e4a592c")) AND (NOT (Image.keyword:*paexec*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Execution-of-Renamed-PaExec <<EOF\n{\n  "metadata": {\n    "title": "Execution of Renamed PaExec",\n    "description": "Detects execution of renamed paexec via imphash and executable product string",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036",\n      "FIN7",\n      "car.2013-05-009"\n    ],\n    "query": "((Product.keyword:(*PAExec*) AND Imphash:(\\"11D40A7B7876288F919AB819CC2D9802\\" \\"6444f8a34e99b8f7d9647de66aabe516\\" \\"dfd6aa3f7b2b1035b76b718f1ddc689f\\" \\"1a6cca4d5460b1710a12dea39e4a592c\\")) AND (NOT (Image.keyword:*paexec*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Product.keyword:(*PAExec*) AND Imphash:(\\"11D40A7B7876288F919AB819CC2D9802\\" \\"6444f8a34e99b8f7d9647de66aabe516\\" \\"dfd6aa3f7b2b1035b76b718f1ddc689f\\" \\"1a6cca4d5460b1710a12dea39e4a592c\\")) AND (NOT (Image.keyword:*paexec*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Execution of Renamed PaExec\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Product:("*PAExec*") AND Imphash:("11D40A7B7876288F919AB819CC2D9802" "6444f8a34e99b8f7d9647de66aabe516" "dfd6aa3f7b2b1035b76b718f1ddc689f" "1a6cca4d5460b1710a12dea39e4a592c")) AND NOT (Image:"*paexec*"))
```


### splunk
    
```
(((Product="*PAExec*") (Imphash="11D40A7B7876288F919AB819CC2D9802" OR Imphash="6444f8a34e99b8f7d9647de66aabe516" OR Imphash="dfd6aa3f7b2b1035b76b718f1ddc689f" OR Imphash="1a6cca4d5460b1710a12dea39e4a592c")) NOT (Image="*paexec*"))
```


### logpoint
    
```
((Product IN ["*PAExec*"] Imphash IN ["11D40A7B7876288F919AB819CC2D9802", "6444f8a34e99b8f7d9647de66aabe516", "dfd6aa3f7b2b1035b76b718f1ddc689f", "1a6cca4d5460b1710a12dea39e4a592c"])  -(Image="*paexec*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*.*PAExec.*))(?=.*(?:.*11D40A7B7876288F919AB819CC2D9802|.*6444f8a34e99b8f7d9647de66aabe516|.*dfd6aa3f7b2b1035b76b718f1ddc689f|.*1a6cca4d5460b1710a12dea39e4a592c))))(?=.*(?!.*(?:.*(?=.*.*paexec.*)))))'
```



