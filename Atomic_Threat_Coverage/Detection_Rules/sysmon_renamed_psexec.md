| Title                | Renamed PsExec                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of a renamed PsExec often used by attackers or malware                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Software that illegaly integrates PsExec in a renamed form</li><li>Administrators that have renamed PsExec and no one knows why</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks](https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-05-009</li><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Renamed PsExec
status: experimental
description: Detects the execution of a renamed PsExec often used by attackers or malware 
references:
    - https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks
author: Florian Roth
date: 2019/05/21
tags:
    - car.2013-05-009
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        Description: 'Execute processes remotely'
        Product: 'Sysinternals PsExec'
    filter:
        Image: '*\PsExec.exe'
    condition: selection and not filter
falsepositives:
    - Software that illegaly integrates PsExec in a renamed form
    - Administrators that have renamed PsExec and no one knows why
level: high

```





### es-qs
    
```
((Description:"Execute\\ processes\\ remotely" AND Product:"Sysinternals\\ PsExec") AND (NOT (Image.keyword:*\\\\PsExec.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Renamed-PsExec <<EOF\n{\n  "metadata": {\n    "title": "Renamed PsExec",\n    "description": "Detects the execution of a renamed PsExec often used by attackers or malware",\n    "tags": [\n      "car.2013-05-009"\n    ],\n    "query": "((Description:\\"Execute\\\\ processes\\\\ remotely\\" AND Product:\\"Sysinternals\\\\ PsExec\\") AND (NOT (Image.keyword:*\\\\\\\\PsExec.exe)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Description:\\"Execute\\\\ processes\\\\ remotely\\" AND Product:\\"Sysinternals\\\\ PsExec\\") AND (NOT (Image.keyword:*\\\\\\\\PsExec.exe)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed PsExec\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Description:"Execute processes remotely" AND Product:"Sysinternals PsExec") AND NOT (Image:"*\\\\PsExec.exe"))
```


### splunk
    
```
((Description="Execute processes remotely" Product="Sysinternals PsExec") NOT (Image="*\\\\PsExec.exe"))
```


### logpoint
    
```
((Description="Execute processes remotely" Product="Sysinternals PsExec")  -(Image="*\\\\PsExec.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*Execute processes remotely)(?=.*Sysinternals PsExec)))(?=.*(?!.*(?:.*(?=.*.*\\PsExec\\.exe)))))'
```



