| Title                | Renamed PsExec                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of a renamed PsExec often used by attackers or malware                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Software that illegaly integrates PsExec in a renamed form</li><li>Administrators that have renamed PsExec and no one knows why</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks](https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
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
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Renamed-PsExec <<EOF\n{\n  "metadata": {\n    "title": "Renamed PsExec",\n    "description": "Detects the execution of a renamed PsExec often used by attackers or malware",\n    "tags": [\n      "car.2013-05-009"\n    ]\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((Description:\\"Execute\\\\ processes\\\\ remotely\\" AND Product:\\"Sysinternals\\\\ PsExec\\") AND (NOT (Image.keyword:*\\\\\\\\PsExec.exe)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Renamed PsExec\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
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



