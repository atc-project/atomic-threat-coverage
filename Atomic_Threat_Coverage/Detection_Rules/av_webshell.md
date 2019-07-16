| Title                | Antivirus Web Shell Detection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a highly relevant Antivirus alert that reports a web shell                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Web Shell Detection
description: Detects a highly relevant Antivirus alert that reports a web shell
date: 2018/09/09
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
tags:
    - attack.persistence
    - attack.t1100
logsource:
    product: antivirus
detection:
    selection:
        Signature: 
            - PHP/Backdoor
            - JSP/Backdoor
            - ASP/Backdoor
            - Backdoor.PHP
            - Backdoor.JSP
            - Backdoor.ASP
            - "*Webshell*"
    condition: selection
fields:
    - FileName
    - User
falsepositives:
    - Unlikely
level: critical

```





### es-qs
    
```
Signature.keyword:(PHP\\/Backdoor JSP\\/Backdoor ASP\\/Backdoor Backdoor.PHP Backdoor.JSP Backdoor.ASP *Webshell*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Antivirus-Web-Shell-Detection <<EOF\n{\n  "metadata": {\n    "title": "Antivirus Web Shell Detection",\n    "description": "Detects a highly relevant Antivirus alert that reports a web shell",\n    "tags": [\n      "attack.persistence",\n      "attack.t1100"\n    ],\n    "query": "Signature.keyword:(PHP\\\\/Backdoor JSP\\\\/Backdoor ASP\\\\/Backdoor Backdoor.PHP Backdoor.JSP Backdoor.ASP *Webshell*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Signature.keyword:(PHP\\\\/Backdoor JSP\\\\/Backdoor ASP\\\\/Backdoor Backdoor.PHP Backdoor.JSP Backdoor.ASP *Webshell*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Antivirus Web Shell Detection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nFileName = {{_source.FileName}}\\n    User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Signature:("PHP\\/Backdoor" "JSP\\/Backdoor" "ASP\\/Backdoor" "Backdoor.PHP" "Backdoor.JSP" "Backdoor.ASP" "*Webshell*")
```


### splunk
    
```
(Signature="PHP/Backdoor" OR Signature="JSP/Backdoor" OR Signature="ASP/Backdoor" OR Signature="Backdoor.PHP" OR Signature="Backdoor.JSP" OR Signature="Backdoor.ASP" OR Signature="*Webshell*") | table FileName,User
```


### logpoint
    
```
Signature IN ["PHP/Backdoor", "JSP/Backdoor", "ASP/Backdoor", "Backdoor.PHP", "Backdoor.JSP", "Backdoor.ASP", "*Webshell*"]
```


### grep
    
```
grep -P '^(?:.*PHP/Backdoor|.*JSP/Backdoor|.*ASP/Backdoor|.*Backdoor\\.PHP|.*Backdoor\\.JSP|.*Backdoor\\.ASP|.*.*Webshell.*)'
```



