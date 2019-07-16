| Title                | Antivirus Password Dumper Detection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a highly relevant Antivirus alert that reports a password dumper                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Password Dumper Detection
description: Detects a highly relevant Antivirus alert that reports a password dumper
date: 2018/09/09
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: antivirus
detection:
    selection:
        Signature: 
            - "*DumpCreds*"
            - "*Mimikatz*"
            - "*PWCrack*"
            - "HTool/WCE"
            - "*PSWtool*"
            - "*PWDump*"
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
Signature.keyword:(*DumpCreds* *Mimikatz* *PWCrack* HTool\\/WCE *PSWtool* *PWDump*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Antivirus-Password-Dumper-Detection <<EOF\n{\n  "metadata": {\n    "title": "Antivirus Password Dumper Detection",\n    "description": "Detects a highly relevant Antivirus alert that reports a password dumper",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "Signature.keyword:(*DumpCreds* *Mimikatz* *PWCrack* HTool\\\\/WCE *PSWtool* *PWDump*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Signature.keyword:(*DumpCreds* *Mimikatz* *PWCrack* HTool\\\\/WCE *PSWtool* *PWDump*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Antivirus Password Dumper Detection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nFileName = {{_source.FileName}}\\n    User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Signature:("*DumpCreds*" "*Mimikatz*" "*PWCrack*" "HTool\\/WCE" "*PSWtool*" "*PWDump*")
```


### splunk
    
```
(Signature="*DumpCreds*" OR Signature="*Mimikatz*" OR Signature="*PWCrack*" OR Signature="HTool/WCE" OR Signature="*PSWtool*" OR Signature="*PWDump*") | table FileName,User
```


### logpoint
    
```
Signature IN ["*DumpCreds*", "*Mimikatz*", "*PWCrack*", "HTool/WCE", "*PSWtool*", "*PWDump*"]
```


### grep
    
```
grep -P '^(?:.*.*DumpCreds.*|.*.*Mimikatz.*|.*.*PWCrack.*|.*HTool/WCE|.*.*PSWtool.*|.*.*PWDump.*)'
```



