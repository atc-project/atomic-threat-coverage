| Title                | Mimikatz Use                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Naughty administrators</li><li>Penetration test</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz Use
description: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)
author: Florian Roth
tags:
    - attack.s0002
    - attack.t1003
    - attack.lateral_movement
    - attack.credential_access
logsource:
    product: windows
detection:
    keywords:
        - mimikatz
        - mimilib
        - <3 eo.oe
        - eo.oe.kiwi
        - privilege::debug
        - sekurlsa::logonpasswords
        - lsadump::sam
        - mimidrv.sys
    condition: keywords
falsepositives:
    - Naughty administrators
    - Penetration test
level: critical

```





### es-qs
    
```
(mimikatz OR mimilib OR 3\\ eo.oe OR eo.oe.kiwi OR privilege\\:\\:debug OR sekurlsa\\:\\:logonpasswords OR lsadump\\:\\:sam OR mimidrv.sys)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Mimikatz-Use <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(mimikatz OR mimilib OR 3\\\\ eo.oe OR eo.oe.kiwi OR privilege\\\\:\\\\:debug OR sekurlsa\\\\:\\\\:logonpasswords OR lsadump\\\\:\\\\:sam OR mimidrv.sys)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Mimikatz Use\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
("mimikatz" OR "mimilib" OR "<3 eo.oe" OR "eo.oe.kiwi" OR "privilege\\:\\:debug" OR "sekurlsa\\:\\:logonpasswords" OR "lsadump\\:\\:sam" OR "mimidrv.sys")
```


### splunk
    
```
("mimikatz" OR "mimilib" OR "<3 eo.oe" OR "eo.oe.kiwi" OR "privilege::debug" OR "sekurlsa::logonpasswords" OR "lsadump::sam" OR "mimidrv.sys")
```


### logpoint
    
```
("mimikatz" OR "mimilib" OR "<3 eo.oe" OR "eo.oe.kiwi" OR "privilege::debug" OR "sekurlsa::logonpasswords" OR "lsadump::sam" OR "mimidrv.sys")
```


### grep
    
```
grep -P '^(?:.*(?:.*mimikatz|.*mimilib|.*<3 eo\\.oe|.*eo\\.oe\\.kiwi|.*privilege::debug|.*sekurlsa::logonpasswords|.*lsadump::sam|.*mimidrv\\.sys))'
```



