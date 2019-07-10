| Title                | AD Privileged Users or Groups Reconnaissance                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          | <ul><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>if source account name is not an admin then its super suspicious</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html](https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: AD Privileged Users or Groups Reconnaissance
description: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs
references:
    - https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html
tags:
    - attack.discovery
    - attack.t1087
status: experimental
author: Samir Bousseaden
logsource:
    product: windows
    service: security
    definition: 'Requirements: enable Object Access SAM on your Domain Controllers'
detection:
    selection:
        EventID: 4661
        ObjectType:
        - 'SAM_USER'
        - 'SAM_GROUP'
        ObjectName:
         - '*-512'
         - '*-502'
         - '*-500'
         - '*-505'
         - '*-519'
         - '*-520'
         - '*-544'
         - '*-551'
         - '*-555'
         - '*admin*'
    condition: selection
falsepositives:
    - if source account name is not an admin then its super suspicious
level: high

```





### es-qs
    
```
(EventID:"4661" AND ObjectType:("SAM_USER" "SAM_GROUP") AND ObjectName.keyword:(*\\-512 *\\-502 *\\-500 *\\-505 *\\-519 *\\-520 *\\-544 *\\-551 *\\-555 *admin*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/AD-Privileged-Users-or-Groups-Reconnaissance <<EOF\n{\n  "metadata": {\n    "title": "AD Privileged Users or Groups Reconnaissance",\n    "description": "Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087"\n    ],\n    "query": "(EventID:\\"4661\\" AND ObjectType:(\\"SAM_USER\\" \\"SAM_GROUP\\") AND ObjectName.keyword:(*\\\\-512 *\\\\-502 *\\\\-500 *\\\\-505 *\\\\-519 *\\\\-520 *\\\\-544 *\\\\-551 *\\\\-555 *admin*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4661\\" AND ObjectType:(\\"SAM_USER\\" \\"SAM_GROUP\\") AND ObjectName.keyword:(*\\\\-512 *\\\\-502 *\\\\-500 *\\\\-505 *\\\\-519 *\\\\-520 *\\\\-544 *\\\\-551 *\\\\-555 *admin*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'AD Privileged Users or Groups Reconnaissance\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4661" AND ObjectType:("SAM_USER" "SAM_GROUP") AND ObjectName:("*\\-512" "*\\-502" "*\\-500" "*\\-505" "*\\-519" "*\\-520" "*\\-544" "*\\-551" "*\\-555" "*admin*"))
```


### splunk
    
```
(EventID="4661" (ObjectType="SAM_USER" OR ObjectType="SAM_GROUP") (ObjectName="*-512" OR ObjectName="*-502" OR ObjectName="*-500" OR ObjectName="*-505" OR ObjectName="*-519" OR ObjectName="*-520" OR ObjectName="*-544" OR ObjectName="*-551" OR ObjectName="*-555" OR ObjectName="*admin*"))
```


### logpoint
    
```
(EventID="4661" ObjectType IN ["SAM_USER", "SAM_GROUP"] ObjectName IN ["*-512", "*-502", "*-500", "*-505", "*-519", "*-520", "*-544", "*-551", "*-555", "*admin*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4661)(?=.*(?:.*SAM_USER|.*SAM_GROUP))(?=.*(?:.*.*-512|.*.*-502|.*.*-500|.*.*-505|.*.*-519|.*.*-520|.*.*-544|.*.*-551|.*.*-555|.*.*admin.*)))'
```



