| Title                | Transferring files with credential data via network shares                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Transferring files with well-known filenames (sensitive files with credential data) using network shares                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Transferring sensitive files for legitimate administration work by legitimate administrator</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| Author               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Transferring files with credential data via network shares
id: 910ab938-668b-401b-b08c-b596e80fdca5
description: Transferring files with well-known filenames (sensitive files with credential data) using network shares
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        RelativeTargetName|contains:
            - '\mimidrv'
            - '\lsass'
            - '\windows\minidump\'
            - '\hiberfil'
            - '\sqldmpr'
            - '\sam'
            - '\ntds.dit'
            - '\security'
    condition: selection
falsepositives:
    - Transferring sensitive files for legitimate administration work by legitimate administrator
level: medium
status: experimental

```





### es-qs
    
```
(EventID:"5145" AND RelativeTargetName.keyword:(*\\\\mimidrv* OR *\\\\lsass* OR *\\\\windows\\\\minidump\\* OR *\\\\hiberfil* OR *\\\\sqldmpr* OR *\\\\sam* OR *\\\\ntds.dit* OR *\\\\security*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Transferring-files-with-credential-data-via-network-shares <<EOF\n{\n  "metadata": {\n    "title": "Transferring files with credential data via network shares",\n    "description": "Transferring files with well-known filenames (sensitive files with credential data) using network shares",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"5145\\" AND RelativeTargetName.keyword:(*\\\\\\\\mimidrv* OR *\\\\\\\\lsass* OR *\\\\\\\\windows\\\\\\\\minidump\\\\* OR *\\\\\\\\hiberfil* OR *\\\\\\\\sqldmpr* OR *\\\\\\\\sam* OR *\\\\\\\\ntds.dit* OR *\\\\\\\\security*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"5145\\" AND RelativeTargetName.keyword:(*\\\\\\\\mimidrv* OR *\\\\\\\\lsass* OR *\\\\\\\\windows\\\\\\\\minidump\\\\* OR *\\\\\\\\hiberfil* OR *\\\\\\\\sqldmpr* OR *\\\\\\\\sam* OR *\\\\\\\\ntds.dit* OR *\\\\\\\\security*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Transferring files with credential data via network shares\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5145" AND RelativeTargetName.keyword:(*\\\\mimidrv* *\\\\lsass* *\\\\windows\\\\minidump\\* *\\\\hiberfil* *\\\\sqldmpr* *\\\\sam* *\\\\ntds.dit* *\\\\security*))
```


### splunk
    
```
(EventID="5145" (RelativeTargetName="*\\\\mimidrv*" OR RelativeTargetName="*\\\\lsass*" OR RelativeTargetName="*\\\\windows\\\\minidump\\*" OR RelativeTargetName="*\\\\hiberfil*" OR RelativeTargetName="*\\\\sqldmpr*" OR RelativeTargetName="*\\\\sam*" OR RelativeTargetName="*\\\\ntds.dit*" OR RelativeTargetName="*\\\\security*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" RelativeTargetName IN ["*\\\\mimidrv*", "*\\\\lsass*", "*\\\\windows\\\\minidump\\*", "*\\\\hiberfil*", "*\\\\sqldmpr*", "*\\\\sam*", "*\\\\ntds.dit*", "*\\\\security*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*(?:.*.*\\mimidrv.*|.*.*\\lsass.*|.*.*\\windows\\minidump\\.*|.*.*\\hiberfil.*|.*.*\\sqldmpr.*|.*.*\\sam.*|.*.*\\ntds\\.dit.*|.*.*\\security.*)))'
```



