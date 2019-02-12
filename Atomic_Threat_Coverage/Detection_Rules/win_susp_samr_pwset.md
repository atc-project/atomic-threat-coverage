| Title                | Possible Remote Password Change Through SAMR                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). "Audit User Account Management" in "Advanced Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1212](https://attack.mitre.org/tactics/T1212)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1212](../Triggering/T1212.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Dimitrios Slamaris                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Possible Remote Password Change Through SAMR 
description: Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). "Audit User Account Management" in "Advanced Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.
author: Dimitrios Slamaris
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: windows
    service: security
detection:
    samrpipe:
        EventID: 5145
        RelativeTargetName: samr
    passwordchanged:
        EventID: 4738
    passwordchanged_filter:
        PasswordLastSet: null
    timeframe: 15s 
    condition: ( passwordchanged and not passwordchanged_filter ) | near samrpipe
level: medium

```








### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Remote-Password-Change-Through-SAMR <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "15s"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4738\\" AND NOT (NOT _exists_:PasswordLastSet))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Remote Password Change Through SAMR\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```




