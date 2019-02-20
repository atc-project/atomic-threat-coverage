| Title                | Rubeus Hack Tool                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects command line parameters used by Rubeus hack tool                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>unlikely</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: Rubeus Hack Tool
description: Detects command line parameters used by Rubeus hack tool 
author: Florian Roth
references: 
    - https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/
date: 2018/12/19
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
detection:
    condition: selection
falsepositives:
    - unlikely
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine: 
            - '* asreproast *'
            - '* dump /service:krbtgt *'
            - '* kerberoast *'
            - '* createnetonly /program:*'
            - '* ptt /ticket:*'
            - '* /impersonateuser:*'
            - '* renew /ticket:*'
            - '* asktgt /user:*'
            - '* harvest /interval:*'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: 
            - '* asreproast *'
            - '* dump /service:krbtgt *'
            - '* kerberoast *'
            - '* createnetonly /program:*'
            - '* ptt /ticket:*'
            - '* /impersonateuser:*'
            - '* renew /ticket:*'
            - '* asktgt /user:*'
            - '* harvest /interval:*'
```





### Kibana query

```
(EventID:"1" AND CommandLine.keyword:(*\\ asreproast\\ * *\\ dump\\ \\/service\\:krbtgt\\ * *\\ kerberoast\\ * *\\ createnetonly\\ \\/program\\:* *\\ ptt\\ \\/ticket\\:* *\\ \\/impersonateuser\\:* *\\ renew\\ \\/ticket\\:* *\\ asktgt\\ \\/user\\:* *\\ harvest\\ \\/interval\\:*))\n(EventID:"4688" AND ProcessCommandLine.keyword:(*\\ asreproast\\ * *\\ dump\\ \\/service\\:krbtgt\\ * *\\ kerberoast\\ * *\\ createnetonly\\ \\/program\\:* *\\ ptt\\ \\/ticket\\:* *\\ \\/impersonateuser\\:* *\\ renew\\ \\/ticket\\:* *\\ asktgt\\ \\/user\\:* *\\ harvest\\ \\/interval\\:*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Rubeus-Hack-Tool <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\ asreproast\\\\ * *\\\\ dump\\\\ \\\\/service\\\\:krbtgt\\\\ * *\\\\ kerberoast\\\\ * *\\\\ createnetonly\\\\ \\\\/program\\\\:* *\\\\ ptt\\\\ \\\\/ticket\\\\:* *\\\\ \\\\/impersonateuser\\\\:* *\\\\ renew\\\\ \\\\/ticket\\\\:* *\\\\ asktgt\\\\ \\\\/user\\\\:* *\\\\ harvest\\\\ \\\\/interval\\\\:*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Rubeus Hack Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Rubeus-Hack-Tool-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND ProcessCommandLine.keyword:(*\\\\ asreproast\\\\ * *\\\\ dump\\\\ \\\\/service\\\\:krbtgt\\\\ * *\\\\ kerberoast\\\\ * *\\\\ createnetonly\\\\ \\\\/program\\\\:* *\\\\ ptt\\\\ \\\\/ticket\\\\:* *\\\\ \\\\/impersonateuser\\\\:* *\\\\ renew\\\\ \\\\/ticket\\\\:* *\\\\ asktgt\\\\ \\\\/user\\\\:* *\\\\ harvest\\\\ \\\\/interval\\\\:*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Rubeus Hack Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:("* asreproast *" "* dump \\/service\\:krbtgt *" "* kerberoast *" "* createnetonly \\/program\\:*" "* ptt \\/ticket\\:*" "* \\/impersonateuser\\:*" "* renew \\/ticket\\:*" "* asktgt \\/user\\:*" "* harvest \\/interval\\:*"))\n(EventID:"4688" AND ProcessCommandLine:("* asreproast *" "* dump \\/service\\:krbtgt *" "* kerberoast *" "* createnetonly \\/program\\:*" "* ptt \\/ticket\\:*" "* \\/impersonateuser\\:*" "* renew \\/ticket\\:*" "* asktgt \\/user\\:*" "* harvest \\/interval\\:*"))
```

