| Title                | Rubeus Hack Tool                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects command line parameters used by Rubeus hack tool                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
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
logsource:
    category: process_creation
    product: windows
detection:
    selection:
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
    condition: selection
falsepositives:
    - unlikely
level: critical

```





### es-qs
    
```
CommandLine.keyword:(*\\ asreproast\\ * *\\ dump\\ \\/service\\:krbtgt\\ * *\\ kerberoast\\ * *\\ createnetonly\\ \\/program\\:* *\\ ptt\\ \\/ticket\\:* *\\ \\/impersonateuser\\:* *\\ renew\\ \\/ticket\\:* *\\ asktgt\\ \\/user\\:* *\\ harvest\\ \\/interval\\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Rubeus-Hack-Tool <<EOF\n{\n  "metadata": {\n    "title": "Rubeus Hack Tool",\n    "description": "Detects command line parameters used by Rubeus hack tool",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.s0005"\n    ],\n    "query": "CommandLine.keyword:(*\\\\ asreproast\\\\ * *\\\\ dump\\\\ \\\\/service\\\\:krbtgt\\\\ * *\\\\ kerberoast\\\\ * *\\\\ createnetonly\\\\ \\\\/program\\\\:* *\\\\ ptt\\\\ \\\\/ticket\\\\:* *\\\\ \\\\/impersonateuser\\\\:* *\\\\ renew\\\\ \\\\/ticket\\\\:* *\\\\ asktgt\\\\ \\\\/user\\\\:* *\\\\ harvest\\\\ \\\\/interval\\\\:*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\ asreproast\\\\ * *\\\\ dump\\\\ \\\\/service\\\\:krbtgt\\\\ * *\\\\ kerberoast\\\\ * *\\\\ createnetonly\\\\ \\\\/program\\\\:* *\\\\ ptt\\\\ \\\\/ticket\\\\:* *\\\\ \\\\/impersonateuser\\\\:* *\\\\ renew\\\\ \\\\/ticket\\\\:* *\\\\ asktgt\\\\ \\\\/user\\\\:* *\\\\ harvest\\\\ \\\\/interval\\\\:*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Rubeus Hack Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("* asreproast *" "* dump \\/service\\:krbtgt *" "* kerberoast *" "* createnetonly \\/program\\:*" "* ptt \\/ticket\\:*" "* \\/impersonateuser\\:*" "* renew \\/ticket\\:*" "* asktgt \\/user\\:*" "* harvest \\/interval\\:*")
```


### splunk
    
```
(CommandLine="* asreproast *" OR CommandLine="* dump /service:krbtgt *" OR CommandLine="* kerberoast *" OR CommandLine="* createnetonly /program:*" OR CommandLine="* ptt /ticket:*" OR CommandLine="* /impersonateuser:*" OR CommandLine="* renew /ticket:*" OR CommandLine="* asktgt /user:*" OR CommandLine="* harvest /interval:*")
```


### logpoint
    
```
CommandLine IN ["* asreproast *", "* dump /service:krbtgt *", "* kerberoast *", "* createnetonly /program:*", "* ptt /ticket:*", "* /impersonateuser:*", "* renew /ticket:*", "* asktgt /user:*", "* harvest /interval:*"]
```


### grep
    
```
grep -P '^(?:.*.* asreproast .*|.*.* dump /service:krbtgt .*|.*.* kerberoast .*|.*.* createnetonly /program:.*|.*.* ptt /ticket:.*|.*.* /impersonateuser:.*|.*.* renew /ticket:.*|.*.* asktgt /user:.*|.*.* harvest /interval:.*)'
```



