| Title                | Suspicious Certutil Command                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140](https://attack.mitre.org/tactics/T1140)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1140](../Triggering/T1140.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/835149808817991680](https://twitter.com/JohnLaTwC/status/835149808817991680)</li><li>[https://twitter.com/subTee/status/888102593838362624](https://twitter.com/subTee/status/888102593838362624)</li><li>[https://twitter.com/subTee/status/888071631528235010](https://twitter.com/subTee/status/888071631528235010)</li><li>[https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/](https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li></ul>                                                          |
| Author               | Florian Roth, juju4                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0189</li><li>attack.s0189</li><li>attack.g0007</li><li>attack.g0007</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Certutil Command
status: experimental
description: Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility
author: Florian Roth, juju4
references:
    - https://twitter.com/JohnLaTwC/status/835149808817991680
    - https://twitter.com/subTee/status/888102593838362624
    - https://twitter.com/subTee/status/888071631528235010
    - https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine: 
            - '*certutil * -decode *'
            - '*certutil * -decodehex *'
            - '*certutil *-urlcache* http*'
            - '*certutil *-urlcache* ftp*'
            - '*certutil *-URL*'
            - '*certutil *-ping*'
            - '*certutil.exe * -decode *'
            - '*certutil.exe * -decodehex *'
            - '*certutil.exe *-urlcache* http*'
            - '*certutil.exe *-urlcache* ftp*'
            - '*certutil.exe *-URL*'
            - '*certutil.exe *-ping*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.s0189
    - attack.g0007
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high



```





### Kibana query

```
(EventID:"1" AND CommandLine:("*certutil * \\-decode *" "*certutil * \\-decodehex *" "*certutil *\\-urlcache* http*" "*certutil *\\-urlcache* ftp*" "*certutil *\\-URL*" "*certutil *\\-ping*" "*certutil.exe * \\-decode *" "*certutil.exe * \\-decodehex *" "*certutil.exe *\\-urlcache* http*" "*certutil.exe *\\-urlcache* ftp*" "*certutil.exe *\\-URL*" "*certutil.exe *\\-ping*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Certutil-Command <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine:(\\"*certutil * \\\\-decode *\\" \\"*certutil * \\\\-decodehex *\\" \\"*certutil *\\\\-urlcache* http*\\" \\"*certutil *\\\\-urlcache* ftp*\\" \\"*certutil *\\\\-URL*\\" \\"*certutil *\\\\-ping*\\" \\"*certutil.exe * \\\\-decode *\\" \\"*certutil.exe * \\\\-decodehex *\\" \\"*certutil.exe *\\\\-urlcache* http*\\" \\"*certutil.exe *\\\\-urlcache* ftp*\\" \\"*certutil.exe *\\\\-URL*\\" \\"*certutil.exe *\\\\-ping*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Certutil Command\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:("*certutil * \\-decode *" "*certutil * \\-decodehex *" "*certutil *\\-urlcache* http*" "*certutil *\\-urlcache* ftp*" "*certutil *\\-URL*" "*certutil *\\-ping*" "*certutil.exe * \\-decode *" "*certutil.exe * \\-decodehex *" "*certutil.exe *\\-urlcache* http*" "*certutil.exe *\\-urlcache* ftp*" "*certutil.exe *\\-URL*" "*certutil.exe *\\-ping*"))
```

