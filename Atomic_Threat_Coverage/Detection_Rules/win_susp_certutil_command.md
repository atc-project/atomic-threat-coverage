| Title                | Suspicious Certutil Command                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/835149808817991680](https://twitter.com/JohnLaTwC/status/835149808817991680)</li><li>[https://twitter.com/subTee/status/888102593838362624](https://twitter.com/subTee/status/888102593838362624)</li><li>[https://twitter.com/subTee/status/888071631528235010](https://twitter.com/subTee/status/888071631528235010)</li><li>[https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/](https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li><li>[https://twitter.com/egre55/status/1087685529016193025](https://twitter.com/egre55/status/1087685529016193025)</li><li>[https://lolbas-project.github.io/lolbas/Binaries/Certutil/](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)</li></ul>  |
| Author               | Florian Roth, juju4, keepwatch |
| Other Tags           | <ul><li>attack.s0189</li><li>attack.s0189</li><li>attack.g0007</li><li>attack.g0007</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Certutil Command
status: experimental
description: Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with
    the built-in certutil utility
author: Florian Roth, juju4, keepwatch
modified: 2019/01/22
references:
    - https://twitter.com/JohnLaTwC/status/835149808817991680
    - https://twitter.com/subTee/status/888102593838362624
    - https://twitter.com/subTee/status/888071631528235010
    - https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -decode *'
            - '* /decode *'
            - '* -decodehex *'
            - '* /decodehex *'
            - '* -urlcache *'
            - '* /urlcache *'
            - '* -verifyctl *'
            - '* /verifyctl *'
            - '* -encode *'
            - '* /encode *'
            - '*certutil* -URL*'
            - '*certutil* /URL*'
            - '*certutil* -ping*'
            - '*certutil* /ping*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1105
    - attack.s0189
    - attack.g0007
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```





### es-qs
    
```
CommandLine.keyword:(*\\ \\-decode\\ * *\\ \\/decode\\ * *\\ \\-decodehex\\ * *\\ \\/decodehex\\ * *\\ \\-urlcache\\ * *\\ \\/urlcache\\ * *\\ \\-verifyctl\\ * *\\ \\/verifyctl\\ * *\\ \\-encode\\ * *\\ \\/encode\\ * *certutil*\\ \\-URL* *certutil*\\ \\/URL* *certutil*\\ \\-ping* *certutil*\\ \\/ping*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Certutil-Command <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Certutil Command",\n    "description": "Detects a suspicious Microsoft certutil execution with sub commands like \'decode\' sub command, which is sometimes used to decode malicious code with the built-in certutil utility",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1140",\n      "attack.t1105",\n      "attack.s0189",\n      "attack.g0007"\n    ],\n    "query": "CommandLine.keyword:(*\\\\ \\\\-decode\\\\ * *\\\\ \\\\/decode\\\\ * *\\\\ \\\\-decodehex\\\\ * *\\\\ \\\\/decodehex\\\\ * *\\\\ \\\\-urlcache\\\\ * *\\\\ \\\\/urlcache\\\\ * *\\\\ \\\\-verifyctl\\\\ * *\\\\ \\\\/verifyctl\\\\ * *\\\\ \\\\-encode\\\\ * *\\\\ \\\\/encode\\\\ * *certutil*\\\\ \\\\-URL* *certutil*\\\\ \\\\/URL* *certutil*\\\\ \\\\-ping* *certutil*\\\\ \\\\/ping*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\ \\\\-decode\\\\ * *\\\\ \\\\/decode\\\\ * *\\\\ \\\\-decodehex\\\\ * *\\\\ \\\\/decodehex\\\\ * *\\\\ \\\\-urlcache\\\\ * *\\\\ \\\\/urlcache\\\\ * *\\\\ \\\\-verifyctl\\\\ * *\\\\ \\\\/verifyctl\\\\ * *\\\\ \\\\-encode\\\\ * *\\\\ \\\\/encode\\\\ * *certutil*\\\\ \\\\-URL* *certutil*\\\\ \\\\/URL* *certutil*\\\\ \\\\-ping* *certutil*\\\\ \\\\/ping*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Certutil Command\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("* \\-decode *" "* \\/decode *" "* \\-decodehex *" "* \\/decodehex *" "* \\-urlcache *" "* \\/urlcache *" "* \\-verifyctl *" "* \\/verifyctl *" "* \\-encode *" "* \\/encode *" "*certutil* \\-URL*" "*certutil* \\/URL*" "*certutil* \\-ping*" "*certutil* \\/ping*")
```


### splunk
    
```
(CommandLine="* -decode *" OR CommandLine="* /decode *" OR CommandLine="* -decodehex *" OR CommandLine="* /decodehex *" OR CommandLine="* -urlcache *" OR CommandLine="* /urlcache *" OR CommandLine="* -verifyctl *" OR CommandLine="* /verifyctl *" OR CommandLine="* -encode *" OR CommandLine="* /encode *" OR CommandLine="*certutil* -URL*" OR CommandLine="*certutil* /URL*" OR CommandLine="*certutil* -ping*" OR CommandLine="*certutil* /ping*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["* -decode *", "* /decode *", "* -decodehex *", "* /decodehex *", "* -urlcache *", "* /urlcache *", "* -verifyctl *", "* /verifyctl *", "* -encode *", "* /encode *", "*certutil* -URL*", "*certutil* /URL*", "*certutil* -ping*", "*certutil* /ping*"]
```


### grep
    
```
grep -P '^(?:.*.* -decode .*|.*.* /decode .*|.*.* -decodehex .*|.*.* /decodehex .*|.*.* -urlcache .*|.*.* /urlcache .*|.*.* -verifyctl .*|.*.* /verifyctl .*|.*.* -encode .*|.*.* /encode .*|.*.*certutil.* -URL.*|.*.*certutil.* /URL.*|.*.*certutil.* -ping.*|.*.*certutil.* /ping.*)'
```



