| Title                | Suspicious Use of Procdump                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unlikely, because no one should dump an lsass process memory</li><li>Another tool that uses the command line switches of Procdump</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[Internal Research](Internal Research)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-05-009</li><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Use of Procdump
description: Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This
    way we're also able to catch cases in which the attacker has renamed the procdump executable.
status: experimental
references:
    - Internal Research
author: Florian Roth
date: 2018/10/30
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.credential_access
    - attack.t1003
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '* -ma *'
    selection2:
        CommandLine:
            - '* lsass.exe*'
    condition: selection1 and selection2
falsepositives:
    - Unlikely, because no one should dump an lsass process memory
    - Another tool that uses the command line switches of Procdump
level: medium

```





### es-qs
    
```
(CommandLine.keyword:(*\\ \\-ma\\ *) AND CommandLine.keyword:(*\\ lsass.exe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Use-of-Procdump <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Use of Procdump",\n    "description": "Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we\'re also able to catch cases in which the attacker has renamed the procdump executable.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036",\n      "attack.credential_access",\n      "attack.t1003",\n      "car.2013-05-009"\n    ],\n    "query": "(CommandLine.keyword:(*\\\\ \\\\-ma\\\\ *) AND CommandLine.keyword:(*\\\\ lsass.exe*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:(*\\\\ \\\\-ma\\\\ *) AND CommandLine.keyword:(*\\\\ lsass.exe*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Use of Procdump\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine:("* \\-ma *") AND CommandLine:("* lsass.exe*"))
```


### splunk
    
```
((CommandLine="* -ma *") (CommandLine="* lsass.exe*"))
```


### logpoint
    
```
(CommandLine IN ["* -ma *"] CommandLine IN ["* lsass.exe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -ma .*))(?=.*(?:.*.* lsass\\.exe.*)))'
```



