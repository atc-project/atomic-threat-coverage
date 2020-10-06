| Title                    | Turla Group Lateral Movement       |
|:-------------------------|:------------------|
| **Description**          | Detects automated lateral movement by Turla group |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li><li>[T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083)</li><li>[T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li><li>[T1083: File and Directory Discovery](../Triggers/T1083.md)</li><li>[T1135: Network Share Discovery](../Triggers/T1135.md)</li></ul>  |
| **Severity Level**       |  Severity Level for this Detection Rule wasn't defined yet  |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securelist.com/the-epic-turla-operation/65545/](https://securelist.com/the-epic-turla-operation/65545/)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>attack.g0010</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Turla Group Lateral Movement
id: c601f20d-570a-4cde-a7d6-e17f99cb8e7f
status: experimental
description: Detects automated lateral movement by Turla group
references:
    - https://securelist.com/the-epic-turla-operation/65545/
tags:
    - attack.g0010
    - attack.execution
    - attack.t1059
    - attack.lateral_movement
    - attack.t1077 # an old one
    - attack.t1021.002
    - attack.discovery
    - attack.t1083
    - attack.t1135
author: Markus Neis
date: 2017/11/07
modified: 2020/08/27
logsource:
    category: process_creation
    product: windows
falsepositives:
   - Unknown
---
detection:
   selection:
      CommandLine:
         - 'net use \\%DomainController%\C$ "P@ssw0rd" *'
         - 'dir c:\\*.doc* /s'
         - 'dir %TEMP%\\*.exe'
   condition: selection
level: critical
---
detection:
   netCommand1:
      CommandLine: 'net view /DOMAIN'
   netCommand2:
      CommandLine: 'net session'
   netCommand3:
      CommandLine: 'net share'
   timeframe: 1m
   condition: netCommand1 | near netCommand2 and netCommand3
level: medium

```





### powershell
    
```

```


### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c601f20d-570a-4cde-a7d6-e17f99cb8e7f <<EOF\n{\n  "metadata": {\n    "title": "Turla Group Lateral Movement",\n    "description": "Detects automated lateral movement by Turla group",\n    "tags": [\n      "attack.g0010",\n      "attack.execution",\n      "attack.t1059",\n      "attack.lateral_movement",\n      "attack.t1077",\n      "attack.t1021.002",\n      "attack.discovery",\n      "attack.t1083",\n      "attack.t1135"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(net\\\\ use\\\\ \\\\\\\\%DomainController%\\\\\\\\C$\\\\ \\\\\\"P@ssw0rd\\\\\\"\\\\ * OR dir\\\\ c\\\\:\\\\\\\\*.doc*\\\\ \\\\/s OR dir\\\\ %TEMP%\\\\\\\\*.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(net\\\\ use\\\\ \\\\\\\\%DomainController%\\\\\\\\C$\\\\ \\\\\\"P@ssw0rd\\\\\\"\\\\ * OR dir\\\\ c\\\\:\\\\\\\\*.doc*\\\\ \\\\/s OR dir\\\\ %TEMP%\\\\\\\\*.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Turla Group Lateral Movement\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c601f20d-570a-4cde-a7d6-e17f99cb8e7f-2 <<EOF\n{\n  "metadata": {\n    "title": "Turla Group Lateral Movement",\n    "description": "Detects automated lateral movement by Turla group",\n    "tags": [\n      "attack.g0010",\n      "attack.execution",\n      "attack.t1059",\n      "attack.lateral_movement",\n      "attack.t1077",\n      "attack.t1021.002",\n      "attack.discovery",\n      "attack.t1083",\n      "attack.t1135"\n    ],\n    "query": "winlog.event_data.CommandLine:\\"net\\\\ view\\\\ \\\\/DOMAIN\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "1m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine:\\"net\\\\ view\\\\ \\\\/DOMAIN\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Turla Group Lateral Movement\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P \'^(?:.*net use \\\\%DomainController%\\C\\$ "P@ssw0rd" .*|.*dir c:\\\\.*\\.doc.* /s|.*dir %TEMP%\\\\.*\\.exe)\'\ngrep -P \'^net view /DOMAIN\'
```



