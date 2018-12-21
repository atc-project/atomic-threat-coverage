| Title                | Reconnaissance Activity with Net Command                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a set of commands often used in recon stages by different attack groups                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073](https://attack.mitre.org/tactics/T1073)</li><li>[T1012](https://attack.mitre.org/tactics/T1012)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_windows_sysmon_process_creation_1](../Data_Needed/DN_0003_windows_sysmon_process_creation_1.md)</li><li>[DN_0002_windows_process_creation_with_commandline_4688](../Data_Needed/DN_0002_windows_process_creation_with_commandline_4688.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1012](../Triggering/T1012.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/haroonmeer/status/939099379834658817](https://twitter.com/haroonmeer/status/939099379834658817)</li><li>[https://twitter.com/c_APT_ure/status/939475433711722497](https://twitter.com/c_APT_ure/status/939475433711722497)</li><li>[https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html](https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html)</li></ul>                                                          |
| Author               | Florian Roth, Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Reconnaissance Activity with Net Command
status: experimental
description: 'Detects a set of commands often used in recon stages by different attack groups' 
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author:  Florian Roth, Markus Neis
date: 2018/08/22
tags:
    - attack.discovery
    - attack.t1073
    - attack.t1012 
detection:
    selection:
        CommandLine: 
            - 'tasklist'
            - 'net time'
            - 'systeminfo'
            - 'whoami'
            - 'nbtstat'
            - 'net start'
            - '*\net1 start'
            - 'qprocess'
            - 'nslookup'
            - 'hostname.exe'
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain' 
            - '*\net1 user net localgroup administrators' 
            - 'netstat -an'
    timeframe: 15s 
    condition: selection | count() > 4
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
---
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688

```








### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Reconnaissance-Activity-with-Net-Command <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "15s"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine:(\\"tasklist\\" \\"net time\\" \\"systeminfo\\" \\"whoami\\" \\"nbtstat\\" \\"net start\\" \\"*\\\\\\\\net1 start\\" \\"qprocess\\" \\"nslookup\\" \\"hostname.exe\\" \\"*\\\\\\\\net1 user \\\\/domain\\" \\"*\\\\\\\\net1 group \\\\/domain\\" \\"*\\\\\\\\net1 group \\\\\\"domain admins\\\\\\" \\\\/domain\\" \\"*\\\\\\\\net1 group \\\\\\"Exchange Trusted Subsystem\\\\\\" \\\\/domain\\" \\"*\\\\\\\\net1 accounts \\\\/domain\\" \\"*\\\\\\\\net1 user net localgroup administrators\\" \\"netstat \\\\-an\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "gt": 4\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Reconnaissance Activity with Net Command\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Reconnaissance-Activity-with-Net-Command-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "15s"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine:(\\"tasklist\\" \\"net time\\" \\"systeminfo\\" \\"whoami\\" \\"nbtstat\\" \\"net start\\" \\"*\\\\\\\\net1 start\\" \\"qprocess\\" \\"nslookup\\" \\"hostname.exe\\" \\"*\\\\\\\\net1 user \\\\/domain\\" \\"*\\\\\\\\net1 group \\\\/domain\\" \\"*\\\\\\\\net1 group \\\\\\"domain admins\\\\\\" \\\\/domain\\" \\"*\\\\\\\\net1 group \\\\\\"Exchange Trusted Subsystem\\\\\\" \\\\/domain\\" \\"*\\\\\\\\net1 accounts \\\\/domain\\" \\"*\\\\\\\\net1 user net localgroup administrators\\" \\"netstat \\\\-an\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "gt": 4\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Reconnaissance Activity with Net Command\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```




