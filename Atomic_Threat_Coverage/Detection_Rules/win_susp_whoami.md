| Title                | Whoami Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/haroonmeer/status/939099379834658817](https://twitter.com/haroonmeer/status/939099379834658817)</li><li>[https://twitter.com/c_APT_ure/status/939475433711722497](https://twitter.com/c_APT_ure/status/939475433711722497)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-03-001</li><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Whoami Execution
status: experimental
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
author: Florian Roth
date: 2018/05/22
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: whoami
    condition: selection
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
level: high

```





### es-qs
    
```
CommandLine:"whoami"
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Whoami-Execution <<EOF\n{\n  "metadata": {\n    "title": "Whoami Execution",\n    "description": "Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators",\n    "tags": [\n      "attack.discovery",\n      "attack.t1033",\n      "car.2016-03-001"\n    ],\n    "query": "CommandLine:\\"whoami\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine:\\"whoami\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Whoami Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:"whoami"
```


### splunk
    
```
CommandLine="whoami"
```


### logpoint
    
```
CommandLine="whoami"
```


### grep
    
```
grep -P '^whoami'
```



