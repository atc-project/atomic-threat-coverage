| Title                    | APT29 Google Update Service Install       |
|:-------------------------|:------------------|
| **Description**          | This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\Program Files (x86)\Google\Update\GoogleUpdate.exe so the service names and executable locations used by APT29 are specific enough to be detected in log files. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html](https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.g0016</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: APT29 Google Update Service Install
id: c069f460-2b87-4010-8dcf-e45bab362624
description: This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\Program Files (x86)\Google\Update\GoogleUpdate.exe
    so the service names and executable locations used by APT29 are specific enough to be detected in log files.
references:
    - https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
tags:
    - attack.persistence
    - attack.g0016
    - attack.t1050
date: 2017/11/01
author: Thomas Patzke 
logsource:
    product: windows
    service: system
detection:
    service_install:
        EventID: 7045
        ServiceName: 'Google Update'
    timeframe: 5m
    condition: service_install | near process
falsepositives:
    - Unknown
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    process:
        Image:
            - 'C:\Program Files(x86)\Google\GoogleService.exe'
            - 'C:\Program Files(x86)\Google\GoogleUpdate.exe'
fields:
    - ComputerName
    - User
    - CommandLine

```





### powershell
    
```

```


### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c069f460-2b87-4010-8dcf-e45bab362624 <<EOF\n{\n  "metadata": {\n    "title": "APT29 Google Update Service Install",\n    "description": "This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\\\\Program Files (x86)\\\\Google\\\\Update\\\\GoogleUpdate.exe so the service names and executable locations used by APT29 are specific enough to be detected in log files.",\n    "tags": [\n      "attack.persistence",\n      "attack.g0016",\n      "attack.t1050"\n    ],\n    "query": "(winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceName:\\"Google\\\\ Update\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "5m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceName:\\"Google\\\\ Update\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'APT29 Google Update Service Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
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
grep -P '^(?:.*(?=.*7045)(?=.*Google Update))'
```



