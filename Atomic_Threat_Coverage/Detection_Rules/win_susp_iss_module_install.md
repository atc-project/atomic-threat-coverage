| Title                | IIS Native-Code Module Command Line Installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious IIS native-code module installations via command line                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown as it may vary from organisation to arganisation how admins use to install IIS modules</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/](https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: IIS Native-Code Module Command Line Installation
description: Detects suspicious IIS native-code module installations via command line
status: experimental
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
author: Florian Roth
modified: 2012/12/11
tags:
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\APPCMD.EXE install module /name:*'
    condition: selection
falsepositives:
    - Unknown as it may vary from organisation to arganisation how admins use to install IIS modules
level: medium

```





### es-qs
    
```
CommandLine.keyword:(*\\\\APPCMD.EXE\\ install\\ module\\ \\/name\\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/IIS-Native-Code-Module-Command-Line-Installation <<EOF\n{\n  "metadata": {\n    "title": "IIS Native-Code Module Command Line Installation",\n    "description": "Detects suspicious IIS native-code module installations via command line",\n    "tags": [\n      "attack.persistence",\n      "attack.t1100"\n    ],\n    "query": "CommandLine.keyword:(*\\\\\\\\APPCMD.EXE\\\\ install\\\\ module\\\\ \\\\/name\\\\:*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\\\\\APPCMD.EXE\\\\ install\\\\ module\\\\ \\\\/name\\\\:*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'IIS Native-Code Module Command Line Installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("*\\\\APPCMD.EXE install module \\/name\\:*")
```


### splunk
    
```
(CommandLine="*\\\\APPCMD.EXE install module /name:*")
```


### logpoint
    
```
CommandLine IN ["*\\\\APPCMD.EXE install module /name:*"]
```


### grep
    
```
grep -P '^(?:.*.*\\APPCMD\\.EXE install module /name:.*)'
```



