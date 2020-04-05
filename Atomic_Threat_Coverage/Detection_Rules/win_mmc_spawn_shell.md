| Title                    | MMC Spawning Windows Shell       |
|:-------------------------|:------------------|
| **Description**          | Detects a Windows command line executable started from MMC. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1175: Component Object Model and Distributed COM](https://attack.mitre.org/techniques/T1175)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1175: Component Object Model and Distributed COM](../Triggers/T1175.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Karneades, Swisscom CSIRT |


## Detection Rules

### Sigma rule

```
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: experimental
description: Detects a Windows command line executable started from MMC.
author: Karneades, Swisscom CSIRT
date: 2019/08/05
tags:
    - attack.lateral_movement
    - attack.t1175
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mmc.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - Image
    - ParentCommandLine
level: high

```





### es-qs
    
```
(ParentImage.keyword:*\\\\mmc.exe AND Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\reg.exe OR *\\\\regsvr32.exe OR *\\\\BITSADMIN*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/05a2ab7e-ce11-4b63-86db-ab32e763e11d <<EOF\n{\n  "metadata": {\n    "title": "MMC Spawning Windows Shell",\n    "description": "Detects a Windows command line executable started from MMC.",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1175"\n    ],\n    "query": "(ParentImage.keyword:*\\\\\\\\mmc.exe AND Image.keyword:(*\\\\\\\\cmd.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\sh.exe OR *\\\\\\\\bash.exe OR *\\\\\\\\reg.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\BITSADMIN*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:*\\\\\\\\mmc.exe AND Image.keyword:(*\\\\\\\\cmd.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\sh.exe OR *\\\\\\\\bash.exe OR *\\\\\\\\reg.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\BITSADMIN*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'MMC Spawning Windows Shell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\n            Image = {{_source.Image}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage.keyword:*\\\\mmc.exe AND Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\sh.exe *\\\\bash.exe *\\\\reg.exe *\\\\regsvr32.exe *\\\\BITSADMIN*))
```


### splunk
    
```
(ParentImage="*\\\\mmc.exe" (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\reg.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\BITSADMIN*")) | table CommandLine,Image,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage="*\\\\mmc.exe" Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\reg.exe", "*\\\\regsvr32.exe", "*\\\\BITSADMIN*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\mmc\\.exe)(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\reg\\.exe|.*.*\\regsvr32\\.exe|.*.*\\BITSADMIN.*)))'
```



