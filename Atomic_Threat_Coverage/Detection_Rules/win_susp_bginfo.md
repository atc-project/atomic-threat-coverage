| Title                    | Application Whitelisting Bypass via Bginfo       |
|:-------------------------|:------------------|
| **Description**          | Execute VBscript code that is referenced within the *.bgi file. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml)</li><li>[https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/](https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting Bypass via Bginfo
id: aaf46cdc-934e-4284-b329-34aa701e3771
status: experimental
description: Execute VBscript code that is referenced within the *.bgi file.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml
    - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
  selection:
    Image|endswith: '\bginfo.exe'
    CommandLine|contains|all:
        - '/popup'
        - '/nolicprompt'
  condition: selection
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\bginfo.exe" -and $_.message -match "CommandLine.*.*/popup.*" -and $_.message -match "CommandLine.*.*/nolicprompt.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\bginfo.exe AND winlog.event_data.CommandLine.keyword:*\\/popup* AND winlog.event_data.CommandLine.keyword:*\\/nolicprompt*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/aaf46cdc-934e-4284-b329-34aa701e3771 <<EOF\n{\n  "metadata": {\n    "title": "Application Whitelisting Bypass via Bginfo",\n    "description": "Execute VBscript code that is referenced within the *.bgi file.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\bginfo.exe AND winlog.event_data.CommandLine.keyword:*\\\\/popup* AND winlog.event_data.CommandLine.keyword:*\\\\/nolicprompt*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\bginfo.exe AND winlog.event_data.CommandLine.keyword:*\\\\/popup* AND winlog.event_data.CommandLine.keyword:*\\\\/nolicprompt*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Application Whitelisting Bypass via Bginfo\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\bginfo.exe AND CommandLine.keyword:*\\/popup* AND CommandLine.keyword:*\\/nolicprompt*)
```


### splunk
    
```
(Image="*\\\\bginfo.exe" CommandLine="*/popup*" CommandLine="*/nolicprompt*")
```


### logpoint
    
```
(Image="*\\\\bginfo.exe" CommandLine="*/popup*" CommandLine="*/nolicprompt*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\bginfo\\.exe)(?=.*.*/popup.*)(?=.*.*/nolicprompt.*))'
```



