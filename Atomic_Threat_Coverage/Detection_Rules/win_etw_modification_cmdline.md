| Title                    | COMPlus_ETWEnabled Command Line Arguments       |
|:-------------------------|:------------------|
| **Description**          | Potential adversaries stopping ETW providers recording loaded .NET assemblies. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/_xpn_/status/1268712093928378368](https://twitter.com/_xpn_/status/1268712093928378368)</li><li>[https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr](https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr)</li><li>[https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables](https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables)</li><li>[https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38](https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38)</li><li>[https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39](https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39)</li><li>[https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_](https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_)</li><li>[https://bunnyinside.com/?term=f71e8cb9c76a](https://bunnyinside.com/?term=f71e8cb9c76a)</li><li>[http://managed670.rssing.com/chan-5590147/all_p1.html](http://managed670.rssing.com/chan-5590147/all_p1.html)</li><li>[https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code](https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code)</li></ul>  |
| **Author**               | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |


## Detection Rules

### Sigma rule

```
title: COMPlus_ETWEnabled Command Line Arguments
id: 41421f44-58f9-455d-838a-c398859841d4
status: experimental
description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
references:
  - https://twitter.com/_xpn_/status/1268712093928378368
  - https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
  - https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
  - https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
  - https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
  - https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
  - https://bunnyinside.com/?term=f71e8cb9c76a
  - http://managed670.rssing.com/chan-5590147/all_p1.html
  - https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/05/02
modified: 2020/08/29
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'COMPlus_ETWEnabled=0'
    condition: selection
falsepositives:
    - unknown
level: critical
```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*COMPlus_ETWEnabled=0.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*COMPlus_ETWEnabled\\=0*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/41421f44-58f9-455d-838a-c398859841d4 <<EOF\n{\n  "metadata": {\n    "title": "COMPlus_ETWEnabled Command Line Arguments",\n    "description": "Potential adversaries stopping ETW providers recording loaded .NET assemblies.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1562"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:*COMPlus_ETWEnabled\\\\=0*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:*COMPlus_ETWEnabled\\\\=0*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'COMPlus_ETWEnabled Command Line Arguments\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*COMPlus_ETWEnabled=0*
```


### splunk
    
```
CommandLine="*COMPlus_ETWEnabled=0*"
```


### logpoint
    
```
CommandLine="*COMPlus_ETWEnabled=0*"
```


### grep
    
```
grep -P '^.*COMPlus_ETWEnabled=0.*'
```



