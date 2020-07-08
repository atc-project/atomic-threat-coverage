| Title                    | COMPlus_ETWEnabled Registry Modification       |
|:-------------------------|:------------------|
| **Description**          | Potential adversaries stopping ETW providers recording loaded .NET assemblies. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/_xpn_/status/1268712093928378368](https://twitter.com/_xpn_/status/1268712093928378368)</li><li>[https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr](https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr)</li><li>[https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables](https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables)</li><li>[https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38](https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38)</li><li>[https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39](https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39)</li><li>[https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_](https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_)</li><li>[https://bunnyinside.com/?term=f71e8cb9c76a](https://bunnyinside.com/?term=f71e8cb9c76a)</li><li>[http://managed670.rssing.com/chan-5590147/all_p1.html](http://managed670.rssing.com/chan-5590147/all_p1.html)</li><li>[https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code](https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code)</li></ul>  |
| **Author**               | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |


## Detection Rules

### Sigma rule

```
title: COMPlus_ETWEnabled Registry Modification
id: a4c90ea1-2634-4ca0-adbb-35eae169b6fc
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
date: 2020/06/05
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4657
        ObjectName|endswith: '\SOFTWARE\Microsoft\.NETFramework' 
        ObjectValueName: 'ETWEnabled'
        NewValue: '0'
    condition: selection
falsepositives:
    - unknown
level: critical
```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\\SOFTWARE\\Microsoft\\.NETFramework" -and $_.message -match "ObjectValueName.*ETWEnabled" -and $_.message -match "NewValue.*0") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4657" AND winlog.event_data.ObjectName.keyword:*\\SOFTWARE\\Microsoft\\.NETFramework AND winlog.event_data.ObjectValueName:"ETWEnabled" AND NewValue:"0")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a4c90ea1-2634-4ca0-adbb-35eae169b6fc <<EOF
{
  "metadata": {
    "title": "COMPlus_ETWEnabled Registry Modification",
    "description": "Potential adversaries stopping ETW providers recording loaded .NET assemblies.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1112"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4657\" AND winlog.event_data.ObjectName.keyword:*\\\\SOFTWARE\\\\Microsoft\\\\.NETFramework AND winlog.event_data.ObjectValueName:\"ETWEnabled\" AND NewValue:\"0\")"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4657\" AND winlog.event_data.ObjectName.keyword:*\\\\SOFTWARE\\\\Microsoft\\\\.NETFramework AND winlog.event_data.ObjectValueName:\"ETWEnabled\" AND NewValue:\"0\")",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'COMPlus_ETWEnabled Registry Modification'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(EventID:"4657" AND ObjectName.keyword:*\\SOFTWARE\\Microsoft\\.NETFramework AND ObjectValueName:"ETWEnabled" AND NewValue:"0")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4657" ObjectName="*\\SOFTWARE\\Microsoft\\.NETFramework" ObjectValueName="ETWEnabled" NewValue="0")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4657" ObjectName="*\\SOFTWARE\\Microsoft\\.NETFramework" ObjectValueName="ETWEnabled" NewValue="0")
```


### grep
    
```
grep -P '^(?:.*(?=.*4657)(?=.*.*\SOFTWARE\Microsoft\\.NETFramework)(?=.*ETWEnabled)(?=.*0))'
```



