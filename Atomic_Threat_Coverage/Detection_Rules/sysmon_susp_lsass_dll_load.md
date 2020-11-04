| Title                    | DLL Load via LSASS       |
|:-------------------------|:------------------|
| **Description**          | Detects a method to load DLL via LSASS process using an undocumented Registry key |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1177: LSASS Driver](https://attack.mitre.org/techniques/T1177)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.xpnsec.com/exploring-mimikatz-part-1/](https://blog.xpnsec.com/exploring-mimikatz-part-1/)</li><li>[https://twitter.com/SBousseaden/status/1183745981189427200](https://twitter.com/SBousseaden/status/1183745981189427200)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: DLL Load via LSASS
id: b3503044-60ce-4bf4-bbcb-e3db98788823
status: experimental
description: Detects a method to load DLL via LSASS process using an undocumented Registry key
author: Florian Roth
date: 2019/10/16
references:
    - https://blog.xpnsec.com/exploring-mimikatz-part-1/
    - https://twitter.com/SBousseaden/status/1183745981189427200
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
            - 12 
            - 13
        TargetObject: 
            - '*\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt*'
            - '*\CurrentControlSet\Services\NTDS\LsaDbExtPt*'
    condition: selection
tags:
    - attack.execution
    - attack.t1177
falsepositives:
    - Unknown
level: high


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13") -and ($_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt.*" -or $_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:("12" OR "13") AND winlog.event_data.TargetObject.keyword:(*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt* OR *\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b3503044-60ce-4bf4-bbcb-e3db98788823 <<EOF
{
  "metadata": {
    "title": "DLL Load via LSASS",
    "description": "Detects a method to load DLL via LSASS process using an undocumented Registry key",
    "tags": [
      "attack.execution",
      "attack.t1177"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"12\" OR \"13\") AND winlog.event_data.TargetObject.keyword:(*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\DirectoryServiceExtPt* OR *\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\LsaDbExtPt*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"12\" OR \"13\") AND winlog.event_data.TargetObject.keyword:(*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\DirectoryServiceExtPt* OR *\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\LsaDbExtPt*))",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'DLL Load via LSASS'",
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
(EventID:("12" "13") AND TargetObject.keyword:(*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt* *\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="12" OR EventCode="13") (TargetObject="*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt*" OR TargetObject="*\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt*"))
```


### logpoint
    
```
(event_id IN ["12", "13"] TargetObject IN ["*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt*", "*\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*12|.*13))(?=.*(?:.*.*\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt.*|.*.*\CurrentControlSet\Services\NTDS\LsaDbExtPt.*)))'
```



