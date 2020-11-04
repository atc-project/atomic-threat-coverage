| Title                    | DHCP Callout DLL Installation       |
|:-------------------------|:------------------|
| **Description**          | Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>  |
| **Author**               | Dimitrios Slamaris |


## Detection Rules

### Sigma rule

```
title: DHCP Callout DLL Installation
id: 9d3436ef-9476-4c43-acca-90ce06bdf33a
status: experimental
description: Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the
    DHCP server (restart required)
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
author: Dimitrios Slamaris
tags:
    - attack.defense_evasion
    - attack.t1073
    - attack.t1112
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject:
            - '*\Services\DHCPServer\Parameters\CalloutDlls'
            - '*\Services\DHCPServer\Parameters\CalloutEnabled'
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\Services\\DHCPServer\\Parameters\\CalloutDlls" -or $_.message -match "TargetObject.*.*\\Services\\DHCPServer\\Parameters\\CalloutEnabled")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\Services\\DHCPServer\\Parameters\\CalloutDlls OR *\\Services\\DHCPServer\\Parameters\\CalloutEnabled))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9d3436ef-9476-4c43-acca-90ce06bdf33a <<EOF
{
  "metadata": {
    "title": "DHCP Callout DLL Installation",
    "description": "Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073",
      "attack.t1112"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls OR *\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutDlls OR *\\\\Services\\\\DHCPServer\\\\Parameters\\\\CalloutEnabled))",
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
        "subject": "Sigma Rule 'DHCP Callout DLL Installation'",
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
(EventID:"13" AND TargetObject.keyword:(*\\Services\\DHCPServer\\Parameters\\CalloutDlls *\\Services\\DHCPServer\\Parameters\\CalloutEnabled))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\Services\\DHCPServer\\Parameters\\CalloutDlls" OR TargetObject="*\\Services\\DHCPServer\\Parameters\\CalloutEnabled"))
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*\\Services\\DHCPServer\\Parameters\\CalloutDlls", "*\\Services\\DHCPServer\\Parameters\\CalloutEnabled"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\Services\DHCPServer\Parameters\CalloutDlls|.*.*\Services\DHCPServer\Parameters\CalloutEnabled)))'
```



