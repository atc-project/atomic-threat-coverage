| Title                    | DHCP Server Error Failed Loading the CallOut DLL       |
|:-------------------------|:------------------|
| **Description**          | This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0049_1034_dhcp_service_failed_to_load_callout_dlls](../Data_Needed/DN_0049_1034_dhcp_service_failed_to_load_callout_dlls.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1574.002: DLL Side-Loading](../Triggers/T1574.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>  |
| **Author**               | Dimitrios Slamaris, @atc_project (fix) |


## Detection Rules

### Sigma rule

```
title: DHCP Server Error Failed Loading the CallOut DLL
id: 75edd3fd-7146-48e5-9848-3013d7f0282c
description: This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded
status: experimental
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
modified: 2019/07/17
tags:
    - attack.defense_evasion
    - attack.t1073           # an old one
    - attack.t1574.002
author: "Dimitrios Slamaris, @atc_project (fix)"
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 1031
            - 1032
            - 1034
        Source: Microsoft-Windows-DHCP-Server
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName System | where {(($_.ID -eq "1031" -or $_.ID -eq "1032" -or $_.ID -eq "1034") -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:("1031" OR "1032" OR "1034") AND winlog.event_data.Source:"Microsoft\-Windows\-DHCP\-Server")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/75edd3fd-7146-48e5-9848-3013d7f0282c <<EOF
{
  "metadata": {
    "title": "DHCP Server Error Failed Loading the CallOut DLL",
    "description": "This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073",
      "attack.t1574.002"
    ],
    "query": "(winlog.event_id:(\"1031\" OR \"1032\" OR \"1034\") AND winlog.event_data.Source:\"Microsoft\\-Windows\\-DHCP\\-Server\")"
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
                    "query": "(winlog.event_id:(\"1031\" OR \"1032\" OR \"1034\") AND winlog.event_data.Source:\"Microsoft\\-Windows\\-DHCP\\-Server\")",
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
        "subject": "Sigma Rule 'DHCP Server Error Failed Loading the CallOut DLL'",
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
(EventID:("1031" "1032" "1034") AND Source:"Microsoft\-Windows\-DHCP\-Server")
```


### splunk
    
```
(source="WinEventLog:System" (EventCode="1031" OR EventCode="1032" OR EventCode="1034") Source="Microsoft-Windows-DHCP-Server")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["1031", "1032", "1034"] Source="Microsoft-Windows-DHCP-Server")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*1031|.*1032|.*1034))(?=.*Microsoft-Windows-DHCP-Server))'
```



