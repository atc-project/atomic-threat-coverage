| Title                    | Suspicious Outbound Kerberos Connection       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0087_5156_windows_filtering_platform_has_permitted_connection](../Data_Needed/DN_0087_5156_windows_filtering_platform_has_permitted_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other browsers</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/GhostPack/Rubeus8](https://github.com/GhostPack/Rubeus8)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious Outbound Kerberos Connection
id: eca91c7c-9214-47b9-b4c5-cb1d7e4f2350
status: experimental
description: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
references:
    - https://github.com/GhostPack/Rubeus8
author: Ilyas Ochkov, oscd.community
date: 2019/10/24
modified: 2019/11/13
tags:
    - attack.lateral_movement
    - attack.t1208
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestinationPort: 88
    filter:
        Image|endswith:
            - '\lsass.exe'
            - '\opera.exe'
            - '\chrome.exe'
            - '\firefox.exe'
    condition: selection and not filter 
falsepositives:
    - Other browsers
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5156" -and $_.message -match "DestinationPort.*88") -and  -not (($_.message -match "Image.*.*\\lsass.exe" -or $_.message -match "Image.*.*\\opera.exe" -or $_.message -match "Image.*.*\\chrome.exe" -or $_.message -match "Image.*.*\\firefox.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"5156" AND winlog.event_data.DestinationPort:"88") AND (NOT (winlog.event_data.Image.keyword:(*\\lsass.exe OR *\\opera.exe OR *\\chrome.exe OR *\\firefox.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/eca91c7c-9214-47b9-b4c5-cb1d7e4f2350 <<EOF
{
  "metadata": {
    "title": "Suspicious Outbound Kerberos Connection",
    "description": "Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.",
    "tags": [
      "attack.lateral_movement",
      "attack.t1208"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5156\" AND winlog.event_data.DestinationPort:\"88\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\lsass.exe OR *\\\\opera.exe OR *\\\\chrome.exe OR *\\\\firefox.exe))))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5156\" AND winlog.event_data.DestinationPort:\"88\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\lsass.exe OR *\\\\opera.exe OR *\\\\chrome.exe OR *\\\\firefox.exe))))",
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
        "subject": "Sigma Rule 'Suspicious Outbound Kerberos Connection'",
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
((EventID:"5156" AND DestinationPort:"88") AND (NOT (Image.keyword:(*\\lsass.exe *\\opera.exe *\\chrome.exe *\\firefox.exe))))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5156" DestinationPort="88") NOT ((Image="*\\lsass.exe" OR Image="*\\opera.exe" OR Image="*\\chrome.exe" OR Image="*\\firefox.exe")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="5156" DestinationPort="88")  -(Image IN ["*\\lsass.exe", "*\\opera.exe", "*\\chrome.exe", "*\\firefox.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5156)(?=.*88)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\lsass\.exe|.*.*\opera\.exe|.*.*\chrome\.exe|.*.*\firefox\.exe))))))'
```



