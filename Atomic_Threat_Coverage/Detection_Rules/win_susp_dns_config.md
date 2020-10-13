| Title                    | DNS Server Error Failed Loading the ServerLevelPluginDLL       |
|:-------------------------|:------------------|
| **Description**          | This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_150_dns_server_could_not_load_dll](../Data_Needed/DN_0036_150_dns_server_could_not_load_dll.md)</li><li>[DN_0043_770_dns_server_plugin_dll_has_been_loaded](../Data_Needed/DN_0043_770_dns_server_plugin_dll_has_been_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1574.002: DLL Side-Loading](../Triggers/T1574.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li><li>[https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx)</li><li>[https://twitter.com/gentilkiwi/status/861641945944391680](https://twitter.com/gentilkiwi/status/861641945944391680)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: DNS Server Error Failed Loading the ServerLevelPluginDLL
id: cbe51394-cd93-4473-b555-edf0144952d9
description: This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded
status: experimental
date: 2017/05/08
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
    - https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx
    - https://twitter.com/gentilkiwi/status/861641945944391680
tags:
    - attack.defense_evasion
    - attack.t1073           # an old one
    - attack.t1574.002
author: Florian Roth
logsource:
    product: windows
    service: dns-server
detection:
    selection:
        EventID:
            - 150
            - 770
    condition: selection
falsepositives:
    - Unknown
level: critical



```





### powershell
    
```
Get-WinEvent | where {($_.ID -eq "150" -or $_.ID -eq "770") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"DNS\ Server" AND winlog.event_id:("150" OR "770"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cbe51394-cd93-4473-b555-edf0144952d9 <<EOF
{
  "metadata": {
    "title": "DNS Server Error Failed Loading the ServerLevelPluginDLL",
    "description": "This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded",
    "tags": [
      "attack.defense_evasion",
      "attack.t1073",
      "attack.t1574.002"
    ],
    "query": "(winlog.channel:\"DNS\\ Server\" AND winlog.event_id:(\"150\" OR \"770\"))"
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
                    "query": "(winlog.channel:\"DNS\\ Server\" AND winlog.event_id:(\"150\" OR \"770\"))",
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
        "subject": "Sigma Rule 'DNS Server Error Failed Loading the ServerLevelPluginDLL'",
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
EventID:("150" "770")
```


### splunk
    
```
(EventCode="150" OR EventCode="770")
```


### logpoint
    
```
(event_source="DNS Server" event_id IN ["150", "770"])
```


### grep
    
```
grep -P '^(?:.*150|.*770)'
```



