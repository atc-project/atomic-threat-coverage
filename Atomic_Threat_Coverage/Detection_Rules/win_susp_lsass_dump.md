| Title                    | Password Dumper Activity on LSASS       |
|:-------------------------|:------------------|
| **Description**          | Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/jackcr/status/807385668833968128](https://twitter.com/jackcr/status/807385668833968128)</li></ul>  |
| **Author**               |  Author of this Detection Rule haven't introduced himself  |
| Other Tags           | <ul><li>attack.t1003.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Password Dumper Activity on LSASS
id: aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
status: experimental
date: 2017/02/12
references:
    - https://twitter.com/jackcr/status/807385668833968128
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ProcessName: 'C:\Windows\System32\lsass.exe'
        AccessMask: '0x705'
        ObjectType: 'SAM_DOMAIN'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ProcessName.*C:\\Windows\\System32\\lsass.exe" -and $_.message -match "AccessMask.*0x705" -and $_.message -match "ObjectType.*SAM_DOMAIN") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4656" AND winlog.event_data.ProcessName:"C\:\\Windows\\System32\\lsass.exe" AND winlog.event_data.AccessMask:"0x705" AND winlog.event_data.ObjectType:"SAM_DOMAIN")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c <<EOF
{
  "metadata": {
    "title": "Password Dumper Activity on LSASS",
    "description": "Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.001"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4656\" AND winlog.event_data.ProcessName:\"C\\:\\\\Windows\\\\System32\\\\lsass.exe\" AND winlog.event_data.AccessMask:\"0x705\" AND winlog.event_data.ObjectType:\"SAM_DOMAIN\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4656\" AND winlog.event_data.ProcessName:\"C\\:\\\\Windows\\\\System32\\\\lsass.exe\" AND winlog.event_data.AccessMask:\"0x705\" AND winlog.event_data.ObjectType:\"SAM_DOMAIN\")",
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
        "subject": "Sigma Rule 'Password Dumper Activity on LSASS'",
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
(EventID:"4656" AND ProcessName:"C\:\\Windows\\System32\\lsass.exe" AND AccessMask:"0x705" AND ObjectType:"SAM_DOMAIN")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4656" ProcessName="C:\\Windows\\System32\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4656" ProcessName="C:\\Windows\\System32\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN")
```


### grep
    
```
grep -P '^(?:.*(?=.*4656)(?=.*C:\Windows\System32\lsass\.exe)(?=.*0x705)(?=.*SAM_DOMAIN))'
```



