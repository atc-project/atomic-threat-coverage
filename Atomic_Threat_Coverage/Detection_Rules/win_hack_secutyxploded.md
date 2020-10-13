| Title                    | SecurityXploded Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of SecurityXploded Tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1555: Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1503: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1503)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://securityxploded.com/](https://securityxploded.com/)</li><li>[https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/](https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: SecurityXploded Tool
id: 7679d464-4f74-45e2-9e01-ac66c5eb041a
description: Detects the execution of SecurityXploded Tools
author: Florian Roth
references:
    - https://securityxploded.com/
    - https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/
date: 2018/12/19
modified: 2020/09/01
tags:
    - attack.credential_access
    - attack.t1555
    - attack.t1003  # an old one
    - attack.t1503  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Company: SecurityXploded
    selection2:
        Image|endswith: 'PasswordDump.exe'
    selection3:
        OriginalFilename|endswith: 'PasswordDump.exe'
    condition: 1 of them
falsepositives:
    - unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Company.*SecurityXploded" -or $_.message -match "Image.*.*PasswordDump.exe" -or $_.message -match "OriginalFilename.*.*PasswordDump.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(Company:"SecurityXploded" OR winlog.event_data.Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7679d464-4f74-45e2-9e01-ac66c5eb041a <<EOF
{
  "metadata": {
    "title": "SecurityXploded Tool",
    "description": "Detects the execution of SecurityXploded Tools",
    "tags": [
      "attack.credential_access",
      "attack.t1555",
      "attack.t1003",
      "attack.t1503"
    ],
    "query": "(Company:\"SecurityXploded\" OR winlog.event_data.Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)"
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
                    "query": "(Company:\"SecurityXploded\" OR winlog.event_data.Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)",
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
        "subject": "Sigma Rule 'SecurityXploded Tool'",
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
(Company:"SecurityXploded" OR Image.keyword:*PasswordDump.exe OR OriginalFilename.keyword:*PasswordDump.exe)
```


### splunk
    
```
(Company="SecurityXploded" OR Image="*PasswordDump.exe" OR OriginalFilename="*PasswordDump.exe")
```


### logpoint
    
```
(Company="SecurityXploded" OR Image="*PasswordDump.exe" OR OriginalFilename="*PasswordDump.exe")
```


### grep
    
```
grep -P '^(?:.*(?:.*SecurityXploded|.*.*PasswordDump\.exe|.*.*PasswordDump\.exe))'
```



