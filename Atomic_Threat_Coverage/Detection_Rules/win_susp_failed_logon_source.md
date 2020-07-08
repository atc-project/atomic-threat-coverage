| Title                    | Failed Logon From Public IP       |
|:-------------------------|:------------------|
| **Description**          | A login from a public IP can indicate a misconfigured firewall or network boundary. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li><li>[T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)</li><li>[T1133: External Remote Services](https://attack.mitre.org/techniques/T1133)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate logon attempts over the internet</li><li>IPv4-to-IPv6 mapped IPs</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | NVISO |


## Detection Rules

### Sigma rule

```
title: Failed Logon From Public IP
id: f88e112a-21aa-44bd-9b01-6ee2a2bbbed1
description: A login from a public IP can indicate a misconfigured firewall or network boundary.
author: NVISO
date: 2020/05/06
tags:
    - attack.initial_access
    - attack.persistence
    - attack.t1078
    - attack.t1190
    - attack.t1133
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    unknown:
        IpAddress|contains: '-'
    privatev4:
        IpAddress|startswith:
            - '10.' #10.0.0.0/8
            - '192.168.' #192.168.0.0/16
            - '172.16.' #172.16.0.0/12
            - '172.17.'
            - '172.18.'
            - '172.19.'
            - '172.20.'
            - '172.21.'
            - '172.22.'
            - '172.23.'
            - '172.24.'
            - '172.25.'
            - '172.26.'
            - '172.27.'
            - '172.28.'
            - '172.29.'
            - '172.30.'
            - '172.31.'
            - '127.' #127.0.0.0/8
            - '169.254.' #169.254.0.0/16
    privatev6:
        - IpAddress: '::1' #loopback 
        - IpAddress|startswith:
            - 'fe80::' #link-local
            - 'fc00::' #unique local
    condition: selection and not (unknown or privatev4 or privatev6)
falsepositives:
    - Legitimate logon attempts over the internet
    - IPv4-to-IPv6 mapped IPs
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4625" -and  -not ((($_.message -match "IpAddress.*.*-.*" -or ($_.message -match "IpAddress.*10..*" -or $_.message -match "IpAddress.*192.168..*" -or $_.message -match "IpAddress.*172.16..*" -or $_.message -match "IpAddress.*172.17..*" -or $_.message -match "IpAddress.*172.18..*" -or $_.message -match "IpAddress.*172.19..*" -or $_.message -match "IpAddress.*172.20..*" -or $_.message -match "IpAddress.*172.21..*" -or $_.message -match "IpAddress.*172.22..*" -or $_.message -match "IpAddress.*172.23..*" -or $_.message -match "IpAddress.*172.24..*" -or $_.message -match "IpAddress.*172.25..*" -or $_.message -match "IpAddress.*172.26..*" -or $_.message -match "IpAddress.*172.27..*" -or $_.message -match "IpAddress.*172.28..*" -or $_.message -match "IpAddress.*172.29..*" -or $_.message -match "IpAddress.*172.30..*" -or $_.message -match "IpAddress.*172.31..*" -or $_.message -match "IpAddress.*127..*" -or $_.message -match "IpAddress.*169.254..*") -or $_.message -match "IpAddress.*::1" -or ($_.message -match "IpAddress.*fe80::.*" -or $_.message -match "IpAddress.*fc00::.*"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4625" AND (NOT ((winlog.channel:"Security" AND (winlog.event_data.IpAddress.keyword:*\-* OR winlog.event_data.IpAddress.keyword:(10.* OR 192.168.* OR 172.16.* OR 172.17.* OR 172.18.* OR 172.19.* OR 172.20.* OR 172.21.* OR 172.22.* OR 172.23.* OR 172.24.* OR 172.25.* OR 172.26.* OR 172.27.* OR 172.28.* OR 172.29.* OR 172.30.* OR 172.31.* OR 127.* OR 169.254.*) OR winlog.event_data.IpAddress:"\:\:1" OR winlog.event_data.IpAddress.keyword:(fe80\:\:* OR fc00\:\:*))))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f88e112a-21aa-44bd-9b01-6ee2a2bbbed1 <<EOF
{
  "metadata": {
    "title": "Failed Logon From Public IP",
    "description": "A login from a public IP can indicate a misconfigured firewall or network boundary.",
    "tags": [
      "attack.initial_access",
      "attack.persistence",
      "attack.t1078",
      "attack.t1190",
      "attack.t1133"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4625\" AND (NOT ((winlog.channel:\"Security\" AND (winlog.event_data.IpAddress.keyword:*\\-* OR winlog.event_data.IpAddress.keyword:(10.* OR 192.168.* OR 172.16.* OR 172.17.* OR 172.18.* OR 172.19.* OR 172.20.* OR 172.21.* OR 172.22.* OR 172.23.* OR 172.24.* OR 172.25.* OR 172.26.* OR 172.27.* OR 172.28.* OR 172.29.* OR 172.30.* OR 172.31.* OR 127.* OR 169.254.*) OR winlog.event_data.IpAddress:\"\\:\\:1\" OR winlog.event_data.IpAddress.keyword:(fe80\\:\\:* OR fc00\\:\\:*))))))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4625\" AND (NOT ((winlog.channel:\"Security\" AND (winlog.event_data.IpAddress.keyword:*\\-* OR winlog.event_data.IpAddress.keyword:(10.* OR 192.168.* OR 172.16.* OR 172.17.* OR 172.18.* OR 172.19.* OR 172.20.* OR 172.21.* OR 172.22.* OR 172.23.* OR 172.24.* OR 172.25.* OR 172.26.* OR 172.27.* OR 172.28.* OR 172.29.* OR 172.30.* OR 172.31.* OR 127.* OR 169.254.*) OR winlog.event_data.IpAddress:\"\\:\\:1\" OR winlog.event_data.IpAddress.keyword:(fe80\\:\\:* OR fc00\\:\\:*))))))",
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
        "subject": "Sigma Rule 'Failed Logon From Public IP'",
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
(EventID:"4625" AND (NOT ((IpAddress.keyword:*\-* OR IpAddress.keyword:(10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.* 127.* 169.254.*) OR IpAddress:"\:\:1" OR IpAddress.keyword:(fe80\:\:* fc00\:\:*)))))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4625" NOT ((source="WinEventLog:Security" (IpAddress="*-*" OR (IpAddress="10.*" OR IpAddress="192.168.*" OR IpAddress="172.16.*" OR IpAddress="172.17.*" OR IpAddress="172.18.*" OR IpAddress="172.19.*" OR IpAddress="172.20.*" OR IpAddress="172.21.*" OR IpAddress="172.22.*" OR IpAddress="172.23.*" OR IpAddress="172.24.*" OR IpAddress="172.25.*" OR IpAddress="172.26.*" OR IpAddress="172.27.*" OR IpAddress="172.28.*" OR IpAddress="172.29.*" OR IpAddress="172.30.*" OR IpAddress="172.31.*" OR IpAddress="127.*" OR IpAddress="169.254.*") OR IpAddress="::1" OR (IpAddress="fe80::*" OR IpAddress="fc00::*")))))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4625"  -((event_source="Microsoft-Windows-Security-Auditing" (IpAddress="*-*" OR IpAddress IN ["10.*", "192.168.*", "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*", "172.22.*", "172.23.*", "172.24.*", "172.25.*", "172.26.*", "172.27.*", "172.28.*", "172.29.*", "172.30.*", "172.31.*", "127.*", "169.254.*"] OR IpAddress="::1" OR IpAddress IN ["fe80::*", "fc00::*"]))))
```


### grep
    
```
grep -P '^(?:.*(?=.*4625)(?=.*(?!.*(?:.*(?:.*(?:.*.*-.*|.*(?:.*10\..*|.*192\.168\..*|.*172\.16\..*|.*172\.17\..*|.*172\.18\..*|.*172\.19\..*|.*172\.20\..*|.*172\.21\..*|.*172\.22\..*|.*172\.23\..*|.*172\.24\..*|.*172\.25\..*|.*172\.26\..*|.*172\.27\..*|.*172\.28\..*|.*172\.29\..*|.*172\.30\..*|.*172\.31\..*|.*127\..*|.*169\.254\..*)|.*::1|.*(?:.*fe80::.*|.*fc00::.*)))))))'
```



