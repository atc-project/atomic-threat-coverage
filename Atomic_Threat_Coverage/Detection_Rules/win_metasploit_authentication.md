| Title                    | Metasploit SMB Authentication       |
|:-------------------------|:------------------|
| **Description**          | Alerts on Metasploit host's authentications on the domain. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Linux hostnames composed of 16 characters.</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb)</li></ul>  |
| **Author**               | Chakib Gzenayi (@Chak092), Hosni Mribah |


## Detection Rules

### Sigma rule

```
title: Metasploit SMB Authentication
description: Alerts on Metasploit host's authentications on the domain.
id: 72124974-a68b-4366-b990-d30e0b2a190d
author: Chakib Gzenayi (@Chak092), Hosni Mribah
date: 2020/05/06
modified: 2020/08/23
references: 
    - https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb
tags:
    - attack.lateral_movement
    - attack.t1077          # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
        - 4625
        - 4624
        LogonType: 3
        AuthenticationPackage: 'NTLM'
        WorkstationName|re: '^[A-Za-z0-9]{16}$'
    selection2:
        ProcessName:
        EventID: 4776
        SourceWorkstation|re: '^[A-Za-z0-9]{16}$'
    condition: selection1 OR selection2
falsepositives:
    - Linux hostnames composed of 16 characters.
level: high

```





### powershell
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_metasploit_authentication.yml): Backend does not support map values of type <class 'sigma.parser.modifiers.type.SigmaRegularExpressionModifier'>
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:("4625" OR "4624") AND winlog.event_data.LogonType:"3" AND AuthenticationPackage:"NTLM" AND winlog.event_data.WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:winlog.event_data.ProcessName AND winlog.event_id:"4776" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/72124974-a68b-4366-b990-d30e0b2a190d <<EOF
{
  "metadata": {
    "title": "Metasploit SMB Authentication",
    "description": "Alerts on Metasploit host's authentications on the domain.",
    "tags": [
      "attack.lateral_movement",
      "attack.t1077",
      "attack.t1021.002"
    ],
    "query": "(winlog.channel:\"Security\" AND ((winlog.event_id:(\"4625\" OR \"4624\") AND winlog.event_data.LogonType:\"3\" AND AuthenticationPackage:\"NTLM\" AND winlog.event_data.WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:winlog.event_data.ProcessName AND winlog.event_id:\"4776\" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/)))"
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
                    "query": "(winlog.channel:\"Security\" AND ((winlog.event_id:(\"4625\" OR \"4624\") AND winlog.event_data.LogonType:\"3\" AND AuthenticationPackage:\"NTLM\" AND winlog.event_data.WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:winlog.event_data.ProcessName AND winlog.event_id:\"4776\" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/)))",
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
        "subject": "Sigma Rule 'Metasploit SMB Authentication'",
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
((EventID:("4625" "4624") AND LogonType:"3" AND AuthenticationPackage:"NTLM" AND WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:ProcessName AND EventID:"4776" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/))
```


### splunk
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_metasploit_authentication.yml): Type modifier 're' is not supported by backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_metasploit_authentication.yml): Type modifier 're' is not supported by backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_metasploit_authentication.yml): Node type not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```



