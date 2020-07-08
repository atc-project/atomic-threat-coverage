| Title                    | Metasploit SMB Authentication       |
|:-------------------------|:------------------|
| **Description**          | Alerts on Metasploit host's authentications on the domain. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1110: Brute Force](https://attack.mitre.org/techniques/T1110)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Linux hostnames composed of 16 characters.</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[h](h)</li><li>[t](t)</li><li>[t](t)</li><li>[p](p)</li><li>[s](s)</li><li>[:](:)</li><li>[/](/)</li><li>[/](/)</li><li>[g](g)</li><li>[i](i)</li><li>[t](t)</li><li>[h](h)</li><li>[u](u)</li><li>[b](b)</li><li>[.](.)</li><li>[c](c)</li><li>[o](o)</li><li>[m](m)</li><li>[/](/)</li><li>[r](r)</li><li>[a](a)</li><li>[p](p)</li><li>[i](i)</li><li>[d](d)</li><li>[7](7)</li><li>[/](/)</li><li>[m](m)</li><li>[e](e)</li><li>[t](t)</li><li>[a](a)</li><li>[s](s)</li><li>[p](p)</li><li>[l](l)</li><li>[o](o)</li><li>[i](i)</li><li>[t](t)</li><li>[-](-)</li><li>[f](f)</li><li>[r](r)</li><li>[a](a)</li><li>[m](m)</li><li>[e](e)</li><li>[w](w)</li><li>[o](o)</li><li>[r](r)</li><li>[k](k)</li><li>[/](/)</li><li>[b](b)</li><li>[l](l)</li><li>[o](o)</li><li>[b](b)</li><li>[/](/)</li><li>[m](m)</li><li>[a](a)</li><li>[s](s)</li><li>[t](t)</li><li>[e](e)</li><li>[r](r)</li><li>[/](/)</li><li>[l](l)</li><li>[i](i)</li><li>[b](b)</li><li>[/](/)</li><li>[r](r)</li><li>[e](e)</li><li>[x](x)</li><li>[/](/)</li><li>[p](p)</li><li>[r](r)</li><li>[o](o)</li><li>[t](t)</li><li>[o](o)</li><li>[/](/)</li><li>[s](s)</li><li>[m](m)</li><li>[b](b)</li><li>[/](/)</li><li>[c](c)</li><li>[l](l)</li><li>[i](i)</li><li>[e](e)</li><li>[n](n)</li><li>[t](t)</li><li>[.](.)</li><li>[r](r)</li><li>[b](b)</li></ul>  |
| **Author**               | Chakib Gzenayi (@Chak092), Hosni Mribah |


## Detection Rules

### Sigma rule

```
title: Metasploit SMB Authentication
description: Alerts on Metasploit host's authentications on the domain.
id: 72124974-a68b-4366-b990-d30e0b2a190d
author: Chakib Gzenayi (@Chak092), Hosni Mribah
date: 2020/05/06
references: https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb
tags:
    - attack.credential_access
    - attack.t1110
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
      "attack.credential_access",
      "attack.t1110"
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



