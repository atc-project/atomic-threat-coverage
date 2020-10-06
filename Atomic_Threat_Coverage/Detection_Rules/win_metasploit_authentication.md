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

```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:("4625" OR "4624") AND winlog.event_data.LogonType:"3" AND AuthenticationPackage:"NTLM" AND winlog.event_data.WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:winlog.event_data.ProcessName AND winlog.event_id:"4776" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/72124974-a68b-4366-b990-d30e0b2a190d <<EOF\n{\n  "metadata": {\n    "title": "Metasploit SMB Authentication",\n    "description": "Alerts on Metasploit host\'s authentications on the domain.",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1077",\n      "attack.t1021.002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:(\\"4625\\" OR \\"4624\\") AND winlog.event_data.LogonType:\\"3\\" AND AuthenticationPackage:\\"NTLM\\" AND winlog.event_data.WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:winlog.event_data.ProcessName AND winlog.event_id:\\"4776\\" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:(\\"4625\\" OR \\"4624\\") AND winlog.event_data.LogonType:\\"3\\" AND AuthenticationPackage:\\"NTLM\\" AND winlog.event_data.WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:winlog.event_data.ProcessName AND winlog.event_id:\\"4776\\" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Metasploit SMB Authentication\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("4625" "4624") AND LogonType:"3" AND AuthenticationPackage:"NTLM" AND WorkstationName:/^[A-Za-z0-9]{16}$/) OR (NOT _exists_:ProcessName AND EventID:"4776" AND SourceWorkstation:/^[A-Za-z0-9]{16}$/))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```

```



