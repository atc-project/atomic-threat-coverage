| Title                    | GALLIUM Artefacts       |
|:-------------------------|:------------------|
| **Description**          | Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/](https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/)</li><li>[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800669(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800669(v=ws.11))</li></ul>  |
| **Author**               | Tim Burrell |


## Detection Rules

### Sigma rule

```
action: global
title: GALLIUM Artefacts
id: 440a56bf-7873-4439-940a-1c8a671073c2
status: experimental
description: Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.
author: Tim Burrell
date: 2020/02/07
references:
    - https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800669(v=ws.11)
tags:
    - attack.credential_access
    - attack.command_and_control
falsepositives:
    - unknown
level: high
---
logsource:
    product: windows
    category: process_creation
detection:
    exec_selection:
        sha1:
            - '53a44c2396d15c3a03723fa5e5db54cafd527635'
            - '9c5e496921e3bc882dc40694f1dcc3746a75db19'
            - 'aeb573accfd95758550cf30bf04f389a92922844'
            - '79ef78a797403a4ed1a616c68e07fff868a8650a'
            - '4f6f38b4cec35e895d91c052b1f5a83d665c2196'
            - '1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d'
            - 'e841a63e47361a572db9a7334af459ddca11347a'
            - 'c28f606df28a9bc8df75a4d5e5837fc5522dd34d'
            - '2e94b305d6812a9f96e6781c888e48c7fb157b6b'
            - 'dd44133716b8a241957b912fa6a02efde3ce3025'
            - '8793bf166cb89eb55f0593404e4e933ab605e803'
            - 'a39b57032dbb2335499a51e13470a7cd5d86b138'
            - '41cc2b15c662bc001c0eb92f6cc222934f0beeea'
            - 'd209430d6af54792371174e70e27dd11d3def7a7'
            - '1c6452026c56efd2c94cea7e0f671eb55515edb0'
            - 'c6b41d3afdcdcaf9f442bbe772f5da871801fd5a'
            - '4923d460e22fbbf165bbbaba168e5a46b8157d9f'
            - 'f201504bd96e81d0d350c3a8332593ee1c9e09de'
            - 'ddd2db1127632a2a52943a2fe516a2e7d05d70d2'
    condition: exec_selection
---
logsource:
    product: windows
    service: dns-server
detection:
    c2_selection:
        EventID: 257
        QNAME: 
            - 'asyspy256.ddns.net'
            - 'hotkillmail9sddcc.ddns.net'
            - 'rosaf112.ddns.net'
            - 'cvdfhjh1231.myftp.biz'
            - 'sz2016rose.ddns.net'
            - 'dffwescwer4325.myftp.biz'
            - 'cvdfhjh1231.ddns.net'
    condition: c2_selection
---
logsource:
    product: windows
    category: process_creation
detection:
    legitimate_process_path:
        Image|contains:
            - ':\Program Files(x86)\'
            - ':\Program Files\'
    legitimate_executable:
        sha1:
            - 'e570585edc69f9074cb5e8a790708336bd45ca0f'
    condition: legitimate_executable and not legitimate_process_path

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "53a44c2396d15c3a03723fa5e5db54cafd527635" -or $_.message -match "9c5e496921e3bc882dc40694f1dcc3746a75db19" -or $_.message -match "aeb573accfd95758550cf30bf04f389a92922844" -or $_.message -match "79ef78a797403a4ed1a616c68e07fff868a8650a" -or $_.message -match "4f6f38b4cec35e895d91c052b1f5a83d665c2196" -or $_.message -match "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" -or $_.message -match "e841a63e47361a572db9a7334af459ddca11347a" -or $_.message -match "c28f606df28a9bc8df75a4d5e5837fc5522dd34d" -or $_.message -match "2e94b305d6812a9f96e6781c888e48c7fb157b6b" -or $_.message -match "dd44133716b8a241957b912fa6a02efde3ce3025" -or $_.message -match "8793bf166cb89eb55f0593404e4e933ab605e803" -or $_.message -match "a39b57032dbb2335499a51e13470a7cd5d86b138" -or $_.message -match "41cc2b15c662bc001c0eb92f6cc222934f0beeea" -or $_.message -match "d209430d6af54792371174e70e27dd11d3def7a7" -or $_.message -match "1c6452026c56efd2c94cea7e0f671eb55515edb0" -or $_.message -match "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" -or $_.message -match "4923d460e22fbbf165bbbaba168e5a46b8157d9f" -or $_.message -match "f201504bd96e81d0d350c3a8332593ee1c9e09de" -or $_.message -match "ddd2db1127632a2a52943a2fe516a2e7d05d70d2") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent | where {($_.ID -eq "257" -and ($_.message -match "asyspy256.ddns.net" -or $_.message -match "hotkillmail9sddcc.ddns.net" -or $_.message -match "rosaf112.ddns.net" -or $_.message -match "cvdfhjh1231.myftp.biz" -or $_.message -match "sz2016rose.ddns.net" -or $_.message -match "dffwescwer4325.myftp.biz" -or $_.message -match "cvdfhjh1231.ddns.net")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent | where {(($_.message -match "e570585edc69f9074cb5e8a790708336bd45ca0f") -and  -not (($_.message -match "Image.*.*:\\\\Program Files(x86)\\\\.*" -or $_.message -match "Image.*.*:\\\\Program Files\\\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
sha1:("53a44c2396d15c3a03723fa5e5db54cafd527635" OR "9c5e496921e3bc882dc40694f1dcc3746a75db19" OR "aeb573accfd95758550cf30bf04f389a92922844" OR "79ef78a797403a4ed1a616c68e07fff868a8650a" OR "4f6f38b4cec35e895d91c052b1f5a83d665c2196" OR "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" OR "e841a63e47361a572db9a7334af459ddca11347a" OR "c28f606df28a9bc8df75a4d5e5837fc5522dd34d" OR "2e94b305d6812a9f96e6781c888e48c7fb157b6b" OR "dd44133716b8a241957b912fa6a02efde3ce3025" OR "8793bf166cb89eb55f0593404e4e933ab605e803" OR "a39b57032dbb2335499a51e13470a7cd5d86b138" OR "41cc2b15c662bc001c0eb92f6cc222934f0beeea" OR "d209430d6af54792371174e70e27dd11d3def7a7" OR "1c6452026c56efd2c94cea7e0f671eb55515edb0" OR "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" OR "4923d460e22fbbf165bbbaba168e5a46b8157d9f" OR "f201504bd96e81d0d350c3a8332593ee1c9e09de" OR "ddd2db1127632a2a52943a2fe516a2e7d05d70d2")\n(winlog.channel:"DNS\\ Server" AND winlog.event_id:"257" AND QNAME:("asyspy256.ddns.net" OR "hotkillmail9sddcc.ddns.net" OR "rosaf112.ddns.net" OR "cvdfhjh1231.myftp.biz" OR "sz2016rose.ddns.net" OR "dffwescwer4325.myftp.biz" OR "cvdfhjh1231.ddns.net"))\n(sha1:("e570585edc69f9074cb5e8a790708336bd45ca0f") AND (NOT (winlog.event_data.Image.keyword:(*\\:\\\\Program\\ Files\\(x86\\)\\\\* OR *\\:\\\\Program\\ Files\\\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/440a56bf-7873-4439-940a-1c8a671073c2 <<EOF\n{\n  "metadata": {\n    "title": "GALLIUM Artefacts",\n    "description": "Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.",\n    "tags": [\n      "attack.credential_access",\n      "attack.command_and_control"\n    ],\n    "query": "sha1:(\\"53a44c2396d15c3a03723fa5e5db54cafd527635\\" OR \\"9c5e496921e3bc882dc40694f1dcc3746a75db19\\" OR \\"aeb573accfd95758550cf30bf04f389a92922844\\" OR \\"79ef78a797403a4ed1a616c68e07fff868a8650a\\" OR \\"4f6f38b4cec35e895d91c052b1f5a83d665c2196\\" OR \\"1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d\\" OR \\"e841a63e47361a572db9a7334af459ddca11347a\\" OR \\"c28f606df28a9bc8df75a4d5e5837fc5522dd34d\\" OR \\"2e94b305d6812a9f96e6781c888e48c7fb157b6b\\" OR \\"dd44133716b8a241957b912fa6a02efde3ce3025\\" OR \\"8793bf166cb89eb55f0593404e4e933ab605e803\\" OR \\"a39b57032dbb2335499a51e13470a7cd5d86b138\\" OR \\"41cc2b15c662bc001c0eb92f6cc222934f0beeea\\" OR \\"d209430d6af54792371174e70e27dd11d3def7a7\\" OR \\"1c6452026c56efd2c94cea7e0f671eb55515edb0\\" OR \\"c6b41d3afdcdcaf9f442bbe772f5da871801fd5a\\" OR \\"4923d460e22fbbf165bbbaba168e5a46b8157d9f\\" OR \\"f201504bd96e81d0d350c3a8332593ee1c9e09de\\" OR \\"ddd2db1127632a2a52943a2fe516a2e7d05d70d2\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "sha1:(\\"53a44c2396d15c3a03723fa5e5db54cafd527635\\" OR \\"9c5e496921e3bc882dc40694f1dcc3746a75db19\\" OR \\"aeb573accfd95758550cf30bf04f389a92922844\\" OR \\"79ef78a797403a4ed1a616c68e07fff868a8650a\\" OR \\"4f6f38b4cec35e895d91c052b1f5a83d665c2196\\" OR \\"1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d\\" OR \\"e841a63e47361a572db9a7334af459ddca11347a\\" OR \\"c28f606df28a9bc8df75a4d5e5837fc5522dd34d\\" OR \\"2e94b305d6812a9f96e6781c888e48c7fb157b6b\\" OR \\"dd44133716b8a241957b912fa6a02efde3ce3025\\" OR \\"8793bf166cb89eb55f0593404e4e933ab605e803\\" OR \\"a39b57032dbb2335499a51e13470a7cd5d86b138\\" OR \\"41cc2b15c662bc001c0eb92f6cc222934f0beeea\\" OR \\"d209430d6af54792371174e70e27dd11d3def7a7\\" OR \\"1c6452026c56efd2c94cea7e0f671eb55515edb0\\" OR \\"c6b41d3afdcdcaf9f442bbe772f5da871801fd5a\\" OR \\"4923d460e22fbbf165bbbaba168e5a46b8157d9f\\" OR \\"f201504bd96e81d0d350c3a8332593ee1c9e09de\\" OR \\"ddd2db1127632a2a52943a2fe516a2e7d05d70d2\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'GALLIUM Artefacts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/440a56bf-7873-4439-940a-1c8a671073c2-2 <<EOF\n{\n  "metadata": {\n    "title": "GALLIUM Artefacts",\n    "description": "Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.",\n    "tags": [\n      "attack.credential_access",\n      "attack.command_and_control"\n    ],\n    "query": "(winlog.channel:\\"DNS\\\\ Server\\" AND winlog.event_id:\\"257\\" AND QNAME:(\\"asyspy256.ddns.net\\" OR \\"hotkillmail9sddcc.ddns.net\\" OR \\"rosaf112.ddns.net\\" OR \\"cvdfhjh1231.myftp.biz\\" OR \\"sz2016rose.ddns.net\\" OR \\"dffwescwer4325.myftp.biz\\" OR \\"cvdfhjh1231.ddns.net\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"DNS\\\\ Server\\" AND winlog.event_id:\\"257\\" AND QNAME:(\\"asyspy256.ddns.net\\" OR \\"hotkillmail9sddcc.ddns.net\\" OR \\"rosaf112.ddns.net\\" OR \\"cvdfhjh1231.myftp.biz\\" OR \\"sz2016rose.ddns.net\\" OR \\"dffwescwer4325.myftp.biz\\" OR \\"cvdfhjh1231.ddns.net\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'GALLIUM Artefacts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/440a56bf-7873-4439-940a-1c8a671073c2-3 <<EOF\n{\n  "metadata": {\n    "title": "GALLIUM Artefacts",\n    "description": "Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.",\n    "tags": [\n      "attack.credential_access",\n      "attack.command_and_control"\n    ],\n    "query": "(sha1:(\\"e570585edc69f9074cb5e8a790708336bd45ca0f\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\:\\\\\\\\Program\\\\ Files\\\\(x86\\\\)\\\\\\\\* OR *\\\\:\\\\\\\\Program\\\\ Files\\\\\\\\*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(sha1:(\\"e570585edc69f9074cb5e8a790708336bd45ca0f\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\:\\\\\\\\Program\\\\ Files\\\\(x86\\\\)\\\\\\\\* OR *\\\\:\\\\\\\\Program\\\\ Files\\\\\\\\*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'GALLIUM Artefacts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
sha1:("53a44c2396d15c3a03723fa5e5db54cafd527635" "9c5e496921e3bc882dc40694f1dcc3746a75db19" "aeb573accfd95758550cf30bf04f389a92922844" "79ef78a797403a4ed1a616c68e07fff868a8650a" "4f6f38b4cec35e895d91c052b1f5a83d665c2196" "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" "e841a63e47361a572db9a7334af459ddca11347a" "c28f606df28a9bc8df75a4d5e5837fc5522dd34d" "2e94b305d6812a9f96e6781c888e48c7fb157b6b" "dd44133716b8a241957b912fa6a02efde3ce3025" "8793bf166cb89eb55f0593404e4e933ab605e803" "a39b57032dbb2335499a51e13470a7cd5d86b138" "41cc2b15c662bc001c0eb92f6cc222934f0beeea" "d209430d6af54792371174e70e27dd11d3def7a7" "1c6452026c56efd2c94cea7e0f671eb55515edb0" "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" "4923d460e22fbbf165bbbaba168e5a46b8157d9f" "f201504bd96e81d0d350c3a8332593ee1c9e09de" "ddd2db1127632a2a52943a2fe516a2e7d05d70d2")\n(EventID:"257" AND QNAME:("asyspy256.ddns.net" "hotkillmail9sddcc.ddns.net" "rosaf112.ddns.net" "cvdfhjh1231.myftp.biz" "sz2016rose.ddns.net" "dffwescwer4325.myftp.biz" "cvdfhjh1231.ddns.net"))\n(sha1:("e570585edc69f9074cb5e8a790708336bd45ca0f") AND (NOT (Image.keyword:(*\\:\\\\Program Files\\(x86\\)\\\\* *\\:\\\\Program Files\\\\*))))
```


### splunk
    
```
(sha1="53a44c2396d15c3a03723fa5e5db54cafd527635" OR sha1="9c5e496921e3bc882dc40694f1dcc3746a75db19" OR sha1="aeb573accfd95758550cf30bf04f389a92922844" OR sha1="79ef78a797403a4ed1a616c68e07fff868a8650a" OR sha1="4f6f38b4cec35e895d91c052b1f5a83d665c2196" OR sha1="1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" OR sha1="e841a63e47361a572db9a7334af459ddca11347a" OR sha1="c28f606df28a9bc8df75a4d5e5837fc5522dd34d" OR sha1="2e94b305d6812a9f96e6781c888e48c7fb157b6b" OR sha1="dd44133716b8a241957b912fa6a02efde3ce3025" OR sha1="8793bf166cb89eb55f0593404e4e933ab605e803" OR sha1="a39b57032dbb2335499a51e13470a7cd5d86b138" OR sha1="41cc2b15c662bc001c0eb92f6cc222934f0beeea" OR sha1="d209430d6af54792371174e70e27dd11d3def7a7" OR sha1="1c6452026c56efd2c94cea7e0f671eb55515edb0" OR sha1="c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" OR sha1="4923d460e22fbbf165bbbaba168e5a46b8157d9f" OR sha1="f201504bd96e81d0d350c3a8332593ee1c9e09de" OR sha1="ddd2db1127632a2a52943a2fe516a2e7d05d70d2")\n(EventCode="257" (QNAME="asyspy256.ddns.net" OR QNAME="hotkillmail9sddcc.ddns.net" OR QNAME="rosaf112.ddns.net" OR QNAME="cvdfhjh1231.myftp.biz" OR QNAME="sz2016rose.ddns.net" OR QNAME="dffwescwer4325.myftp.biz" OR QNAME="cvdfhjh1231.ddns.net"))\n((sha1="e570585edc69f9074cb5e8a790708336bd45ca0f") NOT ((Image="*:\\\\Program Files(x86)\\\\*" OR Image="*:\\\\Program Files\\\\*")))
```


### logpoint
    
```
sha1 IN ["53a44c2396d15c3a03723fa5e5db54cafd527635", "9c5e496921e3bc882dc40694f1dcc3746a75db19", "aeb573accfd95758550cf30bf04f389a92922844", "79ef78a797403a4ed1a616c68e07fff868a8650a", "4f6f38b4cec35e895d91c052b1f5a83d665c2196", "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d", "e841a63e47361a572db9a7334af459ddca11347a", "c28f606df28a9bc8df75a4d5e5837fc5522dd34d", "2e94b305d6812a9f96e6781c888e48c7fb157b6b", "dd44133716b8a241957b912fa6a02efde3ce3025", "8793bf166cb89eb55f0593404e4e933ab605e803", "a39b57032dbb2335499a51e13470a7cd5d86b138", "41cc2b15c662bc001c0eb92f6cc222934f0beeea", "d209430d6af54792371174e70e27dd11d3def7a7", "1c6452026c56efd2c94cea7e0f671eb55515edb0", "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a", "4923d460e22fbbf165bbbaba168e5a46b8157d9f", "f201504bd96e81d0d350c3a8332593ee1c9e09de", "ddd2db1127632a2a52943a2fe516a2e7d05d70d2"]\n(event_source="DNS Server" event_id="257" QNAME IN ["asyspy256.ddns.net", "hotkillmail9sddcc.ddns.net", "rosaf112.ddns.net", "cvdfhjh1231.myftp.biz", "sz2016rose.ddns.net", "dffwescwer4325.myftp.biz", "cvdfhjh1231.ddns.net"])\n(sha1 IN ["e570585edc69f9074cb5e8a790708336bd45ca0f"]  -(Image IN ["*:\\\\Program Files(x86)\\\\*", "*:\\\\Program Files\\\\*"]))
```


### grep
    
```
grep -P '^(?:.*53a44c2396d15c3a03723fa5e5db54cafd527635|.*9c5e496921e3bc882dc40694f1dcc3746a75db19|.*aeb573accfd95758550cf30bf04f389a92922844|.*79ef78a797403a4ed1a616c68e07fff868a8650a|.*4f6f38b4cec35e895d91c052b1f5a83d665c2196|.*1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d|.*e841a63e47361a572db9a7334af459ddca11347a|.*c28f606df28a9bc8df75a4d5e5837fc5522dd34d|.*2e94b305d6812a9f96e6781c888e48c7fb157b6b|.*dd44133716b8a241957b912fa6a02efde3ce3025|.*8793bf166cb89eb55f0593404e4e933ab605e803|.*a39b57032dbb2335499a51e13470a7cd5d86b138|.*41cc2b15c662bc001c0eb92f6cc222934f0beeea|.*d209430d6af54792371174e70e27dd11d3def7a7|.*1c6452026c56efd2c94cea7e0f671eb55515edb0|.*c6b41d3afdcdcaf9f442bbe772f5da871801fd5a|.*4923d460e22fbbf165bbbaba168e5a46b8157d9f|.*f201504bd96e81d0d350c3a8332593ee1c9e09de|.*ddd2db1127632a2a52943a2fe516a2e7d05d70d2)'\ngrep -P '^(?:.*(?=.*257)(?=.*(?:.*asyspy256\\.ddns\\.net|.*hotkillmail9sddcc\\.ddns\\.net|.*rosaf112\\.ddns\\.net|.*cvdfhjh1231\\.myftp\\.biz|.*sz2016rose\\.ddns\\.net|.*dffwescwer4325\\.myftp\\.biz|.*cvdfhjh1231\\.ddns\\.net)))'\ngrep -P '^(?:.*(?=.*(?:.*e570585edc69f9074cb5e8a790708336bd45ca0f))(?=.*(?!.*(?:.*(?=.*(?:.*.*:\\Program Files\\(x86\\)\\\\.*|.*.*:\\Program Files\\\\.*))))))'
```



