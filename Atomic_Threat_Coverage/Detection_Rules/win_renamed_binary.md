| Title                | Renamed Binary                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)</li><li>[https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html](https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html)</li><li>[https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html](https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html)</li></ul>  |
| Author               | Matthew Green - @mgreen27, Ecco, James Pemberton / @4A616D6573, oscd.community (improvements) |


## Detection Rules

### Sigma rule

```
title: Renamed Binary
id: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
status: experimental
description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
author: Matthew Green - @mgreen27, Ecco, James Pemberton / @4A616D6573, oscd.community (improvements)
date: 2019/06/15
modified: 2019/11/11
references:
    - https://attack.mitre.org/techniques/T1036/
    - https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
    - https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html
tags:
    - attack.t1036
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'cmd.exe'
            - 'powershell.exe'
            - 'powershell_ise.exe'
            - 'psexec.exe'
            - 'psexec.c'  # old versions of psexec (2016 seen)
            - 'cscript.exe'
            - 'wscript.exe'
            - 'mshta.exe'
            - 'regsvr32.exe'
            - 'wmic.exe'
            - 'certutil.exe'
            - 'rundll32.exe'
            - 'cmstp.exe'
            - 'msiexec.exe'
            - '7z.exe'
            - 'winrar.exe'
            - 'wevtutil.exe'
            - 'net.exe'
            - 'net1.exe'
    filter:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\psexec.exe'
            - '\psexec64.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\wmic.exe'
            - '\certutil.exe'
            - '\rundll32.exe'
            - '\cmstp.exe'
            - '\msiexec.exe'
            - '\7z.exe'
            - '\winrar.exe'
            - '\wevtutil.exe'
            - '\net.exe'
            - '\net1.exe'
    condition: selection and not filter
falsepositives:
    - Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist
level: medium

```





### es-qs
    
```
(OriginalFileName:("cmd.exe" OR "powershell.exe" OR "powershell_ise.exe" OR "psexec.exe" OR "psexec.c" OR "cscript.exe" OR "wscript.exe" OR "mshta.exe" OR "regsvr32.exe" OR "wmic.exe" OR "certutil.exe" OR "rundll32.exe" OR "cmstp.exe" OR "msiexec.exe" OR "7z.exe" OR "winrar.exe" OR "wevtutil.exe" OR "net.exe" OR "net1.exe") AND (NOT (Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\powershell_ise.exe OR *\\\\psexec.exe OR *\\\\psexec64.exe OR *\\\\cscript.exe OR *\\\\wscript.exe OR *\\\\mshta.exe OR *\\\\regsvr32.exe OR *\\\\wmic.exe OR *\\\\certutil.exe OR *\\\\rundll32.exe OR *\\\\cmstp.exe OR *\\\\msiexec.exe OR *\\\\7z.exe OR *\\\\winrar.exe OR *\\\\wevtutil.exe OR *\\\\net.exe OR *\\\\net1.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Renamed-Binary <<EOF\n{\n  "metadata": {\n    "title": "Renamed Binary",\n    "description": "Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.",\n    "tags": [\n      "attack.t1036",\n      "attack.defense_evasion"\n    ],\n    "query": "(OriginalFileName:(\\"cmd.exe\\" OR \\"powershell.exe\\" OR \\"powershell_ise.exe\\" OR \\"psexec.exe\\" OR \\"psexec.c\\" OR \\"cscript.exe\\" OR \\"wscript.exe\\" OR \\"mshta.exe\\" OR \\"regsvr32.exe\\" OR \\"wmic.exe\\" OR \\"certutil.exe\\" OR \\"rundll32.exe\\" OR \\"cmstp.exe\\" OR \\"msiexec.exe\\" OR \\"7z.exe\\" OR \\"winrar.exe\\" OR \\"wevtutil.exe\\" OR \\"net.exe\\" OR \\"net1.exe\\") AND (NOT (Image.keyword:(*\\\\\\\\cmd.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\powershell_ise.exe OR *\\\\\\\\psexec.exe OR *\\\\\\\\psexec64.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\certutil.exe OR *\\\\\\\\rundll32.exe OR *\\\\\\\\cmstp.exe OR *\\\\\\\\msiexec.exe OR *\\\\\\\\7z.exe OR *\\\\\\\\winrar.exe OR *\\\\\\\\wevtutil.exe OR *\\\\\\\\net.exe OR *\\\\\\\\net1.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(OriginalFileName:(\\"cmd.exe\\" OR \\"powershell.exe\\" OR \\"powershell_ise.exe\\" OR \\"psexec.exe\\" OR \\"psexec.c\\" OR \\"cscript.exe\\" OR \\"wscript.exe\\" OR \\"mshta.exe\\" OR \\"regsvr32.exe\\" OR \\"wmic.exe\\" OR \\"certutil.exe\\" OR \\"rundll32.exe\\" OR \\"cmstp.exe\\" OR \\"msiexec.exe\\" OR \\"7z.exe\\" OR \\"winrar.exe\\" OR \\"wevtutil.exe\\" OR \\"net.exe\\" OR \\"net1.exe\\") AND (NOT (Image.keyword:(*\\\\\\\\cmd.exe OR *\\\\\\\\powershell.exe OR *\\\\\\\\powershell_ise.exe OR *\\\\\\\\psexec.exe OR *\\\\\\\\psexec64.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\certutil.exe OR *\\\\\\\\rundll32.exe OR *\\\\\\\\cmstp.exe OR *\\\\\\\\msiexec.exe OR *\\\\\\\\7z.exe OR *\\\\\\\\winrar.exe OR *\\\\\\\\wevtutil.exe OR *\\\\\\\\net.exe OR *\\\\\\\\net1.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed Binary\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(OriginalFileName:("cmd.exe" "powershell.exe" "powershell_ise.exe" "psexec.exe" "psexec.c" "cscript.exe" "wscript.exe" "mshta.exe" "regsvr32.exe" "wmic.exe" "certutil.exe" "rundll32.exe" "cmstp.exe" "msiexec.exe" "7z.exe" "winrar.exe" "wevtutil.exe" "net.exe" "net1.exe") AND (NOT (Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\powershell_ise.exe *\\\\psexec.exe *\\\\psexec64.exe *\\\\cscript.exe *\\\\wscript.exe *\\\\mshta.exe *\\\\regsvr32.exe *\\\\wmic.exe *\\\\certutil.exe *\\\\rundll32.exe *\\\\cmstp.exe *\\\\msiexec.exe *\\\\7z.exe *\\\\winrar.exe *\\\\wevtutil.exe *\\\\net.exe *\\\\net1.exe))))
```


### splunk
    
```
((OriginalFileName="cmd.exe" OR OriginalFileName="powershell.exe" OR OriginalFileName="powershell_ise.exe" OR OriginalFileName="psexec.exe" OR OriginalFileName="psexec.c" OR OriginalFileName="cscript.exe" OR OriginalFileName="wscript.exe" OR OriginalFileName="mshta.exe" OR OriginalFileName="regsvr32.exe" OR OriginalFileName="wmic.exe" OR OriginalFileName="certutil.exe" OR OriginalFileName="rundll32.exe" OR OriginalFileName="cmstp.exe" OR OriginalFileName="msiexec.exe" OR OriginalFileName="7z.exe" OR OriginalFileName="winrar.exe" OR OriginalFileName="wevtutil.exe" OR OriginalFileName="net.exe" OR OriginalFileName="net1.exe") NOT ((Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\powershell_ise.exe" OR Image="*\\\\psexec.exe" OR Image="*\\\\psexec64.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\certutil.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\cmstp.exe" OR Image="*\\\\msiexec.exe" OR Image="*\\\\7z.exe" OR Image="*\\\\winrar.exe" OR Image="*\\\\wevtutil.exe" OR Image="*\\\\net.exe" OR Image="*\\\\net1.exe")))
```


### logpoint
    
```
(event_id="1" OriginalFileName IN ["cmd.exe", "powershell.exe", "powershell_ise.exe", "psexec.exe", "psexec.c", "cscript.exe", "wscript.exe", "mshta.exe", "regsvr32.exe", "wmic.exe", "certutil.exe", "rundll32.exe", "cmstp.exe", "msiexec.exe", "7z.exe", "winrar.exe", "wevtutil.exe", "net.exe", "net1.exe"]  -(Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\powershell_ise.exe", "*\\\\psexec.exe", "*\\\\psexec64.exe", "*\\\\cscript.exe", "*\\\\wscript.exe", "*\\\\mshta.exe", "*\\\\regsvr32.exe", "*\\\\wmic.exe", "*\\\\certutil.exe", "*\\\\rundll32.exe", "*\\\\cmstp.exe", "*\\\\msiexec.exe", "*\\\\7z.exe", "*\\\\winrar.exe", "*\\\\wevtutil.exe", "*\\\\net.exe", "*\\\\net1.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*cmd\\.exe|.*powershell\\.exe|.*powershell_ise\\.exe|.*psexec\\.exe|.*psexec\\.c|.*cscript\\.exe|.*wscript\\.exe|.*mshta\\.exe|.*regsvr32\\.exe|.*wmic\\.exe|.*certutil\\.exe|.*rundll32\\.exe|.*cmstp\\.exe|.*msiexec\\.exe|.*7z\\.exe|.*winrar\\.exe|.*wevtutil\\.exe|.*net\\.exe|.*net1\\.exe))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\powershell_ise\\.exe|.*.*\\psexec\\.exe|.*.*\\psexec64\\.exe|.*.*\\cscript\\.exe|.*.*\\wscript\\.exe|.*.*\\mshta\\.exe|.*.*\\regsvr32\\.exe|.*.*\\wmic\\.exe|.*.*\\certutil\\.exe|.*.*\\rundll32\\.exe|.*.*\\cmstp\\.exe|.*.*\\msiexec\\.exe|.*.*\\7z\\.exe|.*.*\\winrar\\.exe|.*.*\\wevtutil\\.exe|.*.*\\net\\.exe|.*.*\\net1\\.exe))))))'
```



