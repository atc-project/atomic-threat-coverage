| Title                | Suspicious Process Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process starts on Windows systems based on keywords                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/](https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/)</li><li>[https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s](https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s)</li><li>[https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)</li><li>[https://twitter.com/subTee/status/872244674609676288](https://twitter.com/subTee/status/872244674609676288)</li><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples)</li><li>[https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html](https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li><li>[https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html](https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html)</li><li>[https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat](https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat)</li><li>[https://twitter.com/vector_sec/status/896049052642533376](https://twitter.com/vector_sec/status/896049052642533376)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Suspicious Process Creation
description: Detects suspicious process starts on Windows systems based on keywords
status: experimental
references:
    - https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/
    - https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s
    - https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
    - https://twitter.com/subTee/status/872244674609676288
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples
    - https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
    - https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html
    - https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat
    - https://twitter.com/vector_sec/status/896049052642533376
author: Florian Roth
detection:
    selection:
        CommandLine: 
            # Hacking activity
            - 'vssadmin.exe delete shadows*'
            - 'vssadmin delete shadows*'
            - 'vssadmin create shadow /for=C:*'
            - 'copy \\?\GLOBALROOT\Device\*\windows\ntds\ntds.dit*'
            - 'copy \\?\GLOBALROOT\Device\*\config\SAM*'
            - 'reg SAVE HKLM\SYSTEM *'
            - '* sekurlsa:*'
            - 'net localgroup adminstrators * /add'
            - 'net group "Domain Admins" * /ADD /DOMAIN'
            - 'certutil.exe *-urlcache* http*'
            - 'certutil.exe *-urlcache* ftp*'
            # Malware
            - 'netsh advfirewall firewall *\AppData\*'
            - 'attrib +S +H +R *\AppData\*'
            - 'schtasks* /create *\AppData\*'
            - 'schtasks* /sc minute*'
            - '*\Regasm.exe *\AppData\*'
            - '*\Regasm *\AppData\*'
            - '*\bitsadmin* /transfer*'
            - '*\certutil.exe * -decode *'
            - '*\certutil.exe * -decodehex *'
            - '*\certutil.exe -ping *'
            - 'icacls * /grant Everyone:F /T /C /Q'
            - '* wmic shadowcopy delete *'
            - '* wbadmin.exe delete catalog -quiet*'  # http://blog.talosintelligence.com/2018/02/olympic-destroyer.html
            # Scripts
            - '*\wscript.exe *.jse'
            - '*\wscript.exe *.js'
            - '*\wscript.exe *.vba'
            - '*\wscript.exe *.vbe'
            - '*\cscript.exe *.jse'
            - '*\cscript.exe *.js'
            - '*\cscript.exe *.vba'
            - '*\cscript.exe *.vbe'
            # UAC bypass
            - '*\fodhelper.exe'
            # persistence
            - '*waitfor*/s*'
            - '*waitfor*/si persist*'
            # remote
            - '*remote*/s*'
            - '*remote*/c*'
            - '*remote*/q*'
            # AddInProcess
            - '*AddInProcess*'
            # NotPowershell (nps) attack
            # - '*msbuild*'  # too many false positives
    condition: selection
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688

```





### Kibana query

```
(EventID:"1" AND CommandLine:("vssadmin.exe delete shadows*" "vssadmin delete shadows*" "vssadmin create shadow \\/for\\=C\\:*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\windows\\\\ntds\\\\ntds.dit*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\config\\\\SAM*" "reg SAVE HKLM\\\\SYSTEM *" "* sekurlsa\\:*" "net localgroup adminstrators * \\/add" "net group \\"Domain Admins\\" * \\/ADD \\/DOMAIN" "certutil.exe *\\-urlcache* http*" "certutil.exe *\\-urlcache* ftp*" "netsh advfirewall firewall *\\\\AppData\\*" "attrib \\+S \\+H \\+R *\\\\AppData\\*" "schtasks* \\/create *\\\\AppData\\*" "schtasks* \\/sc minute*" "*\\\\Regasm.exe *\\\\AppData\\*" "*\\\\Regasm *\\\\AppData\\*" "*\\\\bitsadmin* \\/transfer*" "*\\\\certutil.exe * \\-decode *" "*\\\\certutil.exe * \\-decodehex *" "*\\\\certutil.exe \\-ping *" "icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q" "* wmic shadowcopy delete *" "* wbadmin.exe delete catalog \\-quiet*" "*\\\\wscript.exe *.jse" "*\\\\wscript.exe *.js" "*\\\\wscript.exe *.vba" "*\\\\wscript.exe *.vbe" "*\\\\cscript.exe *.jse" "*\\\\cscript.exe *.js" "*\\\\cscript.exe *.vba" "*\\\\cscript.exe *.vbe" "*\\\\fodhelper.exe" "*waitfor*\\/s*" "*waitfor*\\/si persist*" "*remote*\\/s*" "*remote*\\/c*" "*remote*\\/q*" "*AddInProcess*"))\n(EventID:"4688" AND CommandLine:("vssadmin.exe delete shadows*" "vssadmin delete shadows*" "vssadmin create shadow \\/for\\=C\\:*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\windows\\\\ntds\\\\ntds.dit*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\config\\\\SAM*" "reg SAVE HKLM\\\\SYSTEM *" "* sekurlsa\\:*" "net localgroup adminstrators * \\/add" "net group \\"Domain Admins\\" * \\/ADD \\/DOMAIN" "certutil.exe *\\-urlcache* http*" "certutil.exe *\\-urlcache* ftp*" "netsh advfirewall firewall *\\\\AppData\\*" "attrib \\+S \\+H \\+R *\\\\AppData\\*" "schtasks* \\/create *\\\\AppData\\*" "schtasks* \\/sc minute*" "*\\\\Regasm.exe *\\\\AppData\\*" "*\\\\Regasm *\\\\AppData\\*" "*\\\\bitsadmin* \\/transfer*" "*\\\\certutil.exe * \\-decode *" "*\\\\certutil.exe * \\-decodehex *" "*\\\\certutil.exe \\-ping *" "icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q" "* wmic shadowcopy delete *" "* wbadmin.exe delete catalog \\-quiet*" "*\\\\wscript.exe *.jse" "*\\\\wscript.exe *.js" "*\\\\wscript.exe *.vba" "*\\\\wscript.exe *.vbe" "*\\\\cscript.exe *.jse" "*\\\\cscript.exe *.js" "*\\\\cscript.exe *.vba" "*\\\\cscript.exe *.vbe" "*\\\\fodhelper.exe" "*waitfor*\\/s*" "*waitfor*\\/si persist*" "*remote*\\/s*" "*remote*\\/c*" "*remote*\\/q*" "*AddInProcess*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Process-Creation <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine:(\\"vssadmin.exe delete shadows*\\" \\"vssadmin delete shadows*\\" \\"vssadmin create shadow \\\\/for\\\\=C\\\\:*\\" \\"copy \\\\\\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\*\\\\\\\\windows\\\\\\\\ntds\\\\\\\\ntds.dit*\\" \\"copy \\\\\\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\*\\\\\\\\config\\\\\\\\SAM*\\" \\"reg SAVE HKLM\\\\\\\\SYSTEM *\\" \\"* sekurlsa\\\\:*\\" \\"net localgroup adminstrators * \\\\/add\\" \\"net group \\\\\\"Domain Admins\\\\\\" * \\\\/ADD \\\\/DOMAIN\\" \\"certutil.exe *\\\\-urlcache* http*\\" \\"certutil.exe *\\\\-urlcache* ftp*\\" \\"netsh advfirewall firewall *\\\\\\\\AppData\\\\*\\" \\"attrib \\\\+S \\\\+H \\\\+R *\\\\\\\\AppData\\\\*\\" \\"schtasks* \\\\/create *\\\\\\\\AppData\\\\*\\" \\"schtasks* \\\\/sc minute*\\" \\"*\\\\\\\\Regasm.exe *\\\\\\\\AppData\\\\*\\" \\"*\\\\\\\\Regasm *\\\\\\\\AppData\\\\*\\" \\"*\\\\\\\\bitsadmin* \\\\/transfer*\\" \\"*\\\\\\\\certutil.exe * \\\\-decode *\\" \\"*\\\\\\\\certutil.exe * \\\\-decodehex *\\" \\"*\\\\\\\\certutil.exe \\\\-ping *\\" \\"icacls * \\\\/grant Everyone\\\\:F \\\\/T \\\\/C \\\\/Q\\" \\"* wmic shadowcopy delete *\\" \\"* wbadmin.exe delete catalog \\\\-quiet*\\" \\"*\\\\\\\\wscript.exe *.jse\\" \\"*\\\\\\\\wscript.exe *.js\\" \\"*\\\\\\\\wscript.exe *.vba\\" \\"*\\\\\\\\wscript.exe *.vbe\\" \\"*\\\\\\\\cscript.exe *.jse\\" \\"*\\\\\\\\cscript.exe *.js\\" \\"*\\\\\\\\cscript.exe *.vba\\" \\"*\\\\\\\\cscript.exe *.vbe\\" \\"*\\\\\\\\fodhelper.exe\\" \\"*waitfor*\\\\/s*\\" \\"*waitfor*\\\\/si persist*\\" \\"*remote*\\\\/s*\\" \\"*remote*\\\\/c*\\" \\"*remote*\\\\/q*\\" \\"*AddInProcess*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Process Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Process-Creation-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine:(\\"vssadmin.exe delete shadows*\\" \\"vssadmin delete shadows*\\" \\"vssadmin create shadow \\\\/for\\\\=C\\\\:*\\" \\"copy \\\\\\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\*\\\\\\\\windows\\\\\\\\ntds\\\\\\\\ntds.dit*\\" \\"copy \\\\\\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\*\\\\\\\\config\\\\\\\\SAM*\\" \\"reg SAVE HKLM\\\\\\\\SYSTEM *\\" \\"* sekurlsa\\\\:*\\" \\"net localgroup adminstrators * \\\\/add\\" \\"net group \\\\\\"Domain Admins\\\\\\" * \\\\/ADD \\\\/DOMAIN\\" \\"certutil.exe *\\\\-urlcache* http*\\" \\"certutil.exe *\\\\-urlcache* ftp*\\" \\"netsh advfirewall firewall *\\\\\\\\AppData\\\\*\\" \\"attrib \\\\+S \\\\+H \\\\+R *\\\\\\\\AppData\\\\*\\" \\"schtasks* \\\\/create *\\\\\\\\AppData\\\\*\\" \\"schtasks* \\\\/sc minute*\\" \\"*\\\\\\\\Regasm.exe *\\\\\\\\AppData\\\\*\\" \\"*\\\\\\\\Regasm *\\\\\\\\AppData\\\\*\\" \\"*\\\\\\\\bitsadmin* \\\\/transfer*\\" \\"*\\\\\\\\certutil.exe * \\\\-decode *\\" \\"*\\\\\\\\certutil.exe * \\\\-decodehex *\\" \\"*\\\\\\\\certutil.exe \\\\-ping *\\" \\"icacls * \\\\/grant Everyone\\\\:F \\\\/T \\\\/C \\\\/Q\\" \\"* wmic shadowcopy delete *\\" \\"* wbadmin.exe delete catalog \\\\-quiet*\\" \\"*\\\\\\\\wscript.exe *.jse\\" \\"*\\\\\\\\wscript.exe *.js\\" \\"*\\\\\\\\wscript.exe *.vba\\" \\"*\\\\\\\\wscript.exe *.vbe\\" \\"*\\\\\\\\cscript.exe *.jse\\" \\"*\\\\\\\\cscript.exe *.js\\" \\"*\\\\\\\\cscript.exe *.vba\\" \\"*\\\\\\\\cscript.exe *.vbe\\" \\"*\\\\\\\\fodhelper.exe\\" \\"*waitfor*\\\\/s*\\" \\"*waitfor*\\\\/si persist*\\" \\"*remote*\\\\/s*\\" \\"*remote*\\\\/c*\\" \\"*remote*\\\\/q*\\" \\"*AddInProcess*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Process Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:("vssadmin.exe delete shadows*" "vssadmin delete shadows*" "vssadmin create shadow \\/for=C\\:*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\windows\\\\ntds\\\\ntds.dit*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\config\\\\SAM*" "reg SAVE HKLM\\\\SYSTEM *" "* sekurlsa\\:*" "net localgroup adminstrators * \\/add" "net group \\"Domain Admins\\" * \\/ADD \\/DOMAIN" "certutil.exe *\\-urlcache* http*" "certutil.exe *\\-urlcache* ftp*" "netsh advfirewall firewall *\\\\AppData\\*" "attrib \\+S \\+H \\+R *\\\\AppData\\*" "schtasks* \\/create *\\\\AppData\\*" "schtasks* \\/sc minute*" "*\\\\Regasm.exe *\\\\AppData\\*" "*\\\\Regasm *\\\\AppData\\*" "*\\\\bitsadmin* \\/transfer*" "*\\\\certutil.exe * \\-decode *" "*\\\\certutil.exe * \\-decodehex *" "*\\\\certutil.exe \\-ping *" "icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q" "* wmic shadowcopy delete *" "* wbadmin.exe delete catalog \\-quiet*" "*\\\\wscript.exe *.jse" "*\\\\wscript.exe *.js" "*\\\\wscript.exe *.vba" "*\\\\wscript.exe *.vbe" "*\\\\cscript.exe *.jse" "*\\\\cscript.exe *.js" "*\\\\cscript.exe *.vba" "*\\\\cscript.exe *.vbe" "*\\\\fodhelper.exe" "*waitfor*\\/s*" "*waitfor*\\/si persist*" "*remote*\\/s*" "*remote*\\/c*" "*remote*\\/q*" "*AddInProcess*"))\n(EventID:"4688" AND CommandLine:("vssadmin.exe delete shadows*" "vssadmin delete shadows*" "vssadmin create shadow \\/for=C\\:*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\windows\\\\ntds\\\\ntds.dit*" "copy \\\\\\?\\\\GLOBALROOT\\\\Device\\*\\\\config\\\\SAM*" "reg SAVE HKLM\\\\SYSTEM *" "* sekurlsa\\:*" "net localgroup adminstrators * \\/add" "net group \\"Domain Admins\\" * \\/ADD \\/DOMAIN" "certutil.exe *\\-urlcache* http*" "certutil.exe *\\-urlcache* ftp*" "netsh advfirewall firewall *\\\\AppData\\*" "attrib \\+S \\+H \\+R *\\\\AppData\\*" "schtasks* \\/create *\\\\AppData\\*" "schtasks* \\/sc minute*" "*\\\\Regasm.exe *\\\\AppData\\*" "*\\\\Regasm *\\\\AppData\\*" "*\\\\bitsadmin* \\/transfer*" "*\\\\certutil.exe * \\-decode *" "*\\\\certutil.exe * \\-decodehex *" "*\\\\certutil.exe \\-ping *" "icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q" "* wmic shadowcopy delete *" "* wbadmin.exe delete catalog \\-quiet*" "*\\\\wscript.exe *.jse" "*\\\\wscript.exe *.js" "*\\\\wscript.exe *.vba" "*\\\\wscript.exe *.vbe" "*\\\\cscript.exe *.jse" "*\\\\cscript.exe *.js" "*\\\\cscript.exe *.vba" "*\\\\cscript.exe *.vbe" "*\\\\fodhelper.exe" "*waitfor*\\/s*" "*waitfor*\\/si persist*" "*remote*\\/s*" "*remote*\\/c*" "*remote*\\/q*" "*AddInProcess*"))
```

