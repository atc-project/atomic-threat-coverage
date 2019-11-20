| Title                | Suspicious Process Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process starts on Windows systems based on keywords                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/](https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/)</li><li>[https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s](https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s)</li><li>[https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)</li><li>[https://twitter.com/subTee/status/872244674609676288](https://twitter.com/subTee/status/872244674609676288)</li><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples)</li><li>[https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html](https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li><li>[https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html](https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html)</li><li>[https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat](https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat)</li><li>[https://twitter.com/vector_sec/status/896049052642533376](https://twitter.com/vector_sec/status/896049052642533376)</li><li>[http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf](http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-001</li><li>car.2013-07-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Process Creation
id: 5f0f47a5-cb16-4dbe-9e31-e8d976d73de3
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
    - http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf
author: Florian Roth
modified: 2018/12/11
tags:
    - car.2013-07-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - vssadmin.exe delete shadows*
            - vssadmin delete shadows*
            - vssadmin create shadow /for=C:*
            - copy \\?\GLOBALROOT\Device\\*\windows\ntds\ntds.dit*
            - copy \\?\GLOBALROOT\Device\\*\config\SAM*
            - reg SAVE HKLM\SYSTEM *
            - reg SAVE HKLM\SAM *
            - '* sekurlsa:*'
            - net localgroup administrators * /add
            - net group "Domain Admins" * /ADD /DOMAIN
            - certutil.exe *-urlcache* http*
            - certutil.exe *-urlcache* ftp*
            - netsh advfirewall firewall *\AppData\\*
            - attrib +S +H +R *\AppData\\*
            - schtasks* /create *\AppData\\*
            - schtasks* /sc minute*
            - '*\Regasm.exe *\AppData\\*'
            - '*\Regasm *\AppData\\*'
            - '*\bitsadmin* /transfer*'
            - '*\certutil.exe * -decode *'
            - '*\certutil.exe * -decodehex *'
            - '*\certutil.exe -ping *'
            - icacls * /grant Everyone:F /T /C /Q
            - '* wmic shadowcopy delete *'
            - '* wbadmin.exe delete catalog -quiet*'
            - '*\wscript.exe *.jse'
            - '*\wscript.exe *.js'
            - '*\wscript.exe *.vba'
            - '*\wscript.exe *.vbe'
            - '*\cscript.exe *.jse'
            - '*\cscript.exe *.js'
            - '*\cscript.exe *.vba'
            - '*\cscript.exe *.vbe'
            - '*\fodhelper.exe'
            - '*waitfor*/s*'
            - '*waitfor*/si persist*'
            - '*remote*/s*'
            - '*remote*/c*'
            - '*remote*/q*'
            - '*AddInProcess*'
            - '* /stext *'
            - '* /scomma *'
            - '* /stab *'
            - '* /stabular *'
            - '* /shtml *'
            - '* /sverhtml *'
            - '* /sxml *'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### splunk
    
```
(CommandLine="vssadmin.exe delete shadows*" OR CommandLine="vssadmin delete shadows*" OR CommandLine="vssadmin create shadow /for=C:*" OR CommandLine="copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit*" OR CommandLine="copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM*" OR CommandLine="reg SAVE HKLM\\\\SYSTEM *" OR CommandLine="reg SAVE HKLM\\\\SAM *" OR CommandLine="* sekurlsa:*" OR CommandLine="net localgroup administrators * /add" OR CommandLine="net group \\"Domain Admins\\" * /ADD /DOMAIN" OR CommandLine="certutil.exe *-urlcache* http*" OR CommandLine="certutil.exe *-urlcache* ftp*" OR CommandLine="netsh advfirewall firewall *\\\\AppData\\\\*" OR CommandLine="attrib +S +H +R *\\\\AppData\\\\*" OR CommandLine="schtasks* /create *\\\\AppData\\\\*" OR CommandLine="schtasks* /sc minute*" OR CommandLine="*\\\\Regasm.exe *\\\\AppData\\\\*" OR CommandLine="*\\\\Regasm *\\\\AppData\\\\*" OR CommandLine="*\\\\bitsadmin* /transfer*" OR CommandLine="*\\\\certutil.exe * -decode *" OR CommandLine="*\\\\certutil.exe * -decodehex *" OR CommandLine="*\\\\certutil.exe -ping *" OR CommandLine="icacls * /grant Everyone:F /T /C /Q" OR CommandLine="* wmic shadowcopy delete *" OR CommandLine="* wbadmin.exe delete catalog -quiet*" OR CommandLine="*\\\\wscript.exe *.jse" OR CommandLine="*\\\\wscript.exe *.js" OR CommandLine="*\\\\wscript.exe *.vba" OR CommandLine="*\\\\wscript.exe *.vbe" OR CommandLine="*\\\\cscript.exe *.jse" OR CommandLine="*\\\\cscript.exe *.js" OR CommandLine="*\\\\cscript.exe *.vba" OR CommandLine="*\\\\cscript.exe *.vbe" OR CommandLine="*\\\\fodhelper.exe" OR CommandLine="*waitfor*/s*" OR CommandLine="*waitfor*/si persist*" OR CommandLine="*remote*/s*" OR CommandLine="*remote*/c*" OR CommandLine="*remote*/q*" OR CommandLine="*AddInProcess*" OR CommandLine="* /stext *" OR CommandLine="* /scomma *" OR CommandLine="* /stab *" OR CommandLine="* /stabular *" OR CommandLine="* /shtml *" OR CommandLine="* /sverhtml *" OR CommandLine="* /sxml *")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Process Creation]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Process Creation status: experimental \
description: Detects suspicious process starts on Windows systems based on keywords \
references: ['https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/', 'https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s', 'https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/', 'https://twitter.com/subTee/status/872244674609676288', 'https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples', 'https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html', 'https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/', 'https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html', 'https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat', 'https://twitter.com/vector_sec/status/896049052642533376', 'http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf'] \
tags: ['car.2013-07-001'] \
author: Florian Roth \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects suspicious process starts on Windows systems based on keywords
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="vssadmin.exe delete shadows*" OR CommandLine="vssadmin delete shadows*" OR CommandLine="vssadmin create shadow /for=C:*" OR CommandLine="copy \\?\\GLOBALROOT\\Device\\*\\windows\\ntds\\ntds.dit*" OR CommandLine="copy \\?\\GLOBALROOT\\Device\\*\\config\\SAM*" OR CommandLine="reg SAVE HKLM\\SYSTEM *" OR CommandLine="reg SAVE HKLM\\SAM *" OR CommandLine="* sekurlsa:*" OR CommandLine="net localgroup administrators * /add" OR CommandLine="net group \"Domain Admins\" * /ADD /DOMAIN" OR CommandLine="certutil.exe *-urlcache* http*" OR CommandLine="certutil.exe *-urlcache* ftp*" OR CommandLine="netsh advfirewall firewall *\\AppData\\*" OR CommandLine="attrib +S +H +R *\\AppData\\*" OR CommandLine="schtasks* /create *\\AppData\\*" OR CommandLine="schtasks* /sc minute*" OR CommandLine="*\\Regasm.exe *\\AppData\\*" OR CommandLine="*\\Regasm *\\AppData\\*" OR CommandLine="*\\bitsadmin* /transfer*" OR CommandLine="*\\certutil.exe * -decode *" OR CommandLine="*\\certutil.exe * -decodehex *" OR CommandLine="*\\certutil.exe -ping *" OR CommandLine="icacls * /grant Everyone:F /T /C /Q" OR CommandLine="* wmic shadowcopy delete *" OR CommandLine="* wbadmin.exe delete catalog -quiet*" OR CommandLine="*\\wscript.exe *.jse" OR CommandLine="*\\wscript.exe *.js" OR CommandLine="*\\wscript.exe *.vba" OR CommandLine="*\\wscript.exe *.vbe" OR CommandLine="*\\cscript.exe *.jse" OR CommandLine="*\\cscript.exe *.js" OR CommandLine="*\\cscript.exe *.vba" OR CommandLine="*\\cscript.exe *.vbe" OR CommandLine="*\\fodhelper.exe" OR CommandLine="*waitfor*/s*" OR CommandLine="*waitfor*/si persist*" OR CommandLine="*remote*/s*" OR CommandLine="*remote*/c*" OR CommandLine="*remote*/q*" OR CommandLine="*AddInProcess*" OR CommandLine="* /stext *" OR CommandLine="* /scomma *" OR CommandLine="* /stab *" OR CommandLine="* /stabular *" OR CommandLine="* /shtml *" OR CommandLine="* /sverhtml *" OR CommandLine="* /sxml *") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Process_Creation_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=car.2013-07-001,level=medium"
```
