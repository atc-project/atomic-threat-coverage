| Title                | Suspicious Process Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process starts on Windows systems based on keywords                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/](https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/)</li><li>[https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s](https://www.youtube.com/watch?v=H3t_kHQG1Js&feature=youtu.be&t=15m35s)</li><li>[https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)</li><li>[https://twitter.com/subTee/status/872244674609676288](https://twitter.com/subTee/status/872244674609676288)</li><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/remote-tool-examples)</li><li>[https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html](https://tyranidslair.blogspot.ca/2017/07/dg-on-windows-10-s-executing-arbitrary.html)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li><li>[https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html](https://subt0x10.blogspot.ca/2017/04/bypassing-application-whitelisting.html)</li><li>[https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat](https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46#file-rat-bat)</li><li>[https://twitter.com/vector_sec/status/896049052642533376](https://twitter.com/vector_sec/status/896049052642533376)</li><li>[http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf](http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
# Sigma rule: rules/windows/builtin/win_susp_process_creations.yml
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
    - http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf
author: Florian Roth
modified: 2018/12/11
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
            - net localgroup adminstrators * /add
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





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
CommandLine:("vssadmin.exe delete shadows*" "vssadmin delete shadows*" "vssadmin create shadow \\/for=C\\:*" "copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit*" "copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM*" "reg SAVE HKLM\\\\SYSTEM *" "reg SAVE HKLM\\\\SAM *" "* sekurlsa\\:*" "net localgroup adminstrators * \\/add" "net group \\"Domain Admins\\" * \\/ADD \\/DOMAIN" "certutil.exe *\\-urlcache* http*" "certutil.exe *\\-urlcache* ftp*" "netsh advfirewall firewall *\\\\AppData\\\\*" "attrib \\+S \\+H \\+R *\\\\AppData\\\\*" "schtasks* \\/create *\\\\AppData\\\\*" "schtasks* \\/sc minute*" "*\\\\Regasm.exe *\\\\AppData\\\\*" "*\\\\Regasm *\\\\AppData\\\\*" "*\\\\bitsadmin* \\/transfer*" "*\\\\certutil.exe * \\-decode *" "*\\\\certutil.exe * \\-decodehex *" "*\\\\certutil.exe \\-ping *" "icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q" "* wmic shadowcopy delete *" "* wbadmin.exe delete catalog \\-quiet*" "*\\\\wscript.exe *.jse" "*\\\\wscript.exe *.js" "*\\\\wscript.exe *.vba" "*\\\\wscript.exe *.vbe" "*\\\\cscript.exe *.jse" "*\\\\cscript.exe *.js" "*\\\\cscript.exe *.vba" "*\\\\cscript.exe *.vbe" "*\\\\fodhelper.exe" "*waitfor*\\/s*" "*waitfor*\\/si persist*" "*remote*\\/s*" "*remote*\\/c*" "*remote*\\/q*" "*AddInProcess*" "* \\/stext *" "* \\/scomma *" "* \\/stab *" "* \\/stabular *" "* \\/shtml *" "* \\/sverhtml *" "* \\/sxml *")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P \'^(?:.*vssadmin\\.exe delete shadows.*|.*vssadmin delete shadows.*|.*vssadmin create shadow /for=C:.*|.*copy \\\\?\\GLOBALROOT\\Device\\\\.*\\windows\\ntds\\ntds\\.dit.*|.*copy \\\\?\\GLOBALROOT\\Device\\\\.*\\config\\SAM.*|.*reg SAVE HKLM\\SYSTEM .*|.*reg SAVE HKLM\\SAM .*|.*.* sekurlsa:.*|.*net localgroup adminstrators .* /add|.*net group "Domain Admins" .* /ADD /DOMAIN|.*certutil\\.exe .*-urlcache.* http.*|.*certutil\\.exe .*-urlcache.* ftp.*|.*netsh advfirewall firewall .*\\AppData\\\\.*|.*attrib \\+S \\+H \\+R .*\\AppData\\\\.*|.*schtasks.* /create .*\\AppData\\\\.*|.*schtasks.* /sc minute.*|.*.*\\Regasm\\.exe .*\\AppData\\\\.*|.*.*\\Regasm .*\\AppData\\\\.*|.*.*\\bitsadmin.* /transfer.*|.*.*\\certutil\\.exe .* -decode .*|.*.*\\certutil\\.exe .* -decodehex .*|.*.*\\certutil\\.exe -ping .*|.*icacls .* /grant Everyone:F /T /C /Q|.*.* wmic shadowcopy delete .*|.*.* wbadmin\\.exe delete catalog -quiet.*|.*.*\\wscript\\.exe .*\\.jse|.*.*\\wscript\\.exe .*\\.js|.*.*\\wscript\\.exe .*\\.vba|.*.*\\wscript\\.exe .*\\.vbe|.*.*\\cscript\\.exe .*\\.jse|.*.*\\cscript\\.exe .*\\.js|.*.*\\cscript\\.exe .*\\.vba|.*.*\\cscript\\.exe .*\\.vbe|.*.*\\fodhelper\\.exe|.*.*waitfor.*/s.*|.*.*waitfor.*/si persist.*|.*.*remote.*/s.*|.*.*remote.*/c.*|.*.*remote.*/q.*|.*.*AddInProcess.*|.*.* /stext .*|.*.* /scomma .*|.*.* /stab .*|.*.* /stabular .*|.*.* /shtml .*|.*.* /sverhtml .*|.*.* /sxml .*)\'
```



