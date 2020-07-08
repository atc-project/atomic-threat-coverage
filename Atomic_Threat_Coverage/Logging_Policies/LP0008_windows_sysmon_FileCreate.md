| Title            | LP0008_windows_sysmon_FileCreate                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.                                                               |
| **Default**      | Partially (Other)                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>11</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

Sysmon event id 11 is enabled by default however default configuration might not be sufficient.
Sample configuration providing much better visibility might be found here: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

```
  <!--DATA: UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime-->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\Start Menu</TargetFilename> <!--Microsoft:Windows: Startup links and shortcut modification [ https://attack.mitre.org/wiki/Technique/T1023 ] -->
    <TargetFilename condition="contains">\Startup\</TargetFilename> <!--Microsoft:Office: Changes to user's auto-launched files and shortcuts-->
    <TargetFilename condition="contains">\Content.Outlook\</TargetFilename> <!--Microsoft:Outlook: attachments-->
    <TargetFilename condition="contains">\Downloads\</TargetFilename> <!--Downloaded files. Does not include "Run" files in IE-->
    <TargetFilename condition="end with">.application</TargetFilename> <!--Microsoft:ClickOnce: [ https://blog.netspi.com/all-you-need-is-one-a-clickonce-love-story/ ] -->
    <TargetFilename condition="end with">.appref-ms</TargetFilename> <!--Microsoft:ClickOnce application | Credit @ion-storm -->
    <TargetFilename condition="end with">.bat</TargetFilename> <!--Batch scripting-->
    <TargetFilename condition="end with">.chm</TargetFilename>
    <TargetFilename condition="end with">.cmd</TargetFilename> <!--Batch scripting: Batch scripts can also use the .cmd extension | Credit: @mmazanec -->
    <TargetFilename condition="end with">.cmdline</TargetFilename> <!--Microsoft:dotNet: Executed by cvtres.exe-->
    <TargetFilename condition="end with">.docm</TargetFilename> <!--Microsoft:Office:Word: Macro-->
    <TargetFilename condition="end with">.exe</TargetFilename> <!--Executable-->
    <TargetFilename condition="end with">.jar</TargetFilename> <!--Java applets-->
    <TargetFilename condition="end with">.jnlp</TargetFilename> <!--Java applets-->
    <TargetFilename condition="end with">.jse</TargetFilename> <!--Scripting [ Example: https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Mal~Phires-C/detailed-analysis.aspx ] -->
    <TargetFilename condition="end with">.hta</TargetFilename> <!--Scripting-->
    <TargetFilename condition="end with">.pptm</TargetFilename> <!--Microsoft:Office:Word: Macro-->
    <TargetFilename condition="end with">.ps1</TargetFilename> <!--PowerShell [ More information: http://www.hexacorn.com/blog/2014/08/27/beyond-good-ol-run-key-part-16/ ] -->
    <TargetFilename condition="end with">.sys</TargetFilename> <!--System driver files-->
    <TargetFilename condition="end with">.scr</TargetFilename> <!--System driver files-->
    <TargetFilename condition="end with">.vbe</TargetFilename> <!--VisualBasicScripting-->
    <TargetFilename condition="end with">.vbs</TargetFilename> <!--VisualBasicScripting-->
    <TargetFilename condition="end with">.xlsm</TargetFilename> <!--Microsoft:Office:Word: Macro-->
    <TargetFilename condition="end with">proj</TargetFilename><!--Microsoft:MSBuild:Script: More information: https://twitter.com/subTee/status/885919612969394177-->
    <TargetFilename condition="end with">.sln</TargetFilename><!--Microsoft:MSBuild:Script: More information: https://twitter.com/subTee/status/885919612969394177-->
    <TargetFilename condition="begin with">C:\Users\Default</TargetFilename> <!--Microsoft:Windows: Changes to default user profile-->
    <TargetFilename condition="begin with">C:\Windows\system32\Drivers</TargetFilename> <!--Microsoft: Drivers dropped here-->
    <TargetFilename condition="begin with">C:\Windows\SysWOW64\Drivers</TargetFilename> <!--Microsoft: Drivers dropped here-->
    <TargetFilename condition="begin with">C:\Windows\system32\GroupPolicy\Machine\Scripts</TargetFilename> <!--Group policy [ More information: http://www.hexacorn.com/blog/2017/01/07/beyond-good-ol-run-key-part-52/ ] -->
    <TargetFilename condition="begin with">C:\Windows\system32\GroupPolicy\User\Scripts</TargetFilename> <!--Group policy [ More information: http://www.hexacorn.com/blog/2017/01/07/beyond-good-ol-run-key-part-52/ ] -->
    <TargetFilename condition="begin with">C:\Windows\system32\Wbem</TargetFilename> <!--Microsoft:WMI: [ More information: http://2014.hackitoergosum.org/slides/day1_WMI_Shell_Andrei_Dumitrescu.pdf ] -->
    <TargetFilename condition="begin with">C:\Windows\SysWOW64\Wbem</TargetFilename> <!--Microsoft:WMI: [ More information: http://2014.hackitoergosum.org/slides/day1_WMI_Shell_Andrei_Dumitrescu.pdf ] -->
    <TargetFilename condition="begin with">C:\Windows\system32\WindowsPowerShell</TargetFilename> <!--Microsoft:Powershell: Look for modifications for persistence [ https://www.malwarearchaeology.com/cheat-sheets ] -->
    <TargetFilename condition="begin with">C:\Windows\SysWOW64\WindowsPowerShell</TargetFilename> <!--Microsoft:Powershell: Look for modifications for persistence [ https://www.malwarearchaeology.com/cheat-sheets ] -->
    <TargetFilename condition="begin with">C:\Windows\Tasks\</TargetFilename> <!--Microsoft:ScheduledTasks [ https://attack.mitre.org/wiki/Technique/T1053 ] -->
    <TargetFilename condition="begin with">C:\Windows\system32\Tasks</TargetFilename> <!--Microsoft:ScheduledTasks [ https://attack.mitre.org/wiki/Technique/T1053 ] -->
    <!--Windows application compatibility-->
    <TargetFilename condition="begin with">C:\Windows\AppPatch\Custom</TargetFilename> <!--Microsoft:Windows: Application compatibility shims [ https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html ] -->
    <TargetFilename condition="contains">VirtualStore</TargetFilename> <!--Microsoft:Windows: UAC virtualization [ https://blogs.msdn.microsoft.com/oldnewthing/20150902-00/?p=91681 ] -->
    <!--Exploitable file names-->
    <TargetFilename condition="end with">.xls</TargetFilename> <!--Legacy Office files are often used for attacks-->
    <TargetFilename condition="end with">.ppt</TargetFilename> <!--Legacy Office files are often used for attacks-->
    <TargetFilename condition="end with">.rft</TargetFilename> <!--RTF files often 0day malware vectors when opened by Office-->
  </FileCreate>

  <FileCreate onmatch="exclude">
    <!--SECTION: Microsoft-->
    <Image condition="is">C:\Program Files (x86)\EMET 5.5\EMET_Service.exe</Image> <!--Microsoft:EMET: Writes to C:\Windows\AppPatch\-->
    <!--SECTION: Microsoft:Office-->
    <TargetFilename condition="is">C:\Windows\System32\Tasks\OfficeSoftwareProtectionPlatform\SvcRestartTask</TargetFilename>
    <!--SECTION: Microsoft:Office:Click2Run-->
    <Image condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe</Image> <!-- Microsoft:Office Click2Run-->
    <!--SECTION: Microsoft:Windows-->
    <Image condition="is">C:\Windows\system32\smss.exe</Image> <!-- Microsoft:Windows: Session Manager SubSystem: Creates swapfile.sys,pagefile.sys,hiberfile.sys-->
    <Image condition="is">C:\Windows\system32\CompatTelRunner.exe</Image> <!-- Microsoft:Windows: Windows 10 app, creates tons of cache files-->
    <Image condition="is">\\?\C:\Windows\system32\wbem\WMIADAP.EXE</Image> <!-- Microsoft:Windows: WMI Performance updates-->
    <Image condition="is">C:\Windows\system32\mobsync.exe</Image> <!--Microsoft:Windows: Network file syncing-->
    <TargetFilename condition="begin with">C:\Windows\system32\DriverStore\Temp\</TargetFilename> <!-- Microsoft:Windows: Temp files by DrvInst.exe-->
    <TargetFilename condition="begin with">C:\Windows\system32\wbem\Performance\</TargetFilename> <!-- Microsoft:Windows: Created in wbem by WMIADAP.exe-->
    <TargetFilename condition="end with">WRITABLE.TST</TargetFilename> <!-- Microsoft:Windows: Created in wbem by svchost-->
    <TargetFilename condition="begin with">C:\Windows\Installer\</TargetFilename> <!--Microsoft:Windows:Installer: Ignore MSI installer files caching-->
    <!--SECTION: Microsoft:Windows:Updates-->
    <TargetFilename condition="begin with">C:\$WINDOWS.~BT\Sources\</TargetFilename> <!-- Microsoft:Windows: Feature updates containing lots of .exe and .sys-->
    <Image condition="begin with">C:\Windows\winsxs\amd64_microsoft-windows</Image> <!-- Microsoft:Windows: Windows update-->
    <!--SECTION: Dell-->
    <Image condition="is">C:\Program Files (x86)\Dell\CommandUpdate\InvColPC.exe</Image>
    <!--SECTION: Intel-->
    <Image condition="is">C:\Windows\system32\igfxCUIService.exe</Image> <!--Intel: Drops bat and other files in \Windows in normal operation-->
    <!--SECTION: Adobe-->
    <TargetFilename condition="is">C:\Windows\System32\Tasks\Adobe Acrobat Update Task</TargetFilename>
    <TargetFilename condition="is">C:\Windows\System32\Tasks\Adobe Flash Player Updater</TargetFilename>
  </FileCreate>
```

