| Title          | LP_0002_windows_audit_process_creation_with_commandline                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit Process Creation determines whether the operating  system generates audit events when a process is created (starts).  These audit events can help you track user activity and understand  how a computer is being used. Information includes the name of the  program or the user that created the process (incl. commanline of new process).                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | Medium                                                                    |
| EventID        | <ul><li>4688</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-process-creation.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-process-creation.md)</li><li>[https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration > 
Administrative Templates > 
System > 
Audit Process Creation >
Include command line in process creation events (Enable)
```
Enabling via registry key:
```
reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
```


