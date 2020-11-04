| Title              | DN_0003_1_windows_sysmon_process_creation       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Windows process creation log, including command line |
| **Logging Policy** | <ul><li>[LP0003_windows_sysmon_process_creation](../Logging_Policies/LP0003_windows_sysmon_process_creation.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>Computer</li><li>UtcTime</li><li>Username</li><li>User</li><li>ProcessGuid</li><li>ProcessId</li><li>ProcessName</li><li>CommandLine</li><li>LogonGuid</li><li>LogonId</li><li>TerminalSessionid</li><li>IntegrityLevel</li><li>Hashes</li><li>Imphash</li><li>Sha256hash</li><li>Sha1hash</li><li>Md5hash</li><li>Image</li><li>ParentImage</li><li>ParentProcessGuid</li><li>ParentProcessId</li><li>ParentProcessName</li><li>ParentCommandLine</li><li>OriginalFileName</li><li>FileVersion</li><li>Description</li><li>Product</li><li>Company</li><li>CurrentDirectory</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>1</EventID> 
    <Version>5</Version> 
    <Level>4</Level> 
    <Task>1</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-09T03:44:58.290314900Z" /> 
    <EventRecordID>4219</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="1976" ThreadID="3196" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10</Computer> 
    <Security UserID="S-1-5-18" /> 
    </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-07-09 03:44:58.036</Data> 
    <Data Name="ProcessGuid">{717CFEC0-0DBA-5D24-0000-001087BC0800}</Data> 
    <Data Name="ProcessId">5500</Data> 
    <Data Name="Image">C:\Windows\System32\conhost.exe</Data> 
    <Data Name="FileVersion">10.0.14393.0 (rs1_release.160715-1616)</Data> 
    <Data Name="Description">Console Window Host</Data> 
    <Data Name="Product">Microsoft® Windows® Operating System</Data> 
    <Data Name="Company">Microsoft Corporation</Data> 
    <Data Name="OriginalFileName">CONHOST.EXE</Data> 
    <Data Name="CommandLine">\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1</Data> 
    <Data Name="CurrentDirectory">C:\Windows</Data> 
    <Data Name="User">atc-win-10\yugoslavskiy</Data> 
    <Data Name="LogonGuid">{717CFEC0-0DA0-5D24-0000-0020D0F50300}</Data> 
    <Data Name="LogonId">0x3f5d0</Data> 
    <Data Name="TerminalSessionId">1</Data> 
    <Data Name="IntegrityLevel">Medium</Data> 
    <Data Name="Hashes">MD5=D752C96401E2540A443C599154FC6FA9,SHA256=046F7A1B4DE67562547ED9A180A72F481FC41E803DE49A96D7D7C731964D53A0</Data> 
    <Data Name="ParentProcessGuid">{717CFEC0-0DB9-5D24-0000-0010C9BB0800}</Data> 
    <Data Name="ParentProcessId">4412</Data> 
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data> 
    <Data Name="ParentCommandLine">"C:\Windows\System32\cmd.exe" /q /c rmdir /s /q "C:\Users\yugoslavskiy\AppData\Local\Microsoft\OneDrive\19.086.0502.0006"</Data> 
  </EventData>
</Event>

```




