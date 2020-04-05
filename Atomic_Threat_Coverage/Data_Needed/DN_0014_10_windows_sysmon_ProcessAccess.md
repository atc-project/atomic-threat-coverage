| Title              | DN_0014_10_windows_sysmon_ProcessAccess       |
|:-------------------|:------------------|
| **Description**    | The process accessed event reports when a process opens another process, an  operation that’s often followed by information queries or reading and writing  the address space of the target process |
| **Logging Policy** | <ul><li>[LP_0007_windows_sysmon_ProcessAccess](../Logging_Policies/LP_0007_windows_sysmon_ProcessAccess.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>SourceProcessGUID</li><li>SourceProcessId</li><li>SourceThreadId</li><li>SourceImage</li><li>TargetProcessGUID</li><li>TargetProcessId</li><li>TargetImage</li><li>GrantedAccess</li><li>CallTrace</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>10</EventID> 
    <Version>3</Version> 
    <Level>4</Level> 
    <Task>10</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-01-30T14:28:35.216091900Z" /> 
    <EventRecordID>42444</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3892" ThreadID="5724" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-01-30 14:28:35.212</Data> 
    <Data Name="SourceProcessGUID">{9683FBB1-B470-5C51-0000-0010521EBB00}</Data> 
    <Data Name="SourceProcessId">6916</Data> 
    <Data Name="SourceThreadId">8080</Data> 
    <Data Name="SourceImage">C:\Users\user1\Desktop\mimi\x64\mimikatz.exe</Data> 
    <Data Name="TargetProcessGUID">{9683FBB1-9A52-5C51-0000-0010C3610000}</Data> 
    <Data Name="TargetProcessId">672</Data> 
    <Data Name="TargetImage">C:\windows\system32\lsass.exe</Data> 
    <Data Name="GrantedAccess">0x1010</Data> 
    <Data Name="CallTrace">C:\windows\SYSTEM32\ntdll.dll+9a3c4|C:\windows\System32\KERNELBASE.dll+2fd5d|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+7a906|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+7ac75|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+7a82d|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+4d28c|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+4d0c4|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+4cea1|C:\Users\user1\Desktop\mimi\x64\mimikatz.exe+80675|C:\windows\System32\KERNEL32.DLL+13034|C:\windows\SYSTEM32\ntdll.dll+71471</Data> 
  </EventData>
</Event>

```




