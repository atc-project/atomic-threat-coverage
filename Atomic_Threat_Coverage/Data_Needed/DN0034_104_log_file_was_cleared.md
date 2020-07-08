| Title              | DN0034_104_log_file_was_cleared       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Windows log file was cleared |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://kb.eventtracker.com/evtpass/evtpages/EventId_104_Microsoft-Windows-Eventlog_64337.asp](http://kb.eventtracker.com/evtpass/evtpages/EventId_104_Microsoft-Windows-Eventlog_64337.asp)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | System     |
| **Provider**       | Microsoft-Windows-Eventlog    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>Channel</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /> 
      <EventID>104</EventID> 
      <Version>0</Version> 
      <Level>4</Level> 
      <Task>104</Task> 
      <Opcode>0</Opcode> 
      <Keywords>0x8000000000000000</Keywords> 
      <TimeCreated SystemTime="2019-02-08T22:31:47.796843000Z" /> 
      <EventRecordID>7659</EventRecordID> 
      <Correlation /> 
      <Execution ProcessID="752" ThreadID="1988" /> 
      <Channel>System</Channel> 
      <Computer>ATC-WIN-7.atc.local</Computer> 
      <Security UserID="S-1-5-21-3463664321-2923530833-3546627382-1000" /> 
    </System>
  - <UserData>
    - <LogFileCleared xmlns:auto-ns3="http://schemas.microsoft.com/win/2004/08/events" xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>user1</SubjectUserName> 
        <SubjectDomainName>ATC-WIN-7.atc.local</SubjectDomainName> 
        <Channel>Application</Channel> 
        <BackupPath /> 
      </LogFileCleared>
    </UserData>
  </Event>

```




