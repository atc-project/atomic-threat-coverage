| Title              | DN0054_2102_pnp_or_power_operation_for_usb_device       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Finished PnP or Power operation for USB device |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-DriverFrameworks-UserMode/Operational     |
| **Provider**       | Microsoft-Windows-DriverFrameworks-UserMode    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>UMDFHostDeviceRequest</li><li>lifetime</li><li>instance</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"> 
  - <System> 
    <Provider Name="Microsoft-Windows-DriverFrameworks-UserMode" Guid="{2e35aaeb-857f-4beb-a418-2e6c0e54d988}" /> 
    <EventID>2102</EventID> 
    <Version>1</Version> 
    <Level>4</Level> 
    <Task>37</Task> 
    <Opcode>2</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2010-08-26T17:53:04.155Z" /> 
    <EventRecordID>201772</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3176" ThreadID="3236" /> 
    <Channel>Microsoft-Windows-DriverFrameworks-UserMode/Operational</Channel> 
    <Computer>Sal</Computer> 
    <Security UserID="S-1-5-19" /> 
  </System> 
    - <UserData> 
      - <UMDFHostDeviceRequest lifetime="{0A5BFD5B-1FC3-4985-9A2B-955F2D65E42F}" instance="WPDBUSENUMROOT\UMB\2&37C186B&0&STORAGE#VOLUME#1&19F7E59C&0&_??_USBSTOR#DISK&VEN_GENERIC&PROD_USB_MS_READER&REV_1.03#920321111113&3#" xmlns:auto-ns2="http://schemas.microsoft.com/win/2004/08/events" xmlns="http://www.microsoft.com/DriverFrameworks/UserMode/Event"> 
        - <Request major="22" minor="3"> 
          <Argument>0x0</Argument> 
          <Argument>0x6</Argument> 
          <Argument>0x6</Argument> 
          <Argument>0x0</Argument> 
        </Request> 
        <Status>3221225659</Status> 
      </UMDFHostDeviceRequest> 
    </UserData> 
</Event> 

```




