Import-Module DFSR
Sync-DfsReplicationGroup -GroupName "Domain System Volume" `
  -SourceComputerName SRV-AD-01 `
  -DestinationComputerName SRV-AD-02 `
  -DurationInMinutes 15 -Verbose

Import-Module DFSR
Sync-DfsReplicationGroup -GroupName "Domain System Volume" `
  -SourceComputerName SRV-AD-01 `
  -DestinationComputerName FIX-DC00 `
  -DurationInMinutes 15 -Verbose

dfsrdiag syncnow /partner:SRV-AD-01 /RGName:"Domain System Volume" /Time:15 /Member:SRV-AD-02
dfsrdiag syncnow /partner:SRV-AD-01 /RGName:"Domain System Volume" /Time:15 /Member:FIX-DC00
