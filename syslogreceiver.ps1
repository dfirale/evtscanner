# Writes data received from $port to $file
# Default syslog port = 514
# usage:
# .\syslogreceiver.ps1 -port 514 -file C:\Users\user01\Desktop\syslog.txt

param (
    [Parameter(Mandatory=$true)]$port,
    [Parameter(Mandatory=$true)]$file
)

$endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Any, $port)
Try {
    while($true) {
        $socket = New-Object System.Net.Sockets.UdpClient $port
        $content = $socket.Receive([ref]$endpoint)
        $socket.Close()
        [Text.Encoding]::ASCII.GetString($content) | Add-Content -Path $file
    }

} Catch {
    "$($Error[0])"
}
