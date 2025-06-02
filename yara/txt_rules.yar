rule txtSuspiciousCommands {
    meta:
        description = "Detects suspicious PowerShell, curl, and base64-encoded payloads in .txt files"
        author = "ncb"
        version = "1.0"
        filetype = "txt"

    strings:
        $psEncoded = "powershell -EncodedCommand"
        $psDownload = "IEX (New-Object Net.WebClient).DownloadString"
        $certutil = "certutil -decode"
        $wget = "wget http"
        $curl = "curl -o"
        $invokeWeb = "Invoke-WebRequest"
        $invokeExp = "Invoke-Expression"
        $mshta = "mshta"
        $regsvr = "regsvr32"
        $cmdExec = "cmd.exe /c"
        $b64long = /[A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        2 of ($psEncoded, $psDownload, $certutil, $wget, $curl, $invokeWeb, $invokeExp, $mshta, $regsvr, $cmdExec) or
        $b64long
}


rule txtContainsSuspiciousURLs {
    meta:
        description = "Detects suspicious or known malicious URL patterns in .txt files"
        author = "ChatGPT"
        version = "1.0"
        filetype = "txt"

    strings:
        $url1 = /http[s]?:\/\/[a-zA-Z0-9.\-]{5,}\/[a-zA-Z0-9]{10,}/
        $url2 = "pastebin.com"
        $url3 = "raw.githubusercontent.com"
        $url4 = "ngrok.io"
        $url5 = "bit.ly"
        $url6 = "drive.google.com/uc?id="

    condition:
        2 of ($url*)
}

rule txtEncodedPayloadIndicators {
    meta:
        description = "Detects signs of encoded or obfuscated payloads in .txt files"
        author = "ncb"
        version = "1.0"
        filetype = "txt"

    strings:
        $hexPattern = /0x[0-9A-Fa-f]{2,}/
        $xorOp = "xor" nocase
        $b64Prefix = "TVqQAAMAAAAEAAAA"   // MZ header base64
        $jsDecode = "atob"
        $decodeFunc = "decodeURIComponent"
        $charFromCode = "String.fromCharCode"

    condition:
        2 of ($hexPattern, $xorOp, $b64Prefix, $jsDecode, $decodeFunc, $charFromCode)
}

rule txtKeyloggerIndicator {
    meta:
        description = "Detects indicators of keylogger output patterns in .txt files"
        author = "ncb"
        version = "1.0"
        filetype = "txt"

    strings:
        $k1 = "Key Pressed:"
        $k2 = "Keystroke Log:"
        $k3 = "Window Title:"
        $k4 = "Captured Input:"
        $k5 = "Active Window:"

    condition:
        2 of ($k*)
}
