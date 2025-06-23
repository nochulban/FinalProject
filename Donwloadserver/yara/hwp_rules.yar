//////////////////////////////////////////
// HWP 악성코드 탐지 룰셋 (3종)
//////////////////////////////////////////

rule hwpJScript {
    meta:
        description = "Detects malicious JavaScript embedded in HWP files"
    strings:
        $string1 = "ActiveXObject" nocase
        $string2 = "GetSpecialFolder" nocase
        $string3 = "WriteText" nocase
        $string4 = "SaveToFile" nocase
        $string5 = "eAll" nocase
        $string6 = "Run" nocase fullword
    condition:
        ($string1 and $string2 and $string3 and $string4) or
        ($string1 and $string6) or
        ($string1 and $string2 and $string5 and $string6)
}

rule hwpMalwareEps {
    meta:
        description = "Detects malicious EPS payloads inside HWP files"
    strings:
        $regex1 = /<[0-9A-Fa-f]{500,}>/
        $string1 = "4 mod get xor put" nocase
        $string2 = "exec" nocase
        $string3 = "/concatstrings" nocase
        $string4 = "dup dup 4 2 roll copy length" nocase
        $string5 = "and" nocase
        $string6 = "get xor" nocase
        $string7 = "string dup" nocase
        $string8 = "putinterval" nocase
        $string9 = "repeat" nocase
        $string10 = "aload" nocase
        $string11 = ".eqproc" nocase
        $string12 = "{1} put" nocase
        $string13 = "get closefile" nocase
    condition:
        $regex1 and 1 of (
            $string1, $string2, $string3, $string4,
            $string5, $string6, $string7, $string8,
            $string9, $string10, $string11, $string12, $string13
        )
}

rule hwpMaliciousApi {
    meta:
        description = "Detects common malicious API usage in HWP OLE"
    strings:
        $string1 = "UrlDownloadToFile"
        $string2 = "GetTempPath"
        $string3 = "GetWindowsDirectory"
        $string4 = "GetSystemDirectory"
        $string5 = "ShellExecute"
        $string6 = "IsBadReadPtr"
        $string7 = "CreateFile"
        $string8 = "CreateHandle"
        $string9 = "ReadFile"
        $string10 = "WriteFile"
        $string11 = "SetFilePointer"
        $string12 = "VirtualAlloc"
        $string13 = "GetProcAddress"
        $string14 = "LoadLibrary"
        $string15 = "GetProcAddr"
        $string16 = "WinExec"
        $string17 = "Execute"
    condition:
        any of them
}