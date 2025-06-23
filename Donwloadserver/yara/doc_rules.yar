// 암호화된 Office 문서 탐지
rule docEncryptedPackage {
    meta:
        author = "ncb"
        description = "Detects Office documents using the EncryptedPackage structure"
        version = "1.0"
    strings:
        // OLE 포맷 문서의 매직 넘버 (DOC 등)
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // 암호화된 문서에서 사용되는 구조명
        $encrypted = "EncryptedPackage" wide

    condition:
        // OLE 파일이고 EncryptedPackage가 포함되어 있을 경우
        $magic at 0 and $encrypted
}

////////////////////////////////////////////////////////////

// VBA 매크로 포함 문서 탐지 (.doc, .docx 모두 커버)
rule docContainsVbaProject {
    meta:
        author = "ncb"
        description = "Detects Office documents with embedded VBA macros (vbaProject.bin)"
        version = "1.0"
    strings:
        // OLE 매직 넘버 (DOC)
        $magic1 = { D0 CF 11 E0 A1 B1 1A E1 }

        // ZIP 포맷 매직 넘버 (DOCX)
        $magic2 = { 50 4B 03 04 }

        // 매크로 바이너리 파일명
        $vba1 = "vbaProject.bin" wide

        // 레거시 VBA 프로젝트 명
        $vba2 = "VBA_PROJECT" wide nocase

    condition:
        // OLE 또는 ZIP 포맷이면서 VBA 흔적이 있을 경우
        (any of ($magic*)) and (any of ($vba*))
}

////////////////////////////////////////////////////////////

// 자동 실행 매크로 함수 탐지 (AutoOpen, Workbook_Open 등)
rule docOleAutoOpenMacro {
    meta:
        author = "ncb"
        description = "Detects AutoOpen-style macro triggers in OLE Office documents"
        version = "1.0"
    strings:
        // OLE 기반 문서 매직 넘버
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }

        // 매크로 실행 지점 함수들
        $auto1 = "AutoOpen"
        $auto2 = "Document_Open"
        $auto3 = "Workbook_Open"

    condition:
        // OLE 문서이며 자동 실행 매크로 중 하나 포함
        $ole at 0 and 1 of ($auto*)
}

////////////////////////////////////////////////////////////

// 매크로 내부에서 쉘 명령 실행 흔적 탐지
rule docMacroShellCommand {
    meta:
        author = "ncb"
        description = "Detects usage of shell commands inside Office macros"
        version = "1.0"
    strings:
        // OLE 문서 매직 넘버
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // 실행 가능한 명령어 관련 문자열
        $cmd1 = "cmd.exe"
        $cmd2 = "powershell"
        $cmd3 = "wscript.shell"
        $cmd4 = "CreateObject(\"Shell.Application\")"

    condition:
        // OLE 문서이며 명령어 실행 관련 문자열 포함
        $magic at 0 and 1 of ($cmd*)
}

////////////////////////////////////////////////////////////

// 악성 의심 문자열 포함 여부 탐지 (.exe, URL, AutoClose 등)
rule docSuspiciousStrings {
    meta:
        author = "ncb"
        description = "Detects suspicious strings often found in malicious Office macros"
        version = "1.0"
    strings:
        // OLE 문서 매직 넘버
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // 외부 호출 또는 실행과 관련된 문자열
        $s1 = "http://"
        $s2 = "https://"
        $s3 = ".exe"
        $s4 = ".scr"
        $s5 = "AutoClose"

    condition:
        // 문서 시작부에 OLE 매직 넘버가 있고, 의심 문자열 2개 이상 포함
        $magic at 0 and 2 of ($s*)
}