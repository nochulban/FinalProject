// 숨겨진 매크로 시트가 포함된 OLE Excel 문서 탐지
rule xlsHiddenMacroSheet {
    meta:
        author = "ncb"
        description = "Detects hidden macro sheets in OLE-format Excel files (BIFF structure)"
        version = "1.0"
    strings:
        $oleMarker = { D0 CF 11 E0 A1 B1 1A E1 }
        $hidden1 = { 85 00 ?? ?? ?? ?? ?? ?? 01 01 }
        $hidden2 = { 85 00 ?? ?? ?? ?? ?? ?? 02 01 }
    condition:
        $oleMarker at 0 and 1 of ($hidden*)
}

////////////////////////////////////////////////////////////

rule xlsDataConnectionWithUrl {
    meta:
        author = "ncb"
        description = "Detects Excel files with external data connections that auto-connect"
        version = "1.0"
    strings:
        $oleHeader = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
        $url = /https?:\/\/[\w\/\.\-]+/ nocase ascii wide
        $dconn = /\x76\x08\x00\x00\x04\x00[\x40-\x7f\xc0-\xff]/
    condition:
        $oleHeader in (0..1024) and $dconn and $url
}

////////////////////////////////////////////////////////////

rule xlsxWithMacrosheet {
    meta:
        author = "ncb"
        description = "Detects XLSX/XLSM files with macrosheets (XLM macro indicators)"
        version = "1.0"
    strings:
        $zipMagic = { 50 4B 03 04 }
        $macrosheet = /xl\\/macrosheets\\/[a-zA-Z0-9_-]+\\.xmlPK/
    condition:
        $zipMagic at 0 and $macrosheet
}

////////////////////////////////////////////////////////////

// Excel 4.0 매크로 함수들: 외부 실행 관련 문자열 포함 시 탐지
rule xlsSuspiciousExcel4Strings {
    meta:
        author = "ncb"
        description = "Detects suspicious XLM macro commands in Excel files"
        version = "1.0"
    strings:
        $cmd = "CALL(\"Shell32\",\"ShellExecuteA\""
        $regsvr = "regsvr32"
        $dwn = "URLDownloadToFile"
        $ps = "powershell"
        $aut = "Auto_Open"
    condition:
        any of ($cmd, $regsvr, $dwn, $ps, $aut)
}

////////////////////////////////////////////////////////////

// 자동 실행을 위한 수식 포함 셀 (예: HYPERLINK, GET.WORKBOOK)
rule xlsSuspiciousAutoOpenCellFormula {
    meta:
        author = "ncb"
        description = "Detects formula payloads designed to trigger actions on cell selection or opening"
        version = "1.0"
    strings:
        $form1 = "=HYPERLINK("
        $form2 = "=GET.WORKBOOK("
        $form3 = "=EXEC("
        $form4 = "=FORMULA("
    condition:
        2 of ($form*)
}