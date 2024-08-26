// source: https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar


rule INDICATOR_SUSPICIOUS_IMG_Embedded_Archive {
    meta:
        description = "Detects images embedding archives. Observed in TheRat RAT."
        author = "ditekSHen"
        score = 60
    strings:
        $sevenzip1 = { 37 7a bc af 27 1c 00 04 } // 7ZIP, regardless of password-protection
        $sevenzip2 = { 37 e4 53 96 c9 db d6 07 } // 7ZIP zisofs compression format    
        $zipwopass = { 50 4b 03 04 14 00 00 00 } // None password-protected PKZIP
        $zipwipass = { 50 4b 03 04 33 00 01 00 } // Password-protected PKZIP
        $zippkfile = { 50 4b 03 04 0a 00 02 00 } // PKZIP
        $rarheade1 = { 52 61 72 21 1a 07 01 00 } // RARv4
        $rarheade2 = { 52 65 74 75 72 6e 2d 50 } // RARv5
        $rarheade3 = { 52 61 72 21 1a 07 00 cf } // RAR
        $mscabinet = { 4d 53 46 54 02 00 01 00 } // Microsoft cabinet file
        $zlockproe = { 50 4b 03 04 14 00 01 00 } // ZLock Pro encrypted ZIP
        $winzip    = { 57 69 6E 5A 69 70 }       // WinZip compressed archive 
        $pklite    = { 50 4B 4C 49 54 45 }       // PKLITE compressed ZIP archive
        $pksfx     = { 50 4B 53 70 58 }          // PKSFX self-extracting executable compressed file
    condition:
        // JPEG or JFIF or PNG or BMP
        (uint32(0) == 0xe0ffd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and 1 of them
}

rule INDICATOR_SUSPICIOUS_NTLM_Exfiltration_IPPattern {
    meta:
        author = "ditekSHen"
        description = "Detects NTLM hashes exfiltration patterns in command line and various file types"
        score = 60
    strings:
        // Example (CMD): net use \\1.2.3.4@80\t
        $s1 = /net\suse\s\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (PDF): /F (\\\\IP@80\\t)
        $s2 = /\/F\s\(\\\\\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (LNK): URL=file://IP@80/t.htm
        $s3 = /URL=file:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (ICO): IconFile=\\IP@80\t.ico
        $s4 = /IconFile=\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (DOC, DOCX): Target="file://IP@80/t.dotx"
        $s5 = /Target=\x22:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (Subdoc ??): ///IP@80/t
        $s6 = /\/\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (over SSL) - DavWWWRoot keyword actually triggers WebDAV forcibly
        $s7 = /\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@SSL@\d+\\DavWWWRoot/ ascii wide

        // OOXML in addtion to PK magic
        $mso1 = "word/" ascii
        $mso2 = "ppt/" ascii
        $mso3 = "xl/" ascii
        $mso4 = "[Content_Types].xml" ascii
    condition:
        ((uint32(0) == 0x46445025 or (uint16(0) == 0x004c and uint32(4) == 0x00021401) or uint32(0) == 0x00010000 or (uint16(0) == 0x4b50 and 1 of ($mso*))) and 1 of ($s*)) or 1 of ($s*)
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}

rule INDICATOR_SUSPICIOUS_PWSH_AsciiEncoding_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing ASCII encoded files"
    strings:
        $enc1 = "[char[]]([char]97..[char]122)" ascii
        $enc2 = "[char[]]([char]65..[char]90)" ascii
        $s1 = ".DownloadData($" ascii
        $s2 = "[Net.SecurityProtocolType]::TLS12" ascii
        $s3 = "::WriteAllBytes($" ascii
        $s4 = "::FromBase64String($" ascii
        $s5 = "Get-Random" ascii
    condition:
        1 of ($enc*) and 4 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files hex and base64 encoded executables"
        score = 60
    strings:
        $s1 = ".SaveToFile" ascii
        $s2 = ".Run" ascii
        $s3 = "ActiveXObject" ascii
        $s4 = "fromCharCode" ascii
        $s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
        $binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
        $pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii
    condition:
        $binary and $pattern and 2 of ($s*) and filesize < 2500KB
}

// rule INDICATOR_SUSPICIOUS_JS_LocalPersistence {
//     meta:
//         author = "ditekSHen"
//         description = "Detects JavaScript files used for persistence and executable or script execution"
//     strings:
//         $s1 = "ActiveXObject" ascii
//         $s2 = "Shell.Application" ascii
//         $s3 = "ShellExecute" ascii
// 
//         $ext1 = ".exe" ascii
//         $ext2 = ".ps1" ascii
//         $ext3 = ".lnk" ascii
//         $ext4 = ".hta" ascii
//         $ext5 = ".dll" ascii
//         $ext6 = ".vb" ascii
//         $ext7 = ".com" ascii
//         $ext8 = ".js" ascii
// 
//         $action = "\"Open\"" ascii
//     condition:
//        $action and 2 of ($s*) and 1 of ($ext*) and filesize < 500KB
// }


rule INDICATOR_SUSPICIOUS_AMSI_Bypass {
    meta:
        author = "ditekSHen"
        description = "Detects AMSI bypass pattern"
        score = 65
    strings:
        $v1_1 = "[Ref].Assembly.GetType(" ascii nocase
        $v1_2 = "System.Management.Automation.AmsiUtils" ascii
        $v1_3 = "GetField(" ascii nocase
        $v1_4 = "amsiInitFailed" ascii
        $v1_5 = "NonPublic,Static" ascii
        $v1_6 = "SetValue(" ascii nocase
    condition:
        5 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell content designed to retrieve passwords from host"
        score = 60
    strings:
        $namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
        $method1 = "RetrieveAll()" ascii wide nocase
        $method2 = ".RetrievePassword()" ascii wide nocase
    condition:
       $namespace and 1 of ($method*)
}

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}


rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery {
    meta:
        author = "ditekSHen"
        description = "Detects JS potentially executing WMI queries"
        score = 55
    strings:
        $ex = ".ExecQuery(" ascii nocase
        $s1 = "GetObject(" ascii nocase
        $s2 = "String.fromCharCode(" ascii nocase
        $s3 = "ActiveXObject(" ascii nocase
        $s4 = ".Sleep(" ascii nocase
    condition:
       ($ex and all of ($s*))
}


rule INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_UserConfig {
    meta:
        author = "ditekSHen"
        description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"
    strings:
        $s1 = "<configSections>" ascii nocase
        $s2 = "<value>77 90" ascii nocase
    condition:
       uint32(0) == 0x6d783f3c and all of them
}

rule INDICATOR_SUSPICIOUS_CSPROJ {
    meta:
        author = "ditekSHen"
        description = "Detects suspicious .CSPROJ files then compiled with msbuild"
    strings:
        $s1 = "ToolsVersion=" ascii
        $s2 = "/developer/msbuild/" ascii
        $x1 = "[DllImport(\"\\x" ascii
        $x2 = "VirtualAlloc(" ascii nocase
        $x3 = "CallWindowProc(" ascii nocase
    condition:
        uint32(0) == 0x6f72503c and (all of ($s*) and 2 of ($x*))
}

rule INDICATOR_SUSPICIOUS_PWS_CaptureScreenshot {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell script with screenshot capture capability"
        score = 65
    strings:
        $encoder = ".ImageCodecInfo]::GetImageEncoders(" ascii nocase
        $capture1 = ".Sendkeys]::SendWait(\"{PrtSc}\")" ascii nocase
        $capture2 = ".Sendkeys]::SendWait('{PrtSc}')" ascii nocase
        $access = ".Clipboard]::GetImage(" ascii nocase
        $save = ".Save(" ascii nocase
    condition:
        $encoder and (1 of ($capture*) and ($access or $save))
}

rule INDICATOR_SUSPICIOUS_PWS_CaptureBrowserPlugins {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell script with browser plugins capture capability"
        score = 60
    strings:
        $s1 = "$env:APPDATA +" ascii nocase
        $s2 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}|mfa\\.[\\w-]{84}" ascii nocase
        $s3 = "\\leveldb" ascii nocase
        $o1 = ".Match(" ascii nocase
        $o2 = ".Contains(" ascii nocase
        $o3 = ".Add(" ascii nocase
    condition:
        2 of ($s*) and 2 of ($o*)
}

rule INDICATOR_SUSPICIOUS_IMG_Embedded_B64_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects images with specific base64 markers and/or embedding (reversed) base64-encoded executables"
        score = 60
    strings:
        $m1 = "<<BASE64_START>>" ascii
        $m2 = "<<BASE64_END>>" ascii
        $m3 = "BASE64_START" ascii
        $m4 = "BASE64_END" ascii
        $m5 = "BASE64-START" ascii
        $m6 = "BASE64-END" ascii
        $m7 = "BASE64START" ascii
        $m8 = "BASE64END" ascii
        $h1 = "TVqQA" ascii
        $h2 = "AQqVT" ascii
    condition:
        (uint32(0) == 0xd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and ((2 of ($m*)) or (1 of ($h*)))
}
