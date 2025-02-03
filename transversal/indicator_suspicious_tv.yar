rule INDICATOR_SUSPICIOUS_IMG_Embedded_Archive : hardened
{
	meta:
		description = "Detects images embedding archives. Observed in TheRat RAT."
		author = "ditekSHen"
		score = 60

	strings:
		$sevenzip1 = { 37 7a bc af 27 1c 00 04 }
		$sevenzip2 = { 37 e4 53 96 c9 db d6 07 }
		$zipwopass = { 50 4b 03 04 14 00 00 00 }
		$zipwipass = { 50 4b 03 04 33 00 01 00 }
		$zippkfile = { 50 4b 03 04 0a 00 02 00 }
		$rarheade1 = { 52 61 72 21 1a 07 01 00 }
		$rarheade2 = { 52 65 74 75 72 6e 2d 50 }
		$rarheade3 = { 52 61 72 21 1a 07 00 cf }
		$mscabinet = { 4d 53 46 54 02 00 01 00 }
		$zlockproe = { 50 4b 03 04 14 00 01 00 }
		$winzip = { 57 69 6E 5A 69 70 }
		$pklite = { 50 4B 4C 49 54 45 }
		$pksfx = { 50 4B 53 70 58 }

	condition:
		( uint32( 0 ) == 0xe0ffd8ff or uint32( 0 ) == 0x474e5089 or uint16( 0 ) == 0x4d42 ) and 1 of them
}

rule INDICATOR_SUSPICIOUS_NTLM_Exfiltration_IPPattern : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects NTLM hashes exfiltration patterns in command line and various file types"
		score = 60

	strings:
		$s1 = /net\suse\s\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s2 = /\/F\s\(\\\\\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s3 = /URL=file:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s4 = /IconFile=\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s5 = /Target=\x22:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s6 = /\/\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s7 = /\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@SSL@\d+\\DavWWWRoot/ ascii wide
		$mso1 = {77 6f 72 64 2f}
		$mso2 = {70 70 74 2f}
		$mso3 = {78 6c 2f}
		$mso4 = {5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c}

	condition:
		(( uint32( 0 ) == 0x46445025 or ( uint16( 0 ) == 0x004c and uint32( 4 ) == 0x00021401 ) or uint32( 0 ) == 0x00010000 or ( uint16( 0 ) == 0x4b50 and 1 of ( $mso* ) ) ) and 1 of ( $s* ) ) or 1 of ( $s* )
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"

	strings:
		$b1 = {3a 3a 57 72 69 74 65 41 6c 6c 42 79 74 65 73 28}
		$b2 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$b3 = {3a 3a 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28}
		$s1 = {2d 6a 6f 69 6e}
		$s2 = {5b 43 68 61 72 5d 24 5f}
		$s3 = {72 65 76 65 72 73 65}
		$s4 = {20 2b 3d 20}
		$e1 = {53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 2e 50 72 6f 63 65 73 73}
		$e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
		$e3 = /-eq\s'\.(exe|dll)'\)/ ascii
		$e4 = /(Get|Start)-(Process|WmiObject)/ ascii

	condition:
		#s4> 10 and ( ( 3 of ( $b* ) ) or ( 1 of ( $b* ) and 2 of ( $s* ) and 1 of ( $e* ) ) or ( 8 of them ) )
}

rule INDICATOR_SUSPICIOUS_PWSH_AsciiEncoding_Pattern : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell scripts containing ASCII encoded files"

	strings:
		$enc1 = {5b 63 68 61 72 5b 5d 5d 28 5b 63 68 61 72 5d 39 37 2e 2e 5b 63 68 61 72 5d 31 32 32 29}
		$enc2 = {5b 63 68 61 72 5b 5d 5d 28 5b 63 68 61 72 5d 36 35 2e 2e 5b 63 68 61 72 5d 39 30 29}
		$s1 = {2e 44 6f 77 6e 6c 6f 61 64 44 61 74 61 28 24}
		$s2 = {5b 4e 65 74 2e 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 5d 3a 3a 54 4c 53 31 32}
		$s3 = {3a 3a 57 72 69 74 65 41 6c 6c 42 79 74 65 73 28 24}
		$s4 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 24}
		$s5 = {47 65 74 2d 52 61 6e 64 6f 6d}

	condition:
		1 of ( $enc* ) and 4 of ( $s* ) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects JavaScript files hex and base64 encoded executables"
		score = 60

	strings:
		$s1 = {2e 53 61 76 65 54 6f 46 69 6c 65}
		$s2 = {2e 52 75 6e}
		$s3 = {41 63 74 69 76 65 58 4f 62 6a 65 63 74}
		$s4 = {66 72 6f 6d 43 68 61 72 43 6f 64 65}
		$s5 = {5c 78 36 36 5c 78 37 32 5c 78 36 46 5c 78 36 44 5c 78 34 33 5c 78 36 38 5c 78 36 31 5c 78 37 32 5c 78 34 33 5c 78 36 46 5c 78 36 34 5c 78 36 35}
		$binary = {5c 78 35 34 5c 78 35 36 5c 78 37 31 5c 78 35 31 5c 78 34 31 5c 78 34 31}
		$pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii

	condition:
		$binary and $pattern and 2 of ( $s* ) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_AMSI_Bypass : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects AMSI bypass pattern"
		score = 65

	strings:
		$v1_1 = {5b 52 65 66 5d 2e 41 73 73 65 6d 62 6c 79 2e 47 65 74 54 79 70 65 28}
		$v1_2 = {53 79 73 74 65 6d 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e 41 6d 73 69 55 74 69 6c 73}
		$v1_3 = {47 65 74 46 69 65 6c 64 28}
		$v1_4 = {61 6d 73 69 49 6e 69 74 46 61 69 6c 65 64}
		$v1_5 = {4e 6f 6e 50 75 62 6c 69 63 2c 53 74 61 74 69 63}
		$v1_6 = {53 65 74 56 61 6c 75 65 28}

	condition:
		5 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell content designed to retrieve passwords from host"
		score = 60

	strings:
		$namespace = {((57 69 6e 64 6f 77 73 2e 53 65 63 75 72 69 74 79 2e 43 72 65 64 65 6e 74 69 61 6c 73 2e 50 61 73 73 77 6f 72 64 56 61 75 6c 74) | (57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 2e 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 56 00 61 00 75 00 6c 00 74 00))}
		$method1 = {((52 65 74 72 69 65 76 65 41 6c 6c 28 29) | (52 00 65 00 74 00 72 00 69 00 65 00 76 00 65 00 41 00 6c 00 6c 00 28 00 29 00))}
		$method2 = {((2e 52 65 74 72 69 65 76 65 50 61 73 73 77 6f 72 64 28 29) | (2e 00 52 00 65 00 74 00 72 00 69 00 65 00 76 00 65 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 28 00 29 00))}

	condition:
		$namespace and 1 of ( $method* )
}

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects files embedding and abusing the finger command for download"

	strings:
		$pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
		$pat2 = {((2d 43 6f 6d 6d 61 6e 64 20 22 66 69 6e 67 65 72) | (2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 66 00 69 00 6e 00 67 00 65 00 72 00))}
		$ne1 = {4e 6d 61 70 20 73 65 72 76 69 63 65 20 64 65 74 65 63 74 69 6f 6e 20 70 72 6f 62 65 20 6c 69 73 74}

	condition:
		not any of ( $ne* ) and any of ( $pat* )
}

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects JS potentially executing WMI queries"
		score = 55

	strings:
		$ex = {2e 45 78 65 63 51 75 65 72 79 28}
		$s1 = {47 65 74 4f 62 6a 65 63 74 28}
		$s2 = {53 74 72 69 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65 28}
		$s3 = {41 63 74 69 76 65 58 4f 62 6a 65 63 74 28}
		$s4 = {2e 53 6c 65 65 70 28}

	condition:
		($ex and all of ( $s* ) )
}

rule INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_UserConfig : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"

	strings:
		$s1 = {3c 63 6f 6e 66 69 67 53 65 63 74 69 6f 6e 73 3e}
		$s2 = {3c 76 61 6c 75 65 3e 37 37 20 39 30}

	condition:
		uint32( 0 ) == 0x6d783f3c and all of them
}

rule INDICATOR_SUSPICIOUS_CSPROJ : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects suspicious .CSPROJ files then compiled with msbuild"

	strings:
		$s1 = {54 6f 6f 6c 73 56 65 72 73 69 6f 6e 3d}
		$s2 = {2f 64 65 76 65 6c 6f 70 65 72 2f 6d 73 62 75 69 6c 64 2f}
		$x1 = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 5c 78}
		$x2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 28}
		$x3 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 28}

	condition:
		uint32( 0 ) == 0x6f72503c and ( all of ( $s* ) and 2 of ( $x* ) )
}

rule INDICATOR_SUSPICIOUS_PWS_CaptureScreenshot : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell script with screenshot capture capability"
		score = 65

	strings:
		$encoder = {2e 49 6d 61 67 65 43 6f 64 65 63 49 6e 66 6f 5d 3a 3a 47 65 74 49 6d 61 67 65 45 6e 63 6f 64 65 72 73 28}
		$capture1 = {2e 53 65 6e 64 6b 65 79 73 5d 3a 3a 53 65 6e 64 57 61 69 74 28 22 7b 50 72 74 53 63 7d 22 29}
		$capture2 = {2e 53 65 6e 64 6b 65 79 73 5d 3a 3a 53 65 6e 64 57 61 69 74 28 27 7b 50 72 74 53 63 7d 27 29}
		$access = {2e 43 6c 69 70 62 6f 61 72 64 5d 3a 3a 47 65 74 49 6d 61 67 65 28}
		$save = {2e 53 61 76 65 28}

	condition:
		$encoder and ( 1 of ( $capture* ) and ( $access or $save ) )
}

rule INDICATOR_SUSPICIOUS_PWS_CaptureBrowserPlugins : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell script with browser plugins capture capability"
		score = 60

	strings:
		$s1 = {24 65 6e 76 3a 41 50 50 44 41 54 41 20 2b}
		$s2 = {5b 5c 77 2d 5d 7b 32 34 7d 5c 2e 5b 5c 77 2d 5d 7b 36 7d 5c 2e 5b 5c 77 2d 5d 7b 32 37 7d 7c 6d 66 61 5c 2e 5b 5c 77 2d 5d 7b 38 34 7d}
		$s3 = {5c 6c 65 76 65 6c 64 62}
		$o1 = {2e 4d 61 74 63 68 28}
		$o2 = {2e 43 6f 6e 74 61 69 6e 73 28}
		$o3 = {2e 41 64 64 28}

	condition:
		2 of ( $s* ) and 2 of ( $o* )
}

rule INDICATOR_SUSPICIOUS_IMG_Embedded_B64_EXE : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects images with specific base64 markers and/or embedding (reversed) base64-encoded executables"
		score = 60

	strings:
		$m1 = {3c 3c 42 41 53 45 36 34 5f 53 54 41 52 54 3e 3e}
		$m2 = {3c 3c 42 41 53 45 36 34 5f 45 4e 44 3e 3e}
		$m3 = {42 41 53 45 36 34 5f 53 54 41 52 54}
		$m4 = {42 41 53 45 36 34 5f 45 4e 44}
		$m5 = {42 41 53 45 36 34 2d 53 54 41 52 54}
		$m6 = {42 41 53 45 36 34 2d 45 4e 44}
		$m7 = {42 41 53 45 36 34 53 54 41 52 54}
		$m8 = {42 41 53 45 36 34 45 4e 44}
		$h1 = {54 56 71 51 41}
		$h2 = {41 51 71 56 54}

	condition:
		( uint32( 0 ) == 0xd8ff or uint32( 0 ) == 0x474e5089 or uint16( 0 ) == 0x4d42 ) and ( ( 2 of ( $m* ) ) or ( 1 of ( $h* ) ) )
}

