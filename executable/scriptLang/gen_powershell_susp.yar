rule WordDoc_PowerShell_URLDownloadToFile : hardened limited
{
	meta:
		description = "Detects Word Document with PowerShell URLDownloadToFile"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/additional-insights-shamoon2/"
		date = "2017-02-23"
		super_rule = 1
		hash1 = "33ee8a57e142e752a9c8960c4f38b5d3ff82bf17ec060e4114f5b15d22aa902e"
		hash2 = "388b26e22f75a723ce69ad820b61dd8b75e260d3c61d74ff21d2073c56ea565d"
		hash3 = "71e584e7e1fb3cf2689f549192fe3a82fd4cd8ee7c42c15d736ebad47b028087"
		id = "f76c5f91-f67c-5754-b771-73383aba4d64"

	strings:
		$w1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 69 63 72 6f 73 6f 66 74 20 46 6f 72 6d 73 20 32 2e 30 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$w2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 69 63 72 6f 73 6f 66 74 20 57 6f 72 64 20 39 37 2d 32 30 30 33 20 44 6f 63 75 6d 65 6e 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$p1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$p2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xcfd0 and 1 of ( $w* ) and all of ( $p* ) )
}

rule Suspicious_PowerShell_Code_1 : FILE hardened limited
{
	meta:
		description = "Detects suspicious PowerShell code"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "Internal Research"
		date = "2017-02-22"
		id = "ec3c3682-d2de-52b7-bb49-b021ddf7f8ac"

	strings:
		$s1 = /$[a-z]=new-object net.webclient/ ascii
		$s2 = /$[a-z].DownloadFile\("http:/ ascii
		$s3 = /IEX $[a-zA-Z]{1,8}.downloadstring\(["']http/ ascii nocase
		$s4 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 70 20 62 79 70 61 73 73 20 2d 45 6e 63}
		$s5 = {2d 77 20 68 69 64 64 65 6e 20 2d 6e 6f 6e 69 20 2d 6e 6f 70 20 2d 63 20 22 69 65 78 28 4e 65 77 2d 4f 62 6a 65 63 74}
		$s6 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 72 65 67 20 61 64 64 20 48 4b 43 55 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e}

	condition:
		1 of them
}

rule Suspicious_PowerShell_WebDownload_1 : HIGHVOL FILE hardened limited
{
	meta:
		description = "Detects suspicious PowerShell code that downloads from web sites"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "Internal Research"
		date = "2017-02-22"
		modified = "2022-07-27"
		nodeepdive = 1
		id = "a763fb82-c840-531b-b631-f282bf035020"

	strings:
		$s1 = {53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 22 68 74 74 70}
		$s2 = {53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70}
		$s3 = {73 79 73 74 65 6d 2e 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 28 27 68 74 74 70}
		$s4 = {73 79 73 74 65 6d 2e 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 28 22 68 74 74 70}
		$s5 = {47 65 74 53 74 72 69 6e 67 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$fp1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4e 75 47 65 74 2e 65 78 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$fp2 = {63 68 6f 63 6f 6c 61 74 65 79 2e 6f 72 67}
		$fp3 = {20 47 45 54 20 2f}
		$fp4 = {20 50 4f 53 54 20 2f}
		$fp5 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 61 6b 61 2e 6d 73 2f 69 6e 73 74 61 6c 6c 61 7a 75 72 65 63 6c 69 77 69 6e 64 6f 77 73 27 2c 20 27 41 7a 75 72 65 43 4c 49 2e 6d 73 69 27 29}
		$fp6 = {20 34 30 34 20}
		$fp7 = {23 20 52 65 6d 6f 74 65 53 53 48 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 53 63 72 69 70 74}
		$fp8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 68 65 6c 70 49 74 65 6d 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$fp9 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 22 68 74 74 70 73 3a 2f 2f 63 6f 64 65 63 6f 76 2e 69 6f 2f 62 61 73 68}

	condition:
		1 of ( $s* ) and not 1 of ( $fp* )
}

rule PowerShell_in_Word_Doc : hardened limited
{
	meta:
		description = "Detects a powershell and bypass keyword in a Word document"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - ME"
		date = "2017-06-27"
		score = 50
		hash1 = "4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905"
		id = "c9d073ff-25c6-5751-92bf-e22ae7cfd5f5"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 4f 77 45 72 53 48 45 4c 6c 2e 45 78 45 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 42 59 50 41 53 53 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xcfd0 and filesize < 1000KB and all of them )
}

rule Susp_PowerShell_Sep17_1 : hardened limited
{
	meta:
		description = "Detects suspicious PowerShell script in combo with VBS or JS "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-30"
		score = 60
		hash1 = "8e28521749165d2d48bfa1eac685c985ac15fc9ca5df177d4efadf9089395c56"
		id = "6d4b9113-173f-5c12-b440-7f1cef9e6ebb"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {2e 52 75 6e 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 63 20 22 22 49 45 58 20}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 77 69 6e 64 6f 77 2e 72 65 73 69 7a 65 54 6f 20 30 2c 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( filesize < 2KB and 1 of them )
}

rule Susp_PowerShell_Sep17_2 : hardened limited
{
	meta:
		description = "Detects suspicious PowerShell script in combo with VBS or JS "
		score = 40
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-30"
		hash1 = "e387f6c7a55b85e0675e3b91e41e5814f5d0ae740b92f26ddabda6d4f69a8ca8"
		id = "e44d1dfc-0858-5248-a57f-efb5c647f4cc"

	strings:
		$x1 = {2e 52 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 20}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 69 6c 65 45 78 69 73 74 73 28 70 61 74 68 20 2b 20 22 5c 2e 2e 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 77 69 6e 64 6f 77 2e 6d 6f 76 65 54 6f 20 2d 34 30 30 30 2c 20 2d 34 30 30 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 20KB and ( ( uint16( 0 ) == 0x733c and 1 of ( $x* ) ) or 2 of them )
}

rule WScript_Shell_PowerShell_Combo : refined hardened limited
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		date = "2018-02-07"
		score = 50
		hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
		id = "265ec471-d9ed-5cb6-a32b-cfa62fccdf64"

	strings:
		$s1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$p1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$p2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$p3 = {5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$fp1 = {43 6f 70 79 72 69 67 68 74 3a 20 4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 2e}

	condition:
		filesize < 400KB and $s1 and 2 of ( $p* ) and not 1 of ( $fp* )
}

rule SUSP_PowerShell_String_K32_RemProcess : hardened limited
{
	meta:
		description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nccgroup/redsnarf"
		date = "2018-03-31"
		hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
		hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"
		id = "ad646e19-b132-5594-bea2-d74e96c06ebb"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 54 68 72 6f 77 20 22 55 6e 61 62 6c 65 20 74 6f 20 61 6c 6c 6f 63 61 74 65 20 6d 65 6d 6f 72 79 20 69 6e 20 74 68 65 20 72 65 6d 6f 74 65 20 70 72 6f 63 65 73 73 20 66 6f 72 20 73 68 65 6c 6c 63 6f 64 65 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 4b 65 72 6e 65 6c 33 32 48 61 6e 64 6c 65 20 3d 20 24 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 2e 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 2e 49 6e 76 6f 6b 65 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {24 52 53 43 41 64 64 72 20 3d 20 24 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 2e 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 2e 49 6e 76 6f 6b 65 28 24 52 65 6d 6f 74 65 50 72 6f 63 48 61 6e 64 6c 65 2c 20 5b 49 6e 74 50 74 72 5d 3a 3a 5a 65 72 6f 2c 20 5b 55 49 6e 74 50 74 72 5d 5b 55 49 6e 74 36 34 5d 24 53 43 4c 65 6e 67 74 68 2c 20 24 57 69 6e 33 32 43 6f 6e 73 74 61 6e 74 73 2e}
		$s7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 66 20 28 24 52 65 6d 6f 74 65 50 72 6f 63 48 61 6e 64 6c 65 20 2d 65 71 20 5b 49 6e 74 50 74 72 5d 3a 3a 5a 65 72 6f 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 66 20 28 28 24 53 75 63 63 65 73 73 20 2d 65 71 20 24 66 61 6c 73 65 29 20 2d 6f 72 20 28 5b 55 49 6e 74 36 34 5d 24 4e 75 6d 42 79 74 65 73 57 72 69 74 74 65 6e 20 2d 6e 65 20 5b 55 49 6e 74 36 34 5d 24 53 43 4c 65 6e 67 74 68 29 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s9 = {24 53 75 63 63 65 73 73 20 3d 20 24 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 2e 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 2e 49 6e 76 6f 6b 65 28 24 52 65 6d 6f 74 65 50 72 6f 63 48 61 6e 64 6c 65 2c 20 24 52 53 43 41 64 64 72 2c 20 24 53 43 50 53 4d 65 6d 4f 72 69 67 69 6e 61 6c 2c 20 5b 55 49 6e 74 50 74 72 5d 5b 55 49 6e 74 36 34 5d 24 53 43 4c 65 6e 67 74 68 2c 20}
		$s15 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 54 79 70 65 42 75 69 6c 64 65 72 2e 44 65 66 69 6e 65 46 69 65 6c 64 28 27 43 68 61 72 61 63 74 65 72 69 73 74 69 63 73 27 2c 20 5b 55 49 6e 74 33 32 5d 2c 20 27 50 75 62 6c 69 63 27 29 20 7c 20 4f 75 74 2d 4e 75 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x7566 and filesize < 6000KB and 1 of them
}

rule PowerShell_JAB_B64 : hardened limited
{
	meta:
		description = "Detects base464 encoded $ sign at the beginning of a string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
		date = "2018-04-02"
		score = 60
		id = "c18fa17b-aaa5-5a89-bc25-3cc51b5af103"

	strings:
		$s1 = {((28 27 4a 41 42) | (28 00 27 00 4a 00 41 00 42 00))}
		$s2 = {70 6f 77 65 72 73 68 65 6c 6c}

	condition:
		filesize < 30KB and all of them
}

rule SUSP_PS1_FromBase64String_Content_Indicator : FILE hardened
{
	meta:
		description = "Detects suspicious base64 encoded PowerShell expressions"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639"
		date = "2020-01-25"
		id = "326c83ff-5d21-508f-b935-03ccdab6efa7"

	strings:
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 48 34 73) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 48 00 34 00 73 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 54 56 71) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 54 00 56 00 71 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 55 45 73) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 55 00 45 00 73 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 4a 41 42) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 4a 00 41 00 42 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 53 55 56 59) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 53 00 55 00 56 00 59 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 53 51 42 46 41 46) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 53 00 51 00 42 00 46 00 41 00 46 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 53 51 42 75 41 48) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 53 00 51 00 42 00 75 00 41 00 48 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 50 41 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 50 00 41 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 63 77 42 68 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 63 00 77 00 42 00 68 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 61 57 56 34) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 61 00 57 00 56 00 34 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 61 51 42 6c 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 61 00 51 00 42 00 6c 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 52 32 56 30) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 52 00 32 00 56 00 30 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 64 6d 46 79) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 64 00 6d 00 46 00 79 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 64 67 42 68 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 64 00 67 00 42 00 68 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 64 58 4e 70 62 6d) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 64 00 58 00 4e 00 70 00 62 00 6d 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 48 34 73 49 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 48 00 34 00 73 00 49 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 59 32 31 6b) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 59 00 32 00 31 00 6b 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 51 7a 70 63) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 51 00 7a 00 70 00 63 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 59 7a 70 63) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 59 00 7a 00 70 00 63 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 49 41 42) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 49 00 41 00 42 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 48 34 73) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 48 00 34 00 73 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 54 56 71) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 54 00 56 00 71 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 55 45 73) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 55 00 45 00 73 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 4a 41 42) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 4a 00 41 00 42 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 53 55 56 59) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 53 00 55 00 56 00 59 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 53 51 42 46 41 46) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 53 00 51 00 42 00 46 00 41 00 46 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 53 51 42 75 41 48) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 53 00 51 00 42 00 75 00 41 00 48 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 50 41 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 50 00 41 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 63 77 42 68 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 63 00 77 00 42 00 68 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 61 57 56 34) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 61 00 57 00 56 00 34 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 61 51 42 6c 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 61 00 51 00 42 00 6c 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 52 32 56 30) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 52 00 32 00 56 00 30 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 64 6d 46 79) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 64 00 6d 00 46 00 79 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 64 67 42 68 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 64 00 67 00 42 00 68 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 64 58 4e 70 62 6d) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 64 00 58 00 4e 00 70 00 62 00 6d 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 48 34 73 49 41) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 48 00 34 00 73 00 49 00 41 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 59 32 31 6b) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 59 00 32 00 31 00 6b 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 51 7a 70 63) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 51 00 7a 00 70 00 63 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 59 7a 70 63) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 59 00 7a 00 70 00 63 00))}
		$ = {((3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 49 41 42) | (3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 49 00 41 00 42 00))}

	condition:
		filesize < 5000KB and 1 of them
}

