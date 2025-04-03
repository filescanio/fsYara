rule WEBSHELL_ASP_Embedded_Mar21_1 : hardened limited
{
	meta:
		description = "Detects ASP webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-03-05"
		score = 85
		id = "7cf7db9d-8f8a-51db-a0e6-84748e8f9e1f"

	strings:
		$s1 = {3c 73 63 72 69 70 74 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e}
		$s2 = {6e 65 77 20 53 79 73 74 65 6d 2e 49 4f 2e 53 74 72 65 61 6d 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b}
		$s3 = {2e 57 72 69 74 65 28 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b}

	condition:
		filesize < 100KB and all of them
}

rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1 : hardened limited
{
	meta:
		description = "Detects HAFNIUM SecChecker webshell"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/markus_neis/status/1367794681237667840"
		date = "2021-03-05"
		hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
		id = "73db3d78-7ece-53be-9efb-d19801993d5e"

	strings:
		$x1 = {3c 25 69 66 28 53 79 73 74 65 6d 2e 49 4f 2e 46 69 6c 65 2e 45 78 69 73 74 73 28 22 63 3a 5c 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 20 28 78 38 36 29 5c 5c 66 69 72 65 65 79 65 5c 5c 78 61 67 74 2e 65 78 65}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 63 73 66 61 6c 63 6f 6e 73 65 72 76 69 63 65 2e 65 78 65 22 29 29 7b 52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 20 22 33 22 29 3b 7d 25 3e 3c 2f 68 65 61 64 3e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x253c and filesize < 1KB and 1 of them or 2 of them
}

rule APT_HAFNIUM_Forensic_Artefacts_Mar21_1 : hardened loosened limited
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		date = "2021-03-02"
		id = "872822b0-34d9-5ae4-a532-6a8786494fa9"

	strings:
		$s1 = {((6c 73 61 73 73 2e 65 78 65 20 43 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 6c 73 61 73 73) | (6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 20 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 6c 00 73 00 61 00 73 00 73 00))}
		$s2 = {((63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 69 74 2e 7a 69 70) | (63 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 69 00 74 00 2e 00 7a 00 69 00 70 00))}
		$s3 = {((70 6f 77 65 72 63 61 74 2e 70 73 31 27 29 3b 20 70 6f 77 65 72 63 61 74 20 2d 63) | (70 00 6f 00 77 00 65 00 72 00 63 00 61 00 74 00 2e 00 70 00 73 00 31 00 27 00 29 00 3b 00 20 00 70 00 6f 00 77 00 65 00 72 00 63 00 61 00 74 00 20 00 2d 00 63 00))}

	condition:
		1 of them
}

rule APT_WEBSHELL_HAFNIUM_Chopper_WebShell : APT Hafnium WebShell hardened limited
{
	meta:
		description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
		author = "Markus Neis,Swisscom"
		date = "2021-03-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		id = "25dcf166-4aea-5680-b161-c5fc8d74b987"

	strings:
		$x1 = {72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e}
		$s1 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64 28 29 7b 65 76 61 6c 28 52 65 71 75 65 73 74}
		$s2 = {70 72 6f 74 65 63 74 65 64 20 76 6f 69 64 20 50 61 67 65 5f 4c 6f 61 64 28 6f 62 6a 65 63 74 20 73 65 6e 64 65 72 2c 20 45 76 65 6e 74 41 72 67 73 20 65 29 7b 53 79 73 74 65 6d 2e 49 4f 2e 53 74 72 65 61 6d 57 72 69 74 65 72 20 73 77 20 3d 20 6e 65 77 20 53 79 73 74 65 6d 2e 49 4f 2e 53 74 72 65 61 6d 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b 22 70 22 5d 20 2c 20 66 61 6c 73 65 2c 20 45 6e 63 6f 64 69 6e 67 2e 44 65 66 61 75 6c 74 29 3b 73 77 2e 57 72 69 74 65 28 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b 22 66 22 5d 29 3b}
		$s3 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 20 66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64 28 29 7b 65 76 61 6c 20 28 52 65 71 75 65 73 74 5b 22}

	condition:
		filesize < 10KB and $x1 and 1 of ( $s* )
}

rule APT_WEBSHELL_Tiny_WebShell : APT Hafnium WebShell hardened
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		date = "2021-03-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"

	strings:
		$x1 = {3c 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 4a 73 63 72 69 70 74 22 20 44 65 62 75 67 3d 74 72 75 65 25 3e}
		$s1 = {3d 52 65 71 75 65 73 74 2e 46 6f 72 6d 28 22}
		$s2 = {65 76 61 6c 28}

	condition:
		filesize < 300 and all of ( $s* ) and $x1
}

rule HKTL_PS1_PowerCat_Mar21 : hardened limited
{
	meta:
		description = "Detects PowerCat hacktool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/besimorhino/powercat"
		date = "2021-03-02"
		hash1 = "c55672b5d2963969abe045fe75db52069d0300691d4f1f5923afeadf5353b9d2"
		id = "ae3963e8-2fe9-5bc3-bf72-95f136622832"
		score = 75

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 70 6f 77 65 72 63 61 74 20 2d 6c 20 2d 70 20 38 30 30 30 20 2d 72 20 64 6e 73 3a 31 30 2e 31 2e 31 2e 31 3a 35 33 3a 63 32 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 74 72 79 7b 5b 62 79 74 65 5b 5d 5d 24 52 65 74 75 72 6e 65 64 44 61 74 61 20 3d 20 24 45 6e 63 6f 64 69 6e 67 2e 47 65 74 42 79 74 65 73 28 28 49 45 58 20 24 43 6f 6d 6d 61 6e 64 54 6f 45 78 65 63 75 74 65 20 32 3e 26 31 20 7c 20 4f 75 74 2d 53 74 72 69 6e 67 29 29 7d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {52 65 74 75 72 6e 69 6e 67 20 45 6e 63 6f 64 65 64 20 50 61 79 6c 6f 61 64 2e 2e 2e}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 43 6f 6d 6d 61 6e 64 54 6f 45 78 65 63 75 74 65 20 3d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {5b 61 6c 69 61 73 28 22 45 78 65 63 75 74 65 22 29 5d 5b 73 74 72 69 6e 67 5d 24 65 3d 22 22 2c}

	condition:
		uint16( 0 ) == 0x7566 and filesize < 200KB and 1 of ( $x* ) or 3 of them
}

rule HKTL_Nishang_PS1_Invoke_PowerShellTcpOneLine : hardened
{
	meta:
		description = "Detects PowerShell Oneliner in Nishang's repository"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
		date = "2021-03-03"
		hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"
		id = "0218ebbd-2dbe-5838-ab53-1e78e3f97b9e"

	strings:
		$s1 = {((3d 28 5b 74 65 78 74 2e 65 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 29 2e 47 65 74 42 79 74 65 73 28 28 69 65 78 20 24) | (3d 00 28 00 5b 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 41 00 53 00 43 00 49 00 49 00 29 00 2e 00 47 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00 28 00 28 00 69 00 65 00 78 00 20 00 24 00))}
		$s2 = {((2e 47 65 74 53 74 72 65 61 6d 28 29 3b 5b 62 79 74 65 5b 5d 5d 24) | (2e 00 47 00 65 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00 28 00 29 00 3b 00 5b 00 62 00 79 00 74 00 65 00 5b 00 5d 00 5d 00 24 00))}
		$s3 = {((4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 53 6f 63 6b 65 74 73 2e 54 43 50 43 6c 69 65 6e 74 28 27) | (4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 54 00 43 00 50 00 43 00 6c 00 69 00 65 00 6e 00 74 00 28 00 27 00))}

	condition:
		all of them
}

rule WEBSHELL_ASPX_SimpleSeeSharp : Webshell Unclassified hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-03-01"
		description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
		hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"

	strings:
		$header = {3c 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 43 23 22 20 25 3e}
		$body = {3c 25 20 48 74 74 70 50 6f 73 74 65 64 46 69 6c 65 20 74 68 69 73 46 69 6c 65 20 3d 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 5b 30 5d 3b 74 68 69 73 46 69 6c 65 2e 53 61 76 65 41 73 28 50 61 74 68 2e 43 6f 6d 62 69 6e 65}

	condition:
		$header at 0 and $body and filesize < 1KB
}

rule WEBSHELL_ASPX_reGeorgTunnel : Webshell Commodity hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-03-01"
		description = "variation on reGeorgtunnel"
		hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
		reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
		id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"

	strings:
		$s1 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73}
		$s2 = {53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 44 65 66 61 75 6c 74 2e 47 65 74 53 74 72 69 6e 67 28 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 53 74 72 54 72 28 52 65 71 75 65 73 74 2e 48 65 61 64 65 72 73 2e 47 65 74}
		$t1 = {2e 53 70 6c 69 74 28 27 7c 27 29}
		$t2 = {52 65 71 75 65 73 74 2e 48 65 61 64 65 72 73 2e 47 65 74}
		$t3 = {2e 53 75 62 73 74 72 69 6e 67 28}
		$t4 = {6e 65 77 20 53 6f 63 6b 65 74 28}
		$t5 = {49 50 41 64 64 72 65 73 73 20 69 70 3b}

	condition:
		all of ( $s* ) or all of ( $t* )
}

rule WEBSHELL_ASPX_SportsBall : hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-03-01"
		description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
		hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"

	strings:
		$uniq1 = {48 74 74 70 43 6f 6f 6b 69 65 20 6e 65 77 63 6f 6f 6b 20 3d 20 6e 65 77 20 48 74 74 70 43 6f 6f 6b 69 65 28 22 66 71 72 73 70 74 22 2c 20 48 74 74 70 43 6f 6e 74 65 78 74 2e 43 75 72 72 65 6e 74 2e 52 65 71 75 65 73 74 2e 46 6f 72 6d}
		$uniq2 = {5a 4e 32 61 44 41 42 34 72 58 73 73 7a 45 76 43 4c 72 7a 67 63 76 51 34 6f 69 35 4a 31 54 75 69 52 55 4c 6c 51 62 59 77 6c 64 45 3d}
		$var1 = {52 65 73 75 6c 74 2e 49 6e 6e 65 72 54 65 78 74 20 3d 20 73 74 72 69 6e 67 2e 45 6d 70 74 79 3b}
		$var2 = {6e 65 77 63 6f 6f 6b 2e 45 78 70 69 72 65 73 20 3d 20 44 61 74 65 54 69 6d 65 2e 4e 6f 77 2e 41 64 64 44 61 79 73 28}
		$var3 = {53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 2e 50 72 6f 63 65 73 73 20 70 72 6f 63 65 73 73 20 3d 20 6e 65 77 20 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 2e 50 72 6f 63 65 73 73 28 29 3b}
		$var4 = {70 72 6f 63 65 73 73 2e 53 74 61 6e 64 61 72 64 49 6e 70 75 74 2e 57 72 69 74 65 4c 69 6e 65 28 48 74 74 70 43 6f 6e 74 65 78 74 2e 43 75 72 72 65 6e 74 2e 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b 22}
		$var5 = {65 6c 73 65 20 69 66 20 28 21 73 74 72 69 6e 67 2e 49 73 4e 75 6c 6c 4f 72 45 6d 70 74 79 28 48 74 74 70 43 6f 6e 74 65 78 74 2e 43 75 72 72 65 6e 74 2e 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b 22}
		$var6 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 22 73 75 62 6d 69 74 22 20 76 61 6c 75 65 3d 22 55 70 6c 6f 61 64 22 20 2f 3e}

	condition:
		any of ( $uniq* ) or all of ( $var* )
}

rule WEBSHELL_CVE_2021_27065_Webshells : hardened limited
{
	meta:
		description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
		author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
		date = "2021-03-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		id = "27677f35-24a3-59cc-a3ad-b83884128da7"

	strings:
		$script1 = {((73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65) | (73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00))}
		$script2 = {((70 61 67 65 20 6c 61 6e 67 75 61 67 65) | (70 00 61 00 67 00 65 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00))}
		$script3 = {((72 75 6e 61 74 3d 22 73 65 72 76 65 72 22) | (72 00 75 00 6e 00 61 00 74 00 3d 00 22 00 73 00 65 00 72 00 76 00 65 00 72 00 22 00))}
		$script4 = {((2f 73 63 72 69 70 74) | (2f 00 73 00 63 00 72 00 69 00 70 00 74 00))}
		$externalurl = {((65 78 74 65 72 6e 61 6c 75 72 6c) | (65 00 78 00 74 00 65 00 72 00 6e 00 61 00 6c 00 75 00 72 00 6c 00))}
		$internalurl = {((69 6e 74 65 72 6e 61 6c 75 72 6c) | (69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 75 00 72 00 6c 00))}
		$internalauthenticationmethods = {((69 6e 74 65 72 6e 61 6c 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 6d 65 74 68 6f 64 73) | (69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 61 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 6d 00 65 00 74 00 68 00 6f 00 64 00 73 00))}
		$extendedprotectiontokenchecking = {((65 78 74 65 6e 64 65 64 70 72 6f 74 65 63 74 69 6f 6e 74 6f 6b 65 6e 63 68 65 63 6b 69 6e 67) | (65 00 78 00 74 00 65 00 6e 00 64 00 65 00 64 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 74 00 6f 00 6b 00 65 00 6e 00 63 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00))}

	condition:
		filesize < 50KB and any of ( $script* ) and ( $externalurl or $internalurl ) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3 : hardened
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		date = "2021-03-07"
		score = 85
		id = "9c2ba123-63c4-5e9c-a08f-bd9db3304691"

	strings:
		$s1 = {((72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 76 6f 69 64 20 50 61 67 65 5f 4c 6f 61 64 28 6f 62 6a 65 63 74) | (72 00 75 00 6e 00 61 00 74 00 3d 00 22 00 73 00 65 00 72 00 76 00 65 00 72 00 22 00 3e 00 76 00 6f 00 69 00 64 00 20 00 50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00 28 00 6f 00 62 00 6a 00 65 00 63 00 74 00))}
		$s2 = {((52 65 71 75 65 73 74 2e 46 69 6c 65 73 5b 30 5d 2e 53 61 76 65 41 73 28 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 46 00 69 00 6c 00 65 00 73 00 5b 00 30 00 5d 00 2e 00 53 00 61 00 76 00 65 00 41 00 73 00 28 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 4d 00 61 00 70 00 50 00 61 00 74 00 68 00 28 00))}

	condition:
		filesize < 50KB and all of them
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4 : hardened limited
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		date = "2021-03-07"
		score = 85
		id = "93f5b682-642d-5edf-84a9-296bf12cd72b"

	strings:
		$s1 = {((3c 25 40 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 4a 73 63 72 69 70 74 22 25 3e) | (3c 00 25 00 40 00 50 00 61 00 67 00 65 00 20 00 4c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 4a 00 73 00 63 00 72 00 69 00 70 00 74 00 22 00 25 00 3e 00))}
		$s2 = {((2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28) | (2e 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00))}
		$s3 = {((65 76 61 6c 28 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e) | (65 00 76 00 61 00 6c 00 28 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 2e 00))}

	condition:
		filesize < 850 and all of them
}

rule APT_HAFNIUM_ForensicArtefacts_WER_Mar21_1 : hardened limited
{
	meta:
		description = "Detects a Windows Error Report (WER) that indicates and exploitation attempt of the Exchange server as described in CVE-2021-26857 after the corresponding patches have been applied. WER files won't be written upon successful exploitation before applying the patch. Therefore, this indicates an unsuccessful attempt."
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1368471533048446976"
		date = "2021-03-07"
		score = 40
		id = "06771101-10ce-5d6b-99f7-a321aade7f69"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 69 00 6e 00 65 00 74 00 73 00 72 00 76 00 5c 00 77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s7 = {2e 00 56 00 61 00 6c 00 75 00 65 00 3d 00 77 00 33 00 77 00 70 00 23 00 4d 00 53 00 45 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 45 00 43 00 50 00 41 00 70 00 70 00 50 00 6f 00 6f 00 6c 00}

	condition:
		uint16( 0 ) == 0xfeff and filesize < 8KB and all of them
}

rule APT_HAFNIUM_ForensicArtefacts_Cab_Recon_Mar21_1 : hardened limited
{
	meta:
		description = "Detects suspicious CAB files used by HAFNIUM for recon activity"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3?u=dstepanic"
		date = "2021-03-11"
		score = 70
		id = "b0caf9d9-af0a-5181-85e4-6091cd6699e3"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 70 2e 74 78 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 61 72 70 2e 74 78 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 79 73 74 65 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 63 75 72 69 74 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint32( 0 ) == 0x4643534d and filesize < 10000KB and ( $s1 in ( 0 .. 200 ) and $s2 in ( 0 .. 200 ) and $s3 in ( 0 .. 200 ) and $s4 in ( 0 .. 200 ) )
}

rule WEBSHELL_Compiled_Webshell_Mar2021_1 : hardened loosened limited
{
	meta:
		description = "Triggers on temporary pe files containing strings commonly used in webshells."
		author = "Bundesamt fuer Sicherheit in der Informationstechnik"
		date = "2021-03-05"
		modified = "2021-03-12"
		reference = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/Vorfaelle/Exchange-Schwachstellen-2021/MSExchange_Schwachstelle_Detektion_Reaktion.pdf"
		id = "9336bd2c-791c-5c3e-9733-724a6a23864a"

	strings:
		$x1 = /App_Web_[a-zA-Z0-9]{7,8}.dll/ ascii wide fullword
		$a1 = {((7e 2f 61 73 70 6e 65 74 5f 63 6c 69 65 6e 74 2f) | (7e 00 2f 00 61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2f 00))}
		$a2 = {((7e 2f 61 75 74 68 2f) | (7e 00 2f 00 61 00 75 00 74 00 68 00 2f 00))}
		$b1 = {((4a 53 63 72 69 70 74 45 76 61 6c 75 61 74 65) | (4a 00 53 00 63 00 72 00 69 00 70 00 74 00 45 00 76 00 61 00 6c 00 75 00 61 00 74 00 65 00))}
		$c1 = {((67 65 74 5f 52 65 71 75 65 73 74) | (67 00 65 00 74 00 5f 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$c2 = {((67 65 74 5f 46 69 6c 65 73) | (67 00 65 00 74 00 5f 00 46 00 69 00 6c 00 65 00 73 00))}
		$c3 = {((67 65 74 5f 43 6f 75 6e 74) | (67 00 65 00 74 00 5f 00 43 00 6f 00 75 00 6e 00 74 00))}
		$c4 = {((67 65 74 5f 49 74 65 6d) | (67 00 65 00 74 00 5f 00 49 00 74 00 65 00 6d 00))}
		$c5 = {((67 65 74 5f 53 65 72 76 65 72) | (67 00 65 00 74 00 5f 00 53 00 65 00 72 00 76 00 65 00 72 00))}

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 5KB and filesize < 40KB and all of ( $x* ) and 1 of ( $a* ) and ( all of ( $b* ) or all of ( $c* ) )
}

rule APT_MAL_ASP_DLL_HAFNIUM_Mar21_1 : hardened limited
{
	meta:
		description = "Detects HAFNIUM compiled ASP.NET DLLs dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		date = "2021-03-05"
		score = 65
		hash1 = "097f5f700c000a13b91855beb61a931d34fb0abb738a110368f525e25c5bc738"
		hash2 = "15744e767cbaa9b37ff7bb5c036dda9b653fc54fc9a96fe73fbd639150b3daa3"
		hash3 = "52ae4de2e3f0ef7fe27c699cb60d41129a3acd4a62be60accc85d88c296e1ddb"
		hash4 = "5f0480035ee23a12302c88be10e54bf3adbcf271a4bb1106d4975a28234d3af8"
		hash5 = "6243fd2826c528ee329599153355fd00153dee611ca33ec17effcf00205a6e4e"
		hash6 = "ebf6799bb86f0da2b05e66a0fe5a9b42df6dac848f4b951b2ed7b7a4866f19ef"
		id = "68b8252e-a07d-5507-b556-a4d473f98157"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 61 67 65 5f 4c 6f 61 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$sc1 = { 20 00 3A 00 20 00 68 00 74 00 74 00 70 00 3A 00
               2F 00 2F 00 (66|67) 00 2F 00 00 89 A3 0D 00 0A 00 }
		$op1 = { 00 43 00 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f }
		$op2 = { 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f 00 61 00 }
		$op3 = { 01 0e 0e 05 20 01 01 11 79 04 07 01 12 2d 04 07 01 12 31 02 }
		$op4 = { 5e 00 03 00 bc 22 00 00 00 00 01 00 85 03 2b 00 03 00 cc }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and all of ( $s* ) or all of ( $op* )
}

rule WEBSHELL_HAFNIUM_CISA_10328929_01 : trojan webshell exploit CVE_2021_27065 hardened
{
	meta:
		author = "CISA Code & Media Analysis"
		date = "2021-03-17"
		description = "Detects CVE-2021-27065 Webshellz"
		hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
		reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
		id = "81916396-8aaa-5045-b31c-4bcce8d295a5"

	strings:
		$s0 = { 65 76 61 6C 28 52 65 71 75 65 73 74 5B 22 [1-32] 5D 2C 22 75 6E 73 61 66 65 22 29 }
		$s1 = { 65 76 61 6C 28 }
		$s2 = { 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-36] 5D 29 29 2C 22 75 6E 73 61 66 65 22 29 }
		$s3 = { 49 4F 2E 53 74 72 65 61 6D 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
		$s4 = { 57 72 69 74 65 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }

	condition:
		$s0 or ( $s1 and $s2 ) or ( $s3 and $s4 )
}

rule WEBSHELL_HAFNIUM_CISA_10328929_02 : trojan webshell exploit CVE_2021_27065 hardened
{
	meta:
		author = "CISA Code & Media Analysis"
		date = "2021-03-17"
		description = "Detects CVE-2021-27065 Exchange OAB VD MOD"
		hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
		reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
		id = "34a89a6e-fa8a-5c64-a325-30202e20b30f"

	strings:
		$s0 = { 4F 66 66 6C 69 6E 65 41 64 64 72 65 73 73 42 6F 6F 6B 73 }
		$s1 = { 3A 20 68 74 74 70 3A 2F 2F [1] 2F }
		$s2 = { 45 78 74 65 72 6E 61 6C 55 72 6C 20 20 20 20 }

	condition:
		$s0 and $s1 and $s2
}

rule WEBSHELL_ASPX_FileExplorer_Mar21_1 : hardened
{
	meta:
		description = "Detects Chopper like ASPX Webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-03-31"
		score = 80
		hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
		id = "edcaa2a8-6fea-584e-90c2-307a2dfc9f7f"

	strings:
		$x1 = {3c 73 70 61 6e 20 73 74 79 6c 65 3d 22 62 61 63 6b 67 72 6f 75 6e 64 2d 63 6f 6c 6f 72 3a 20 23 37 37 38 38 39 39 3b 20 63 6f 6c 6f 72 3a 20 23 66 66 66 3b 20 70 61 64 64 69 6e 67 3a 20 35 70 78 3b 20 63 75 72 73 6f 72 3a 20 70 6f 69 6e 74 65 72 22 20 6f 6e 63 6c 69 63 6b 3d}
		$xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64
               20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20
               49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72
               20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73
               73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74
               42 6F 78 20 49 44 3D }
		$xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C
               3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ??
               ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20
               6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62
               65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46
               69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61
               62 65 6C 3E 3C 25 2D 2D }
		$r1 = {28 52 65 71 75 65 73 74 2e 46 6f 72 6d 5b}
		$s1 = {2e 54 65 78 74 20 2b 20 22 20 43 72 65 61 74 65 64 21 22 3b}
		$s2 = {44 72 69 76 65 49 6e 66 6f 2e 47 65 74 44 72 69 76 65 73 28 29}
		$s3 = {45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 73 74 72 2e 52 65 70 6c 61 63 65 28}
		$s4 = {65 6e 63 6f 64 65 55 52 49 43 6f 6d 70 6f 6e 65 6e 74 28 62 74 6f 61 28 53 74 72 69 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65 2e 61 70 70 6c 79 28 6e 75 6c 6c 2c 20 6e 65 77 20 55 69 6e 74 38 41 72 72 61 79 28 62 79 74 65 73 29 29 29 29 3b 3b}

	condition:
		uint16( 0 ) == 0x253c and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) or 4 of them
}

rule WEBSHELL_ASPX_Chopper_Like_Mar21_1 : hardened
{
	meta:
		description = "Detects Chopper like ASPX Webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-03-31"
		score = 85
		hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
		id = "a4dc1880-865f-5e20-89a2-3a642c453ef9"

	strings:
		$s1 = {68 74 74 70 3a 2f 2f 66 2f 3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 76 61 72 20 5f 30 78}
		$s2 = {29 29 3b 66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64 28 29 7b 76 61 72 20 5f 30 78}
		$s3 = {3b 65 76 61 6c 28 52 65 71 75 65 73 74 5b 5f 30 78}
		$s4 = {27 2c 27 6f 72 61 6e 67 65 27 2c 27 75 6e 73 61 66 65 27 2c 27}

	condition:
		filesize < 3KB and 1 of them or 2 of them
}

