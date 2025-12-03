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

