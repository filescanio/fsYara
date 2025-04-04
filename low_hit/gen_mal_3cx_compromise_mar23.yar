import "pe"

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 : hardened
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise"
		author = "X__Junior, Florian Roth (Nextron Systems)"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		date = "2023-03-29"
		modified = "2023-04-20"
		score = 85
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"
		id = "a6ea3299-fde5-5206-b5db-eb3a3f5944d9"

	strings:
		$opa1 = { 4C 89 F1 4C 89 EA 41 B8 40 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 F0 FF 15 ?? ?? ?? ?? 4C 8D 4C 24 ?? 45 8B 01 4C 89 F1 4C 89 EA FF 15 }
		$opa2 = { 48 C7 44 24 ?? 00 00 00 00 4C 8D 7C 24 ?? 48 89 F9 48 89 C2 41 89 E8 4D 89 F9 FF 15 ?? ?? ?? ?? 41 83 3F 00 0F 84 ?? ?? ?? ?? 0F B7 03 3D 4D 5A 00 00}
		$opa3 = { 41 80 7C 00 ?? FE 75 ?? 41 80 7C 00 ?? ED 75 ?? 41 80 7C 00 ?? FA 75 ?? 41 80 3C 00 CE}
		$opa4 = { 44 0F B6 CD 46 8A 8C 0C ?? ?? ?? ?? 45 30 0C 0E 48 FF C1}
		$opb1 = { 41 B8 40 00 00 00 49 8B D5 49 8B CC FF 15 ?? ?? ?? ?? 85 C0 74 ?? 41 FF D4 44 8B 45 ?? 4C 8D 4D ?? 49 8B D5 49 8B CC FF 15 }
		$opb2 = { 44 8B C3 48 89 44 24 ?? 48 8B 5C 24 ?? 4C 8D 4D ?? 48 8B CB 48 89 74 24 ?? 48 8B D0 4C 8B F8 FF 15 }
		$opb3 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }
		$opb4 = { 49 63 C1 44 0F B6 44 05 ?? 44 88 5C 05 ?? 44 88 02 0F B6 54 05 ?? 49 03 D0 0F B6 C2 0F B6 54 05 ?? 41 30 12}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5MB and pe.characteristics & pe.DLL and ( 2 of ( $opa* ) or 2 of ( $opb* ) )
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_2 : hardened limited
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/dan__mayer/status/1641170769194672128?s=20"
		date = "2023-03-29"
		score = 80
		hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
		id = "bf3597ff-d62b-5d21-9c9b-e46e685284cf"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 49 00 63 00 6f 00 6e 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 73 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 69 00 63 00 6f 00 6e 00 25 00 64 00 2e 00 69 00 63 00 6f 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 49 00 63 00 6f 00 6e 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 69 00 63 00 6f 00 6e 00 25 00 64 00 2e 00 69 00 63 00 6f 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5f 5f 74 75 74 6d 63 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op1 = { 2d ee a1 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 46 a0 00 00 44 8b 05 7f a2 00 00 e8 0a 0e 00 00 }
		$op4 = { 4c 8d 5c 24 71 0f 57 c0 48 89 44 24 60 89 44 24 68 41 b9 15 cd 5b 07 0f 11 44 24 70 b8 b1 68 de 3a 41 ba a4 7b 93 02 }
		$op5 = { f7 f3 03 d5 69 ca e8 03 00 00 ff 15 c9 0a 02 00 48 8d 44 24 30 45 33 c0 4c 8d 4c 24 38 48 89 44 24 20 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 3 of them or 5 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_3 : hardened
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
		author = "Florian Roth , X__Junior (Nextron Systems)"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		date = "2023-03-29"
		score = 80
		hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
		id = "d2d361b6-8485-57eb-b6eb-88785f42e93e"

	strings:
		$opa1 = { 41 81 C0 ?? ?? ?? ?? 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1 41 69 D0 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 ?? ?? ?? ?? 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 }
		$opa2 = { 8B C8 41 69 D1 ?? ?? ?? ?? C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 4C 0F AF CF 44 69 C2 ?? ?? ?? ?? 4C 03 C9 45 8B D1 4C 0F AF D7}
		$opb1 = { 45 33 C9 48 89 6C 24 ?? 48 8D 44 24 ?? 48 89 6C 24 ?? 8B D3 48 89 B4 24 ?? ?? ?? ?? 48 89 44 24 ?? 45 8D 41 ?? FF 15 }
		$opb2 = { 44 8B 0F 45 8B C6 48 8B 4D ?? 49 8B D7 44 89 64 24 ?? 48 89 7C 24 ?? 44 89 4C 24 ?? 4C 8D 4D ?? 48 89 44 24 ?? 44 89 64 24 ?? 4C 89 64 24 ?? FF 15}
		$opb3 = { 48 FF C2 66 44 39 2C 56 75 ?? 4C 8D 4C 24 ?? 45 33 C0 48 8B CE FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 44 0F B7 44 24 ?? 33 F6 48 8B 54 24 ?? 45 33 C9 48 8B 0B 48 89 74 24 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 89 74 24 ?? FF 15 }
		$opb4 = { 33 C0 48 8D 6B ?? 4C 8D 4C 24 ?? 89 44 24 ?? BA ?? ?? ?? ?? 48 89 44 24 ?? 48 8B CD 89 44 24 ?? 44 8D 40 ?? 8B F8 FF 15}

	condition:
		( all of ( $opa* ) ) or ( 1 of ( $opa* ) and 1 of ( $opb* ) ) or ( 3 of ( $opb* ) )
}

rule SUSP_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 : hardened
{
	meta:
		description = "Detects marker found in malicious DLLs related to 3CX compromise"
		author = "X__Junior, Florian Roth (Nextron Systems)"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		date = "2023-03-29"
		modified = "2023-04-20"
		score = 75
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"
		id = "9fc6eb94-d02f-5bcd-9f55-b6c6a8301b4f"

	strings:
		$opx1 = { 41 80 7C 00 FD FE 75 ?? 41 80 7C 00 FE ED 75 ?? 41 80 7C 00 FF FA 75 ?? 41 80 3C 00 CE }
		$opx2 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }

	condition:
		1 of them
}

rule APT_SUSP_NK_3CX_RC4_Key_Mar23_1 : hardened
{
	meta:
		description = "Detects RC4 key used in 3CX binaries known to be malicious"
		author = "Florian Roth (Nextron Systems)"
		date = "2023-03-29"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		score = 70
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		id = "18ea2185-11a1-51ad-a51a-df9e6357bb58"

	strings:
		$x1 = {33 6a 42 28 32 62 73 47 23 40 63 37}

	condition:
		( uint16( 0 ) == 0xcfd0 or uint16( 0 ) == 0x5a4d ) and $x1
}

import "pe"

rule SUSP_3CX_App_Signed_Binary_Mar23_1 : hardened
{
	meta:
		description = "Detects 3CX application binaries signed with a certificate and created in a time frame in which other known malicious binaries have been created"
		author = "Florian Roth (Nextron Systems)"
		date = "2023-03-29"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		score = 65
		hash1 = "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405"
		hash2 = "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc"
		id = "b6ce4c1d-1b7b-5e0c-af4c-05cb3ad0a4e0"

	strings:
		$sa1 = {33 43 58 20 4c 74 64 31}
		$sa2 = {33 00 43 00 58 00 20 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 41 00 70 00 70 00}
		$sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }

	condition:
		uint16( 0 ) == 0x5a4d and pe.timestamp > 1669680000 and pe.timestamp < 1680108505 and all of ( $sa* ) and $sc1
}

rule SUSP_3CX_MSI_Signed_Binary_Mar23_1 : hardened
{
	meta:
		description = "Detects 3CX MSI installers signed with a known compromised certificate and signed in a time frame in which other known malicious binaries have been signed"
		author = "Florian Roth (Nextron Systems)"
		date = "2023-03-29"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		score = 60
		hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		id = "15d6d8ca-6982-5095-9879-ce97269a71c6"

	strings:
		$a1 = { 84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }
		$s1 = {33 43 58 20 4c 74 64 31}
		$s2 = {32 30 32 33 30 33}

	condition:
		uint16( 0 ) == 0xcfd0 and $a1 and $sc1 and ( $s1 in ( filesize - 20000 .. filesize ) and $s2 in ( filesize - 20000 .. filesize ) )
}

rule APT_MAL_macOS_NK_3CX_Malicious_Samples_Mar23_1 : hardened
{
	meta:
		description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		date = "2023-03-30"
		score = 80
		hash1 = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
		hash2 = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
		hash3 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		id = "ff39e577-7063-5025-bead-68394a86c87c"

	strings:
		$s1 = {32 30 32 33 30 33 31 33 30 36 34 31 35 32 5a 30}
		$s2 = {44 65 76 65 6c 6f 70 65 72 20 49 44 20 41 70 70 6c 69 63 61 74 69 6f 6e 3a 20 33 43 58 20 28 33 33 43 46 34 36 35 34 48 4c 29}

	condition:
		( uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and all of them
}

rule APT_MAL_MacOS_NK_3CX_DYLIB_Mar23_1 : hardened
{
	meta:
		description = "Detects malicious DYLIB files related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		date = "2023-03-30"
		score = 80
		hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		hash2 = "fee4f9dabc094df24d83ec1a8c4e4ff573e5d9973caa676f58086c99561382d7"
		id = "a19904d3-9b2d-561f-b734-20bf09584fa7"

	strings:
		$xc1 = { 37 15 00 13 16 16 1B 55 4F 54 4A 5A 52 2D 13 14 
               1E 15 0D 09 5A 34 2E 5A 4B 4A 54 4A 41 5A 2D 13
               14 4C 4E 41 5A 02 4C 4E 53 5A 3B 0A 0A 16 1F 2D
               1F 18 31 13 0E 55 4F 49 4D 54 49 4C 5A 52 31 32
               2E 37 36 56 5A 16 13 11 1F 5A 3D 1F 19 11 15 53
               5A 39 12 08 15 17 1F 55 4B 4A 42 54 4A 54 4F 49
               4F 43 54 4B 48 42 5A 29 1B 1C 1B 08 13 55 4F 49
               4D 54 49 4C 7A }
		$xc2 = { 41 49 19 02 25 1b 0f 0e 12 25 0e 15 11 1f 14 25 19 15 14 0e 1f 14 0e 47 5f 09 41 25 25 0e 0f 0e 17 1b 47 }
		$xc3 = { 55 29 03 09 0e 1f 17 55 36 13 18 08 1b 08 03 55 39 15 08 1f 29 1f 08 0c 13 19 1f 09 55 29 03 09 0e 1f 17 2c 1f 08 09 13 15 14 54 0a 16 13 09 0e }

	condition:
		1 of them
}

rule APT_SUSP_NK_3CX_Malicious_Samples_Mar23_1 : hardened limited
{
	meta:
		description = "Detects indicator (event name) found in samples related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		date = "2023-03-30"
		score = 70
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		id = "b233846a-19df-579b-a674-233d66824008"

	strings:
		$a1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 56 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 52 00 65 00 66 00 72 00 65 00 73 00 68 00 45 00 76 00 65 00 6e 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		1 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_4 : hardened
{
	meta:
		author = "MalGamy (Nextron Systems)"
		reference = "https://twitter.com/WhichbufferArda/status/1641404343323688964?s=20"
		description = "Detects decrypted payload loaded inside 3CXDesktopApp.exe which downloads info stealer"
		date = "2023-03-29"
		hash = "851c2c99ebafd4e5e9e140cfe3f2d03533846ca16f8151ae8ee0e83c692884b7"
		score = 80
		id = "d11170df-570c-510c-80ec-39048acd0fbd"

	strings:
		$op1 = {41 69 D0 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 [4] 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 [4] 33 C1 4C 0F AF CF 4D 03 CA 45 8B D1 4C 0F AF D7 41 8D 0C 11 49 C1 E9 ?? 02 C8}
		$op2 = {4D 0F AF CC 44 69 C2 [4] 4C 03 C9 45 8B D1 4D 0F AF D4 41 8D 0C 11 41 81 C0 [4] 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1}
		$op3 = {33 C1 4C 0F AF C7 8B C8 C1 E1 ?? 4D 03 C2 33 C1}

	condition:
		2 of them
}

rule MAL_3CXDesktopApp_MacOS_Backdoor_Mar23 : hardened limited
{
	meta:
		author = "X__Junior (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/"
		description = "Detects 3CXDesktopApp MacOS Backdoor component"
		date = "2023-03-30"
		hash = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		score = 80
		id = "80046c8e-0c2a-5885-b140-a6084f48160d"

	strings:
		$sa1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 25 73 2f 2e 6d 61 69 6e 5f 73 74 6f 72 61 67 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$sa2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 25 73 2f 55 70 64 61 74 65 41 67 65 6e 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op1 = { 31 C0 41 80 34 06 ?? 48 FF C0 48 83 F8 ?? 75 ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 4C 89 F7 48 89 D9 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 F7 5B 41 5E 41 5F E9 ?? ?? ?? ?? 5B 41 5E 41 5F C3}
		$op2 = { 0F 11 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 31 C0 80 B4 04 ?? ?? ?? ?? ?? 48 FF C0}

	condition:
		(( uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and filesize < 6MB and ( ( 1 of ( $sa* ) and 1 of ( $op* ) ) or all of ( $sa* ) ) ) or ( all of ( $op* ) )
}

rule APT_MAL_NK_3CX_ICONIC_Stealer_Mar23_1 : hardened limited
{
	meta:
		description = "Detects ICONIC stealer payload used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/volexity/threat-intel/blob/main/2023/2023-03-30%203CX/attachments/iconicstealer.7z"
		date = "2023-03-31"
		score = 80
		hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
		id = "e92b5b90-1146-5235-9711-a4d42689c49b"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 7b 00 22 00 48 00 6f 00 73 00 74 00 4e 00 61 00 6d 00 65 00 22 00 3a 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 22 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 4e 00 61 00 6d 00 65 00 22 00 3a 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 22 00 4f 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 22 00 3a 00 20 00 22 00 25 00 64 00 2e 00 25 00 64 00 2e 00 25 00 64 00 22 00 7d 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 25 00 73 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 42 00 72 00 61 00 76 00 65 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 72 00 61 00 76 00 65 00 2d 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 75 00 72 00 6c 00 2c 00 20 00 74 00 69 00 74 00 6c 00 65 00 20 00 46 00 52 00 4f 00 4d 00 20 00 75 00 72 00 6c 00 73 00 20 00 4f 00 52 00 44 00 45 00 52 00 20 00 42 00 59 00 20 00 69 00 64 00 20 00 44 00 45 00 53 00 43 00 20 00 4c 00 49 00 4d 00 49 00 54 00 20 00 35 00 30 00 30 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 54 45 58 54 20 76 61 6c 75 65 20 69 6e 20 25 73 2e 25 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op1 = { 48 63 d1 48 63 ce 49 03 d1 49 03 cd 4c 63 c7 e8 87 1f 09 00 8b 45 d0 44 8d 04 37 }
		$op2 = { 48 8b c8 8b 56 f0 48 89 46 d8 e8 78 8f f8 ff e9 ec 13 00 00 c7 46 20 ff ff ff ff e9 e0 13 00 00 33 ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4000KB and 4 of them or 6 of them
}

rule APT_MAL_NK_3CX_macOS_Elextron_App_Mar23_1 : hardened limited
{
	meta:
		description = "Detects macOS malware used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2023-03-31"
		score = 80
		hash1 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		hash2 = "f7ba7f9bf608128894196cf7314f68b78d2a6df10718c8e0cd64dbe3b86bc730"
		id = "7a3755d4-37e5-5d3b-93aa-34edb557f2d5"

	strings:
		$a1 = {63 6f 6d 2e 61 70 70 6c 65 2e 73 65 63 75 72 69 74 79 2e 63 73 2e 61 6c 6c 6f 77 2d 75 6e 73 69 67 6e 65 64 2d 65 78 65 63 75 74 61 62 6c 65 2d 6d 65 6d 6f 72 79}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 63 6f 6d 2e 65 6c 65 63 74 72 6f 6e 2e 33 63 78 2d 64 65 73 6b 74 6f 70 2d 61 70 70 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {73 38 54 2f 52 58 4d 6c 41 4c 62 58 66 6f 77 6f 6d 39 71 6b 31 35 46 67 74 64 49 3d}
		$s2 = {6f 38 4e 51 4b 50 4a 45 36 76 6f 56 5a 55 49 47 74 58 69 68 71 37 6c 70 30 63 59 3d}

	condition:
		uint16( 0 ) == 0xfacf and filesize < 400KB and ( all of ( $a* ) and 1 of ( $s* ) )
}

rule MAL_3CXDesktopApp_MacOS_UpdateAgent_Mar23 : hardened
{
	meta:
		description = "Detects 3CXDesktopApp MacOS UpdateAgent backdoor component"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/patrickwardle/status/1641692164303515653?s=20"
		date = "2023-03-30"
		hash = "9e9a5f8d86356796162cee881c843cde9eaedfb3"
		score = 80
		id = "596eb6d0-f96f-5106-ae67-9372d238e4cf"

	strings:
		$a1 = {2f 33 43 58 20 44 65 73 6b 74 6f 70 20 41 70 70 2f 2e 6d 61 69 6e 5f 73 74 6f 72 61 67 65}
		$x1 = {3b 33 63 78 5f 61 75 74 68 5f 74 6f 6b 65 6e 5f 63 6f 6e 74 65 6e 74 3d 25 73 3b 5f 5f 74 75 74 6d 61 3d 74 72 75 65}
		$s1 = {22 75 72 6c 22 3a 20 22 68 74 74 70 73 3a 2f 2f}
		$s3 = {2f 64 65 76 2f 6e 75 6c 6c}
		$s4 = {22 41 63 63 6f 75 6e 74 4e 61 6d 65 22 3a 20 22}

	condition:
		uint16( 0 ) == 0xfeca and filesize < 6MB and ( 1 of ( $x* ) or ( $a1 and all of ( $s* ) ) ) or all of them
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_2 : hardened
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
		date = "2023-04-29"
		hash = "c4887a5cd6d98e273ba6e9ea3c1d8f770ef26239819ea24a1bfebd81d6870505"
		score = 80
		id = "ff1fa0bd-19b7-553a-9506-bc5aa5d29056"

	strings:
		$sa1 = {5c 2e 5c 70 69 70 65 5c 67 65 63 6b 6f 2e 6e 61 74 69 76 65 4d 65 73 73 61 67 69 6e 67}
		$sa2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 39 35 2e 30 2e 34 36 33 38 2e 35 34 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 20 45 64 67 2f 39 35 2e 30 2e 31 30 32 30 2e 34 30}
		$sa3 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 2c 20 74 65 78 74 2f 6a 61 76 61 73 63 72 69 70 74 2c 20 2a 2f 2a 3b 20 71 3d 30 2e 30 31}
		$op1 = { 89 7? 24 ?? 44 8B CD 4C 8B C? 48 89 44 24 ?? 33 D2 33 C9 FF 15}
		$op2 = { 4C 8B CB 4C 89 74 24 ?? 4C 8D 05 ?? ?? ?? ?? 44 89 74 24 ?? 33 D2 33 C9 FF 15}
		$op3 = { 48 89 74 24 ?? 45 33 C0 89 74 24 ?? 41 B9 ?? ?? ?? ?? 89 74 24 ?? 48 8B D8 48 C7 00 ?? ?? ?? ?? 48 8B 0F 41 8D 50 ?? 48 89 44 24 ?? 89 74 24 ?? FF 15}

	condition:
		all of ( $op* ) or all of ( $sa* )
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_3 : hardened
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
		date = "2023-04-29"
		hash = "595392959b609caf088d027a23443cf2fefd043607ccdec3de19ad3bb43a74b1"
		score = 80
		id = "6b6f984e-242a-5b84-baa9-6311992cde9b"

	strings:
		$op1 = { 4C 8B CB 4C 89 74 24 ?? 4C 8D 05 ?? ?? ?? ?? 44 89 74 24 ?? 33 D2 33 C9 FF 15}
		$op2 = { 89 7? 24 ?? 44 8B CD 4C 8B C? 48 89 44 24 ?? 33 D2 33 C9 FF 15}
		$op3 = { 8B 54 24 ?? 4C 8D 4C 24 ?? 45 8D 46 ?? 44 89 74 24 ?? 48 8B CB FF 15}
		$op4 = { 48 8D 44 24 ?? 45 33 C9 41 B8 01 00 00 40 48 89 44 24 ?? 41 8B D5 48 8B CF FF 15}

	condition:
		all of them
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_4 : hardened
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
		date = "2023-04-29"
		hash = "9b0761f81afb102bb784b398b16faa965594e469a7fcfdfd553ced19cc17e70b"
		score = 80
		id = "77340ec0-36bb-5c47-995f-4e6f76b68fe1"

	strings:
		$op1 = { 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 }
		$op2 = { 48 8B C8 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 45 33 C0 4C 8D 4D ?? B2 01 41 8D 48 ?? FF D0}
		$op3 = { 33 FF C7 44 24 ?? 38 02 00 00 33 D2 8D 4F ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 FF 74 ?? 48 8D 54 24 ?? 48 8B C8 FF 15 }
		$op4 = { 4C 8D 05 ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8B C8 33 D2 89 4C 24 ?? FF 15 }

	condition:
		all of them
}

