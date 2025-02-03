rule APT_APT29_Win_FlipFlop_LDR : APT29 hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-05-25"
		description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
		hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
		reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
		id = "58696a6f-55a9-5212-9372-a539cc327e6b"

	strings:
		$s1 = {69 72 6e 6a 61 64 6c 65}
		$s2 = {42 41 44 43 46 45 48 47 4a 49 4c 4b 4e 4d 50 4f 52 51 54 53 56 55 58 57 5a 59}
		$s3 = {69 4d 72 63 73 6f 66 6f 20 74 61 42 65 73 43 20 79 72 74 70 67 6f 61 72 68 70 63 69 50 20 6f 72 69 76 65 64 20 72 31 76 30 2e}

	condition:
		all of ( $s* )
}

import "pe"

rule APT_APT28_Win_FreshFire : APT29 hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-05-27"
		description = "The FRESHFIRE malware family. The malware acts as a downloader, pulling down an encrypted snippet of code from a remote source, executing it, and deleting it from the remote server."
		hash = "ad67aaa50fd60d02f1378b4155f69cffa9591eaeb80523489a2355512cc30e8c"
		reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
		id = "050b8e61-139a-5ff5-998a-7de67c9975bf"

	strings:
		$uniq1 = {55 6c 73 77 63 58 4a 4a 57 68 74 48 49 48 72 56 71 57 4a 4a}
		$uniq2 = {67 79 69 62 76 6d 74 00}
		$path1 = {72 6f 6f 74 2f 74 69 6d 65 2f 25 64 2f 25 73 2e 6a 73 6f 6e}
		$path2 = {43 3a 5c 64 65 6c 6c 2e 73 64 72}
		$path3 = {72 6f 6f 74 2f 64 61 74 61 2f 25 64 2f 25 73 2e 6a 73 6f 6e}

	condition:
		(pe.number_of_exports == 1 and pe.exports ( "WaitPrompt" ) ) or any of ( $uniq* ) or 2 of ( $path* )
}

rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_1 : hardened
{
	meta:
		description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		id = "42739aad-a88a-545b-8256-1f727c79c4f8"

	strings:
		$x1 = {5b 69 5d 2e 63 68 61 72 43 6f 64 65 41 74 28 30 29 20 5e 20 32 29 3b 7d}

	condition:
		filesize < 5000KB and 1 of them
}

rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_2 : hardened
{
	meta:
		description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		id = "d5cf3365-fe24-533a-a678-b5b6d4d99997"

	strings:
		$s1 = {73 61 76 65 41 73 28 62 6c 6f 62 2c 20}
		$s2 = {2e 69 73 6f 22 29 3b}
		$s3 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 63 64 2d 69 6d 61 67 65}
		$s4 = {2e 69 6e 64 65 78 4f 66 28 22 57 69 6e 22 29 21 3d 2d 31}

	condition:
		filesize < 5000KB and all of them
}

rule APT_APT29_NOBELIUM_LNK_NV_Link_May21_2 : hardened
{
	meta:
		description = "Detects NV Link as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		id = "52c2caf9-13df-5614-9c9e-afcd76ec77f9"

	strings:
		$s1 = {((52 65 67 69 73 74 65 72 4f 43 58 20 42 4f 4f 4d) | (52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 4f 00 43 00 58 00 20 00 42 00 4f 00 4f 00 4d 00))}
		$s2 = {((63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 42 4f 4f 4d 2e 65 78 65) | (63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 42 00 4f 00 4f 00 4d 00 2e 00 65 00 78 00 65 00))}

	condition:
		filesize < 5000KB and 1 of them
}

rule APT_APT29_NOBELIUM_LNK_Samples_May21_1 : hardened
{
	meta:
		description = "Detects link file characteristics as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 85
		hash1 = "24caf54e7c3fe308444093f7ac64d6d520c8f44ea4251e09e24931bdb72f5548"
		id = "c807ab5a-f66a-5622-81b1-6e69b6df8446"

	strings:
		$a1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$sa1 = {49 00 4d 00 47 00 4d 00 6f 00 75 00 6e 00 74 00 69 00 6e 00 67 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 64 00 6c 00 6c 00}
		$sa2 = {4d 00 6f 00 75 00 6e 00 74 00 49 00 6d 00 67 00 48 00 65 00 6c 00 70 00 65 00 72 00}
		$sb1 = {64 00 69 00 61 00 73 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00}
		$sb2 = {49 00 6e 00 69 00 74 00 69 00 61 00 6c 00 69 00 7a 00 65 00 43 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00}
		$sc1 = {4d 00 73 00 44 00 69 00 73 00 6b 00 4d 00 6f 00 75 00 6e 00 74 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 64 00 6c 00 6c 00}
		$sc2 = {44 00 69 00 73 00 6b 00 44 00 72 00 69 00 76 00 65 00 49 00 6e 00 69 00}
		$sd1 = {47 00 72 00 61 00 70 00 68 00 69 00 63 00 61 00 6c 00 43 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00}
		$sd2 = {56 00 69 00 73 00 75 00 61 00 6c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 43 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00}
		$se1 = {64 00 61 00 74 00 61 00 2f 00 6d 00 73 00 74 00 75 00 2e 00 64 00 6c 00 6c 00 2c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 55 00 70 00 64 00 61 00 74 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}

	condition:
		uint16( 0 ) == 0x004c and filesize < 4KB and $a1 and ( all of ( $sa* ) or all of ( $sb* ) or all of ( $sc* ) or all of ( $sd* ) or all of ( $se* ) )
}

rule APT_APT29_NOBELIUM_BoomBox_May21_1 : hardened
{
	meta:
		description = "Detects BoomBox malware as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 85
		id = "fe964f3e-1cda-5f16-838f-dd7b23cd5651"

	strings:
		$xa1 = {((31 32 33 64 6f 33 79 34 72 33 37 38 6f 35 74 33 34 6f 6e 66 37 74 33 6f 35 37 33 74 66 6f 37 33) | (31 00 32 00 33 00 64 00 6f 00 33 00 79 00 34 00 72 00 33 00 37 00 38 00 6f 00 35 00 74 00 33 00 34 00 6f 00 6e 00 66 00 37 00 74 00 33 00 6f 00 35 00 37 00 33 00 74 00 66 00 6f 00 37 00 33 00))}
		$xa2 = {((31 32 33 33 74 30 34 70 37 6a 6e 33 6e 34 72 67) | (31 00 32 00 33 00 33 00 74 00 30 00 34 00 70 00 37 00 6a 00 6e 00 33 00 6e 00 34 00 72 00 67 00))}

	condition:
		1 of them
}

import "math"

rule APT_APT29_NOBELIUM_BoomBox_PDF_Masq_May21_1 : hardened
{
	meta:
		description = "Detects PDF documents as used by BoomBox as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 70
		id = "bdfb9600-edda-5c8c-ab23-14fb71c8e647"

	strings:
		$ah1 = { 25 50 44 46 2d 31 2e 33 0a 25 }
		$af1 = { 0a 25 25 45 4f 46 0a }
		$fp1 = {65 6e 64 6f 62 6a}
		$fp2 = {65 6e 64 73 74 72 65 61 6d}
		$fp3 = { 20 6F 62 6A 0A }

	condition:
		$ah1 at 0 and $af1 at ( filesize - 7 ) and filesize < 100KB and not 1 of ( $fp* ) and math.entropy ( 16 , filesize ) > 7
}

rule APT_APT29_NOBELIUM_NativeZone_Loader_May21_1 : hardened
{
	meta:
		description = "Detects NativeZone loader as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 85
		hash1 = "136f4083b67bc8dc999eb15bb83042aeb01791fc0b20b5683af6b4ddcf0bbc7d"
		id = "02d9257d-f439-5071-96b0-a973b088e329"

	strings:
		$s1 = {5c 53 79 73 74 65 6d 43 65 72 74 69 66 69 63 61 74 65 73 5c 4c 69 62 5c 43 65 72 74 50 4b 49 50 72 6f 76 69 64 65 72 2e 64 6c 6c}
		$s2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 25 73}
		$s3 = {65 67 6c 47 65 74 43 6f 6e 66 69 67 73}
		$op1 = { 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 33 db 89 5d fc }
		$op2 = { 8b 46 18 e9 30 ff ff ff 90 87 2f 00 10 90 2f 00 10 }
		$op3 = { e8 14 dd ff ff 8b f1 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 3 of them or 4 of them
}

rule APT_APT29_NOBELIUM_BoomBox_May21_2 : hardened
{
	meta:
		description = "Detects BoomBox malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "0acb884f2f4cfa75b726cb8290b20328c8ddbcd49f95a1d761b7d131b95bafec"
		hash2 = "8199f309478e8ed3f03f75e7574a3e9bce09b4423bd7eb08bb5bff03af2b7c27"
		hash3 = "cf1d992f776421f72eabc31d5afc2f2067ae856f1c9c1d6dc643a67cb9349d8c"
		id = "a4144c00-48b2-5520-b773-5d0a5de95fb1"

	strings:
		$x1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 53 00 76 00 63 00 2e 00 64 00 6c 00 6c 00}
		$x2 = {5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 53 00 76 00 63 00 2e 00 64 00 6c 00 6c 00 20 00 5f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00}
		$a1 = {2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 61 00 70 00 69 00 2e 00 63 00 6f 00 6d 00}
		$s1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 7b 00 30 00 7d 00 20 00 7b 00 31 00 7d 00}
		$s2 = {5c 00 5c 00 43 00 65 00 72 00 74 00 50 00 4b 00 49 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {2f 00 74 00 6d 00 70 00 2f 00 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 70 00 64 00 66 00}
		$s4 = {74 00 65 00 6d 00 70 00 2f 00 5b 00 5e 00 22 00 5d 00 2a 00 29 00 22 00}
		$op1 = { 00 78 00 2d 00 41 00 50 00 49 00 2d 00 41 00 72 00 67 00 01 2f 4f 00 72 00 }
		$op2 = { 25 72 98 01 00 70 6f 34 00 00 0a 25 6f 35 00 00 0a 72 71 02 00 70 72 }
		$op3 = { 4d 05 20 00 12 80 91 04 20 01 08 0e 04 20 00 12 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and 3 of them or 4 of them
}

rule APT_APT29_NOBELIUM_Malware_May21_2 : hardened
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "292e5b0a12fea4ff3fc02e1f98b7a370f88152ce71fe62670dd2f5edfaab2ff8"
		hash2 = "776014a63bf3cc7034bd5b6a9c36c75a930b59182fe232535bb7a305e539967b"
		id = "b1462b4b-227f-5aeb-92ea-bda6a86831c7"

	strings:
		$op1 = { 48 03 c8 42 0f b6 04 21 88 03 0f b6 43 01 8b c8 83 e0 0f 48 83 e1 f0 48 03 c8 }
		$op2 = { 48 03 c8 42 0f b6 04 21 88 43 01 41 0f b6 c7 8b c8 83 e0 0f 48 83 e1 f0 48 03 c8 }
		$op3 = { 45 0f b6 43 ff 41 8b c2 99 44 88 03 41 0f b6 2b 83 e2 03 03 c2 40 88 6b 01 }

	condition:
		filesize < 2200KB and all of them
}

rule APT_APT29_NOBELIUM_Stageless_Loader_May21_2 : hardened limited
{
	meta:
		description = "Detects stageless loader as used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "a4f1f09a2b9bc87de90891da6c0fca28e2f88fd67034648060cef9862af9a3bf"
		hash2 = "c4ff632696ec6e406388e1d42421b3cd3b5f79dcb2df67e2022d961d5f5a9e78"
		id = "7b83d327-52fc-5401-ae35-00f6b825678a"

	strings:
		$x1 = {44 4c 4c 5f 73 74 61 67 65 6c 65 73 73 2e 64 6c 6c}
		$s1 = {63 3a 5c 75 73 65 72 73 5c 64 65 76 75 73 65 72 5c 64 6f 63 75 6d 65 6e 74 73}
		$s2 = {56 69 73 75 61 6c 53 65 72 76 69 63 65 43 6f 6d 70 6f 6e 65 6e 74}
		$s3 = {43 68 65 63 6b 55 70 64 74 65 46 72 61 6d 65 4a 61 76 61 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}
		$op1 = { a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 }
		$op2 = { ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 e8 d4 00 10 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 2 of them or 3 of them
}

rule APT_APT29_NOBELIUM_Malware_May21_3 : hardened
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "2a352380d61e89c89f03f4008044241a38751284995d000c73acf9cad38b989e"
		id = "89cb6884-4242-5b5a-b0ac-b31041dd261c"

	strings:
		$s1 = {57 69 6e 33 32 50 72 6f 6a 65 63 74 31 2e 64 6c 6c}
		$op1 = { 59 c3 6a 08 68 70 5e 01 10 e8 d2 8c ff ff 8b 7d 08 8b c7 c1 f8 05 }
		$op2 = { 8d 4d f0 e8 c4 12 00 00 68 64 5b 01 10 8d 45 f0 c7 45 f0 6c 01 01 10 50 e8 ea 13 00 00 cc }
		$op4 = { 40 c3 8b 65 e8 e8 a6 86 ff ff cc 6a 0c 68 88 60 01 10 e8 b0 4d ff ff }
		$xc1 = { 25 73 25 73 00 00 00 00 2F 65 2C 20 00 00 00 00
               43 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00
               77 00 73 00 5C 00 65 00 78 00 70 00 6C 00 6F 00
               72 00 65 00 72 00 2E 00 65 00 78 00 65 }

	condition:
		filesize < 3000KB and ( $xc1 or 3 of them )
}

rule APT_APT29_NOBELIUM_Malware_May21_4 : hardened
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		date = "2021-05-29"
		hash1 = "3b94cc71c325f9068105b9e7d5c9667b1de2bde85b7abc5b29ff649fd54715c4"
		id = "56193475-52b4-5720-abc5-72249e2a0c37"

	strings:
		$s1 = {4b 4d 2e 46 69 6c 65 53 79 73 74 65 6d 2e 64 6c 6c}
		$op1 = { 80 3d 50 6b 04 10 00 0f 85 96 00 00 00 33 c0 40 b9 48 6b 04 10 87 01 33 db 89 5d fc }
		$op2 = { c3 33 c0 b9 7c 6f 04 10 40 87 01 c3 8b ff 55 }
		$op3 = { 8d 4d f4 e8 53 ff ff ff 68 d0 22 01 10 8d 45 f4 50 e8 d8 05 00 00 cc 8b 41 04 }
		$xc1 = { 2E 64 6C 6C 00 00 00 00 41 53 4B 4F 44 00 00 00
               53 75 63 63 65 73 73 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( $xc1 or 3 of them )
}

