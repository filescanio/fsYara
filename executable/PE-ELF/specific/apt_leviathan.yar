rule SeDLL_Javascript_Decryptor : hardened
{
	meta:
		description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		modified = "2023-01-07"
		hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"
		id = "8fafd139-0c4f-5c51-af8f-b4917d2d69b0"

	strings:
		$x1 = {53 45 44 6c 6c 5f 57 69 6e 33 32 2e 64 6c 6c}
		$x2 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 22 00 25 00 73 00 22 00 20 00 44 00 52 00 20 00 5f 00 5f 00 43 00 49 00 4d 00 5f 00 5f 00}
		$s1 = {57 53 63 72 69 70 74 57}
		$s2 = {49 57 53 63 72 69 70 74}
		$s3 = {25 00 73 00 5c 00 25 00 73 00 7e 00 25 00 64 00}
		$s4 = {50 75 74 42 6c 6f 63 6b 54 6f 46 69 6c 65 57 57}
		$s5 = {43 68 65 63 6b 55 70 41 6e 64 44 6f 77 6e 57 57}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and ( 1 of ( $x* ) or 4 of them )
}

rule Leviathan_CobaltStrike_Sample_1 : hardened
{
	meta:
		description = "Detects Cobalt Strike sample from Leviathan report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		hash1 = "5860ddc428ffa900258207e9c385f843a3472f2fbf252d2f6357d458646cf362"
		id = "e29072d8-b4ea-5e94-8a1c-0a1baec5f423"
		score = 75

	strings:
		$x1 = {61 35 34 63 38 31 2e 64 6c 6c}
		$x2 = {25 64 20 69 73 20 61 6e 20 78 36 34 20 70 72 6f 63 65 73 73 20 28 63 61 6e 27 74 20 69 6e 6a 65 63 74 20 78 38 36 20 63 6f 6e 74 65 6e 74 29}
		$x3 = {46 61 69 6c 65 64 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 6c 6f 67 67 65 64 20 6f 6e 20 75 73 65 72 20 25 64 20 28 25 75 29}
		$s1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22}
		$s2 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 75 2f 27 29 3b 20 25 73}
		$s3 = {63 6f 75 6c 64 20 6e 6f 74 20 72 75 6e 20 63 6f 6d 6d 61 6e 64 20 28 77 2f 20 74 6f 6b 65 6e 29 20 62 65 63 61 75 73 65 20 6f 66 20 69 74 73 20 6c 65 6e 67 74 68 20 6f 66 20 25 64 20 62 79 74 65 73 21}
		$s4 = {63 6f 75 6c 64 20 6e 6f 74 20 77 72 69 74 65 20 74 6f 20 70 72 6f 63 65 73 73 20 6d 65 6d 6f 72 79 3a 20 25 64}
		$s5 = {25 73 2e 34 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$s6 = {43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 70 69 70 65 20 28 25 73 29 3a 20 25 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( 1 of ( $x* ) or 3 of them )
}

rule MockDll_Gen : hardened
{
	meta:
		description = "Detects MockDll - regsvr DLL loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		hash1 = "bfc5c6817ff2cc4f3cd40f649e10cc9ae1e52139f35fdddbd32cb4d221368922"
		hash2 = "80b931ab1798d7d8a8d63411861cee07e31bb9a68f595f579e11d3817cfc4aca"
		id = "904a0649-27e7-5024-aa6b-ddb23bba6202"

	strings:
		$x1 = {6d 6f 63 6b 5f 72 75 6e 5f 69 6e 69 5f 57 69 6e 33 32 2e 64 6c 6c}
		$x2 = {6d 6f 63 6b 5f 72 75 6e 5f 69 6e 69 5f 78 36 34 2e 64 6c 6c}
		$s1 = {52 65 61 6c 43 6d 64 3d 25 73 20 25 73}
		$s2 = {4d 6f 63 6b 4d 6f 64 75 6c 65 3d 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 20KB and ( 1 of ( $x* ) or 2 of them )
}

rule VBScript_Favicon_File : hardened
{
	meta:
		description = "VBScript cloaked as Favicon file used in Leviathan incident"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		modified = "2023-01-06"
		hash1 = "39c952c7e14b6be5a9cb1be3f05eafa22e1115806e927f4e2dc85d609bc0eb36"
		id = "84147d4e-d062-5ba4-8019-6bf4b72c36c6"

	strings:
		$x1 = {6d 79 78 6d 6c 20 3d 20 27 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 22 31 2e 30 22 22 20 65 6e 63 6f 64 69 6e 67 3d 22 22 55 54 46 2d 38 22 22 3f 3e 27 3b 6d 79 78 6d 6c 20 3d 20 6d 79 78 6d 6c 20 2b 27 3c 72 6f 6f 74 3e}
		$x2 = {2e 52 75 6e 20 22 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 6d 73 68 74 61 2e 65 78 65}
		$x3 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 56 42 53 63 72 69 70 74 22 3e 57 69 6e 64 6f 77 2e 52 65 53 69 7a 65 54 6f 20 30 2c 20 30 20 3a 20 57 69 6e 64 6f 77 2e 6d 6f 76 65 54 6f 20 2d 32 30 30 30 2c 2d 32 30 30 30 20 3a}
		$s1 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 22 29 20 26}
		$s2 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 74 65 6d 70 25 22 29 20 26 20}

	condition:
		filesize < 100KB and ( uint16( 0 ) == 0x733c and 1 of ( $x* ) ) or ( 3 of them )
}

