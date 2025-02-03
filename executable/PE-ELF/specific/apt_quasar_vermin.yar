rule Quasar_RAT_Jan18_1 : hardened
{
	meta:
		description = "Detects Quasar RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-vermin-quasar-rat-custom-malware-used-ukraine/"
		date = "2018-01-29"
		hash1 = "0157b43eb3c20928b77f8700ad8eb279a0aa348921df074cd22ebaff01edaae6"
		hash2 = "24956d8edcf2a1fd26805ec58cfd1ee7498e1a59af8cc2f4b832a7ab34948c18"
		id = "52408897-bfec-5726-9d01-6ff982d50c28"
		score = 75

	strings:
		$a1 = {70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 32 00 30 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 20 00 3e 00 20 00 6e 00 75 00 6c 00}
		$s2 = {48 61 6e 64 6c 65 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64}
		$s3 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65}
		$s4 = {55 70 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65}
		$s5 = {53 68 65 6c 6c 43 6f 6d 6d 61 6e 64 52 65 73 70 6f 6e 73 65}
		$s6 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s7 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 63 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 21 00}
		$s8 = {2e 43 6f 72 65 2e 52 65 6d 6f 74 65 53 68 65 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and $a1 and 3 of them
}

rule Vermin_Keylogger_Jan18_1 : hardened
{
	meta:
		description = "Detects Vermin Keylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-vermin-quasar-rat-custom-malware-used-ukraine/"
		date = "2018-01-29"
		hash1 = "74ba162eef84bf13d1d79cb26192a4692c09fed57f321230ddb7668a88e3935d"
		hash2 = "e1d917769267302d58a2fd00bc49d4aee5a472227a75f9366b46ce243e9cbef7"
		hash3 = "0157b43eb3c20928b77f8700ad8eb279a0aa348921df074cd22ebaff01edaae6"
		hash4 = "4c5e019e0e55a3fe378aa339d52c235c06ecc5053625a5d54d65c4ae38c6e3da"
		hash5 = "24956d8edcf2a1fd26805ec58cfd1ee7498e1a59af8cc2f4b832a7ab34948c18"
		hash6 = "2963c5eacaad13ace807edd634a4a5896cb5536f961f43afcf8c1f25c08a5eef"
		id = "52192ea1-bb3d-52da-ba18-0645262745e2"

	strings:
		$x1 = {5f 6b 65 79 6c 6f 67 67 65 72 54 61 73 6b 44 65 73 63 72 69 70 74 69 6f 6e}
		$x2 = {5f 6b 65 79 6c 6f 67 67 65 72 54 61 73 6b 41 75 74 68 6f 72}
		$x3 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 52 65 73 70 6f 6e 73 65}
		$x4 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73}
		$x5 = {45 78 65 63 75 74 65 55 6e 69 6e 73 74 61 6c 6c 4b 65 79 4c 6f 67 67 65 72 54 61 73 6b}
		$x6 = {45 78 65 63 75 74 65 49 6e 73 74 61 6c 6c 4b 65 79 4c 6f 67 67 65 72 54 61 73 6b}
		$x7 = {3a 5c 50 72 6f 6a 65 63 74 73 5c 56 65 72 6d 69 6e 5c 4b 65 79 62 6f 61 72 64 48 6f 6f 6b 4c 69 62 5c}
		$x8 = {3a 5c 50 72 6f 6a 65 63 74 73 5c 56 65 72 6d 69 6e 5c 43 72 79 70 74 6f 4c 69 62 5c}
		$s1 = {3c 52 75 6e 48 69 64 64 65 6e 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64}
		$s2 = {73 65 74 5f 53 79 73 74 65 6d 49 6e 66 6f 73}
		$s3 = {73 65 74 5f 52 75 6e 48 69 64 64 65 6e}
		$s4 = {73 65 74 5f 52 65 6d 6f 74 65 50 61 74 68}
		$s5 = {45 78 65 63 75 74 65 53 68 65 6c 6c 43 6f 6d 6d 61 6e 64 54 61 73 6b}
		$s6 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00}
		$s7 = {78 43 6c 69 65 6e 74 2e 43 6f 72 65 2e 52 65 76 65 72 73 65 50 72 6f 78 79 2e 50 61 63 6b 65 74 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and ( 1 of ( $x* ) or 3 of them )
}

