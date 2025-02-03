import "pe"

rule FreeMilk_APT_Mal_1 : hardened
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		date = "2017-10-05"
		hash1 = "34478d6692f8c28332751b31fd695b799d4ab36a8c12f7b728e2cb99ae2efcd9"
		hash2 = "35273d6c25665a19ac14d469e1436223202be655ee19b5b247cb1afef626c9f2"
		hash3 = "0f82ea2f92c7e906ee9ffbbd8212be6a8545b9bb0200eda09cce0ba9d7cb1313"
		id = "eff37dba-d4a9-5e3d-9452-49f04ddcbe0b"

	strings:
		$x1 = {5c 6d 69 6c 6b 5c 52 65 6c 65 61 73 65 5c 6d 69 6c 6b 2e 70 64 62}
		$x2 = {45 3a 5c 42 49 47 5f 50 4f 4f 48 5c 50 72 6f 6a 65 63 74 5c}
		$x3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 4b 00 42 00 32 00 37 00 31 00 38 00 35 00 34 00 2d 00 78 00 38 00 36 00 2e 00 65 00 78 00 65 00}
		$s1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 4b 00 42 00 32 00 37 00 35 00 31 00 32 00 32 00 2d 00 78 00 38 00 36 00 2e 00 65 00 78 00 65 00}
		$s2 = {5c 00 77 00 73 00 61 00 74 00 72 00 61 00 2e 00 74 00 6d 00 70 00}
		$s3 = {25 00 73 00 5c 00 52 00 61 00 72 00 30 00 74 00 6d 00 70 00 45 00 78 00 74 00 72 00 61 00 25 00 64 00 2e 00 72 00 74 00 66 00}
		$s4 = {22 00 25 00 73 00 22 00 20 00 68 00 65 00 6c 00 70 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "108aa007b3d1b4817ff4c04d9b254b39" or 1 of ( $x* ) or 4 of them )
}

import "pe"

rule FreeMilk_APT_Mal_2 : hardened
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		date = "2017-10-05"
		hash1 = "7f35521cdbaa4e86143656ff9c52cef8d1e5e5f8245860c205364138f82c54df"
		id = "ef5f400c-16f8-5374-af16-c8530ddb87ee"

	strings:
		$s1 = {66 61 69 6c 65 64 20 74 6f 20 74 61 6b 65 20 74 68 65 20 73 63 72 65 65 6e 73 68 6f 74 2e 20 65 72 72 3a 20 25 64}
		$s2 = {72 00 75 00 6e 00 73 00 61 00 6d 00 70 00 6c 00 65 00}
		$s3 = {25 00 73 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 25 00 30 00 32 00 58 00 3a 00}
		$s4 = {77 00 69 00 6e 00 2d 00 25 00 64 00 2e 00 25 00 64 00 2e 00 25 00 64 00 2d 00 25 00 64 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( pe.imphash ( ) == "b86f7d2c1c182ec4c074ae1e16b7a3f5" or all of them )
}

rule FreeMilk_APT_Mal_3 : hardened
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		date = "2017-10-05"
		hash1 = "ef40f7ddff404d1193e025081780e32f88883fa4dd496f4189084d772a435cb2"
		id = "152781f0-756b-50ab-b588-4af5fa4ce419"

	strings:
		$s1 = {43 00 4d 00 44 00 2e 00 45 00 58 00 45 00 20 00 2f 00 43 00 20 00 22 00 25 00 73 00 22 00}
		$s2 = {5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 5c 00 73 00 74 00 61 00 72 00 74 00 2e 00 65 00 78 00 65 00}
		$s3 = {2e 00 62 00 61 00 74 00 3b 00 2e 00 63 00 6f 00 6d 00 3b 00 2e 00 63 00 6d 00 64 00 3b 00 2e 00 65 00 78 00 65 00}
		$s4 = {55 6e 65 78 70 65 63 74 65 64 20 66 61 69 6c 75 72 65 20 6f 70 65 6e 69 6e 67 20 48 4b 43 52 20 6b 65 79 3a 20 25 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 900KB and all of them )
}

import "pe"

rule FreeMilk_APT_Mal_4 : hardened
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		date = "2017-10-05"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
		id = "44f919f7-8eda-5e70-88d5-9e81a761192c"

	strings:
		$x1 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 3d 22 54 56 71 51 41 41 4d 41 41 41 41 45}
		$s1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 6c 00 69 00 65 00 6e 00 74 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 4d 00 65 00 6e 00 75 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 5c 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}
		$s2 = {27 57 73 63 72 69 70 74 2e 65 63 68 6f 20 22 42 61 73 65 36 34 20 65 6e 63 6f 64 65 64 3a 20 22 20 2b 20 62 61 73 65 36 34 45 6e 63 6f 64 65 64}
		$s3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61}
		$s4 = {6f 75 74 46 69 6c 65 3d 73 79 73 44 69 72 26 22 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22}
		$s5 = {73 65 74 20 73 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$s6 = {63 6f 6d 6d 61 6e 64 20 3d 6f 75 74 46 69 6c 65 20 26 22 20 73 79 73 75 70 64 61 74 65 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( ( pe.exports ( "getUpdate" ) and pe.number_of_exports == 1 ) or 1 of ( $x* ) or 3 of them )
}

