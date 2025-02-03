rule APT_FIN7_Strings_Aug18_1 : hardened
{
	meta:
		description = "Detects strings from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "b6354e46af0d69b6998dbed2fceae60a3b207584e08179748e65511d45849b00"
		id = "9b940986-e41b-5fbf-9e42-cb0fd550e541"

	strings:
		$s1 = {26 26 63 61 6c 6c 20 25 61 30 31 25 25 61 30 32 25 20 2f 65 3a 6a 73 63 72 69 70 74}
		$s2 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 62 20 2f 65 3a 6a 73 63 72 69 70 74 20 25 54 45 4d 50 25}
		$s3 = {20 77 3d 77 73 63 40 72 69 70 74 20 2f 62 20}
		$s4 = {40 65 63 68 6f 20 25 77 3a 40 3d 25 7c 63 6d 64}
		$s5 = {20 26 20 77 73 63 72 69 70 74 20 2f 2f 62 20 2f 65 3a 6a 73 63 72 69 70 74}

	condition:
		1 of them
}

rule APT_FIN7_Sample_Aug18_2 : hardened
{
	meta:
		description = "Detects FIN7 malware sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "1513c7630c981e4b1d0d5a55809166721df4f87bb0fac2d2b8ff6afae187f01d"
		id = "885eebfe-2587-5744-ba0c-c74ced946050"

	strings:
		$x1 = {44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 6f 00 6c 00 65 00 67 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00}
		$x2 = {2f 2a 7c 2a 7c 20 2a 20 20 43 6f 70 79 72 69 67 68 74 20 32 30 31 36 20 4d 69 63 72 6f 73 6f 66 74 2c 20 49 6e 64 75 73 74 72 69 65 73 2e 7c 2a 7c 20 2a 20 20 41 6c 6c 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2e 7c 2a 7c}
		$x3 = {33 32 2c 20 34 30 2c 20 31 30 32 2c 20 31 30 35 2c 20 31 30 38 2c 20 31 30 31 2c 20 39 35 2c 20 31 31 32 2c 20 39 37 2c 20 31 31 36 2c 20 31 30 34 2c 20 34 31 2c 20 34 31 2c 20 33 32}
		$x4 = {38 33 2c 20 31 30 38 2c 20 31 30 31 2c 20 31 30 31 2c 20 31 31 32 2c 20 34 30 2c 20 35 31 2c 20 34 38 2c 20 34 38 2c 20 34 38 2c 20 34 31 2c 20 35 39 2c 20 31 30 32 2c 20 31 31 35}
		$x5 = {38 30 2c 20 38 30 2c 20 36 38 2c 20 36 35 2c 20 38 34 2c 20 36 35 2c 20 33 37 2c 20 33 34 2c 20 34 31 2c 20 34 34 2c 20 31 31 35 2c 20 31 30 34 2c 20 31 30 31 2c 20 31 30 38 2c 20 31 30 38}

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 2000KB and 1 of them
}

rule APT_FIN7_MalDoc_Aug18_1 : hardened
{
	meta:
		description = "Detects malicious Doc from FIN7 campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "9c12591c850a2d5355be0ed9b3891ccb3f42e37eaf979ae545f2f008b5d124d6"
		id = "f3c430e0-be9a-5c3f-9378-a20ef0492afb"

	strings:
		$s1 = {3c 70 68 6f 74 6f 73 68 6f 70 3a 4c 61 79 65 72 54 65 78 74 3e 49 66 20 74 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 77 61 73 20 64 6f 77 6e 6c 6f 61 64 65 64 20 66 72 6f 6d 20 79 6f 75 72 20 65 6d 61 69 6c 2c 20 70 6c 65 61 73 65 20 63 6c 69 63 6b 20 20 22 45 6e 61 62 6c 65 20 65 64 69 74 69 6e 67 22 20 66 72 6f 6d 20 74 68 65 20 79 65 6c 6c 6f 77 20 62 61 72 20 61 62 6f 76 65}

	condition:
		filesize < 800KB and 1 of them
}

rule APT_FIN7_Sample_Aug18_1 : hardened
{
	meta:
		description = "Detects FIN7 samples mentioned in FireEye report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		score = 70
		hash1 = "a1e95ac1bb684186e9fb5c67f75c7c26ddc8b18ebfdaf061742ddf1675e17d55"
		hash2 = "dc645aae5d283fa175cf463a19615ed4d16b1d5238686245574d8a6a8b0fc8fa"
		hash3 = "eebbce171dab636c5ac0bf0fd14da0e216758b19c0ce2e5c572d7e6642d36d3d"
		id = "0fdd98e8-7536-5159-8085-da7388e5fff2"

	strings:
		$s1 = {5c 70 61 72 20 76 61 72 20 63 6f 6e 73 6f 6c 65 3d 5c 7b 5c 7d 3b 63 6f 6e 73 6f 6c 65 2e 6c 6f 67 3d 66 75 6e 63 74 69 6f 6e 28 29 5c 7b 5c 7d 3b}
		$s2 = {36 31 36 65 36 34 37 39 32 64 37 30 36 33}
		$x1 = {30 30 34 33 30 30 33 61 30 30 35 63 30 30 35 35 30 30 37 33 30 30 36 35 30 30 37 32 30 30 37 33 30 30 35 63 30 30 36 31 30 30 36 65 30 30 36 34 30 30 37 39 30 30 35 63 30 30 34 34 30 30 36 35 30 30 37 33 30 30 36 62 30 30 37 34 30 30 36 66 30 30 37 30 30 30 35 63 30 30 37 35 30 30 36 65 30 30 37 30 30 30 37 32 30 30 36 66 30 30 37 34 30 30 36 35 30 30 36 33 30 30 37 34}
		$x2 = {37 38 30 30 36 35 30 30 36 33 30 30 37 35 30 30 37 34 30 30 36 35 30 30 32 38 30 30 32 32 30 30 34 66 30 30 36 65 30 30 32 30 30 30 34 35 30 30 37 32 30 30 37 32 30 30 36 66 30 30 37 32 30 30 32 30 30 30 35 32 30 30 36 35 30 30 37 33 30 30 37 35 30 30 36 64 30 30 36 35 30 30 32 30 30 30 34 65 30 30 36 35 30 30 37 38 30 30 37 34 30 30 33 61 30 30 37 33 30 30 36 35 30 30}
		$x3 = {5c 70 61 72 20 5c 74 61 62 20 5c 74 61 62 20 5c 74 61 62 20 73 68 2e 52 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 45 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 77 20 48 69 64 64 65 6e 20 2d 46 69 6c 65 20 22 20 26 20 70 54 6f 50 53 43 62 2c 20 30 2c 20 46 61 6c 73 65}
		$x4 = {30 30 32 65 30 30 36 63 30 30 36 65 30 30 36 62 30 30 32 64 30 30 30 30 30 30 34 33 30 30 33 61 30 30 35 63 30 30 35 35 30 30 37 33 30 30 36 35 30 30 37 32 30 30 37 33 30 30 35 63 30 30 37 34 30 30 36 35 30 30 37 33 30 30 37 34 30 30 36 31 30 30 36 34 30 30 36 64 30 30 36 39 30 30 36 65 30 30 32 65 30 30 35 34 30 30 34 35 30 30 35 33 30 30 35 34 30 30 35 63 30 30 34 34}
		$x5 = {30 30 35 63 30 30 35 35 30 30 37 33 30 30 36 35 30 30 37 32 30 30 37 33 30 30 35 63 30 30 35 34 30 30 34 35 30 30 35 33 30 30 35 34 30 30 34 31 30 30 34 34 30 30 37 65 30 30 33 31 30 30 32 65 30 30 35 34 30 30 34 35 30 30 35 33 30 30 35 63 30 30 34 31 30 30 37 30 30 30 37 30 30 30 34 34 30 30 36 31 30 30 37 34 30 30 36 31 30 30 35 63 30 30 34 63 30 30 36 66 30 30 36 33}
		$x6 = {36 63 30 30 36 39 30 30 36 33 30 30 36 31 30 30 37 34 30 30 36 39 30 30 36 66 30 30 36 65 30 30 32 32 30 30 32 32 30 30 32 39 30 30 33 61 30 30 36 35 30 30 37 38 30 30 36 35 30 30 36 33 30 30 37 35 30 30 37 34 30 30 36 35 30 30 32 30 30 30 37 37 30 30 37 30 30 30 37 32 30 30 36 66 30 30 37 34 30 30 36 35 30 30 36 33 30 30 37 34 30 30 32 65 30 30 34 31 30 30 36 33 30 30}
		$x7 = {37 33 37 34 36 35 36 64 33 33 33 32 35 63 36 64 37 33 36 38 37 34 36 31 32 65 36 35 37 38 36 35 30 30 30 30 32 33 30 30 32 65 30 30 32 65 30 30 35 63 30 30 32 65 30 30 32 65 30 30 35 63 30 30 32 65 30 30 32 65 30 30 35 63 30 30 35 37 30 30 36 39 30 30 36 65 30 30 36 34 30 30 36 66 30 30 37 37 30 30 37 33 30 30 35 63 30 30 35 33 30 30 37 39 30 30 37 33 30 30 37 34 30 30}
		$x8 = {5c 70 61 72 20 5c 74 61 62 20 5c 74 61 62 20 73 68 2e 52 75 6e 20 22 25 63 6f 6d 73 70 65 63 25 20 2f 63 20 74 61 73 6b 6c 69 73 74 20 3e 22 22 22 20 26 20 74 70 61 74 68 20 26 20 22 22 22 20 32 3e 26 31 22 2c 20 30 2c 20 74 72 75 65}
		$x9 = {30 30 37 32 30 30 37 39 30 30 37 62 30 30 36 35 30 30 37 36 30 30 36 31 30 30 36 63 30 30 32 38 30 30 32 37 30 30 37 37 30 30 36 31 30 30 36 63 30 30 36 63 30 30 33 64 30 30 34 37 30 30 36 35 30 30 37 34 30 30 34 66 30 30 36 32 30 30 36 61 30 30 36 35 30 30 36 33 30 30 37 34 30 30 32 38 30 30 35 63 30 30 35 63 30 30 32 37 30 30 35 63 30 30 35 63 30 30 32 37 30 30 32 37}
		$x10 = {30 30 36 65 30 30 36 34 30 30 37 39 30 30 35 63 30 30 34 34 30 30 36 35 30 30 37 33 30 30 36 62 30 30 37 34 30 30 36 66 30 30 37 30 30 30 35 63 30 30 37 35 30 30 36 65 30 30 36 63 30 30 36 66 30 30 36 33 30 30 36 62 30 30 32 65 30 30 36 34 30 30 36 66 30 30 36 33 30 30 32 65 30 30 36 63 30 30 36 65 30 30 36 62}

	condition:
		uint16( 0 ) == 0x5c7b and filesize < 3000KB and ( 1 of ( $x* ) or 2 of them )
}

rule APT_FIN7_EXE_Sample_Aug18_1 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "7f16cbe7aa1fbc5b8a95f9d123f45b7e3da144cb88db6e1da3eca38cf88660cb"
		id = "46c82d27-5683-5acd-9a3c-d69613091ecc"

	strings:
		$s1 = {4d 61 6e 63 68 65 20 45 6e 74 65 72 70 72 69 73 65 73 20 4c 69 6d 69 74 65 64 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and 1 of them
}

rule APT_FIN7_EXE_Sample_Aug18_2 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "60cd98fc4cb2ae474e9eab81cd34fd3c3f638ad77e4f5d5c82ca46f3471c3020"
		id = "4522cd85-ba85-5afd-8600-1ebabfaf6d02"

	strings:
		$s1 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 6f 72 20 66 72 6f 6d 20 44 6c 6c 4d 61 69 6e 2e}
		$s2 = {4e 65 74 77 6f 72 6b 20 53 6f 66 74 77 61 72 65 20 4c 74 64 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_3 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "995b90281774798a376db67f906a126257d314efc21b03768941f2f819cf61a6"
		id = "0b0ce882-1c18-5741-bb71-0cef010dc778"

	strings:
		$s1 = {63 76 7a 64 66 68 74 6a 6b 64 68 62 66 73 7a 6e 67 6a 64 6e 67}
		$s2 = {73 00 64 00 66 00 6b 00 6a 00 64 00 66 00 6a 00 66 00 68 00 67 00 75 00 72 00 67 00 76 00 6e 00 63 00 6d 00 6e 00 76 00 6d 00 66 00 64 00 6a 00 64 00 6b 00 66 00 6a 00 64 00 6b 00 66 00 6a 00 64 00 66 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and 1 of them
}

rule APT_FIN7_EXE_Sample_Aug18_4 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "4b5405fc253ed3a89c770096a13d90648eac10a7fb12980e587f73483a07aa4c"
		id = "bead79bb-28c2-59ed-985b-e44b41e7f66a"

	strings:
		$s1 = {63 00 3a 00 5c 00 66 00 69 00 6c 00 65 00 2e 00 64 00 61 00 74 00}
		$s2 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 6f 72 20 66 72 6f 6d 20 44 6c 6c 4d 61 69 6e 2e}
		$s3 = {6c 69 6e 65 47 65 74 43 61 6c 6c 49 44 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_5 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
		id = "6c810662-9ceb-5c3b-8f83-5a4aa2a5d461"

	strings:
		$s1 = {78 30 3d 25 64 2c 20 79 30 3d 25 64 2c 20 78 31 3d 25 64 2c 20 79 31 3d 25 64}
		$s3 = {73 00 64 00 66 00 6b 00 6a 00 64 00 66 00 6a 00 66 00 68 00 67 00 75 00 72 00 67 00 76 00 6e 00 63 00 6d 00 6e 00 76 00 6d 00 66 00 64 00 6a 00 64 00 6b 00 66 00 6a 00 64 00 6b 00 66 00 6a 00 64 00 66 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and all of them
}

import "pe"

rule APT_FIN7_EXE_Sample_Aug18_6 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "1439d301d931c8c4b00717b9057b23f0eb50049916a48773b17397135194424a"
		id = "2b2e6b74-5d71-5656-8faf-37c94607d93e"

	strings:
		$s1 = {63 6f 72 65 53 65 72 76 69 63 65 53 68 65 6c 6c 2e 65 78 65}
		$s2 = {50 74 53 65 73 73 69 6f 6e 41 67 65 6e 74 2e 65 78 65}
		$s3 = {54 69 6e 69 4d 65 74 49 2e 65 78 65}
		$s4 = {50 77 6d 53 76 63 2e 65 78 65}
		$s5 = {75 69 53 65 41 67 6e 74 2e 65 78 65}
		$s7 = {4c 48 4f 53 54 3a}
		$s8 = {54 52 41 4e 53 50 4f 52 54 3a}
		$s9 = {4c 50 4f 52 54 3a}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 20KB and ( pe.exports ( "TiniStart" ) or 4 of them )
}

rule APT_FIN7_EXE_Sample_Aug18_7 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "ce8ce35f85406cd7241c6cc402431445fa1b5a55c548cca2ea30eeb4a423b6f0"
		id = "96943654-a6e8-59c0-ab6c-1ab3906a5d05"

	strings:
		$s1 = {6c 69 62 70 6e 67 20 76 65 72 73 69 6f 6e}
		$s2 = {73 00 64 00 66 00 6b 00 6a 00 64 00 66 00 6a 00 66 00 68 00 67 00 75 00 72 00 67 00 76 00 6e 00 63 00 6d 00 6e 00 76 00 6d 00 66 00 64 00 6a 00 64 00 6b 00 66 00 6a 00 64 00 6b 00 66 00 6a 00 64 00 66 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_8 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"
		id = "1eb9810e-2b50-5a93-925e-073bb17e1e6c"

	strings:
		$s1 = {47 65 74 4c 33 73 74 33 72 72}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and all of them
}

rule APT_FIN7_EXE_Sample_Aug18_10 : hardened
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "8cc02b721683f8b880c8d086ed055006dcf6155a6cd19435f74dd9296b74f5fc"
		id = "2c6f557e-31d3-5377-a3fa-4f1507f28386"

	strings:
		$c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
               00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43
               00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
               00 20 00 31 00 20 00 2D 00 20 00 31 00 39 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule APT_FIN7_Sample_EXE_Aug18_1 : hardened
{
	meta:
		description = "Detects FIN7 Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "608003c2165b0954f396d835882479f2504648892d0393f567e4a4aa90659bf9"
		hash2 = "deb62514704852ccd9171d40877c59031f268db917c23d00a2f0113dab79aa3b"
		hash3 = "16de81428a034c7b2636c4a875809ab62c9eefcd326b50c3e629df3b141cc32b"
		hash4 = "3937abdd1fd63587022ed540a31c58c87c2080cdec51dd24af3201a6310059d4"
		hash5 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
		id = "7c66a234-9dee-5279-b855-892b12d036ff"

	strings:
		$s1 = {78 30 3d 25 64 2c 20 79 30 3d 25 64 2c 20 78 31 3d 25 64 2c 20 79 31 3d 25 64}
		$s2 = {64 78 3d 25 64 2c 20 64 79 3d 25 64}
		$s3 = {45 72 72 6f 72 20 77 69 74 68 20 4a 50 32 48 20 62 6f 78 20 73 69 7a 65}
		$co1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 2E 63 6F 64 65
               00 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of ( $s* ) and $co1 at 0x015D
}

rule APT_FIN7_MsDoc_Sep21_1 : hardened
{
	meta:
		description = "Detects MalDocs used by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		date = "2021-09-07"
		score = 85
		hash1 = "d60b6a8310373c9b84e6760c24185535"
		id = "4fbde087-ec1e-5614-af1e-f342b1766fa2"

	strings:
		$xc1 = { 00 4A 00 6F 00 68 00 6E 00 0B 00 57 00 31 00 30
               00 50 00 72 00 6F 00 4F 00 66 00 66 00 31 00 36 }
		$s1 = {77 6f 72 64 5f 64 61 74 61 2e 62 69 6e}
		$s2 = {56 3a 5c 44 4f 43 5c 46 6f 72 5f 4a 53}
		$s3 = {48 6f 6d 65 43 6f 6d 70 61 6e 79}
		$s4 = {57 31 30 50 72 6f 4f 66 66 31 36}

	condition:
		uint16( 0 ) == 0xcfd0 and ( 1 of ( $x* ) or 3 of them )
}

rule SUSP_OBFUSC_JS_Sept21_2 : hardened
{
	meta:
		description = "Detects JavaScript obfuscation as used in MalDocs by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		date = "2021-09-07"
		score = 65
		id = "5ab9cd60-077c-5066-bd2f-8da261aae1e0"

	strings:
		$s1 = {3d 6e 65 77 20 52 65 67 45 78 70 28 53 74 72 69 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65 28}
		$s2 = {2e 63 68 61 72 43 6f 64 65 41 74 28}
		$s3 = {2e 73 75 62 73 74 72 28 30 2c 20}
		$s4 = {76 61 72 20 73 68 65 6c 6c 20 3d 20 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28}
		$s5 = {3d 20 6e 65 77 20 44 61 74 65 28 29 2e 67 65 74 55 54 43 4d 69 6c 6c 69 73 65 63 6f 6e 64 73 28 29 3b}
		$s6 = {2e 64 65 6c 65 74 65 46 69 6c 65 28 57 53 63 72 69 70 74 2e 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 29 3b}

	condition:
		filesize < 6000KB and ( 4 of them )
}

