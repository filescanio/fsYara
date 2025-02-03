import "pe"

rule APT_TA18_149A_Joanap_Sample1 : hardened
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		date = "2018-05-30"
		hash1 = "ea46ed5aed900cd9f01156a1cd446cbb3e10191f9f980e9f710ea1c20440c781"
		id = "a3a4f9a6-367d-5d99-bffb-f4ff03fa4a09"

	strings:
		$x1 = {63 6d 64 2e 65 78 65 20 2f 71 20 2f 63 20 6e 65 74 20 73 68 61 72 65 20 61 64 6e 69 6d 24}
		$x2 = {5c 5c 25 73 5c 61 64 6e 69 6d 24 5c 73 79 73 74 65 6d 33 32 5c 25 73}
		$s1 = {53 4d 42 5f 44 6c 6c 2e 64 6c 6c}
		$s2 = {25 73 20 55 73 65 72 20 6f 72 20 50 61 73 73 77 6f 72 64 20 69 73 20 6e 6f 74 20 63 6f 72 72 65 63 74 21}
		$s3 = {70 65 72 66 77 30 36 2e 64 61 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "f0087d7b90876a2769f2229c6789fcf3" or 1 of ( $x* ) or 2 of them )
}

import "pe"

rule APT_TA18_149A_Joanap_Sample2 : hardened
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		date = "2018-05-30"
		hash1 = "077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885"
		id = "9f4e6e6c-ee2b-5fa3-bf85-5a1652b38c52"

	strings:
		$s1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 57 6d 6d 76 73 76 63}
		$s2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 53 43 61 72 64 50 72 76}
		$s3 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 57 6d 6d 76 73 76 63 2e 64 6c 6c}
		$s4 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 63 61 72 64 70 72 76 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "e8cd12071a8e823ebc434c8ee3e23203" or 2 of them )
}

import "pe"

rule APT_TA18_149A_Joanap_Sample3 : hardened
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		date = "2018-05-30"
		hash1 = "a1c483b0ee740291b91b11e18dd05f0a460127acfc19d47b446d11cd0e26d717"
		id = "1c2551bc-01dd-5b30-a4cc-703a868cde73"

	strings:
		$s1 = {6d 73 73 76 63 64 6c 6c 2e 64 6c 6c}
		$s2 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 69 6e 64 65 78 2e 68 74 6d 6c}
		$s3 = {4c 00 4f 00 47 00 49 00 4e 00 44 00 4c 00 47 00}
		$s4 = {72 75 6e 64 6c 6c}
		$s5 = {25 25 73 5c 25 25 73 25 25 30 25 64 64 2e 25 25 73}
		$s6 = {25 25 73 5c 25 25 73 25 25 30 25 64 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "f6f7b2e00921129d18061822197111cd" or 3 of them )
}

