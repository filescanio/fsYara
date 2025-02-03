rule TA17_318B_volgmer : hardened
{
	meta:
		description = "Malformed User Agent in Volgmer malware"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		date = "2017-11-15"
		id = "20a7f64b-0fee-5235-ac91-2fc811497ac6"

	strings:
		$s = {4d 6f 7a 69 6c 6c 61 72 2f}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and $s
}

import "pe"

rule Volgmer_Malware : hardened
{
	meta:
		description = "Detects Volgmer malware as reported in US CERT TA17-318B"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		date = "2017-11-15"
		hash1 = "ff2eb800ff16745fc13c216ff6d5cc2de99466244393f67ab6ea6f8189ae01dd"
		hash2 = "8fcd303e22b84d7d61768d4efa5308577a09cc45697f7f54be4e528bbb39435b"
		hash3 = "eff3e37d0406c818e3430068d90e7ed2f594faa6bb146ab0a1c00a2f4a4809a5"
		hash4 = "e40a46e95ef792cf20d5c14a9ad0b3a95c6252f96654f392b4bc6180565b7b11"
		hash5 = "6dae368eecbcc10266bba32776c40d9ffa5b50d7f6199a9b6c31d40dfe7877d1"
		hash6 = "fee0081df5ca6a21953f3a633f2f64b7c0701977623d3a4ec36fff282ffe73b9"
		hash7 = "53e9bca505652ef23477e105e6985102a45d9a14e5316d140752df6f3ef43d2d"
		hash8 = "1d0999ba3217cbdb0cc85403ef75587f747556a97dee7c2616e28866db932a0d"
		id = "a8df5f70-69e7-5c95-8af7-7dda6bb9c77a"

	strings:
		$x1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 72 2f 35 2e 30}
		$x2 = {5b 00 43 00 6d 00 64 00 5d 00 20 00 2d 00 20 00 43 00 4d 00 44 00 5f 00 42 00 4f 00 54 00 43 00 4d 00 44 00 5f 00 43 00 4f 00 4e 00 4e 00 4c 00 4f 00 47 00 5f 00 47 00 45 00 54 00}
		$x3 = {5b 54 65 73 74 43 6f 6e 6e 65 63 74 20 54 6f 20 42 6f 74 5d 20 2d 20 50 6f 72 74 20 3d 20 25 64}
		$x4 = {62 35 30 61 33 33 38 32 36 34 32 32 36 62 36 64 35 37 63 31 39 33 36 64 39 64 62 31 34 30 62 61 37 34 61 32 38 39 33 30 32 37 30 61 30 38 33 33 35 33 36 34 35 61 39 62 35 31 38 36 36 31 66 34 66 63 65 61 31 36 30 64 37}
		$s1 = {25 00 73 00 69 00 67 00 66 00 78 00 25 00 63 00 25 00 63 00 25 00 63 00 2e 00 65 00 78 00 65 00}
		$s2 = {48 5f 25 73 5f 25 30 31 36 49 36 34 58 5f 25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 54 58 54}
		$s3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 73 00 20 00 3e 00 20 00 25 00 73 00 20 00 32 00 3e 00 26 00 31 00}
		$s4 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 2e 64 6c 6c}
		$s5 = {43 6f 6e 64 20 46 61 69 6c 2e}
		$s6 = {54 68 65 20 25 73 20 25 73 25 73}
		$s7 = {25 73 20 22 25 73 22 25 73 20 22 25 73 22 20 25 73 20 22 25 73 22}
		$s8 = {44 4c 4c 5f 53 70 69 64 65 72 2e 64 6c 6c}

	condition:
		filesize < 400KB and ( 1 of ( $x* ) or ( uint16( 0 ) == 0x5a4d and 2 of them ) ) or ( uint16( 0 ) == 0x5a4d and pe.imphash ( ) == "ea42395e901b33bad504798e0f0fd74b" )
}

