rule PassCV_Sabre_Malware_1 : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "24a9bfbff81615a42e42755711c8d04f359f3bf815fb338022edca860ff1908a"
		hash2 = "e61e56b8f2666b9e605127b4fcc7dc23871c1ae25aa0a4ea23b48c9de35d5f55"
		id = "99a26daa-c563-5b23-89b9-965d8ce7229d"

	strings:
		$x1 = {46 3a 5c 45 78 63 61 6c 69 62 75 72 5c 45 78 63 61 6c 69 62 75 72 5c 45 78 63 61 6c 69 62 75 72 5c}
		$x2 = {62 69 6e 5c 6f 53 61 62 65 72 53 76 63 2e 70 64 62}
		$s1 = {63 6d 64 2e 65 78 65 20 2f 63 20 4d 44 20}
		$s2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 3f 00 69 00 65 00 3d 00 75 00 74 00 66 00 2d 00 38 00 26 00 66 00 3d 00 38 00 26 00 72 00 73 00 76 00 5f 00 62 00 70 00 3d 00 30 00 26 00 72 00 73 00 76 00 5f 00 69 00 64 00 78 00 3d 00 31 00 26 00 74 00 6e 00 3d 00 62 00 61 00 69 00 64 00 75 00 26 00 77 00 64 00 3d 00 69 00 70 00 31 00 33 00 38 00}
		$s3 = {43 00 6c 00 6f 00 75 00 64 00 52 00 75 00 6e 00 2e 00 65 00 78 00 65 00}
		$s4 = {53 00 61 00 62 00 65 00 72 00 53 00 76 00 63 00 42 00 2e 00 65 00 78 00 65 00}
		$s5 = {53 00 61 00 62 00 65 00 72 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00}
		$s6 = {53 00 61 00 62 00 65 00 72 00 53 00 76 00 63 00 57 00 2e 00 65 00 78 00 65 00}
		$s7 = {74 00 69 00 61 00 6e 00 73 00 68 00 69 00 79 00 65 00 64 00 40 00 69 00 61 00 6f 00 6d 00 61 00 6f 00 6d 00 61 00 72 00 6b 00 31 00 23 00 32 00 33 00 6d 00 61 00 72 00 6b 00 31 00 32 00 33 00 74 00 6f 00 6b 00 65 00 6e 00 6d 00 61 00 72 00 6b 00 71 00 77 00 65 00 62 00 6a 00 69 00 75 00 67 00 61 00 36 00 36 00 34 00 31 00 31 00 35 00}
		$s8 = {49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 20 46 61 69 6c 65 64 21}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) and 5 of ( $s* ) ) ) or ( all of them )
}

rule PassCV_Sabre_Malware_Signing_Cert : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		score = 50
		hash1 = "7c32885c258a6d5be37ebe83643f00165da3ebf963471503909781540204752e"
		id = "2b2d1313-6454-5e3f-9b58-5b1a26739ba8"

	strings:
		$s1 = {57 4f 4f 44 54 41 4c 45 20 54 45 43 48 4e 4f 4c 4f 47 59 20 49 4e 43}
		$s2 = {46 6c 79 69 6e 67 62 69 72 64 20 54 65 63 68 6e 6f 6c 6f 67 79 20 4c 69 6d 69 74 65 64}
		$s3 = {4e 65 6f 61 63 74 20 43 6f 2e 2c 20 4c 74 64 2e}
		$s4 = {41 6d 61 7a 47 61 6d 65 20 41 67 65 20 49 6e 74 65 72 6e 65 74 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 20 4c 74 64}
		$s5 = {45 4d 47 20 54 65 63 68 6e 6f 6c 6f 67 79 20 4c 69 6d 69 74 65 64}
		$s6 = {5a 65 6d 69 20 49 6e 74 65 72 61 63 74 69 76 65 20 43 6f 2e 2c 20 4c 74 64}
		$s7 = {33 33 37 20 54 65 63 68 6e 6f 6c 6f 67 79 20 4c 69 6d 69 74 65 64}
		$s8 = {52 75 6e 65 77 61 6b 65 72 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 30}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them )
}

rule PassCV_Sabre_Malware_2 : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "475d1c2d36b2cf28b28b202ada78168e7482a98b42ff980bbb2f65c6483db5b4"
		hash2 = "009645c628e719fad2e280ef60bbd8e49bf057196ac09b3f70065f1ad2df9b78"
		hash3 = "92479c7503393fc4b8dd7c5cd1d3479a182abca3cda21943279c68a8eef9c64b"
		hash4 = "0c7b952c64db7add5b8b50b1199fc7d82e9b6ac07193d9ec30e5b8d353b1f6d2"
		id = "dd9eb5f6-9faa-584d-b3b5-6dcfdc3f359c"

	strings:
		$x1 = {6e 63 50 72 6f 78 79 58 6c 6c}
		$s1 = {55 6e 69 73 63 72 69 62 65 2e 64 6c 6c}
		$s2 = {57 53 32 5f 33 32 2e 64 6c 6c}
		$s3 = {50 72 6f 78 79 44 6c 6c}
		$s4 = {4a 44 4e 53 41 50 49 2e 64 6c 6c}
		$s5 = {78 36 34 2e 64 61 74}
		$s6 = {4c 53 70 79 62 32}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 4000KB and $x1 ) or ( all of them )
}

rule PassCV_Sabre_Malware_Excalibur_1 : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "21566f5ff7d46cc9256dae8bc7e4c57f2b9261f95f6ad2ac921558582ea50dfb"
		hash2 = "02922c5d994e81629d650be2a00507ec5ca221a501fe3827b5ed03b4d9f4fb70"
		id = "eadad36c-49c8-50e1-8334-813d2e760fe9"

	strings:
		$x1 = {46 3a 5c 45 78 63 61 6c 69 62 75 72 5c 45 78 63 61 6c 69 62 75 72 5c}
		$x2 = {45 78 63 61 6c 69 62 75 72 5c 62 69 6e 5c 53 68 65 6c 6c 2e 70 64 62}
		$x3 = {53 00 61 00 62 00 65 00 72 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00}
		$s1 = {42 00 42 00 42 00 2e 00 65 00 78 00 65 00}
		$s2 = {41 00 41 00 41 00 2e 00 65 00 78 00 65 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of ( $x* ) or all of ( $s* ) ) or 3 of them
}

rule PassCV_Sabre_Malware_3 : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "28c7575b2368a9b58d0d1bf22257c4811bd3c212bd606afc7e65904041c29ce1"
		id = "03e5efc0-6076-501f-a600-b3d9008a8711"

	strings:
		$x1 = {4e 00 58 00 4b 00 49 00 4c 00 4c 00}
		$s1 = {32 4f 4c 45 33 32 2e 44 4c 4c}
		$s2 = {6c 00 6f 00 63 00 61 00 6c 00 73 00 70 00 6e 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {21 54 68 69 73 20 69 73 20 61 20 57 69 6e 33 32 20 70 72 6f 67 72 61 6d 2e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 8000KB and $x1 and 2 of ( $s* ) )
}

rule PassCV_Sabre_Malware_4 : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "27463bcb4301f0fdd95bc10bf67f9049e161a4e51425dac87949387c54c9167f"
		id = "f182064d-3a91-5a61-aa0f-2ce491a60126"

	strings:
		$s1 = {51 57 4e 6a 5a 58 42 30 4f 6e}
		$s2 = {56 58 4e 6c 63 69 31 42 5a 32 56 75 64 44 6f 67 54}
		$s3 = {64 47 46 7a 61 79 35 6b 62 6e 4d 45 33 6c 75 4c 6d 4e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule PassCV_Sabre_Tool_NTScan : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "0f290612b26349a551a148304a0bd3b0d0651e9563425d7c362f30bd492d8665"
		id = "6ec3371a-2a1c-53d1-b650-d28728db1b40"

	strings:
		$x1 = {4e 00 54 00 73 00 63 00 61 00 6e 00 2e 00 45 00 58 00 45 00}
		$x2 = {4e 00 54 00 73 00 63 00 61 00 6e 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00}
		$s1 = {61 64 6d 69 6e 24}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 2 of them )
}

rule PassCV_Sabre_Malware_5 : hardened
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "03aafc5f468a84f7dd7d7d38f91ff17ef1ca044e5f5e8bbdfe589f5509b46ae5"
		id = "ce8d1b9e-7750-5796-a048-20bfd48c6aee"

	strings:
		$x1 = {6e 63 69 72 63 54 4d 50 67}
		$x2 = {7e 53 48 45 4c 4c 23}
		$x3 = {4e 2e 61 64 6f 62 65 2e 78 6d}
		$s1 = {4e 45 4c 33 32 2e 44 4c 4c}
		$s2 = {42 00 69 00 74 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s3 = {7c 78 74 70 6c 68 64}
		$s4 = {53 00 45 00 52 00 56 00 49 00 43 00 45 00 43 00 4f 00 52 00 45 00}
		$s5 = {53 00 48 00 41 00 52 00 45 00 43 00 4f 00 4e 00 54 00 52 00 4f 00 4c 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 4000KB and 1 of ( $x* ) or all of ( $s* ) )
}

