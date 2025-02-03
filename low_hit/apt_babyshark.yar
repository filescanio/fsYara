import "pe"

rule MAL_PE_Type_BabyShark_Loader : hardened
{
	meta:
		description = "Detects PE Type babyShark loader mentioned in February 2019 blog post by PaloAltNetworks"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/"
		date = "2019-02-24"
		hash1 = "6f76a8e16908ba2d576cf0e8cdb70114dcb70e0f7223be10aab3a728dc65c41c"
		id = "141e7a67-7930-5fd8-ac91-5d31b99e4ff3"

	strings:
		$x1 = {72 65 67 20 61 64 64 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 6f 6d 6d 61 6e 64 20 50 72 6f 63 65 73 73 6f 72 22 20 2f 76 20 41 75 74 6f 52 75 6e 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 25 73 22 20 2f 66}
		$x2 = /mshta\.exe http:\/\/[a-z0-9\.\/]{5,30}\.hta/
		$xc1 = { 57 69 6E 45 78 65 63 00 6B 65 72 6E 65 6C 33 32
               2E 44 4C 4C 00 00 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and ( pe.imphash ( ) == "57b6d88707d9cd1c87169076c24f962e" or 1 of them or for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . issuer contains "thawte SHA256 Code Signing CA" and pe.signatures [ i ] . serial == "0f:ff:e4:32:a5:3f:f0:3b:92:23:f8:8b:e1:b8:3d:9d" ) )
}

rule APT_NK_BabyShark_KimJoingRAT_Apr19_1 : hardened
{
	meta:
		description = "Detects BabyShark KimJongRAT"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://unit42.paloaltonetworks.com/babyshark-malware-part-two-attacks-continue-using-kimjongrat-and-pcrat/"
		date = "2019-04-27"
		hash1 = "d50a0980da6297b8e4cec5db0a8773635cee74ac6f5c1ff18197dfba549f6712"
		id = "c6bd1e1a-68f2-5a2d-a159-b16ea0d33987"

	strings:
		$x1 = {25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 74 00 74 00 6d 00 70 00 2e 00 6c 00 6f 00 67 00}
		$a1 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e}
		$s1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 73 65 72 76 69 63 65 6c 6f 67 69 6e}
		$s2 = {68 74 74 70 73 3a 2f 2f 6c 6f 67 69 6e 2e 79 61 68 6f 6f 2e 63 6f 6d 2f 63 6f 6e 66 69 67 2f 6c 6f 67 69 6e}
		$s3 = {53 45 4c 45 43 54 20 69 64 2c 20 68 6f 73 74 6e 61 6d 65 2c 20 68 74 74 70 52 65 61 6c 6d 2c 20 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c 2c 20 75 73 65 72 6e 61 6d 65 46 69 65 6c 64 2c 20 70 61 73 73 77 6f 72 64 46 69 65 6c 64 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e}
		$s4 = {5c 6d 6f 7a 73 71 6c 69 74 65 33 2e 64 6c 6c}
		$s5 = {53 4d 54 50 20 50 61 73 73 77 6f 72 64}
		$s6 = {59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or ( $a1 and 3 of ( $s* ) ) )
}

