rule Mirai_Botnet_Malware : hardened
{
	meta:
		description = "Detects Mirai Botnet Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-04"
		modified = "2023-01-27"
		hash1 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash2 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash3 = "20683ff7a5fec1237fc09224af40be029b9548c62c693844624089af568c89d4"
		hash4 = "2efa09c124f277be2199bee58f49fc0ce6c64c0bef30079dfb3d94a6de492a69"
		hash5 = "420bf9215dfb04e5008c5e522eee9946599e2b323b17f17919cd802ebb012175"
		hash6 = "62cdc8b7fffbaf5683a466f6503c03e68a15413a90f6afd5a13ba027631460c6"
		hash7 = "70bb0ec35dd9afcfd52ec4e1d920e7045dc51dca0573cd4c753987c9d79405c0"
		hash8 = "89570ae59462e6472b6769545a999bde8457e47ae0d385caaa3499ab735b8147"
		hash9 = "bf0471b37dba7939524a30d7d5afc8fcfb8d4a7c9954343196737e72ea4e2dc4"
		hash10 = "c61bf95146c68bfbbe01d7695337ed0e93ea759f59f651799f07eecdb339f83f"
		hash11 = "d9573c3850e2ae35f371dff977fc3e5282a5e67db8e3274fd7818e8273fd5c89"
		hash12 = "f1100c84abff05e0501e77781160d9815628e7fd2de9e53f5454dbcac7c84ca5"
		hash13 = "fb713ccf839362bf0fbe01aedd6796f4d74521b133011b408e42c1fd9ab8246b"
		id = "a678e9f7-d516-5bdb-962e-b9d39d8a64bb"

	strings:
		$x1 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f}
		$x2 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67}
		$x3 = {2f 64 65 76 2f 77 61 74 63 68 64 6f 67}
		$x5 = {2e 6d 64 65 62 75 67 2e 61 62 69 33 32}
		$s1 = {4c 43 4f 47 51 47 50 54 47 50}
		$s2 = {51 55 4b 4c 45 4b 4c 55 4b 56 4a 4f 47}
		$s3 = {43 46 4f 4b 4c 4b 51 56 50 43 56 4d 50}
		$s4 = {51 57 52 47 50 54 4b 51 4d 50}
		$s5 = {48 57 43 4c 56 47 41 4a}
		$s6 = {4e 4b 51 56 47 4c 4b 4c 45}

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or 4 of ( $s* ) )
}

rule Mirai_1_May17 : hardened
{
	meta:
		description = "Detects Mirai Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-05-12"
		super_rule = 1
		hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
		hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
		hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
		id = "ac85ee28-a01f-5c3d-a534-0c19a3dc92e7"

	strings:
		$s1 = {47 45 54 20 2f 62 69 6e 73 2f 6d 69 72 61 69 2e 78 38 36 20 48 54 54 50 2f 31 2e 30}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 5000KB and all of them )
}

rule Miari_2_May17 : hardened
{
	meta:
		description = "Detects Mirai Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-05-12"
		super_rule = 1
		hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
		hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
		id = "1c2cc98d-8ca5-5055-8f86-7f85c046ccd9"

	strings:
		$s1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 34 31 2e 30 2e 32 32 37 32 2e 31 30 31 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36}
		$s2 = {47 45 54 20 2f 67 2e 70 68 70 20 48 54 54 50 2f 31 2e 31}
		$s3 = {68 74 74 70 73 3a 2f 2f 25 5b 5e 2f 5d 2f 25 73}
		$s4 = {70 61 73 73 22 20 76 61 6c 75 65 3d 22 5b 5e 22 5d 2a 22}
		$s5 = {6a 62 65 75 70 71 38 34 76 37 2e 32 79 2e 6e 65 74}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 5000KB and 2 of them )
}

rule MAL_ELF_LNX_Mirai_Oct10_1 : hardened
{
	meta:
		description = "Detects ELF Mirai variant"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-10-27"
		modified = "2023-01-27"
		hash1 = "3be2d250a3922aa3f784e232ce13135f587ac713b55da72ef844d64a508ddcfe"
		id = "7bb28f03-03ba-581a-bc03-bd09a52787d9"

	strings:
		$x1 = {20 2d 72 20 2f 76 69 2f 6d 69 70 73 2e 62 75 73 68 69 64 6f 3b 20}
		$x2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f}
		$s1 = {50 4f 53 54 20 2f 63 74 72 6c 74 2f 44 65 76 69 63 65 55 70 67 72 61 64 65 5f 31 20 48 54 54 50 2f 31 2e 31}
		$s2 = {6c 6f 61 64 55 52 4c 3e 24 28 65 63 68 6f 20 48 55 41 57 45 49 55 50 4e 50 29 3c 2f 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e 3c 2f 75 3a 55 70 67 72 61 64 65 3e 3c 2f 73 3a 42 6f 64 79 3e 3c 2f 73 3a 45 6e 76 65 6c 6f 70 65 3e}
		$s3 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f}

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or all of ( $x* ) )
}

rule MAL_ELF_LNX_Mirai_Oct10_2 : hardened
{
	meta:
		description = "Detects ELF malware Mirai related"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-10-27"
		hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
		id = "421b7708-030e-50d1-bf2e-e91758a48c00"

	strings:
		$c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and all of them
}

rule MAL_Mirai_Nov19_1 : hardened
{
	meta:
		description = "Detects Mirai malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/bad_packets/status/1194049104533282816"
		date = "2019-11-13"
		hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
		hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"
		id = "40edcb29-9e10-5b87-ba79-8e3f629829e5"

	strings:
		$s1 = {53 45 52 56 5a 55 58 4f}
		$s2 = {2d 6c 6f 6c 64 6f 6e 67 73}
		$s3 = {2f 64 65 76 2f 6e 75 6c 6c}
		$s4 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78}
		$sc1 = { 47 72 6F 75 70 73 3A 09 30 }

	condition:
		uint16( 0 ) == 0x457f and filesize <= 100KB and 4 of them
}

rule MAL_ARM_LNX_Mirai_Mar13_2022 : hardened
{
	meta:
		description = "Detects new ARM Mirai variant"
		author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
		date = "2022-03-16"
		hash1 = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"
		id = "54d8860e-fc45-5571-b68c-66590c67a705"

	strings:
		$str1 = {2f 68 6f 6d 65 2f 6c 61 6e 64 6c 65 79 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 62 75 69 6c 64 2f 74 65 6d 70 2d 61 72 6d 76 36 6c 2f 67 63 63 2d 63 6f 72 65 2f 67 63 63 2f 63 6f 6e 66 69 67 2f 61 72 6d 2f 6c 69 62 31 66 75 6e 63 73 2e 61 73 6d}
		$str2 = {2f 68 6f 6d 65 2f 6c 61 6e 64 6c 65 79 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 62 75 69 6c 64 2f 74 65 6d 70 2d 61 72 6d 76 36 6c 2f 67 63 63 2d 63 6f 72 65 2f 67 63 63 2f 63 6f 6e 66 69 67 2f 61 72 6d 2f 6c 69 62 31 66 75 6e 63 73 2e 61 73 6d}
		$str3 = {2f 68 6f 6d 65 2f 6c 61 6e 64 6c 65 79 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 62 75 69 6c 64 2f 74 65 6d 70 2d 61 72 6d 76 36 6c 2f 67 63 63 2d 63 6f 72 65 2f 67 63 63 2f 63 6f 6e 66 69 67 2f 61 72 6d}
		$str4 = {2f 68 6f 6d 65 2f 6c 61 6e 64 6c 65 79 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 61 62 6f 72 69 67 69 6e 61 6c 2f 62 75 69 6c 64 2f 73 69 6d 70 6c 65 2d 63 72 6f 73 73 2d 63 6f 6d 70 69 6c 65 72 2d 61 72 6d 76 36 6c 2f 62 69 6e 2f 2e 2e 2f 63 63 2f 69 6e 63 6c 75 64 65}
		$attck1 = {61 74 74 61 63 6b 2e 63}
		$attck2 = {61 74 74 61 63 6b 73 2e 63}
		$attck3 = {61 6e 74 69 5f 67 64 62 5f 65 6e 74 72 79}
		$attck4 = {72 65 73 6f 6c 76 65 5f 63 6e 63 5f 61 64 64 72}
		$attck5 = {61 74 74 61 63 6b 5f 67 72 65 5f 65 74 68}
		$attck6 = {61 74 74 61 63 6b 5f 75 64 70 5f 67 65 6e 65 72 69 63}
		$attck7 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 70}
		$attck8 = {61 74 74 61 63 6b 5f 69 63 6d 70 65 63 68 6f}

	condition:
		uint16( 0 ) == 0x457f and ( 3 of ( $str* ) or 4 of ( $attck* ) )
}

