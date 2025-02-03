rule BronzeButler_Daserf_Delphi_1 : hardened
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "89a80ca92600af64eb9c32cab4e936c7d675cf815424d72438973e2d6788ef64"
		hash2 = "b1bd03cd12638f44d9ace271f65645e7f9b707f86e9bcf790e0e5a96b755556b"
		hash3 = "22e1965154bdb91dd281f0e86c8be96bf1f9a1e5fe93c60a1d30b79c0c0f0d43"
		id = "88372e62-3bba-58dc-825c-f35533e42825"

	strings:
		$s1 = {53 65 72 76 69 63 65 73 2e 65 78 65}
		$s2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 31 31 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 53 56 31 29}
		$s3 = {6c 33 32 2e 64 6c 6c}
		$s4 = {74 50 72 6f 63 65 73 73 3a}
		$s5 = {20 49 6e 6a 65 63 74 50 72}
		$s6 = {57 00 72 00 69 00 74 00 65 00 24 00 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 72 00 65 00 61 00 74 00 69 00 6e 00 67 00 20 00 76 00 61 00 72 00 69 00 61 00 6e 00 74 00 20 00 6f 00 72 00 20 00 73 00 61 00 66 00 65 00 20 00 61 00 72 00 72 00 61 00 79 00 1f 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 20 00 74 00 6f 00 20 00 74 00 69 00 6d 00 65 00 20 00 65 00 6e 00 63 00 6f 00 64 00 65 00}
		$s7 = {6f 6e 5c 72 75 6e 20 2f 76 20}
		$s8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e}
		$s9 = {6d 73 31 6e 67 32 64 33 64 32 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 3 of them )
}

import "pe"

rule BronzeButler_Daserf_C_1 : hardened
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "a4afd9df1b4cc014c3a89d7b4a560fa3e368b02286c42841762714b23e68cc05"
		hash2 = "90ac1fb148ded4f46949a5fea4cd8c65d4ea9585046d66459328a5866f8198b2"
		hash3 = "331ac0965b50958db49b7794cc819b2945d7b5e5e919c185d83e997e205f107b"
		hash4 = "b1fdc6dc330e78a66757b77cc67a0e9931b777cd7af9f839911eecb74c04420a"
		hash5 = "15abe7b1355cd35375de6dde57608f6d3481755fdc9e71d2bfc7c7288db4cd92"
		hash6 = "85544d2bcaf8e6ca32bbc0a9e9583c9db1dce837043f555a7ff66363d5858439"
		hash7 = "2dc24622c1e91642a21a64c0dd31cbe953e8f77bd3d6abcf2c4676c3b11bb162"
		hash8 = "2bdb88fa24cffba240b60416835189c76a9920b6c3f6e09c3c4b171c2f57031c"
		id = "62a5cc4a-7c58-5e4d-ac23-8d1f850a540a"

	strings:
		$s1 = {28 63 29 20 32 30 31 30 20 44 59 41 4d 41 52 20 45 6e 47 69 6e 65 65 72 69 6e 47 2c 20 41 6c 6c 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2c 20 68 74 74 70 3a 2f 2f 77 77 77 2e 64 79 61 6d 61 72 2e 63 6f 6d 2e}
		$s2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 29}
		$a1 = {6e 64 6b 6b 77 71 67 63 6d}
		$a2 = {52 74 6c 47 65 74 43 6f}
		$a3 = {68 75 74 69 6c 73}
		$b1 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 53 79 73 74 65 6d}
		$b2 = {6d 73 69 64 2e 64 61 74}
		$b3 = {44 00 52 00 49 00 56 00 45 00 5f 00 52 00 45 00 4d 00 4f 00 54 00 45 00}
		$b4 = {25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73}
		$b5 = {6a 63 62 68 65 2e 61 73 70}
		$b6 = {65 64 73 65 74 2e 61 73 70}
		$b7 = {62 78 63 76 65 2e 61 73 70}
		$b8 = {68 63 76 65 72 79 2e 70 68 70}
		$b9 = {79 6e 68 6b 65 66 2e 70 68 70}
		$b10 = {64 6b 67 77 65 79 2e 70 68 70}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "088382f4887e3b2c4bd5157f2d72b618" or all of ( $a* ) or 4 of them )
}

rule BronzeButler_DGet_1 : hardened
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "bd81521445639aaa5e3bcb5ece94f73feda3a91880a34a01f92639f8640251d6"
		id = "d60fcc9f-0f17-5871-9e8e-71d26e2f46bc"

	strings:
		$s2 = {44 47 65 74 20 54 6f 6f 6c 20 4d 61 64 65 20 62 79 20 58 5a}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 10KB and 1 of them )
}

rule BronzeButler_UACBypass_1 : hardened
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "fe06b99a0287e2b2d9f7faffbda3a4b328ecc05eab56a3e730cfc99de803b192"
		id = "01853352-58fc-56a3-8c20-08405c71e251"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 42 79 70 61 73 73 55 61 63 44 6c 6c 2e 70 64 62}
		$x2 = {25 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 66 00 69 00 6c 00 65 00 73 00 25 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00}
		$x3 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00}
		$x4 = {42 79 70 61 73 73 55 61 63 2e 70 64 62}
		$x5 = {5b 00 62 00 79 00 70 00 61 00 73 00 73 00 55 00 41 00 43 00 5d 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 58 00 36 00 34 00}
		$x6 = {5b 00 62 00 79 00 70 00 61 00 73 00 73 00 55 00 41 00 43 00 5d 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 58 00 38 00 36 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them )
}

rule BronzeButler_xxmm_1 : hardened
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "7197de18bc5a4c854334ff979f3e4dafa16f43d7bf91edfe46f03e6cc88f7b73"
		id = "0e413e3a-fb61-58bc-9ecb-4ef76e83a7f3"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 52 65 66 6c 65 63 74 69 76 4c 6f 61 64 65 72 2e 70 64 62}
		$x3 = {5c 50 72 6f 6a 65 63 74 73 5c 78 78 6d 6d 32 5c 52 65 6c 65 61 73 65 5c}
		$x5 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 2f 70 68 70 74 75 6e 6e 65 6c 2e 70 68 70}
		$s1 = {78 78 6d 6d 32 2e 65 78 65}
		$s2 = {5c 00 41 00 76 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}
		$s3 = {73 74 64 61 70 69 5f 66 73 5f 66 69 6c 65 5f 64 6f 77 6e 6c 6f 61 64}
		$s4 = {73 74 64 61 70 69 5f 73 79 6e 63 73 68 65 6c 6c 5f 6f 70 65 6e}
		$s5 = {73 74 64 61 70 69 5f 65 78 65 63 75 74 65 5f 73 6c 65 65 70}
		$s6 = {73 74 64 61 70 69 5f 73 79 6e 63 73 68 65 6c 6c 5f 6b 69 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or 4 of them )
}

rule BronzeButler_RarStar_1 : hardened
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "0fc1b4fdf0dc5373f98de8817da9380479606f775f5aa0b9b0e1a78d4b49e5f4"
		id = "770270b3-6743-5efb-84d8-b63f1df800d9"

	strings:
		$s1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 2b 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 2b 00 4d 00 53 00 49 00 45 00 2b 00 38 00 2e 00 30 00 3b 00 2b 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2b 00 4e 00 54 00 2b 00 36 00 2e 00 30 00 3b 00 2b 00 53 00 56 00 31 00 29 00}
		$s2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 2e 00 6a 00 70 00}
		$s3 = {31 36 44 37 33 45 32 32 2d 38 37 33 44 2d 44 35 38 45 2d 34 46 34 32 2d 45 36 30 35 35 42 43 39 38 32 35 45}
		$s4 = {5c 2a 2e 72 61 72}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule Daserf_Nov1_BronzeButler : hardened
{
	meta:
		description = "Detects Daserf malware used by Bronze Butler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/ffeCfd"
		date = "2017-11-08"
		hash1 = "5ede6f93f26ccd6de2f93c9bd0f834279df5f5cfe3457915fae24a3aec46961b"
		id = "58c4d3dc-c516-567b-8746-4e185c3cd328"

	strings:
		$x1 = {6d 73 74 6d 70 31 38 34 35 32 33 34 2e 65 78 65}
		$x2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 30 3b 20 53 56 31 29}
		$x3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 31 31 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 53 56 31 29}
		$s1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 2a 2f 2a}
		$s2 = {50 72 6f 78 79 45 6e 61 62 6c 65}
		$s3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72}
		$s4 = {69 65 78 70 6c 6f 72 65 2e 65 78 65}
		$s5 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75}
		$s6 = {72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73}
		$s7 = {77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72}
		$s8 = {44 6f 63 75 6d 65 6e 74 73 20 61 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or 5 of them )
}

