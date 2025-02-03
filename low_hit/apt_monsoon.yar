import "pe"

rule Monsoon_APT_Malware_1 : hardened
{
	meta:
		description = "Detects malware from Monsoon APT"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2"
		date = "2017-09-08"
		modified = "2023-01-06"
		hash1 = "c9642f44d33e4c990066ce6fa0b0956ff5ace6534b64160004df31b9b690c9cd"
		id = "a543c46d-01fc-5276-a915-183263956455"

	strings:
		$s1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20}
		$s2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 54 65 6d 70 6c 61 74 65 73 5c}
		$s3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "a0c824244f1d36ea1dd2759cf7599cd1" or all of them ) )
}

rule Monsoon_APT_Malware_2 : hardened
{
	meta:
		description = "Detects malware from Monsoon APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2"
		date = "2017-09-08"
		hash1 = "17c3d0fe08e1184c9737144fa065f4530def30d6591e5414a36463609f9aa53a"
		hash2 = "8e0574ebf3dc640ac82987ab6ee2a02fc3dd5eaf4f6b5275272ba887acd15ac0"
		hash3 = "bf93ca5f497fc7f38533d37fd4c083523ececc34aa2d3660d81014c0d9091ae3"
		id = "dbbccf56-7e36-5c3a-b8d9-ee08d077f29f"

	strings:
		$x1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 63 6f 63 6f 2e 65 78 65}
		$x2 = {3a 5c 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c 63 6f 6e 66 69 67}
		$x3 = {20 00 63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 5b 00 42 00 41 00 43 00 4b 00 53 00 50 00 41 00 5b 00 50 00 41 00 47 00 45 00 20 00 44 00 4f 00 5b 00 43 00 41 00 50 00 53 00 20 00 4c 00 4f 00 5b 00 50 00 41 00 47 00 45 00 20 00 55 00 50 00 54 00 50 00 58 00 34 00 39 00 38 00 2e 00 64 00 54 00 50 00 58 00 34 00 39 00 39 00 2e 00 64 00}
		$s1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 54 65 6d 70 6c 61 74 65 73 5c 6d 73 76 63 72 74 2e 64 6c 6c}
		$s2 = {25 00 30 00 34 00 64 00 2f 00 25 00 30 00 32 00 64 00 2f 00 25 00 30 00 32 00 64 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 20 00 2d 00 20 00 7b 00 25 00 73 00 7d 00}
		$s3 = {77 69 6e 69 6e 65 74 2e 64 6c 6c 20 20 20 20}
		$s4 = {44 4d 43 5a 30 30 30 31 2e 64 61 74}
		$s5 = {54 5a 30 30 30 30 30 30 31 2e 64 61 74}
		$s6 = {5c 4d 55 54 2e 64 61 74}
		$s7 = {6f 75 65 6d 6d 2f 65 6d 6d 21 21 21 21 21 21 21 21 21 21 21 21 21}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and ( 1 of ( $x* ) or 3 of them ) )
}

