import "pe"

rule GoldDragon_malware_Feb18_1 : hardened
{
	meta:
		description = "Detects malware from Gold Dragon report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
		date = "2018-02-03"
		score = 90
		id = "1da29f0f-4e83-56a0-b843-3b19d9b9a1b7"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "168c2f7752511dfd263a83d5d08a90db" or pe.imphash ( ) == "0606858bdeb129de33a2b095d7806e74" or pe.imphash ( ) == "51d992f5b9e01533eb1356323ed1cb0f" or pe.imphash ( ) == "bb801224abd8562f9ee8fb261b75e32a" )
}

rule GoldDragon_Aux_File : hardened
{
	meta:
		description = "Detects export from Gold Dragon - February 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
		date = "2018-02-03"
		score = 90
		id = "8f23dec4-e369-500f-a036-32df13e5543e"

	strings:
		$x1 = {2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 72 65 67 6b 65 79 65 6e 75 6d 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f}

	condition:
		filesize < 500KB and 1 of them
}

import "pe"

rule GoldDragon_Ghost419_RAT : hardened
{
	meta:
		description = "Detects Ghost419 RAT from Gold Dragon report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/rW1yvZ"
		date = "2018-02-03"
		modified = "2023-01-06"
		hash1 = "45bfa1327c2c0118c152c7192ada429c6d4ae03b8164ebe36ab5ba9a84f5d7aa"
		hash2 = "ee7a9a7589cbbcac8b6bf1a3d9c5d1c1ada98e68ac2f43ff93f768661b7e4a85"
		hash3 = "dee482e5f461a8e531a6a7ea4728535aafdc4941a8939bc3c55f6cb28c46ad3d"
		hash4 = "2df9e274ce0e71964aca4183cec01fb63566a907981a9e7384c0d73f86578fe4"
		hash5 = "111ab6aa14ef1f8359c59b43778b76c7be5ca72dc1372a3603cd5814bfb2850d"
		hash6 = "0ca12b78644f7e4141083dbb850acbacbebfd3cfa17a4849db844e3f7ef1bee5"
		hash7 = "ae1b32aac4d8a35e2c62e334b794373c7457ebfaaab5e5e8e46f3928af07cde4"
		hash8 = "c54837d0b856205bd4ae01887aae9178f55f16e0e1a1e1ff59bd18dbc8a3dd82"
		hash9 = "db350bb43179f2a43a1330d82f3afeb900db5ff5094c2364d0767a3e6b97c854"
		id = "8ac951d5-4a18-50c5-8ded-8a0a6b585fd6"

	strings:
		$x2 = {57 65 62 4b 69 74 46 6f 72 6d 42 6f 75 6e 64 61 72 79 77 68 70 46 78 4d 42 65 31 39 63 53 6a 46 6e 47}
		$x3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 48 4e 43 5c}
		$x4 = {5c 61 6e 74 65 72 6e 65 74 20 61 62 70 6c 6f 72 65 72}
		$x5 = {25 73 5c 61 62 78 70 6c 6f 72 65 2e 65 78 65}
		$x6 = {47 48 4f 53 54 34 31 39}
		$x7 = {49 2c 6d 20 4f 6e 6c 69 6e 65 2e 20 25 30 34 64 20 2d 20 25 30 32 64 20 2d 20 25 30 32 64 20 2d 20 25 30 32 64 20 2d 20 25 30 32 64}
		$x8 = {2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 72 65 67 6b 65 79 65 6e 75 6d 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f}
		$s0 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29}
		$s1 = {77 77 77 2e 47 6f 6c 64 44 72 61 67 6f 6e 2e 63 6f 6d}
		$s2 = {2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 20 3e 3e 20 25 73}
		$s3 = {2f 63 20 64 69 72 20 25 73 5c 20 3e 3e 20 25 73}
		$s4 = {44 6f 77 6e 4c 6f 61 64 69 6e 67 20 25 30 32 78 2c 20 25 30 32 78 2c 20 25 30 32 78}
		$s5 = {54 72 61 6e 5f 64 6c 6c 2e 64 6c 6c}
		$s6 = {4d 70 43 6d 64 52 75 6e 6b 72 2e 64 6c 6c}
		$s7 = {4d 70 43 6d 64 52 75 6e 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( ( pe.exports ( "ExportFunction" ) and pe.number_of_exports == 1 ) or ( 1 of ( $x* ) and 1 of ( $s* ) ) or 3 of them )
}

import "pe"

rule GoldDragon_RunningRAT : hardened
{
	meta:
		description = "Detects Running RAT from Gold Dragon report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/rW1yvZ"
		date = "2018-02-03"
		hash1 = "0852f2c5741997d8899a34bb95c349d7a9fb7277cd0910656c3ce37a6f11cb88"
		hash2 = "2981e1a1b3c395cee6e4b9e6c46d062cf6130546b04401d724750e4c8382c863"
		hash3 = "7aa99ebc49a130f07304ed25655862a04cc20cb59d129e1416a7dfa04f7d3e51"
		id = "7de93103-46a5-5aba-90cf-26735a6a580e"
		score = 75

	strings:
		$x1 = {43 00 3a 00 5c 00 55 00 53 00 45 00 52 00 53 00 5c 00 57 00 49 00 4e 00 37 00 5f 00 78 00 36 00 34 00 5c 00 72 00 65 00 73 00 75 00 6c 00 74 00 2e 00 6c 00 6f 00 67 00}
		$x2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 52 75 6e 6e 69 6e 67 52 61 74}
		$x3 = {53 79 73 74 65 6d 52 61 74 2e 64 6c 6c}
		$x4 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 45 78 70 6f 72 74 46 75 6e 63 74 69 6f 6e}
		$x5 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 20 52 75 6e 6e 69 6e 67 52 61 74}
		$x6 = {69 78 65 6f 72 61 74 2e 62 69 6e}
		$x7 = {43 3a 5c 55 53 45 52 53 5c 50 75 62 6c 69 63 5c 72 65 73 75 6c 74 2e 6c 6f 67}
		$a1 = {65 6d 61 6e 79 62 74 73 6f 68 74 65 67}
		$a2 = {74 65 6b 63 6f 73 65 73 6f 6c 63}
		$a3 = {65 6d 61 6e 6b 63 6f 73 74 65 67}
		$a4 = {65 6d 61 6e 74 73 6f 68 74 65 67}
		$a5 = {74 70 6f 6b 63 6f 73 74 65 73}
		$a6 = {70 75 74 72 61 74 53 41 53 57}
		$s1 = {50 61 72 65 6e 74 44 6c 6c 2e 64 6c 6c}
		$s2 = {4d 52 20 2d 20 41 6c 72 65 61 64 79 20 45 78 69 73 74 65 64}
		$s3 = {4d 52 20 46 69 72 73 74 20 53 74 61 72 74 65 64 2c 20 52 65 67 69 73 74 65 64 20 4f 4b 21}
		$s4 = {52 4d 2d 4d 20 3a 20 4c 6f 61 64 52 65 73 6f 75 72 63 65 20 4f 4b 21}
		$s5 = {44 3a 5c 72 65 73 75 6c 74 2e 6c 6f 67}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "c78ccc8f02286648c4373d3bf03efc43" or pe.exports ( "RunningRat" ) or 1 of ( $x* ) or 5 of ( $a* ) or 3 of ( $s* ) )
}

rule GoldDragon_RunnignRAT : hardened
{
	meta:
		description = "Detects Running RAT malware from Gold Dragon report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/rW1yvZ"
		date = "2018-02-03"
		modified = "2023-01-07"
		hash1 = "94aa827a514d7aa70c404ec326edaaad4b2b738ffaea5a66c0c9f246738df579"
		hash2 = "5cbc07895d099ce39a3142025c557b7fac41d79914535ab7ffc2094809f12a4b"
		hash3 = "98ccf3a463b81a47fdf4275e228a8f2266e613e08baae8bdcd098e49851ed49a"
		id = "b99b89a4-a764-5d72-8360-8e53461267d9"

	strings:
		$s1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 20}
		$s2 = {69 65 70 72 6f 78 79 2e 64 6c 6c}
		$s3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 64 61 75 6d 63 6c 65 61 6e 65 72 2e 65 78 65}
		$s4 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6c 69 73 74 20}
		$s5 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 20 52 75 6e}
		$s6 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 72 76 3a 31 32 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 31 32 2e 30}
		$s7 = {25 00 73 00 5c 00 25 00 73 00 5f 00 25 00 30 00 33 00 64 00}
		$s8 = {5c 50 49 5f 30 30 31 2e 64 61 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( 3 of them )
}

