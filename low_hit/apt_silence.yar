import "pe"

rule Silence_malware_1 : hardened
{
	meta:
		description = "Detects malware sample mentioned in the Silence report on Securelist"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/the-silence/83009/"
		date = "2017-11-01"
		hash1 = "f24b160e9e9d02b8e31524b8a0b30e7cdc66dd085e24e4c58240e4c4b6ec0ac2"
		id = "f932e3fe-a2d7-55b7-b581-88c0ed45723e"

	strings:
		$x1 = {61 00 64 00 6f 00 62 00 65 00 75 00 64 00 70 00 2e 00 65 00 78 00 65 00}
		$x2 = {25 73 5c 61 64 6f 62 65 75 64 70 2e 65 78 65 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72}
		$x3 = {25 73 5c 69 67 66 78 70 65 72 73 5f 25 30 38 78 2e 65 78 65}
		$x4 = {25 73 5c 61 64 6f 62 65 75 64 70 2e 65 78 65}
		$s1 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 53 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}
		$s2 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 20 00 31 00 39 00 39 00 39 00 20 00 2d 00 20 00 32 00 30 00 31 00 37 00}
		$s3 = {25 73 67 65 74 2e 70 68 70 3f 6e 61 6d 65 3d 25 78}
		$s4 = {56 00 4e 00 41 00 53 00 53 00 52 00 55 00 4e 00 58 00 59 00 43 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "e03edb9bd7cbe200dc59f361db847f8a" or 1 of ( $x* ) or 3 of them )
}

import "pe"

rule Silence_malware_2 : hardened
{
	meta:
		description = "Detects malware sample mentioned in the Silence report on Securelist"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/the-silence/83009/"
		date = "2017-11-01"
		hash1 = "75b8f534b2f56f183465ba2b63cfc80b7d7d1d155697af141447ec7144c2ba27"
		id = "e4c7d753-fd04-5e11-9960-1ad238039c11"

	strings:
		$x1 = {5c 53 63 72 65 65 6e 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 5c 52 65 6c 65 61 73 65 5c 73 6d 6d 73 72 76 2e 70 64 62}
		$x2 = {5c 5c 2e 5c 70 69 70 65 5c 7b 37 33 46 37 39 37 35 41 2d 41 34 41 32 2d 34 41 42 36 2d 39 31 32 31 2d 41 45 43 41 45 36 38 41 41 42 42 42 7d}
		$s1 = {4d 79 20 53 61 6d 70 6c 65 20 53 65 72 76 69 63 65 3a 20 53 65 72 76 69 63 65 4d 61 69 6e 3a 20 53 65 74 53 65 72 76 69 63 65 53 74 61 74 75 73 20 72 65 74 75 72 6e 65 64 20 65 72 72 6f 72}
		$s2 = {5c 6d 73 73 2e 65 78 65}
		$s3 = {5c 6f 75 74 2e 64 61 74}
		$s4 = {5c 6d 73 73 2e 74 78 74}
		$s5 = {44 65 66 61 75 6c 74 20 6d 6f 6e 69 74 6f 72}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "69f3ec173efb6fd3ab5f79e0f8051335" or ( 1 of ( $x* ) or 3 of them ) ) ) or ( 5 of them )
}

