rule CobaltStrike_CN_Group_BeaconDropper_Aug17 : hardened limited
{
	meta:
		description = "Detects Script Dropper of Cobalt Gang used in August 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-09"
		hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
		hash2 = "1c845bb0f6b9a96404af97dcafdc77f1629246e840c01dd9f1580a341f554926"
		hash3 = "6206e372870ea4f363be53557477f9748f1896831a0cdef3b8450a7fb65b86e1"
		id = "5631b0bc-9e25-524a-9003-73779fd492f7"

	strings:
		$x1 = {57 72 69 74 65 4c 69 6e 65 28 22 28 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 29 2e 52 75 6e 28 27 63 6d 64 20 2f 63 20 63 3a 2f}
		$x2 = {57 72 69 74 65 4c 69 6e 65 28 22 20 28 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 29 2e 52 75 6e 28 27 72 65 67 73 76 72 33 32 20 2f 73}
		$x3 = {73 68 2e 52 75 6e 28 65 6e 76 28 27 63 6d 64 20 2f 63 20 73 65 74 20 3e 20 25 74 65 6d 70 25}
		$x4 = {73 68 2e 52 75 6e 28 27 72 65 67 73 76 72 33 32 20 2f 73 20 2f 75 20 2f 69 3a}
		$x5 = {2e 47 65 74 28 27 57 69 6e 33 32 5f 53 63 68 65 64 75 6c 65 64 4a 6f 62 27 29 2e 43 72 65 61 74 65 28 27 72 65 67 73 76 72 33 32 20 2f 73 20 2f 75 20 2f 69 3a}
		$x6 = {73 63 72 6f 62 6a 2e 64 6c 6c 27 2c 27 2a 2a 2a 2a 2a 2a 2a 2a}
		$x7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 77 77 77 2e 74 68 79 73 73 65 6e 6b 72 75 70 70 2d 6d 61 72 69 6e 65 73 79 73 74 65 6d 73 2e 6f 72 67 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 66 2e 57 72 69 74 65 4c 69 6e 65 28 22 20 74 4c 6e 6b 3d 65 6e 76 28 27 25 74 6d 70 25 2f 27 2b 6c 6e 6b 4e 61 6d 65 2b 27 2e 6c 6e 6b 27 29 3b 22 29 3b (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6c 6e 6b 4e 61 6d 65 3d 27 6f 66 66 69 63 65 20 33 36 35 27 3b 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x10 = {3b 73 68 3d 78 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b}

	condition:
		( filesize < 200KB and 1 of them )
}

rule CobaltGang_Malware_Aug17_1 : hardened limited
{
	meta:
		description = "Detects a Cobalt Gang malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
		date = "2017-08-09"
		hash1 = "6d70673b723f338b3febc9f1d69463bdd4775539cb92b5a5d8fccc0d977fa2f0"
		id = "56c6f4f8-ccf5-5665-ac21-67f0a9b67cf1"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 65 00 72 00 76 00 65 00 72 00 53 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 45 00 58 00 45 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 6e 63 6f 72 72 65 63 74 20 76 65 72 73 69 6f 6e 20 6f 66 20 57 53 32 5f 33 32 2e 64 6c 6c 20 66 6f 75 6e 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 43 00 6c 00 69 00 63 00 6b 00 20 00 27 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 27 00 20 00 74 00 6f 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 20 00 20 00 27 00 44 00 69 00 73 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 27 00 20 00 74 00 6f 00 20 00 64 00 69 00 73 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 66 00 72 00 6f 00 6d 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 43 00 6c 00 69 00 63 00 6b 00 20 00 27 00 53 00 74 00 61 00 72 00 74 00 27 00 20 00 74 00 6f 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 74 00 68 00 65 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 20 00 20 00 27 00 53 00 74 00 6f 00 70 00 27 00 20 00 74 00 6f 00 20 00 53 00 74 00 6f 00 70 00 20 00 69 00 74 00 2e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule CobaltGang_Malware_Aug17_2 : hardened limited
{
	meta:
		description = "Detects a Cobalt Gang malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
		date = "2017-08-09"
		hash1 = "80791d5e76782cc3cd14f37f351e33b860818784192ab5b650f1cdf4f131cf72"
		id = "2839c119-0fa4-51f0-a406-5d381cc594a2"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 39 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 35 2e 30 3b 20 42 4f 49 45 39 3b 45 4e 47 42 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}

import "pe"

rule MAL_CRIME_CobaltGang_Malware_Oct19_1 : hardened
{
	meta:
		description = "Detects CobaltGang malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/vxsh4d0w/status/1187353649015611392"
		date = "2019-10-24"
		hash1 = "72125933265f884ceb8ab64ab303ea76aaeb7877faee8976d398acd0d0b7356b"
		hash2 = "893339624602c7b3a6f481aed9509b53e4e995d6771c72d726ba5a6b319608a7"
		hash3 = "3c34bbf641df25f9accd05b27b9058e25554fdfea0e879f5ca21ffa460ad2b01"
		id = "95c16016-b09b-56f3-b5a4-fca18ac70ad5"

	strings:
		$op_a1 = { 0f 44 c2 eb 0a 31 c0 80 fa 20 0f 94 c0 01 c0 5d }
		$op_b1 = { 89 e5 53 8b 55 08 8b 4d 0c 8a 1c 01 88 1c 02 83 }
		$op_b2 = { 89 e5 53 8b 55 08 8b 45 0c 8a 1c 0a 88 1c 08 83 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize <= 2000KB and ( pe.imphash ( ) == "d1e3f8d02cce09520379e5c1e72f862f" or pe.imphash ( ) == "8e26df99c70f79cb8b1ea2ef6f8e52ac" or ( $op_a1 and 1 of ( $op_b* ) ) )
}

