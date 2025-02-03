rule CrowdStrike_SUNSPOT_01 : artifact stellarparticle sunspot hardened
{
	meta:
		author = "(c) 2021 CrowdStrike Inc."
		description = "Detects RC4 and AES key encryption material in SUNSPOT"
		reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
		version = "202101081448"
		date = "2021-01-08"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"
		id = "2a2a5cfc-d059-5942-bd70-c3169e9ceb45"

	strings:
		$key = {fc f3 2a 83 e5 f6 d0 24 a6 bf ce 88 30 c2 48 e7}
		$iv = {81 8c 85 49 b9 00 06 78 0b e9 63 60 26 64 b2 da}

	condition:
		all of them and filesize < 32MB
}

rule CrowdStrike_SUNSPOT_02 : artifact stellarparticle sunspot hardened
{
	meta:
		copyright = "(c) 2021 CrowdStrike Inc."
		description = "Detects mutex names in SUNSPOT"
		version = "202101081448"
		date = "2021-01-08"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"
		reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
		id = "9ecb89e6-475b-5961-8a67-136a0274e1c7"

	strings:
		$mutex_01 = {((7b 31 32 64 36 31 61 34 31 2d 34 62 37 34 2d 37 36 31 30 2d 61 34 64 38 2d 33 30 32 38 64 32 66 35 36 33 39 35 7d) | (7b 00 31 00 32 00 64 00 36 00 31 00 61 00 34 00 31 00 2d 00 34 00 62 00 37 00 34 00 2d 00 37 00 36 00 31 00 30 00 2d 00 61 00 34 00 64 00 38 00 2d 00 33 00 30 00 32 00 38 00 64 00 32 00 66 00 35 00 36 00 33 00 39 00 35 00 7d 00))}
		$mutex_02 = {((7b 35 36 33 33 31 65 34 64 2d 37 36 61 33 2d 30 33 39 30 2d 61 37 65 65 2d 35 36 37 61 64 66 35 38 33 36 62 37 7d) | (7b 00 35 00 36 00 33 00 33 00 31 00 65 00 34 00 64 00 2d 00 37 00 36 00 61 00 33 00 2d 00 30 00 33 00 39 00 30 00 2d 00 61 00 37 00 65 00 65 00 2d 00 35 00 36 00 37 00 61 00 64 00 66 00 35 00 38 00 33 00 36 00 62 00 37 00 7d 00))}

	condition:
		any of them and filesize < 10MB
}

rule CrowdStrike_SUNSPOT_03 : artifact logging stellarparticle sunspot hardened
{
	meta:
		copyright = "(c) 2021 CrowdStrike Inc."
		description = "Detects log format lines in SUNSPOT"
		version = "202101081443"
		last_modified = "2021-01-08"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"
		id = "5535163e-a85a-587d-bb6e-083783f915c9"

	strings:
		$s01 = {5b 45 52 52 4f 52 5d 20 2a 2a 2a 53 74 65 70 31 28 27 25 6c 73 27 2c 27 25 6c 73 27 29 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 2a 2a 2a 0a}
		$s02 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 32 20 66 61 69 6c 73 0a}
		$s03 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 33 20 66 61 69 6c 73 0a}
		$s04 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 34 28 27 25 6c 73 27 29 20 66 61 69 6c 73 0a}
		$s05 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 35 28 27 25 6c 73 27 29 20 66 61 69 6c 73 0a}
		$s06 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 36 28 27 25 6c 73 27 29 20 66 61 69 6c 73 0a}
		$s07 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 37 20 66 61 69 6c 73 0a}
		$s08 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 38 20 66 61 69 6c 73 0a}
		$s09 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 39 28 27 25 6c 73 27 29 20 66 61 69 6c 73 0a}
		$s10 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 30 28 27 25 6c 73 27 2c 27 25 6c 73 27 29 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s11 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 31 28 27 25 6c 73 27 29 20 66 61 69 6c 73 0a}
		$s12 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 32 28 27 25 6c 73 27 2c 27 25 6c 73 27 29 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s13 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 33 30 20 66 61 69 6c 73 0a}
		$s14 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 34 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s15 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 35 20 66 61 69 6c 73 0a}
		$s16 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 36 20 66 61 69 6c 73 0a}
		$s17 = {5b 25 64 5d 20 53 74 65 70 31 37 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s18 = {5b 25 64 5d 20 53 74 65 70 31 38 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s19 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 31 39 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s20 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 32 30 20 66 61 69 6c 73 0a}
		$s21 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 32 31 28 25 64 2c 25 73 2c 25 64 29 20 66 61 69 6c 73 0a}
		$s22 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 32 32 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s23 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 32 33 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 0a}
		$s24 = {5b 25 64 5d 20 53 6f 6c 75 74 69 6f 6e 20 64 69 72 65 63 74 6f 72 79 3a 20 25 6c 73 0a}
		$s25 = {5b 25 64 5d 20 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 3a 25 30 33 64 20 25 6c 73 0a}
		$s26 = {5b 25 64 5d 20 2b 20 27 25 73 27 20}

	condition:
		2 of them and filesize < 10MB
}

