rule MAL_ME_RawDisk_Agent_Jan20_1 : hardened
{
	meta:
		description = "Detects suspicious malware using ElRawDisk"
		author = "Florian Roth (Nextron Systems)"
		reference = "Saudi National Cybersecurity Authority - Destructive Attack DUSTMAN"
		date = "2020-01-02"
		modified = "2022-12-21"
		hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
		id = "0efaae51-1407-5039-9e5a-9c2f13d6a971"

	strings:
		$x1 = {5c 64 72 76 5c 61 67 65 6e 74 2e 70 6c 61 69 6e 2e 70 64 62}
		$x2 = {20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 44 6f 77 6e 20 57 69 74 68 20 53 61 75 64 69 20 4b 69 6e 67 64 6f 6d 2c 20 44 6f 77 6e 20 57 69 74 68 20 42 69 6e 20 53 61 6c 6d 61 6e 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20}
		$s1 = {2e 3f 41 56 45 52 44 45 72 72 6f 72 40 40}
		$s2 = {62 00 34 00 62 00 36 00 31 00 35 00 63 00 32 00 38 00 63 00 63 00 64 00 30 00 35 00 39 00 63 00 66 00 38 00 65 00 64 00 31 00 61 00 62 00 66 00 31 00 63 00 37 00 31 00 66 00 65 00 30 00 33 00 63 00 30 00 33 00 35 00 34 00 35 00 32 00 32 00 39 00 39 00 30 00 61 00 66 00 36 00 33 00 61 00 64 00 66 00 33 00 63 00 39 00 31 00 31 00 65 00 32 00 32 00 38 00 37 00 61 00 34 00 62 00 39 00 30 00 36 00 64 00 34 00 37 00 64 00}
		$s3 = {5c 00 5c 00 3f 00 5c 00 45 00 6c 00 52 00 61 00 77 00 44 00 69 00 73 00 6b 00}
		$s4 = {5c 00 3f 00 3f 00 5c 00 63 00 3a 00}
		$op1 = { e9 3d ff ff ff 33 c0 48 89 05 0d ff 00 00 48 8b }
		$op2 = { 0f b6 0c 01 88 48 34 48 8b 8d a8 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize <= 2000KB and ( 1 of ( $x* ) or 4 of them )
}

rule MAL_ME_RawDisk_Agent_Jan20_2 : hardened
{
	meta:
		description = "Detects suspicious malware using ElRawDisk"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/jfslowik/status/1212501454549741568?s=09"
		date = "2020-01-02"
		modified = "2022-12-21"
		hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
		id = "9817fb22-7bed-5869-aa92-66c458b81c7f"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 44 75 73 74 6d 61 6e 2e 70 64 62}
		$x2 = {2f 63 20 61 67 65 6e 74 2e 65 78 65 20 41}
		$s1 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65}
		$s2 = {54 68 65 20 4d 61 67 69 63 20 57 6f 72 64 21}
		$s3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 72 00 61 00 63 00 6c 00 65 00 5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00}
		$s4 = {5c 00 61 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 2e 00 73 00 79 00 73 00}
		$s5 = {44 00 6f 00 77 00 6e 00 20 00 57 00 69 00 74 00 68 00 20 00 42 00 69 00 6e 00 20 00 53 00 61 00 6c 00 6d 00 61 00 6e 00}
		$sc1 = { 00 5C 00 5C 00 2E 00 5C 00 25 00 73 }
		$op1 = { 49 81 c6 ff ff ff 7f 4c 89 b4 24 98 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize <= 3000KB and ( 1 of ( $x* ) or 3 of them )
}

