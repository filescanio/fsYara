rule APT_MAL_DTRACK_Oct19_1 : hardened
{
	meta:
		description = "Detects DTRACK malware"
		author = "Florian Roth (Nextron Systems)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://twitter.com/a_tweeter_user/status/1188811977851887616?s=21"
		date = "2019-10-28"
		hash1 = "c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c"
		hash2 = "a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68"
		hash3 = "93a01fbbdd63943c151679d037d32b1d82a55d66c6cb93c40ff63f2b770e5ca9"
		hash4 = "3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682"
		hash5 = "bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364"
		hash6 = "58fef66f346fe3ed320e22640ab997055e54c8704fc272392d71e367e2d1c2bb"
		hash7 = "9d9571b93218f9a635cfeb67b3b31e211be062fd0593c0756eb06a1f58e187fd"
		id = "802135bd-234d-574d-b111-fcc9eaa000f8"

	strings:
		$xc1 = { 25 73 2A 2E 2A 00 00 00 5C 00 00 00 25 73 7E 00
               5C 00 00 00 77 62 00 00 64 61 74 00 64 6B 77 65
               72 6F 33 38 6F 65 72 41 5E 74 40 23 00 00 00 00
               63 3A 5C 00 25 73 5C 25 63 2E 74 6D 70 }
		$sx1 = {25 30 32 64 2e 25 30 32 64 2e 25 30 34 64 20 2d 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 3a 25 30 33 64 20 3a 20}
		$sx2 = {25 73 5c 25 63 2e 74 6d 70}
		$sx3 = {64 6b 77 65 72 6f 33 38 6f 65 72 41}
		$sx4 = {61 77 7a 32 71 72 32 31 79 66 62 6a}
		$s1 = {45 78 65 63 75 74 65 5f 25 73 2e 6c 6f 67}
		$s2 = {25 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73}
		$s3 = {43 43 53 5f 4d 6f 7a 69 6c 6c 61 2f 35 2e 30}
		$s4 = {5c 43 24 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 4d 70 4c 6f 67 73 5c}
		$s5 = {31 32 37 2e 30 2e 30 2e 31 20 3e 4e 55 4c 20 26 20 65 63 68 6f 20 45 45 45 45 20 3e 20 22 25 73 22}
		$s6 = {5b 2b 5d 20 44 6f 77 6e 6c 6f 61 64 43 6f 6d 6d 61 6e 64}
		$s7 = {44 43 2d 45 72 72 6f 72 3a 20 54 6f 6f 20 6c 6f 6e 67 20 63 6d 64 20 6c 65 6e 67 74 68}
		$s8 = {25 73 5c 7e 25 64 2e 74 6d 70}
		$s9 = {25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58}
		$op1 = { 0f b6 8d a3 fc ff ff 85 c9 74 09 8b 55 f4 83 c2 }
		$op2 = { 6a 00 8d 85 28 fc ff ff 50 6a 04 8d 4d f8 51 8b }
		$op3 = { 8b 85 c8 fd ff ff 03 85 a4 fc ff ff 89 85 b4 fc }

	condition:
		$xc1 or 2 of ( $sx* ) or 4 of them or ( uint16( 0 ) == 0x5a4d and filesize <= 3000KB and 2 of them )
}

