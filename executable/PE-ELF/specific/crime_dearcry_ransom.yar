rule MAL_RANSOM_Crime_DearCry_Mar2021_1 : hardened
{
	meta:
		description = "Triggers on strings of known DearCry samples"
		author = "Nils Kuhnert"
		date = "2021-03-12"
		reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
		hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
		hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
		hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
		id = "d9714502-f1ea-5fe8-b0ac-1f7a9a30d8f5"

	strings:
		$x1 = {2e 54 49 46 20 2e 54 49 46 46 20 2e 50 44 46 20 2e 58 4c 53 20 2e 58 4c 53 58 20 2e 58 4c 54 4d 20 2e 50 53 20 2e 50 50 53 20 2e 50 50 54 20 2e 50 50 54 58 20 2e 44 4f 43 20 2e 44 4f 43 58 20 2e 4c 4f 47 20 2e 4d 53 47 20 2e 52 54 46 20 2e 54 45 58 20 2e 54 58 54 20 2e 43 41 44 20 2e 57 50 53 20 2e 45 4d 4c 20 2e 49 4e 49 20 2e 43 53 53 20 2e 48 54 4d 20 2e 48 54 4d 4c 20 20 2e 58 48 54 4d 4c 20 2e 4a 53 20 2e 4a 53 50 20 2e 50 48 50 20 2e 4b 45 59 43 48 41 49 4e 20 2e 50 45 4d 20 2e 53 51 4c 20 2e 41 50 4b 20 2e 41 50 50 20 2e 42 41 54 20 2e 43 47 49 20 2e 41 53 50 58 20 2e 43 45 52 20 2e 43 46 4d 20 2e 43 20 2e 43 50 50 20 2e 47 4f 20 2e 43 4f 4e 46 49 47 20 2e 50 4c 20 2e 50 59 20 2e 44 57 47 20 2e 58 4d 4c 20 2e 4a 50 47 20 2e 42 4d 50 20 2e 50 4e 47 20 2e 45 58 45 20 2e 44 4c 4c 20 2e 43 41 44 20 2e 41 56 49 20 2e 48 2e 43 53 56 20 2e 44 41 54 20 2e 49 53 4f 20 2e 50 53 54 20 2e 50 47 44 20 20 2e 37 5a 20 2e 52 41 52 20 2e 5a 49 50 20 2e 5a 49 50 58 20 2e 54 41 52 20 2e 50 44 42 20 2e 42 49 4e 20 2e 44 42 20 2e 4d 44 42 20 2e 4d 44 46 20 2e 42 41 4b 20 2e 4c 4f 47 20 2e 45 44 42 20 2e 53 54 4d 20 2e 44 42 46 20 2e 4f 52 41 20 2e 47 50 47 20 2e 45 44 42 20 2e 4d 46 53}
		$s1 = {63 72 65 61 74 65 20 72 73 61 20 65 72 72 6f 72}
		$s2 = {44 45 41 52 43 52 59 21}
		$s4 = {2f 72 65 61 64 6d 65 2e 74 78 74}
		$s5 = {6d 73 75 70 64 61 74 65}
		$s6 = {59 6f 75 72 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21}
		$s7 = {25 63 3a 5c 25 73}
		$s8 = {43 3a 5c 55 73 65 72 73 5c 6a 6f 68 6e 5c}
		$s9 = {45 6e 63 72 79 70 74 46 69 6c 65 2e 65 78 65 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 1MB and filesize < 2MB and ( 1 of ( $x* ) or 3 of them ) or 5 of them
}

rule MAL_CRIME_RANSOM_DearCry_Mar21_1 : hardened
{
	meta:
		description = "Detects DearCry Ransomware affecting Exchange servers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
		date = "2021-03-12"
		hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
		hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
		hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
		id = "96cd2fe8-8bb9-5a3b-9bf1-c63a1148a817"

	strings:
		$s1 = {64 65 61 72 21 21 21}
		$s2 = {45 6e 63 72 79 70 74 46 69 6c 65 2e 65 78 65 2e 70 64 62}
		$s3 = {2f 72 65 61 64 6d 65 2e 74 78 74}
		$s4 = {43 3a 5c 55 73 65 72 73 5c 6a 6f 68 6e 5c}
		$s5 = {41 6e 64 20 70 6c 65 61 73 65 20 73 65 6e 64 20 6d 65 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 68 61 73 68 21}
		$op1 = { 68 e0 30 52 00 6a 41 68 a5 00 00 00 6a 22 e8 81 d0 f8 ff 83 c4 14 33 c0 5e }
		$op2 = { 68 78 6a 50 00 6a 65 6a 74 6a 10 e8 d9 20 fd ff 83 c4 14 33 c0 5e }
		$op3 = { 31 40 00 13 31 40 00 a4 31 40 00 41 32 40 00 5f 33 40 00 e5 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them or 5 of them
}

