rule PowerShell_Suite_Hacktools_Gen_Strings : hardened limited
{
	meta:
		description = "Detects strings from scripts in the PowerShell-Suite repo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
		date = "2017-12-27"
		hash1 = "79071ba5a984ee05903d566130467483c197cbc2537f25c1e3d7ae4772211fe0"
		hash2 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
		hash3 = "4f51e7676a4d54c1962760ca0ac81beb28008451511af96652c31f4f40e8eb8e"
		hash4 = "17ac9bb0c46838c65303f42a4a346fcba838ebd5833b875e81dd65c82701d8a8"
		hash5 = "fa33aef619e620a88ecccb990e71c1e11ce2445f799979d23be2d1ad4321b6c6"
		hash6 = "5542bd89005819bc4eef8dfc8a158183e5fd7a1438c84da35102588f5813a225"
		hash7 = "c6a99faeba098eb411f0a9fcb772abac2af438fc155131ebfc93a00e3dcfad50"
		hash8 = "a8e06ecf5a8c25619ce85f8a23f2416832cabb5592547609cfea8bd7fcfcc93d"
		hash9 = "6aa5abf58904d347d441ac8852bd64b2bad3b5b03b518bdd06510931a6564d08"
		hash10 = "5608f25930f99d78804be8c9c39bd33f4f8d14360dd1e4cc88139aa34c27376d"
		hash11 = "68b6c0b5479ecede3050a2f44f8bb8783a22beeef4a258c4ff00974f5909b714"
		hash12 = "da25010a22460bbaabff0f7004204aae7d830348e8a4543177b1f3383b2c3100"
		id = "afccdd99-da83-5fde-9e21-52220ded1e47"

	strings:
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 21 5d 20 4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 20 66 61 69 6c 65 64 2e 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {5b 3f 5d 20 45 78 65 63 75 74 69 6e 67 20 6d 6d 63 2e 2e}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 21 5d 20 54 68 69 73 20 6d 65 74 68 6f 64 20 69 73 20 6f 6e 6c 79 20 73 75 70 70 6f 72 74 65 64 20 6f 6e 20 36 34 2d 62 69 74 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 4c 4e 4b 20 3d 20 5b 53 68 65 6c 6c 4c 69 6e 6b 2e 53 68 6f 72 74 63 75 74 5d 3a 3a 46 72 6f 6d 42 79 74 65 41 72 72 61 79 28 24 4c 4e 4b 48 65 61 64 65 72 2e 47 65 74 42 79 74 65 73 28 29 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 43 61 6c 6c 52 65 73 75 6c 74 20 3d 20 5b 55 41 43 54 6f 6b 65 6e 4d 61 67 69 63 5d 3a 3a 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 28 24 53 68 65 6c 6c 45 78 65 63 75 74 65 49 6e 66 6f 2e 68 50 72 6f 63 65 73 73 2c 20 31 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 21 5d 20 55 6e 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 70 72 6f 63 65 73 73 20 28 61 73 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 29 2c 20 74 68 69 73 20 6d 61 79 20 72 65 71 75 69 72 65 20 53 59 53 54 45 4d 20 61 63 63 65 73 73 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {5b 21 5d 20 45 72 72 6f 72 2c 20 4e 54 53 54 41 54 55 53 20 56 61 6c 75 65 3a 20}
		$ = {5b 21 5d 20 55 41 43 20 61 72 74 69 66 61 63 74 3a 20}
		$ = {5b 3e 5d 20 50 72 6f 63 65 73 73 20 64 75 6d 70 20 73 75 63 63 65 73 73 21}
		$ = {5b 21 5d 20 50 72 6f 63 65 73 73 20 64 75 6d 70 20 66 61 69 6c 65 64 21}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 2b 5d 20 45 69 64 6f 6c 6f 6e 20 65 6e 74 72 79 20 70 6f 69 6e 74 3a (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 61 69 74 20 66 6f 72 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 72 75 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 43 6f 6d 6d 61 6e 64 20 3d 20 52 65 61 64 2d 48 6f 73 74 20 22 60 6e 53 4d 42 20 73 68 65 6c 6c 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 73 65 20 4e 65 74 61 70 69 33 32 3a 3a 4e 65 74 53 65 73 73 69 6f 6e 45 6e 75 6d 20 74 6f 20 65 6e 75 6d 65 72 61 74 65 20 61 63 74 69 76 65 20 73 65 73 73 69 6f 6e 73 20 6f 6e 20 64 6f 6d 61 69 6e 20 6a 6f 69 6e 65 64 20 6d 61 63 68 69 6e 65 73 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {49 6e 76 6f 6b 65 2d 43 72 65 61 74 65 50 72 6f 63 65 73 73 20 2d 42 69 6e 61 72 79 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c}
		$ = {5b 3f 5d 20 54 68 72 65 61 64 20 62 65 6c 6f 6e 67 73 20 74 6f 3a 20}
		$ = {5b 3f 5d 20 4f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 20 63 6f 72 65 20 63 6f 75 6e 74 3a 20}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 3e 5d 20 43 61 6c 6c 69 6e 67 20 41 64 76 61 70 69 33 32 3a 3a 4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 20 2d 2d 3e 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {43 61 6c 6c 69 6e 67 20 41 64 76 61 70 69 33 32 3a 3a 4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 20 2d 2d 3e 20 4c 53 41 53 53}
		$ = {5b 21 5d 20 4d 6d 6d 2c 20 73 6f 6d 65 74 68 69 6e 67 20 77 65 6e 74 20 77 72 6f 6e 67 21 20 47 65 74 4c 61 73 74 45 72 72 6f 72 20 72 65 74 75 72 6e 65 64 3a}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 66 20 28 28 24 46 69 6c 65 42 79 74 65 73 5b 30 2e 2e 31 5d 20 7c 20 25 20 7b 5b 43 68 61 72 5d 24 5f 7d 29 20 2d 6a 6f 69 6e 20 27 27 20 2d 63 6e 65 20 27 4d 5a 27 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 100KB and 1 of them
}

rule PowerShell_Suite_Eidolon : hardened limited
{
	meta:
		description = "Detects PowerShell Suite Eidolon script - file Start-Eidolon.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
		date = "2017-12-27"
		hash1 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
		id = "5440d8fc-b939-556f-a8a0-ef5feb29e32f"

	strings:
		$ = {5b 2b 5d 20 45 69 64 6f 6c 6f 6e 20 65 6e 74 72 79 20 70 6f 69 6e 74 3a}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 3a 5c 50 53 3e 20 53 74 61 72 74 2d 45 69 64 6f 6c 6f 6e 20 2d 54 61 72 67 65 74 20 43 3a 5c 53 6f 6d 65 5c 46 69 6c 65 2e 50 61 74 68 20 2d 4d 69 6d 69 6b 61 74 7a 20 2d 56 65 72 62 6f 73 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$ = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 49 6e 74 31 36 5d 24 50 45 41 72 63 68 20 3d 20 27 30 78 7b 30 7d 27 20 2d 66 20 28 28 28 24 50 61 79 6c 6f 61 64 42 79 74 65 73 5b 28 24 4f 70 74 4f 66 66 73 65 74 2b 31 29 2e 2e 28 24 4f 70 74 4f 66 66 73 65 74 29 5d 29 20 7c 20 25 20 7b 24 5f 2e 54 6f 53 74 72 69 6e 67 28 27 58 32 27 29 7d 29 20 2d 6a 6f 69 6e 20 27 27 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x7566 and filesize < 13000KB and 1 of them
}

