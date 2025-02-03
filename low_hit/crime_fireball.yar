rule Fireball_de_svr : hardened
{
	meta:
		description = "Detects Fireball malware - file de_svr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "f964a4b95d5c518fd56f06044af39a146d84b801d9472e022de4c929a5b8fdcc"
		id = "29395239-66d8-5340-b884-9b8f036cc27f"

	strings:
		$s1 = {63 6d 64 2e 65 78 65 20 2f 63 20 4d 44 20}
		$s2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 2c 00 25 00 73 00}
		$s3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 31 00 32 00 7a 00 70 00 62 00 65 00 74 00 67 00 73 00 31 00 70 00 63 00 6f 00 2e 00 63 00 6c 00 6f 00 75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 65 00 74 00 2f 00 57 00 65 00 61 00 74 00 68 00 65 00 72 00 61 00 70 00 69 00 2f 00 73 00 68 00 65 00 6c 00 6c 00}
		$s4 = {43 3a 5c 76 33 5c 65 78 65 5c 64 65 5f 73 76 72 5f 69 6e 73 74 2e 70 64 62}
		$s5 = {49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 20 46 61 69 6c 65 64 21}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 3000KB and 4 of them )
}

rule Fireball_lancer : hardened
{
	meta:
		description = "Detects Fireball malware - file lancer.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "7d68386554e514f38f98f24e8056c11c0a227602ed179d54ed08f2251dc9ea93"
		id = "2209bcb4-74a6-5c39-962c-ccd4ce62619e"

	strings:
		$x1 = {5c 69 6e 73 74 6c 73 70 5c 52 65 6c 65 61 73 65 5c 4c 61 6e 63 65 72 2e 70 64 62}
		$x2 = {6c 00 61 00 6e 00 63 00 65 00 72 00 75 00 73 00 65 00 2e 00 64 00 61 00 74 00}
		$s1 = {4c 61 6e 63 65 72 2e 64 6c 6c}
		$s2 = {52 00 75 00 6e 00 44 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00}
		$s3 = {4d 00 69 00 63 00 72 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {41 00 47 00 36 00 34 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {22 00 2c 00 53 00 74 00 61 00 72 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and ( 1 of ( $x* ) or 3 of ( $s* ) ) ) or ( 6 of them )
}

rule QQBrowser : hardened
{
	meta:
		description = "Not malware but suspicious browser - file QQBrowser.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		score = 50
		hash1 = "adcf6b8aa633286cd3a2ce7c79befab207802dec0e705ed3c74c043dabfc604c"
		id = "457507c5-0411-5d72-891b-ae3e428ea2d6"

	strings:
		$s1 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 57 69 74 68 6f 75 74 44 75 6d 70}
		$s2 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 69 00 75 00 6d 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 43 00 72 00 61 00 73 00 68 00 44 00 75 00 6d 00 70 00 41 00 74 00 74 00 65 00 6d 00 70 00 74 00 73 00}
		$s4 = {51 00 51 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5f 00 42 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule chrome_elf : hardened
{
	meta:
		description = "Detects Fireball malware - file chrome_elf.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "e4d4f6fbfbbbf3904ca45d296dc565138a17484c54aebbb00ba9d57f80dfe7e5"
		id = "8680d5b5-e26f-5a3f-aeab-b965afe91027"

	strings:
		$x2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 53 00 43 00 20 00 48 00 4f 00 55 00 52 00 4c 00 59 00 20 00 2f 00 4d 00 4f 00 20 00 25 00 64 00 20 00 2f 00 53 00 54 00 20 00 30 00 30 00 3a 00 25 00 30 00 32 00 64 00 3a 00 30 00 30 00 20 00 2f 00 54 00 4e 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 54 00 52 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 52 00 55 00 20 00 22 00 53 00 59 00 53 00 54 00 45 00 4d 00 22 00}
		$s6 = {61 48 52 30 63 44 6f 76 4c 32 52 32 4d 6d 30 78 64 58 56 74 62 6e 4e 6e 64 48 55 75 59 32 78 76 64 57 52 6d 63 6d 39 75 64 43 35 75 5a 58 51 76 64 6a 51 76 5a 33 52 6e 4c 79 56 7a 50 32 46 6a 64 47 6c 76 62 6a 31 32 61 58 4e 70 64 43 35 6a 61 47 56 73 5a 69 35 70 62 6e 4e 30 59 57 78 73}
		$s7 = {51 75 65 72 79 49 6e 74 65 72 66 61 63 65 20 63 61 6c 6c 20 66 61 69 6c 65 64 20 66 6f 72 20 49 45 78 65 63 41 63 74 69 6f 6e 3a 20 25 78}
		$s10 = {25 00 73 00 20 00 25 00 73 00 2c 00 52 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 5f 00 44 00 6f 00 20 00 25 00 73 00}
		$s13 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 61 6e 20 69 6e 73 74 61 6e 63 65 20 6f 66 20 49 54 61 73 6b 53 65 72 76 69 63 65 3a 20 25 78}
		$s16 = {52 75 6e 64 6c 6c 33 32 5f 44 6f}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and 4 of them )
}

rule Fireball_regkey : hardened
{
	meta:
		description = "Detects Fireball malware - file regkey.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		modified = "2022-12-21"
		hash1 = "fff2818caa9040486a634896f329b8aebaec9121bdf9982841f0646763a1686b"
		id = "6e22bb93-8c8b-510f-a9e4-6e57c392c2ae"

	strings:
		$s1 = {5c 57 69 6e 4d 61 69 6e 5c 52 65 6c 65 61 73 65 5c 57 69 6e 4d 61 69 6e 2e 70 64 62}
		$s2 = {53 00 63 00 72 00 65 00 65 00 6e 00 53 00 68 00 6f 00 74 00}
		$s3 = {57 00 49 00 4e 00 4d 00 41 00 49 00 4e 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule Fireball_winsap : hardened
{
	meta:
		description = "Detects Fireball malware - file winsap.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "c7244d139ef9ea431a5b9cc6a2176a6a9908710892c74e215431b99cd5228359"
		id = "e68e7738-f325-5b73-9e61-4e2413b7b7be"

	strings:
		$s1 = {61 48 52 30 63 44 6f 76 4c 32}
		$s2 = {25 00 73 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 20 00 25 00 73 00}
		$s3 = {5c 00 53 00 45 00 54 00 55 00 50 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {57 69 6e 53 41 50 2e 64 6c 6c}
		$s5 = {45 72 72 6f 72 20 25 75 20 69 6e 20 57 69 6e 48 74 74 70 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65 2e}
		$s6 = {55 00 50 00 44 00 41 00 54 00 45 00 20 00 4f 00 56 00 45 00 52 00 57 00 52 00 49 00 54 00 45 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and 4 of them )
}

rule Fireball_archer : hardened
{
	meta:
		description = "Detects Fireball malware - file archer.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		modified = "2022-12-21"
		hash1 = "9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022"
		id = "16bb95c1-af69-5688-8999-f097d02d2ffc"

	strings:
		$x1 = {5c 61 72 63 68 65 72 5f 6c 79 6c 5c 52 65 6c 65 61 73 65 5c 41 72 63 68 65 72 5f 49 6e 70 75 74 2e 70 64 62}
		$s1 = {41 72 63 68 65 72 5f 49 6e 70 75 74 2e 64 6c 6c}
		$s2 = {49 6e 73 74 61 6c 6c 41 72 63 68 65 72 53 76 63}
		$s3 = {25 00 73 00 5f 00 25 00 30 00 38 00 58 00}
		$s4 = {64 00 5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( $x1 or 3 of them )
}

rule clearlog : hardened
{
	meta:
		description = "Detects Fireball malware - file clearlog.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "14093ce6d0fe8ab60963771f48937c669103842a0400b8d97f829b33c420f7e3"
		id = "3eb58a7a-b04d-52c2-8c3c-c149da8d4aa8"

	strings:
		$x1 = {5c 43 6c 65 61 72 4c 6f 67 5c 52 65 6c 65 61 73 65 5c 6c 6f 67 43 2e 70 64 62}
		$s1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 22 00 22 00}
		$s2 = {6c 6f 67 43 2e 64 6c 6c}
		$s3 = {68 00 68 00 68 00 68 00 68 00 2e 00 65 00 78 00 65 00}
		$s4 = {74 00 74 00 74 00 74 00 74 00 2e 00 65 00 78 00 65 00}
		$s5 = {4c 6f 67 67 65 72 20 4e 61 6d 65 3a}
		$s6 = {63 00 6c 00 65 00 2e 00 6c 00 6f 00 67 00 2e 00 31 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and $x1 or 2 of them )
}

rule Fireball_gubed : hardened
{
	meta:
		description = "Detects Fireball malware - file gubed.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		modified = "2022-12-21"
		hash1 = "e3f69a1fb6fcaf9fd93386b6ba1d86731cd9e5648f7cff5242763188129cd158"
		id = "cba2913f-4d9a-5925-ad9a-f5815a635291"

	strings:
		$x1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 4d 00 52 00 54 00 2e 00 65 00 78 00 65 00}
		$x2 = {74 00 49 00 70 00 68 00 6c 00 70 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00}
		$x3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 25 00 73 00 2f 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 3f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 73 00 3d 00 25 00 73 00 26 00 72 00 65 00 71 00 73 00 3d 00 76 00 69 00 73 00 69 00 74 00 2e 00 73 00 74 00 61 00 72 00 74 00 6c 00 6f 00 61 00 64 00}
		$x4 = {5c 47 75 62 65 64 5c 52 65 6c 65 61 73 65 5c 47 75 62 65 64 2e 70 64 62}
		$x5 = {64 00 32 00 68 00 72 00 70 00 6e 00 66 00 79 00 62 00 33 00 77 00 76 00 33 00 6b 00 2e 00 63 00 6c 00 6f 00 75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 65 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}

