rule Pirpi_1609_A : hardened
{
	meta:
		description = "Detects Pirpi Backdoor - and other malware (generic rule)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "2a5a0bc350e774bd784fc25090518626b65a3ce10c7401f44a1616ea2ae32f4c"
		hash2 = "8caa179ec20b6e3938d17132980e0b9fe8ef753a70052f7e857b339427eb0f78"
		id = "72b996e2-56cf-5a8d-8d8b-97eda7105d26"

	strings:
		$x1 = {65 78 70 61 6e 64 2e 65 78 65 31 2e 67 69 66}
		$c1 = {65 78 70 61 6e 64 2e 65 78 65}
		$c2 = {63 74 66 2e 65 78 65}
		$s1 = {66 00 6c 00 76 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}
		$s2 = {77 00 77 00 77 00 2e 00 54 00 68 00 69 00 6e 00 6b 00 57 00 6f 00 72 00 6b 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00}
		$s3 = {63 74 66 6e 6f 6e 2e 65 78 65}
		$s4 = {66 6c 76 25 64 2e 65 78 65}
		$s5 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 42 49 4f 53}
		$s6 = {31 32 38 31 31 5b 25 64 5d 2e 67 69 66}
		$s7 = {47 00 65 00 74 00 41 00 70 00 70 00 30 00 33 00}
		$s8 = {66 00 6c 00 76 00 55 00 70 00 64 00 61 00 74 00 65 00}
		$s9 = {25 64 2d 25 34 2e 34 64 25 64}
		$s10 = {68 74 74 70 3a 2f 2f 25 73 2f 25 35 2e 35 64 2e 68 74 6d 6c}
		$s11 = {66 00 6c 00 76 00 62 00 68 00 6f 00 2e 00 65 00 78 00 65 00}
		$op1 = { 74 08 c1 cb 0d 03 da 40 eb }
		$op2 = { 03 f5 56 8b 76 20 03 f5 33 c9 49 }
		$op3 = { 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( $x1 or all of ( $c* ) or all of ( $op* ) ) ) or ( 8 of them )
}

rule Pirpi_1609_B : hardened
{
	meta:
		description = "Detects Pirpi Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "498b98c02e19f4b03dc6a3a8b6ff8761ef2c0fedda846ced4b6f1c87b52468e7"
		id = "caf63b97-efd7-5cd4-8954-b86db4d93cf5"

	strings:
		$s1 = {74 63 6f 6e 6e 20 3c 69 70 3e 20 3c 70 6f 72 74 3e 20 2f 2f 73 65 74 20 74 65 6d 70 20 63 6f 6e 6e 65 63 74 20 76 61 6c 75 65 2c 20 61 6e 64 20 64 69 73 63 6f 6e 6e 65 63 74 2e}
		$s2 = {45 2a 20 4c 69 73 74 65 6e 43 68 65 63 6b 53 73 6c 20 53 73 6c 52 65 63 76 20 66 64 28 25 64 29 20 45 72 72 6f 72 20 72 65 74 3a 25 64 20 25 64}
		$s3 = {25 73 20 25 73 20 4c 2a 20 4c 69 73 74 65 6e 43 68 65 63 6b 53 73 6c 20 66 64 28 25 64 29 20 53 73 6c 56 28 2d 25 64 2d 29}
		$s4 = {53 3a 25 64 2e 25 64 2d 25 64 2e 25 64 20 56 28 25 64 2e 25 64 29 20 4c 69 73 74 65 6e 20 4f 6e 20 25 64 20 4f 6b 2e}
		$s5 = {45 2a 20 4c 69 73 74 65 6e 43 68 65 63 6b 53 73 6c 20 66 64 28 25 64 29 20 53 73 6c 41 63 63 65 70 74 20 45 72 72 20 25 64}
		$s6 = {25 73 2d 25 73 20 4e 31 31 30 20 53 73 6c 20 43 6f 6e 6e 65 63 74 20 4f 6b 28 25 73 3a 25 64 29 2e}
		$s7 = {25 73 2d 25 73 20 4e 31 31 30 20 42 61 73 69 63 20 43 6f 6e 6e 65 63 74 20 4f 6b 28 25 73 3a 25 64 29 2e}
		$s8 = {74 63 6f 6e 6e 20 3c 69 70 3e 20 3c 70 6f 72 74 3e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 4 of them )
}

