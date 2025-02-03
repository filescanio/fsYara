rule GhostDragon_Gh0stRAT : hardened
{
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		date = "2016-04-23"
		hash1 = "f9a669d22866cd041e2d520c5eb093188962bea8864fdfd0c0abb2b254e9f197"
		hash2 = "99ee5b764a5db1cb6b8a4f62605b5536487d9c35a28a23de8f9174659f65bcb2"
		hash3 = "6c7f8ba75889e0021c4616fcbee86ac06cd7f5e1e355e0cbfbbb5110c08bb6df"
		hash4 = "b803381535ac24ce7c8fdcf6155566d208dfca63fd66ec71bbc6754233e251f5"
		id = "a74330ab-5249-5125-8f48-27aec7c6eeb4"

	strings:
		$x1 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 25 73 20 2f 76 20 53 65 72 76 69 63 65 44 6c 6c 20 2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a 20 2f 64 20 22 25 73 22}
		$x2 = {47 6c 6f 62 61 6c 5c 52 45 41 4c 43 48 45 4c 5f 47 4c 4f 42 41 4c 5f 53 55 42 4d 49 54 5f 32 30 30 33 31 30 32 30 5f}
		$x3 = {5c 78 63 6c 6f 6c 67 32 2e 74 6d 70}
		$x4 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e}
		$x5 = {25 73 78 73 64 25 64 2e 70 69 66}
		$x6 = {25 73 5c 25 73 33 32 2e 64 6c 5f}
		$x7 = {25 2d 32 33 73 20 25 2d 31 36 73 20 20 30 78 25 78 28 25 30 32 64 29}
		$x8 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 73 74 61 72 74 29}
		$x9 = {25 73 5c 25 73 36 34 2e 64 6c 5f}
		$s1 = {76 69 65 77 73 63 2e 64 6c 6c}
		$s2 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 20 20 4b 65 65 70 2d 41 6c 69 76 65}
		$s3 = {5c 73 66 63 5f 6f 73 2e 64 6c 6c}
		$s4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29}
		$s5 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e}
		$s6 = {43 4f 4e 4e 45 43 54 20 20 20 25 73 3a 25 64 20 20 20 48 54 54 50 2f 31 2e 31}
		$s7 = {57 69 6e 64 6f 77 73 55 70 70 65 72 56 65 72 73 69 6f 6e}
		$s8 = {5b 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 5d 20 28 25 73 29}
		$s9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 61 74 61 41 63 63 65 73 73 5c 25 73}
		$s10 = {25 73 20 73 70 25 64 28 25 64 29}
		$s11 = {4f 70 65 6e 53 43 20 45 52 52 4f 52 20}
		$s12 = {67 65 74 20 72 67 73 70 61 74 68 20 65 72 72 6f 72 20}
		$s13 = {47 6c 6f 62 61 6c 5c 47 4c 4f 42 41 4c 5f 53 55 42 4d 49 54 5f 30 32 33 34 5f}
		$s14 = {47 6c 6f 62 61 6c 5c 5f 76 63 5f 63 6b 5f 20 25 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $x* ) or 4 of ( $s* ) ) ) or ( 6 of them )
}

rule GhostDragon_Gh0stRAT_Sample2 : hardened
{
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		date = "2016-04-23"
		hash1 = "71a52058f6b5cef66302c19169f67cf304507b4454cca83e2c36151da8da1d97"
		id = "424cb978-c4d1-5847-8852-e25ec2a02139"

	strings:
		$x1 = {41 64 6f 62 65 57 70 6b}
		$x2 = {73 65 65 6b 69 6e 2e 64 6c 6c}
		$c1 = {57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 36 2e 30 29}
		$c2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 31 30 2e 30 3b 20}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 80KB and ( all of ( $x* ) or all of ( $c* ) ) ) or ( all of them )
}

rule GhostDragon_Gh0stRAT_Sample3 : hardened
{
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		date = "2016-04-23"
		hash1 = "1be9c68b31247357328596a388010c9cfffadcb6e9841fb22de8b0dc2d161c42"
		id = "6d4bb99d-28de-59c2-b6f0-6da3cac4ed73"
		score = 60

	strings:
		$op1 = { 44 24 15 65 88 54 24 16 c6 44 24 }
		$op2 = { 44 24 1b 43 c6 44 24 1c 75 88 54 24 1e }
		$op3 = { 1e 79 c6 44 24 1f 43 c6 44 24 20 75 88 54 24 22 }

	condition:
		all of them
}

