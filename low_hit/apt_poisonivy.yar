rule PoisonIvy_Sample_APT : hardened
{
	meta:
		description = "Detects a PoisonIvy APT malware group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b874b76ff7b281c8baa80e4a71fc9be514093c70"
		id = "8d3b8222-8949-57dc-99b7-092189416efd"

	strings:
		$s0 = {70 69 64 6c 6c 2e 64 6c 6c}
		$s1 = {73 00 65 00 6e 00 73 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00}
		$s4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00}
		$s5 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$s9 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4d 00 65 00 64 00 69 00 61 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 47KB and all of them
}

rule PoisonIvy_Sample_APT_2 : hardened
{
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "333f956bf3d5fc9b32183e8939d135bc0fcc5770"
		id = "4d64ccd2-add8-5749-8178-f2c5336e1495"

	strings:
		$s0 = {70 69 64 6c 6c 2e 64 6c 6c}
		$s1 = {73 00 65 00 6e 00 73 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {39 00 2e 00 30 00 2e 00 31 00 2e 00 35 00 36 00}
		$s3 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00}
		$s4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00}
		$s5 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$s6 = {22 25 3d 25 31 34 3d}
		$s7 = {30 39 31 41 31 47 31 52 31 5f 31 67 31 75 31 7a 31}
		$s8 = {67 48 73 4d 5a 7a}
		$s9 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4d 00 65 00 64 00 69 00 61 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00}
		$s10 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 2e 00}
		$s11 = {4d 46 43 34 32 2e 44 4c 4c}
		$s12 = {4d 53 56 43 52 54 2e 64 6c 6c}
		$s13 = {53 00 70 00 65 00 63 00 69 00 61 00 6c 00 42 00 75 00 69 00 6c 00 64 00}
		$s14 = {50 00 72 00 69 00 76 00 61 00 74 00 65 00 42 00 75 00 69 00 6c 00 64 00}
		$s15 = {43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 73 00}
		$s16 = {30 00 34 00 30 00 39 00 30 00 34 00 62 00 30 00}
		$s17 = {4c 00 65 00 67 00 61 00 6c 00 54 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 73 00}
		$s18 = {43 72 65 61 74 65 54 68 72 65 61 64}
		$s19 = {6e 74 64 6c 6c 2e 64 6c 6c}
		$s20 = {5f 61 64 6a 75 73 74 5f 66 64 69 76}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 47KB and all of them
}

rule PoisonIvy_Sample_APT_3 : hardened
{
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "df3e1668ac20edecc12f2c1a873667ea1a6c3d6a"
		id = "e2e0bf75-7704-585f-b2b3-727d14946c76"

	strings:
		$s0 = {5c 6e 6f 74 65 70 61 64 2e 65 78 65}
		$s1 = {5c 52 61 73 41 75 74 6f 2e 64 6c 6c}
		$s3 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule PoisonIvy_Sample_APT_4 : hardened
{
	meta:
		description = "Detects a PoisonIvy Sample APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "558f0f0b728b6da537e2666fbf32f3c9c7bd4c0c"
		id = "02bf546b-99a2-5ffb-8ee7-7bb005ef953b"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s1 = {69 64 6c 6c 2e 64 6c 6c}
		$s2 = {6d 00 67 00 6d 00 74 00 73 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 28 00 52 00 29 00}
		$s4 = {53 65 72 76 69 63 65 4d 61 69 6e}
		$s5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s6 = {53 65 74 53 65 72 76 69 63 65 53 74 61 74 75 73}
		$s7 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00}
		$s8 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 7 of them
}

rule PoisonIvy_Sample_5 : hardened
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "545e261b3b00d116a1d69201ece8ca78d9704eb2"
		id = "61f7efd4-745a-5f06-a66d-b4b2a2ecc614"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s2 = {70 69 64 6c 6c 2e 64 6c 6c}
		$s3 = {5c 6d 73 70 6d 73 6e 73 76 2e 64 6c 6c}
		$s4 = {5c 73 66 63 2e 65 78 65}
		$s13 = {53 65 72 76 69 63 65 4d 61 69 6e}
		$s15 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$s17 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule PoisonIvy_Sample_6 : hardened
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash1 = "8c2630ab9b56c00fd748a631098fa4339f46d42b"
		hash2 = "36b4cbc834b2f93a8856ff0e03b7a6897fb59bd3"
		id = "f364fad0-3684-5500-b21b-396f1e259217"

	strings:
		$x1 = {31 32 34 2e 31 33 33 2e 32 35 32 2e 31 35 30}
		$x3 = {68 74 74 70 3a 2f 2f 31 32 34 2e 31 33 33 2e 32 35 34 2e 31 37 31 2f 75 70 2f 75 70 2e 61 73 70 3f 69 64 3d 25 30 38 78 26 70 63 6e 61 6d 65 3d 25 73}
		$z1 = {5c 74 65 6d 70 5c 73 69 2e 74 78 74}
		$z2 = {44 00 61 00 65 00 6d 00 6f 00 6e 00 20 00 44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 20 00 4c 00 69 00 6e 00 6b 00 20 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00}
		$z3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 43 00 54 00 46 00 20 00 4c 00 6f 00 61 00 64 00 65 00 72 00}
		$z4 = {5c 74 61 70 70 6d 67 6d 74 73 2e 64 6c 6c}
		$z5 = {5c 61 70 70 6d 67 6d 74 73 2e 64 6c 6c}
		$s0 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 4c 6f 77 5c 63 74 66 6d 6f 6e 2e 6c 6f 67}
		$s1 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 63 74 66 6d 6f 6e 2e 74 6d 70}
		$s2 = {5c 74 65 6d 70 5c 63 74 66 6d 6f 6e 2e 74 6d 70}
		$s3 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 56}
		$s4 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30}
		$s5 = {73 74 61 72 74 20 72 65 61 64 20 68 69 73 74 72 79 20 6b 65 79}
		$s6 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22}
		$s7 = {5b 70 61 73 73 77 6f 72 64 5d 25 73}
		$s8 = {44 61 65 6d 6f 6e 2e 64 6c 6c}
		$s9 = {5b 75 73 65 72 6e 61 6d 65 5d 25 73}
		$s10 = {61 64 76 70 61 63 6b}
		$s11 = {25 73 25 32 2e 32 58}
		$s12 = {61 64 76 41 50 49 33 32}

	condition:
		( uint16( 0 ) == 0x5a4d and 1 of ( $x* ) ) or ( 8 of ( $s* ) ) or ( 1 of ( $z* ) and 3 of ( $s* ) )
}

rule PoisonIvy_Sample_7 : hardened
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "9480cf544beeeb63ffd07442233eb5c5f0cf03b3"
		id = "01224053-d95e-5144-981b-76cd7e57e1c3"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s2 = {70 69 64 6c 6c 2e 64 6c 6c}
		$s10 = {53 65 72 76 69 63 65 4d 61 69 6e}
		$s11 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$s12 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s13 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 28 00 52 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

rule PoisonIvy_RAT_ssMUIDLL : hardened
{
	meta:
		description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
		author = "Florian Roth (Nextron Systems) (with the help of yarGen and Binarly)"
		reference = "http://goo.gl/WiwtYT"
		date = "2016-04-22"
		hash1 = "7a424ad3f3106b87e8e82c7125834d7d8af8730a2a97485a639928f66d5f6bf4"
		hash2 = "6eb7657603edb2b75ed01c004d88087abe24df9527b272605b8517a423557fe6"
		hash3 = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		hash4 = "8b805f508879ecdc9bba711cfbdd570740c4825b969c1b4db980c134ac8fef1c"
		hash5 = "ac99d4197e41802ff9f8852577955950332947534d8e2a0e3b6c1dd1715490d4"
		id = "f2535b70-cf17-5435-9fc8-2dfdf70d95ac"

	strings:
		$s1 = {73 73 4d 55 49 44 4c 4c 2e 64 6c 6c}
		$op1 = { 6a 00 c6 07 e9 ff d6 }
		$op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 }
		$op3 = { 6a 00 88 7f 02 ff d6 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 20KB and ( all of ( $op* ) ) ) or ( all of them )
}

