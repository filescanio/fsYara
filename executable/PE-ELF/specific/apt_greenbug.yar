rule Greenbug_Malware_1 : hardened
{
	meta:
		description = "Detects Malware from Greenbug Incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
		id = "3375a392-4896-572c-9688-00f01ea86ca7"

	strings:
		$s1 = {76 61 69 6c 61 62 6c 65 7a}
		$s2 = {53 66 6f 75 67 6c 72}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}

rule Greenbug_Malware_2 : hardened
{
	meta:
		description = "Detects Backdoor from Greenbug Incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		hash1 = "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
		hash2 = "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
		hash3 = "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
		id = "e5d5ddae-cf6d-579f-9a67-9406838b5e0b"

	strings:
		$x1 = {7c 7c 7c 43 6f 6d 6d 61 6e 64 20 65 78 65 63 75 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79}
		$x2 = {5c 52 65 6c 65 61 73 65 5c 42 6f 74 20 46 72 65 73 68 2e 70 64 62}
		$x3 = {43 00 3a 00 5c 00 64 00 64 00 64 00 5c 00 61 00 31 00 2e 00 74 00 78 00 74 00}
		$x4 = {42 6f 74 73 5c 42 6f 74 35 5c 78 36 34 5c 52 65 6c 65 61 73 65}
		$x5 = {42 6f 74 35 5c 52 65 6c 65 61 73 65 5c 49 73 6d 2e 70 64 62}
		$x6 = {42 6f 74 5c 52 65 6c 65 61 73 65 5c 49 73 6d 2e 70 64 62}
		$x7 = {5c 42 6f 74 20 46 72 65 73 68 5c 52 65 6c 65 61 73 65 5c 42 6f 74}
		$s1 = {2f 00 48 00 6f 00 6d 00 65 00 2f 00 53 00 61 00 76 00 65 00 46 00 69 00 6c 00 65 00 3f 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 49 00 64 00 3d 00 43 00 6d 00 64 00 52 00 65 00 73 00 75 00 6c 00 74 00 3d 00}
		$s2 = {72 61 42 33 47 3a 53 75 6e 3a 53 75 6e 64 61 79 3a 4d 6f 6e 3a 4d 6f 6e 64 61 79 3a 54 75 65 3a 54 75 65 73 64 61 79 3a 57 65 64 3a 57 65 64 6e 65 73 64 61 79 3a 54 68 75 3a 54 68 75 72 73 64 61 79 3a 46 72 69 3a 46 72 69 64 61 79 3a 53 61 74 3a 53 61 74 75 72 64 61 79}
		$s3 = {53 00 65 00 74 00 2d 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 5c 00 62 00 2a 00 7b 00 2e 00 2b 00 3f 00 7d 00 5c 00 6e 00}
		$s4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or 2 of them ) ) or ( 3 of them )
}

rule Greenbug_Malware_3 : hardened
{
	meta:
		description = "Detects Backdoor from Greenbug Incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		super_rule = 1
		hash1 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
		hash2 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
		id = "68142bcd-4bd0-5c80-97fc-38811565e21c"

	strings:
		$x1 = {46 3a 5c 50 72 6f 6a 65 63 74 73 5c 42 6f 74 5c 42 6f 74 5c 52 65 6c 65 61 73 65 5c 49 73 6d 2e 70 64 62}
		$x2 = {43 00 3a 00 5c 00 64 00 64 00 64 00 5c 00 77 00 65 00 72 00 32 00 2e 00 74 00 78 00 74 00}
		$x3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 6d 00 70 00 34 00 33 00 68 00 68 00 31 00 31 00 2e 00 74 00 78 00 74 00}

	condition:
		1 of them
}

rule Greenbug_Malware_4 : hardened
{
	meta:
		description = "Detects ISMDoor Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		super_rule = 1
		hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
		hash2 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
		id = "d45dea36-6051-5531-afd2-abf27cd06a12"
		score = 75

	strings:
		$s1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 6c 6f 67 6f 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 20 22 53 65 74 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 2d 73 63 6f 70 65 20 63 75 72 72 65 6e 74 75 73 65 72}
		$s2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 20 22 53 65 74 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 2d 73 63 6f 70 65 20 63 75 72 72 65 6e 74 75 73 65 72 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 75 6e 72 65 73 74 72 69 63 74 65 64 20 2d 66 3b 20 2e 20 22}
		$s3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 74 6d 70 38 38 37 33}
		$s4 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 77 69 6e 69 74 2e 65 78 65 20 2f 66}
		$s5 = {69 6e 76 6f 6b 65 2d 70 73 75 61 63 6d 65}
		$s6 = {2d 6d 65 74 68 6f 64 20 6f 6f 62 65 20 2d 70 61 79 6c 6f 61 64 20 22 22}
		$s7 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 73 00 74 00 61 00 74 00 32 00 2e 00 64 00 61 00 74 00}
		$s8 = {49 6e 76 6f 6b 65 2d 62 79 70 61 73 73 75 61 63}
		$s9 = {53 00 74 00 61 00 72 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 20 00 44 00 6f 00 6e 00 65 00}
		$s10 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 49 74 2e 65 78 65}
		$s11 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 54 6d 70 39 39 33 32 75 31 2e 62 61 74 22}
		$s12 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 6d 00 70 00 34 00 33 00 68 00 68 00 31 00 31 00 2e 00 74 00 78 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them
}

rule Greenbug_Malware_5 : hardened
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		modified = "2023-01-27"
		super_rule = 1
		hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
		hash2 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
		hash3 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
		hash4 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
		id = "12362711-f466-5f9e-9227-1cf84aec93e5"

	strings:
		$x1 = {63 6d 64 20 2f 75 20 2f 63 20 57 4d 49 43 20 2f 4e 6f 64 65 3a 6c 6f 63 61 6c 68 6f 73 74 20 2f 4e 61 6d 65 73 70 61 63 65 3a 5c 5c 72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72}
		$x2 = {63 6d 64 20 2f 61 20 2f 63 20 6e 65 74 20 75 73 65 72 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 2f 64 6f 6d 61 69 6e 20 3e 3e}
		$x3 = {63 6d 64 20 2f 61 20 2f 63 20 6e 65 74 73 74 61 74 20 2d 61 6e 74 20 3e 3e 22 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c}
		$o1 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 28 4e 65 74 20 55 73 65 72 29 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}

	condition:
		filesize < 2000KB and ( ( uint16( 0 ) == 0x5a4d and 1 of them ) or $o1 )
}

import "pe"

rule Greenbug_Malware_Nov17_1 : hardened
{
	meta:
		description = "Detects Greenbug Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/greenbug/"
		date = "2017-11-26"
		hash1 = "6e55e161dc9ace3076640a36ef4a8819bb85c6d5e88d8e852088478f79cf3b7c"
		hash2 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
		id = "50816c09-5f38-5e05-9915-b96f00ee4b88"

	strings:
		$x1 = {41 67 65 6e 74 56 32 2e 65 78 65 20 20 2d 63 20 20 53 61 6d 70 6c 65 44 6f 6d 61 69 6e 2e 63 6f 6d}
		$x2 = {2e 6e 74 70 75 70 64 61 74 65 73 65 72 76 65 72 2e 63 6f 6d}
		$x3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 61 2e 61 22}
		$x4 = {61 36 37 64 30 64 62 38 38 35 61 33 34 33 32 35 37 36 35 34 38 61 32 61 30 33 37 30 37 33 33 34}
		$x5 = {61 36 37 64 30 64 62 38 61 32 61 31 37 33 33 34 37 36 35 34 34 33 32 35 30 33 37 30 32 61 61 33}
		$x6 = {21 21 21 20 63 61 6e 20 6e 6f 74 20 63 72 65 61 74 65 20 6f 75 74 70 75 74 20 66 69 6c 65 20 21 21 21}
		$s1 = {5c 72 75 6e 6c 6f 67 2a}
		$s2 = {63 61 6e 20 6e 6f 74 20 73 70 65 63 69 66 79 20 75 73 65 72 6e 61 6d 65 21 21}
		$s3 = {41 67 65 6e 74 20 63 61 6e 20 6e 6f 74 20 62 65 20 63 6f 6e 66 69 67 75 72 65 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( pe.imphash ( ) == "58ba44f7ff5436a603fec3df97d815ea" or pe.imphash ( ) == "538805ecd776b9a42e71aebf94fde1b1" or 1 of ( $x* ) or 3 of them )
}

