rule Casper_Backdoor_x86 : hardened
{
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015-03-05"
		modified = "2023-01-27"
		hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
		score = 80
		id = "9e54f00c-74a7-56cc-87e5-8dec1233cbb5"

	strings:
		$s1 = {22 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 22 00}
		$s2 = {66 69 72 65 66 6f 78 2e 65 78 65}
		$s3 = {22 00 48 00 6f 00 73 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 22 00}
		$x1 = {5c 55 73 65 72 73 5c 2a}
		$x2 = {5c 52 6f 61 6d 69 6e 67 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 2a}
		$x3 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 2a}
		$x4 = {5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 2a}
		$y1 = {25 00 73 00 3b 00 20 00 25 00 53 00 3d 00 25 00 53 00}
		$y2 = {25 73 3b 20 25 73 3d 25 73}
		$y3 = {43 6f 6f 6b 69 65 3a 20 25 73 3d 25 73}
		$y4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 25 00 53 00 3a 00 25 00 64 00}
		$z1 = {68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 63 6f 6d 2f}
		$z2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 39 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 35 2e 30 3b 20 4d 41 4c 43 29}
		$z3 = {4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 22 00}

	condition:
		( filesize < 250KB and all of ( $s* ) ) or ( 3 of ( $x* ) and 2 of ( $y* ) and 2 of ( $z* ) )
}

rule Casper_EXE_Dropper : hardened
{
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/05"
		hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
		score = 80
		id = "a901d045-6f9b-57e8-8347-6f78178b7231"

	strings:
		$s0 = {3c 43 6f 6d 6d 61 6e 64 3e}
		$s1 = {3c 2f 43 6f 6d 6d 61 6e 64 3e}
		$s2 = {22 20 2f 64 20 22}
		$s4 = {27 25 73 27 20 25 73}
		$s5 = {6e 00 4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00}
		$s6 = {40 00 52 00 65 00 74 00 75 00 72 00 6e 00 56 00 61 00 6c 00 75 00 65 00}
		$s7 = {49 44 3a 20 30 78 25 78}
		$s8 = {4e 61 6d 65 3a 20 25 53}

	condition:
		7 of them
}

rule Casper_Included_Strings : hardened
{
	meta:
		description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 75
		id = "34ba474d-0858-534a-8f32-db5a709e8814"

	strings:
		$a0 = {63 6d 64 2e 65 78 65 20 2f 43 20 46 4f 52 20 2f 4c 20 25 25 69 20 49 4e 20 28 31 2c 31 2c 25 64 29 20 44 4f 20 49 46 20 45 58 49 53 54}
		$a1 = {26 20 53 59 53 54 45 4d 49 4e 46 4f 29 20 45 4c 53 45 20 45 58 49 54}
		$c1 = {64 00 6f 00 6d 00 63 00 6f 00 6d 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00}
		$c2 = {6a 70 69 63 2e 67 6f 76 2e 73 79}
		$c3 = {61 00 69 00 6f 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00}
		$c4 = {70 65 72 66 61 75 64 69 6f 2e 64 61 74}
		$c5 = {43 61 73 70 65 72 5f 44 4c 4c 2e 64 6c 6c}
		$c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 }
		$c7 = {7b 34 32 31 36 35 36 37 41 2d 34 35 31 32 2d 39 38 32 35 2d 37 37 34 35 46 38 35 36 7d}

	condition:
		all of ( $a* ) or uint16( 0 ) == 0x5a4d and ( 2 of ( $c* ) )
}

rule Casper_SystemInformation_Output : hardened
{
	meta:
		description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 70
		id = "aaae200c-7ef1-52eb-be5b-36e0ad29ecef"

	strings:
		$a0 = {2a 2a 2a 2a 2a 20 53 59 53 54 45 4d 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 20 2a 2a 2a 2a 2a 2a}
		$a1 = {2a 2a 2a 2a 2a 20 53 45 43 55 52 49 54 59 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 20 2a 2a 2a 2a 2a 2a}
		$a2 = {41 6e 74 69 76 69 72 75 73 3a 20}
		$a3 = {46 69 72 65 77 61 6c 6c 3a 20}
		$a4 = {2a 2a 2a 2a 2a 20 45 58 45 43 55 54 49 4f 4e 20 43 4f 4e 54 45 58 54 20 2a 2a 2a 2a 2a 2a}
		$a5 = {49 64 65 6e 74 69 74 79 3a 20}
		$a6 = {3c 43 4f 4e 46 49 47 20 54 49 4d 45 53 54 41 4d 50 3d}

	condition:
		all of them
}

