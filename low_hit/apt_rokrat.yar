rule ROKRAT_Malware : hardened
{
	meta:
		description = "Detects ROKRAT Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/04/introducing-rokrat.html"
		date = "2017-04-03"
		modified = "2021-09-14"
		hash1 = "051463a14767c6477b6dacd639f30a8a5b9e126ff31532b58fc29c8364604d00"
		hash2 = "cd166565ce09ef410c5bba40bad0b49441af6cfb48772e7e4a9de3d646b4851c"
		id = "52e7e144-b704-5254-9a0f-928fbc96f877"

	strings:
		$x1 = {63 3a 5c 75 73 65 72 73 5c 61 70 70 64 61 74 61 5c 6c 6f 63 61 6c 5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$x2 = {63 3a 5c 74 65 6d 70 5c 65 70 69 73 6f 64 65 33 2e 6d 70 34}
		$x3 = {4d 41 43 2d 53 49 4c 2d 54 45 44 2d 46 4f 4f 2d 59 49 4d 2d 4c 41 4e 2d 57 41 4e 2d 53 45 43 2d 42 49 4c 2d 54 41 42}
		$x4 = {63 3a 5c 74 65 6d 70 5c 25 64 2e 74 6d 70}
		$s1 = {25 73 25 73 25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 6a 61 72}
		$s2 = {5c 41 62 6f 61 72 64 5c 41 63 6d 25 63 25 63 25 63 2e 65 78 65}
		$a1 = {79 74 68 6f 6e}
		$a2 = {69 64 64 6c 65 72}
		$a3 = {65 67 6d 6f 6e}
		$a6 = {69 72 65 73 68 61}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25000KB and ( 1 of ( $x* ) or ( 5 of them ) )
}

import "pe"

rule ROKRAT_Dropper_Nov17 : hardened
{
	meta:
		description = "Detects dropper for ROKRAT malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		date = "2017-11-28"
		hash1 = "eb6d25e08b2b32a736b57f8df22db6d03dc82f16da554f4e8bb67120eacb1d14"
		hash2 = "a29b07a6fe5d7ce3147dd7ef1d7d18df16e347f37282c43139d53cce25ae7037"
		id = "4f3156a2-6b1b-5c65-b8fa-84c0b739d703"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2500KB and pe.imphash ( ) == "c6187b1b5f4433318748457719dd6f39"
}

rule Freeenki_Infostealer_Nov17 : hardened
{
	meta:
		description = "Detects Freenki infostealer malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		date = "2017-11-28"
		modified = "2023-01-06"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
		id = "01365093-e40a-524a-8a13-217742542f1e"

	strings:
		$x1 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 3d 22 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41}
		$x2 = {63 6f 6d 6d 61 6e 64 20 3d 6f 75 74 46 69 6c 65 20 26 22 20 73 79 73 75 70 64 61 74 65 22}
		$x3 = {6f 75 74 46 69 6c 65 3d 73 79 73 44 69 72 26 22 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22}
		$s1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 6c 00 69 00 65 00 6e 00 74 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 4d 00 65 00 6e 00 75 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 5c 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}
		$s2 = {63 3a 5c 54 45 4d 50 5c 43 72 61 73 68 52 65 70 6f 72 74 73 5c}
		$s3 = {6f 62 6a 53 68 65 6c 6c 2e 72 75 6e 20 63 6f 6d 6d 61 6e 64 2c 20 30 2c 20 54 72 75 65}
		$s4 = {73 79 73 44 69 72 20 3d 20 73 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 77 69 6e 64 69 72 25 22 29}
		$s5 = {27 57 73 63 72 69 70 74 2e 65 63 68 6f 20 22 42 61 73 65 36 34 20 65 6e 63 6f 64 65 64 3a 20 22 20 2b 20 62 61 73 65 36 34 45 6e 63 6f 64 65 64}
		$s6 = {73 65 74 20 73 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$a1 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61}
		$a2 = {53 45 4c 45 43 54 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 2c 20 73 69 67 6e 6f 6e 5f 72 65 61 6c 6d 20 46 52 4f 4d 20 6c 6f 67 69 6e 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( 1 of ( $x* ) or 3 of them or all of ( $a* ) )
}

import "pe"

rule Freeenki_Infostealer_Nov17_Export_Sig_Testing : hardened
{
	meta:
		description = "Detects Freenki infostealer malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		date = "2017-11-28"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
		id = "929f9d41-2e71-5a86-b12f-489355bdf88d"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and pe.exports ( "getUpdate" ) and pe.number_of_exports == 1
}

rule ROKRAT_Nov17_1 : hardened
{
	meta:
		description = "Detects ROKRAT malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-11-28"
		id = "6bf3653b-1f96-5060-b6fd-82ccc83fad77"

	strings:
		$s1 = {5c 54 2b 4d 5c 52 65 73 75 6c 74 5c 44 6f 63 50 72 69 6e 74 2e 70 64 62}
		$s2 = {64 3a 5c 48 69 67 68 53 63 68 6f 6f 6c 5c 76 65 72 73 69 6f 6e 20 31 33 5c 32 6e 64 42 44}
		$s3 = {65 3a 5c 48 61 70 70 79 5c 57 6f 72 6b 5c 53 6f 75 72 63 65 5c 76 65 72 73 69 6f 6e}
		$x1 = {5c 61 70 70 64 61 74 61 5c 6c 6f 63 61 6c 5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$x2 = {63 3a 5c 74 65 6d 70 5c 65 73 6f 66 74 73 63 72 61 70 2e 6a 70 67}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 15000KB and 1 of them )
}

