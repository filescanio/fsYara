import "pe"

rule Sofacy_Oct17_1 : hardened
{
	meta:
		description = "Detects Sofacy malware reported in October 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
		date = "2017-10-23"
		hash1 = "522fd9b35323af55113455d823571f71332e53dde988c2eb41395cf6b0c15805"
		id = "6896dcf3-e422-5a40-bc1e-d1f35ae95c14"

	strings:
		$x1 = {25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 6e 00 65 00 74 00 77 00 66 00 2e 00 64 00 6c 00 6c 00}
		$x2 = {73 65 74 20 70 61 74 68 20 3d 20 22 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 6e 65 74 77 66 2e 64 6c 6c 22}
		$x3 = {25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 6e 00 65 00 74 00 77 00 66 00 2e 00 62 00 61 00 74 00}
		$x4 = {4b 6c 70 53 76 63 2e 64 6c 6c}
		$g1 = {73 65 74 20 70 61 74 68 20 3d 20 22 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c}
		$g2 = {25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00}
		$s1 = {73 74 61 72 74 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 70 61 74 68 20 25 2c 23 31 61}
		$s2 = {67 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00}
		$s3 = {73 20 2d 20 25 6c 75}
		$s4 = {62 65 20 72 75 6e 20 69}
		$s5 = {69 6e 67 54 6f 42 69 6e 68 61 72 79}
		$s6 = {25 6a 25 58 6a 73}
		$s7 = {69 66 20 4e 4f 54 20 65 78 69 73 74 20 25 70 61 74 68 20 25 20 28 65 78 69 74 29}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "a2d1be6502b4b3c28959a4fb0196ea45" or pe.exports ( "KlpSvc" ) or ( 1 of ( $x* ) or 4 of them ) or ( $s1 and all of ( $g* ) ) )
}

import "pe"

rule Sofacy_Oct17_2 : hardened
{
	meta:
		description = "Detects Sofacy malware reported in October 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
		date = "2017-10-23"
		hash1 = "ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18"
		id = "c820eab0-9b64-5718-8681-a4f515ee462b"

	strings:
		$x1 = {6e 00 65 00 74 00 77 00 66 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {25 00 73 00 20 00 2d 00 20 00 25 00 73 00 20 00 2d 00 20 00 25 00 32 00 2e 00 32 00 78 00}
		$s2 = {25 73 20 2d 20 25 6c 75}
		$s3 = {25 00 73 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 25 00 73 00}
		$s4 = {25 6a 25 58 6a 73 66}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 90KB and ( pe.imphash ( ) == "13344e2a717849489bcd93692f9646f7" or ( 4 of them ) ) ) or ( all of them )
}

