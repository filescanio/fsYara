rule FIN7_Dropper_Aug17 : hardened
{
	meta:
		description = "Detects Word Dropper from Proofpoint FIN7 Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
		date = "2017-08-04"
		hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
		hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"
		id = "4929dff6-9f33-5d22-b560-c2195440a1cc"
		score = 70

	strings:
		$x1 = {74 70 69 72 63 73 6a 3a 65 2f 20 62 2f 2f 20 65 78 65 2e 74 70 69 72 63 73 77 22 20 72 74 2f}
		$s1 = {53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 24}
		$s2 = {50 00 52 00 4f 00 4a 00 45 00 43 00 54 00 2e 00 54 00 48 00 49 00 53 00 44 00 4f 00 43 00 55 00 4d 00 45 00 4e 00 54 00 2e 00 41 00 55 00 54 00 4f 00 4f 00 50 00 45 00 4e 00}
		$s3 = {50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 54 00 68 00 69 00 73 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 41 00 75 00 74 00 6f 00 4f 00 70 00 65 00 6e 00}
		$s4 = {5c 73 79 73 74 65 6d 33}
		$s5 = {53 68 65 6c 6c 56}

	condition:
		( uint16( 0 ) == 0xcfd0 and filesize < 700KB and 1 of ( $x* ) or all of ( $s* ) )
}

rule FIN7_Backdoor_Aug17 : hardened limited
{
	meta:
		description = "Detects Word Dropper from Proofpoint FIN7 Report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
		date = "2017-08-04"
		id = "906daf88-520b-57b5-825e-29f060b43183"

	strings:
		$x1 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 62 20 2f 65 3a 6a 73 63 72 69 70 74 20 43 3a 5c 55 73 65 72 73 5c}
		$x2 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 62 20 2f 65 3a 6a 73 63 72 69 70 74 20 43 3a 5c 55 73 65 72 73 5c}
		$x3 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 66 20 2f 74 6e 20 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 53 79 73 74 65 6d 22 20 2f 74 72 20 22 77 73 63 72 69 70 74 2e 65 78 65}
		$x4 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 46 20 2f 54 4e 20 22 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65}
		$x5 = {73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 46 20 2f 54 4e 20 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65}
		$x6 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 62 20 2f 65 3a 6a 73 63 72 69 70 74 20 25 54 4d 50 25 5c 64 65 62 75 67 2e 74 78 74}
		$s1 = {2f 3f 70 61 67 65 3d 77 61 69 74}
		$a1 = {61 75 74 6f 69 74 33 2e 65 78 65}
		$a2 = {64 75 6d 70 63 61 70 2e 65 78 65}
		$a3 = {74 73 68 61 72 6b 2e 65 78 65}
		$a4 = {70 72 6c 5f 63 63 2e 65 78 65}
		$v1 = {76 6d 77 61 72 65}
		$v2 = {50 43 49 5c 5c 56 45 4e 5f 38 30 45 45 26 44 45 56 5f 43 41 46 45}
		$v3 = {56 4d 57 56 4d 43 49 48 4f 53 54 44 45 56}
		$c1 = {61 70 6f 77 65 72 73 68 65 6c 6c}
		$c2 = {77 70 6f 77 65 72 73 68 65 6c 6c}
		$c3 = {67 65 74 5f 70 61 73 73 77 6f 72 64 73}
		$c4 = {6b 69 6c 6c 5f 70 72 6f 63 65 73 73}
		$c5 = {67 65 74 5f 73 63 72 65 65 6e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 5000KB and ( 1 of ( $x* ) or all of ( $a* ) or all of ( $v* ) or 3 of ( $c* ) ) ) or 5 of them
}

