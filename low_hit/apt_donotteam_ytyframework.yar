import "pe"

rule APT_DonotTeam_YTYframework : APT DonotTeam Windows hardened
{
	meta:
		author = "James E.C, ProofPoint"
		description = "Modular malware framework with similarities to EHDevel"
		hashes = "1e0c1b97925e1ed90562d2c68971e038d8506b354dd6c1d2bcc252d2a48bc31c"
		reference = "https://www.arbornetworks.com/blog/asert/donot-team-leverages-new-modular-malware-framework-south-asia/"
		reference2 = "https://labs.bitdefender.com/2017/09/ehdevel-the-story-of-a-continuously-improving-advanced-threat-creation-toolkit/"
		date = "08-03-2018"
		id = "6dd07019-aa5a-5966-8331-b6f6758b0652"

	strings:
		$x1 = {((2f 66 6f 6f 74 62 61 6c 6c 2f 64 6f 77 6e 6c 6f 61 64 32 2f) | (2f 00 66 00 6f 00 6f 00 74 00 62 00 61 00 6c 00 6c 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 32 00 2f 00))}
		$x2 = {((2f 66 6f 6f 74 62 61 6c 6c 2f 64 6f 77 6e 6c 6f 61 64 2f) | (2f 00 66 00 6f 00 6f 00 74 00 62 00 61 00 6c 00 6c 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00))}
		$x3 = {43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 58 00 70 00 3e 00}
		$x_c2 = {35 2e 31 33 35 2e 31 39 39 2e 30}
		$a1 = {67 65 74 47 6f 6f 67 6c 65}
		$a2 = {2f 00 71 00 20 00 2f 00 6e 00 6f 00 72 00 65 00 74 00 73 00 74 00 61 00 72 00 74 00}
		$a3 = {49 73 49 6e 53 61 6e 64 62 6f 78}
		$a4 = {73 79 73 73 79 73 74 65 6d 6e 65 77}
		$a5 = {79 74 79 69 6e 66 6f}
		$a6 = {5c 79 74 79 62 6f 74 68 5c 79 74 79 20}
		$s1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 4e 00 61 00 6d 00 65 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00}
		$s2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 53 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 44 00 69 00 73 00 6b 00 44 00 72 00 69 00 76 00 65 00}
		$s4 = {56 00 4d 00 3a 00 20 00 59 00 65 00 73 00}
		$s5 = {56 00 4d 00 3a 00 20 00 4e 00 6f 00}
		$s6 = {68 65 6c 70 64 6c 6c 2e 64 6c 6c}
		$s7 = {62 6f 6f 74 68 65 6c 70 2e 65 78 65}
		$s8 = {53 00 62 00 69 00 65 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00}
		$s9 = {64 00 62 00 67 00 68 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00}
		$s10 = {59 65 73 4e 6f 4d 61 79 62 65}
		$s11 = {73 61 76 65 44 61 74 61}
		$s12 = {73 61 76 65 4c 6f 67 73}

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 500KB and ( pe.imphash ( ) == "87775285899fa860b9963b11596a2ded" or 1 of ( $x* ) or 3 of ( $a* ) or 6 of ( $s* ) )
}

