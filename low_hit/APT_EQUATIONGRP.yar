rule EQGRP_noclient_3_0_5 : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$x1 = {2d 43 20 25 73 20 31 32 37 2e 30 2e 30 2e 31 22 20 73 63 72 69 70 6d 65 20 2d 46 20 2d 74 20 4a 41 43 4b 50 4f 50 49 4e 34 20 27 26}
		$x2 = {43 6f 6d 6d 61 6e 64 20 74 6f 6f 20 6c 6f 6e 67 21 20 20 57 68 61 74 20 74 68 65 20 48 45 4c 4c 20 61 72 65 20 79 6f 75 20 74 72 79 69 6e 67 20 74 6f 20 64 6f 20 74 6f 20 6d 65 3f 21 3f 21 20 20 54 72 79 20 6f 6e 65 20 73 6d 61 6c 6c 65 72 20 74 68 61 6e 20 25 64 20 62 6f 7a 6f 2e}
		$x3 = {73 68 20 2d 63 20 22 70 69 6e 67 20 2d 63 20 32 20 25 73 3b 20 67 72 65 70 20 25 73 20 2f 70 72 6f 63 2f 6e 65 74 2f 61 72 70 20 3e 2f 74 6d 70 2f 67 78 20 22}
		$x4 = {45 72 72 6f 72 20 66 72 6f 6d 20 6f 75 72 74 6e 2c 20 64 69 64 20 6e 6f 74 20 66 69 6e 64 20 6b 65 79 73 3d 74 61 72 67 65 74 20 69 6e 20 74 6e 2e 73 70 61 79 65 64}
		$x5 = {6f 75 72 74 6e 20 2d 64 20 2d 44 20 25 73 20 2d 57 20 31 32 37 2e 30 2e 30 2e 31 3a 25 64 20 20 2d 69 20 25 73 20 2d 70 20 25 64 20 25 73 20 25 73}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 700KB and 1 of them ) or ( all of them )
}

rule EQGRP_installdate : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file installdate.pl"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$x1 = {23 50 72 6f 76 69 64 65 20 68 65 78 20 6f 72 20 45 50 20 6c 6f 67 20 61 73 20 63 6f 6d 6d 61 6e 64 2d 6c 69 6e 65 20 61 72 67 75 6d 65 6e 74 20 6f 72 20 61 73 20 69 6e 70 75 74}
		$x2 = {70 72 69 6e 74 20 22 47 69 6d 6d 65 20 68 65 78 3a 20 22 3b}
		$x3 = {69 66 20 28 24 6c 69 6e 65 20 3d 7e 20 2f 52 65 67 5f 44 77 6f 72 64 3a 20 20 28 5c 64 5c 64 3a 5c 64 5c 64 3a 5c 64 5c 64 2e 5c 64 2b 20 5c 64 2b 20 2d 20 29 3f 28 5c 53 2a 29 2f 29 20 7b}
		$s1 = {69 66 20 28 24 5f 20 3d 7e 20 2f 49 6e 73 74 61 6c 6c 44 61 74 65 2f 29 20 7b}
		$s2 = {69 66 20 28 6e 6f 74 28 24 63 6d 64 49 6e 70 75 74 29 29 20 7b}
		$s3 = {70 72 69 6e 74 20 22 24 68 65 78 20 69 6e 20 64 65 63 69 6d 61 6c 3d 24 64 65 63 5c 6e 5c 6e 22 3b}

	condition:
		filesize < 2KB and ( 1 of ( $x* ) or 3 of them )
}

rule EQGRP_teflondoor : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file teflondoor.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$x1 = {25 73 3a 20 61 62 6f 72 74 2e 20 20 43 6f 64 65 20 69 73 20 25 64 2e 20 20 4d 65 73 73 61 67 65 20 69 73 20 27 25 73 27}
		$x2 = {25 73 3a 20 25 6c 69 20 62 20 28 25 6c 69 25 25 29}
		$s1 = {6e 6f 20 77 69 6e 73 6f 63 6b}
		$s2 = {25 73 3a 20 25 73 20 66 69 6c 65 20 27 25 73 27}
		$s3 = {70 65 65 72 3a 20 63 6f 6e 6e 65 63 74}
		$s4 = {72 65 61 64 3a 20 77 72 69 74 65}
		$s5 = {25 73 3a 20 64 6f 6e 65 21}
		$s6 = {25 73 3a 20 25 6c 69 20 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and 1 of ( $x* ) and 3 of them
}

rule EQGRP_durablenapkin_solaris_2_0_1 : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$s1 = {72 65 63 76 5f 61 63 6b 3a 20 25 73 3a 20 53 65 72 76 69 63 65 20 6e 6f 74 20 73 75 70 70 6c 69 65 64 20 62 79 20 70 72 6f 76 69 64 65 72}
		$s2 = {73 65 6e 64 5f 72 65 71 75 65 73 74 3a 20 70 75 74 6d 73 67 20 22 25 73 22 3a 20 25 73}
		$s3 = {70 6f 72 74 20 75 6e 64 65 66 69 6e 65 64}
		$s4 = {72 65 63 76 5f 61 63 6b 3a 20 25 73 20 67 65 74 6d 73 67 3a 20 25 73}
		$s5 = {3e 3e 20 25 64 20 2d 2d 20 25 64}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 40KB and 2 of them )
}

rule EQGRP_teflonhandle : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$s1 = {25 73 20 5b 69 6e 66 69 6c 65 5d 20 5b 6f 75 74 66 69 6c 65 5d 20 2f 6b 20 30 78 5b 25 69 20 63 68 61 72 61 63 74 65 72 20 68 65 78 20 6b 65 79 5d 20 3c 2f 67 3e}
		$s2 = {46 69 6c 65 20 25 73 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 2e 20 20 4f 76 65 72 77 72 69 74 65 3f 20 28 79 2f 6e 29 20}
		$s3 = {52 61 6e 64 6f 6d 20 4b 65 79 20 3a 20 30 78}
		$s4 = {64 6f 6e 65 20 28 25 69 20 62 79 74 65 73 20 77 72 69 74 74 65 6e 29 2e}
		$s5 = {25 73 20 2d 2d 3e 20 25 73 2e 2e 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 20KB and 2 of them
}

rule EQGRP_false : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file false.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
            00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
            2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
            0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
            0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
            00 25 64 20 2D 20 25 64 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and $s1
}

rule EQGRP_bc_genpkt : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file bc-genpkt"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$x1 = {6c 6f 61 64 20 61 75 78 69 6c 69 61 72 79 20 6f 62 6a 65 63 74 3d 25 73 20 72 65 71 75 65 73 74 65 64 20 62 79 20 66 69 6c 65 3d 25 73}
		$x2 = {73 69 7a 65 20 6f 66 20 6e 65 77 20 70 61 63 6b 65 74 2c 20 73 68 6f 75 6c 64 20 62 65 20 25 64 20 3c 3d 20 73 69 7a 65 20 3c 3d 20 25 64 20 62 79 74 65 73}
		$x3 = {76 65 72 62 6f 73 69 74 79 20 2d 20 73 68 6f 77 20 6c 65 6e 67 74 68 73 2c 20 70 61 63 6b 65 74 20 64 75 6d 70 73 2c 20 65 74 63}
		$s1 = {25 73 3a 20 65 72 72 6f 72 20 77 68 69 6c 65 20 6c 6f 61 64 69 6e 67 20 73 68 61 72 65 64 20 6c 69 62 72 61 72 69 65 73 3a 20 25 73 25 73 25 73 25 73 25 73}
		$s2 = {63 61 6e 6e 6f 74 20 64 79 6e 61 6d 69 63 61 6c 6c 79 20 6c 6f 61 64 20 65 78 65 63 75 74 61 62 6c 65}
		$s3 = {62 69 6e 64 69 6e 67 20 66 69 6c 65 20 25 73 20 74 6f 20 25 73 3a 20 25 73 20 73 79 6d 62 6f 6c 20 60 25 73 27 20 5b 25 73 5d}
		$s4 = {72 61 6e 64 6f 6d 69 7a 65 20 74 68 65 20 69 6e 69 74 69 61 74 6f 72 20 63 6f 6f 6b 69 65}

	condition:
		uint16( 0 ) == 0x457f and filesize < 1000KB and ( 1 of ( $s* ) and 3 of them )
}

rule EQGRP_dn_1_0_2_1 : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$s1 = {56 61 6c 69 64 20 63 6f 6d 6d 61 6e 64 73 20 61 72 65 3a 20 53 4d 41 43 2c 20 44 4d 41 43 2c 20 49 4e 54 2c 20 50 41 43 4b 2c 20 44 4f 4e 45 2c 20 47 4f}
		$s2 = {69 6e 76 61 6c 69 64 20 66 6f 72 6d 61 74 20 73 75 67 67 65 73 74 20 44 4d 41 43 3d 30 30 3a 30 30 3a 30 30 3a 30 30 3a 30 30 3a 30 30}
		$s3 = {53 4d 41 43 3d 25 30 32 78 3a 25 30 32 78 3a 25 30 32 78 3a 25 30 32 78 3a 25 30 32 78 3a 25 30 32 78}
		$s4 = {4e 6f 74 20 65 76 65 72 79 74 68 69 6e 67 20 69 73 20 73 65 74 20 79 65 74}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 30KB and 2 of them )
}

rule EQGRP_morel : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file morel.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"

	strings:
		$s1 = {25 64 20 2d 20 25 64 2c 20 25 64}
		$s2 = {25 64 20 2d 20 25 6c 75 2e 25 6c 75 20 25 64 2e 25 6c 75}
		$s3 = {25 64 20 2d 20 25 64 20 25 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 60KB and all of them )
}

rule EQGRP_bc_parser : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file bc-parser"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"

	strings:
		$s1 = {2a 2a 2a 20 54 61 72 67 65 74 20 6d 61 79 20 62 65 20 73 75 73 63 65 70 74 69 62 6c 65 20 74 6f 20 46 41 4c 53 45 4d 4f 52 45 4c 20 20 20 20 20 20 2a 2a 2a}
		$s2 = {2a 2a 2a 20 54 61 72 67 65 74 20 69 73 20 73 75 73 63 65 70 74 69 62 6c 65 20 74 6f 20 46 41 4c 53 45 4d 4f 52 45 4c 20 20 20 20 20 20 20 20 20 20 2a 2a 2a}

	condition:
		uint16( 0 ) == 0x457f and 1 of them
}

rule EQGRP_1212 : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - file 1212.pl"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$s1 = {69 66 20 28 21 28 28 24 73 72 63 69 70 2c 24 64 73 74 69 70 2c 24 73 72 63 70 6f 72 74 2c 24 64 73 74 70 6f 72 74 29 20 3d 20 28 24 6c 69 6e 65 3d 7e 2f 5e 28 5b 61 2d 66 30 2d 39 5d 7b 38 7d 29 28 5b 61 2d 66 30 2d 39 5d 7b 38 7d 29 28 5b 61 2d 66 30 2d 39 5d 7b 34 7d 29 28 5b 61 2d 66 30 2d 39 5d 7b 34 7d 29 24 2f 29 29 29}
		$s2 = {24 61 6e 73 3d 22 24 73 72 63 69 70 3a 24 73 72 63 70 6f 72 74 20 2d 3e 20 24 64 73 74 69 70 3a 24 64 73 74 70 6f 72 74 22 3b}
		$s3 = {72 65 74 75 72 6e 20 22 45 52 52 4f 52 3a 24 6c 69 6e 65 20 69 73 20 6e 6f 74 20 61 20 76 61 6c 69 64 20 70 6f 72 74 22 3b}
		$s4 = {24 64 73 74 70 6f 72 74 3d 68 65 78 74 6f 50 6f 72 74 28 24 64 73 74 70 6f 72 74 29 3b}
		$s5 = {73 75 62 20 68 65 78 74 6f 50 6f 72 74}
		$s6 = {24 62 79 74 65 5f 74 61 62 6c 65 7b 22 24 63 68 61 72 73 5b 24 73 69 78 74 65 65 6e 73 5d 24 63 68 61 72 73 5b 24 6f 6e 65 73 5d 22 7d 3d 24 69 3b}

	condition:
		filesize < 6KB and 4 of them
}

rule EQGRP_1212_dehex : hardened
{
	meta:
		description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"

	strings:
		$s1 = {72 65 74 75 72 6e 20 22 45 52 52 4f 52 3a 24 6c 69 6e 65 20 69 73 20 6e 6f 74 20 61 20 76 61 6c 69 64 20 61 64 64 72 65 73 73 22 3b}
		$s2 = {70 72 69 6e 74 20 22 45 52 52 4f 52 3a 20 74 68 65 20 66 69 6c 65 6e 61 6d 65 20 6f 72 20 68 65 78 20 72 65 70 72 65 73 65 6e 74 61 74 69 6f 6e 20 6e 65 65 64 73 20 74 6f 20 62 65 20 6f 6e 65 20 61 72 67 75 6d 65 6e 74 20 74 72 79 20 75 73 69 6e 67 20 5c 5c 22 27 73 5c 6e 22 3b}
		$s3 = {70 75 73 68 28 40 6f 63 74 65 74 73 2c 24 62 79 74 65 5f 74 61 62 6c 65 7b 24 74 65 6d 70 69 7d 29 3b}
		$s4 = {24 62 79 74 65 5f 74 61 62 6c 65 7b 22 24 63 68 61 72 73 5b 24 73 69 78 74 65 65 6e 73 5d 24 63 68 61 72 73 5b 24 6f 6e 65 73 5d 22 7d 3d 24 69 3b}
		$s5 = {70 72 69 6e 74 20 68 65 78 74 6f 49 50 28 24 41 52 47 56 5b 30 5d 29 3b}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 6KB and ( 5 of ( $s* ) ) ) or ( all of them )
}

rule install_get_persistent_filenames : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"

	strings:
		$s1 = {47 65 6e 65 72 61 74 65 73 20 74 68 65 20 70 65 72 73 69 73 74 65 6e 63 65 20 66 69 6c 65 20 6e 61 6d 65 20 61 6e 64 20 70 72 69 6e 74 73 20 69 74 20 6f 75 74 2e}

	condition:
		( uint16( 0 ) == 0x457f and all of them )
}

rule EQGRP_create_dns_injection : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file create_dns_injection.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"

	strings:
		$s1 = {4e 61 6d 65 3a 20 20 20 41 20 68 6f 73 74 6e 61 6d 65 3a 20 27 68 6f 73 74 2e 6e 65 74 77 6f 72 6b 2e 63 6f 6d 27 2c 20 61 20 64 65 63 69 6d 61 6c 20 6e 75 6d 65 72 69 63 20 6f 66 66 73 65 74 20 77 69 74 68 69 6e}
		$s2 = {2d 61 20 77 77 77 2e 62 61 64 67 75 79 2e 6e 65 74 2c 43 4e 41 4d 45 2c 31 38 30 30 2c 68 6f 73 74 2e 62 61 64 67 75 79 2e 6e 65 74 20 5c 5c}

	condition:
		1 of them
}

rule EQGRP_screamingplow : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file screamingplow.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"

	strings:
		$s1 = {57 68 61 74 20 69 73 20 74 68 65 20 6e 61 6d 65 20 6f 66 20 79 6f 75 72 20 50 42 44 3a}
		$s2 = {59 6f 75 20 61 72 65 20 6e 6f 77 20 72 65 61 64 79 20 66 6f 72 20 61 20 53 63 72 65 61 6d 50 6c 6f 77}

	condition:
		1 of them
}

rule EQGRP_MixText : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file MixText.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"

	strings:
		$s1 = {42 69 6e 53 74 6f 72 65 20 65 6e 61 62 6c 65 64 20 69 6d 70 6c 61 6e 74 73 2e}

	condition:
		1 of them
}

rule EQGRP_tunnel_state_reader : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file tunnel_state_reader"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"

	strings:
		$s1 = {41 63 74 69 76 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 77 69 6c 6c 20 62 65 20 6d 61 69 6e 74 61 69 6e 65 64 20 66 6f 72 20 74 68 69 73 20 74 75 6e 6e 65 6c 2e 20 54 69 6d 65 6f 75 74 3a}
		$s5 = {25 73 3a 20 63 6f 6d 70 61 74 69 62 6c 65 20 77 69 74 68 20 42 4c 41 54 53 54 49 4e 47 20 76 65 72 73 69 6f 6e 20 31 2e 32}

	condition:
		1 of them
}

rule EQGRP_payload : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file payload.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"

	strings:
		$s1 = {63 61 6e 27 74 20 66 69 6e 64 20 74 61 72 67 65 74 20 76 65 72 73 69 6f 6e 20 6d 6f 64 75 6c 65 21}
		$s2 = {63 6c 61 73 73 20 50 61 79 6c 6f 61 64 3a}

	condition:
		all of them
}

rule EQGRP_eligiblecandidate : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"

	strings:
		$o1 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 74 69 6d 65 64 20 6f 75 74 2e 20 4f 6e 6c 79 20 61 20 70 72 6f 62 6c 65 6d 20 69 66 20 74 68 65 20 63 61 6c 6c 62 61 63 6b 20 77 61 73 20 6e 6f 74 20 72 65 63 65 69 76 65 64 2e}
		$o2 = {43 6f 75 6c 64 20 6e 6f 74 20 72 65 6c 69 61 62 6c 79 20 64 65 74 65 63 74 20 63 6f 6f 6b 69 65 2e 20 55 73 69 6e 67 20 27 73 65 73 73 69 6f 6e 5f 69 64 27 2e 2e 2e}
		$c1 = {64 65 66 20 62 75 69 6c 64 5f 65 78 70 6c 6f 69 74 5f 70 61 79 6c 6f 61 64 28 73 65 6c 66 2c 63 6d 64 3d 22 2f 74 6d 70 2f 68 74 74 70 64 22 29 3a}
		$c2 = {73 65 6c 66 2e 62 75 69 6c 64 5f 65 78 70 6c 6f 69 74 5f 70 61 79 6c 6f 61 64 28 63 6d 64 29}

	condition:
		1 of them
}

rule EQGRP_BUSURPER_2211_724 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"

	strings:
		$s1 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s2 = {5f 73 74 61 72 74 5f 74 65 78 74}
		$s3 = {49 4d 50 4c 41 4e 54}
		$s4 = {4b 45 45 50 47 4f 49 4e 47}
		$s5 = {75 70 67 72 61 64 65 5f 69 6d 70 6c 61 6e 74}

	condition:
		all of them
}

rule EQGRP_networkProfiler_orderScans : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"

	strings:
		$x1 = {55 6e 61 62 6c 65 20 74 6f 20 73 61 76 65 20 6f 66 66 20 70 72 65 64 65 66 69 6e 65 64 53 63 61 6e 73 20 64 69 72 65 63 74 6f 72 79}
		$x2 = {52 65 2d 6f 72 64 65 72 73 20 74 68 65 20 6e 65 74 77 6f 72 6b 50 72 6f 66 69 6c 65 72 20 73 63 61 6e 73 20 73 6f 20 74 68 65 79 20 73 68 6f 77 20 75 70 20 69 6e 20 6f 72 64 65 72 20 69 6e 20 74 68 65 20 4c 50}

	condition:
		1 of them
}

rule EQGRP_epicbanana_2_1_0_1 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"

	strings:
		$s1 = {66 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 76 65 72 73 69 6f 6e 2d 73 70 65 63 69 66 69 63 20 70 61 79 6c 6f 61 64}
		$s2 = {28 61 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 64 69 64 20 22 6d 61 6b 65 20 5b 76 65 72 73 69 6f 6e 5d 22 20 69 6e 20 76 65 72 73 69 6f 6e 73 3f 29}

	condition:
		1 of them
}

rule EQGRP_sniffer_xml2pcap : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file sniffer_xml2pcap"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f5e5d75cfcd86e5c94b0e6f21bbac886c7e540698b1556d88a83cc58165b8e42"

	strings:
		$x1 = {2d 73 2f 2d 2d 73 72 63 69 70 20 3c 73 6f 75 72 63 65 49 50 3e 20 20 55 73 65 20 67 69 76 65 6e 20 73 6f 75 72 63 65 20 49 50 20 28 69 66 20 73 6e 69 66 66 65 72 20 64 6f 65 73 6e 27 74 20 63 6f 6c 6c 65 63 74 20 73 6f 75 72 63 65 20 49 50 29}
		$x2 = {63 6f 6e 76 65 72 74 20 61 6e 20 58 4d 4c 20 66 69 6c 65 20 67 65 6e 65 72 61 74 65 64 20 62 79 20 74 68 65 20 42 4c 41 54 53 54 49 4e 47 20 73 6e 69 66 66 65 72 20 6d 6f 64 75 6c 65 20 69 6e 74 6f 20 61 20 70 63 61 70 20 63 61 70 74 75 72 65 20 66 69 6c 65 2e}

	condition:
		1 of them
}

rule EQGRP_BananaAid : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BananaAid"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"

	strings:
		$x1 = {28 6d 69 67 68 74 20 68 61 76 65 20 74 6f 20 64 65 6c 65 74 65 20 6b 65 79 20 69 6e 20 7e 2f 2e 73 73 68 2f 6b 6e 6f 77 6e 5f 68 6f 73 74 73 20 6f 6e 20 6c 69 6e 75 78 20 62 6f 78 29}
		$x2 = {73 63 70 20 42 47 4c 45 45 2d}
		$x3 = {73 68 6f 75 6c 64 20 62 65 20 34 62 66 65 39 34 62 31 20 66 6f 72 20 63 6c 65 61 6e 20 62 6f 6f 74 6c 6f 61 64 65 72 20 76 65 72 73 69 6f 6e 20 33 2e 30 3b 20}
		$x4 = {73 63 70 20 3c 63 6f 6e 66 69 67 75 72 65 64 20 69 6d 70 6c 61 6e 74 3e 20 3c 75 73 65 72 6e 61 6d 65 3e 40 3c 49 50 61 64 64 72 3e 3a 6f 6e 66 69 67}

	condition:
		1 of them
}

rule EQGRP_bo : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file bo"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"

	strings:
		$s1 = {45 52 52 4f 52 3a 20 66 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 25 73 3a 20 25 64}
		$s2 = {5f 5f 6c 69 62 63 5f 73 74 61 72 74 5f 6d 61 69 6e 40 40 47 4c 49 42 43 5f 32 2e 30}
		$s3 = {73 65 72 69 61 6c 20 6e 75 6d 62 65 72 3a 20 25 73}
		$s4 = {73 74 72 65 72 72 6f 72 40 40 47 4c 49 42 43 5f 32 2e 30}
		$s5 = {45 52 52 4f 52 3a 20 6d 6d 61 70 20 66 61 69 6c 65 64 3a 20 25 64}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 20KB and all of them )
}

rule EQGRP_SecondDate_2211 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"

	strings:
		$s1 = {53 44 5f 70 72 6f 63 65 73 73 43 6f 6e 74 72 6f 6c 50 61 63 6b 65 74}
		$s2 = {45 6e 63 72 79 70 74 69 6f 6e 5f 72 63 34 53 65 74 4b 65 79}
		$s3 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s4 = {5e 47 45 54 2e 2a 28 3f 3a 2f 20 7c 5c 2e 28 3f 3a 68 74 6d 7c 61 73 70 7c 70 68 70 29 29 2e 2a 5c 72 5c 6e}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 200KB and all of them )
}

rule EQGRP_config_jp1_UA : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"

	strings:
		$x1 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 77 69 6c 6c 20 63 6f 6e 66 69 67 75 72 65 20 61 20 4a 45 54 50 4c 4f 57 20 55 73 65 72 61 72 65 61 20 66 69 6c 65 2e}
		$x2 = {45 72 72 6f 72 20 72 75 6e 6e 69 6e 67 20 63 6f 6e 66 69 67 5f 69 6d 70 6c 61 6e 74 2e}
		$x3 = {4e 4f 54 45 3a 20 20 49 54 20 41 53 53 55 4d 45 53 20 59 4f 55 20 41 52 45 20 4f 50 45 52 41 54 49 4e 47 20 49 4e 20 54 48 45 20 49 4e 53 54 41 4c 4c 2f 4c 50 2f 4a 50 20 44 49 52 45 43 54 4f 52 59 2e 20 54 48 49 53 20 41 53 53 55 4d 50 54 49 4f 4e 20}
		$x4 = {46 69 72 73 74 20 49 50 20 61 64 64 72 65 73 73 20 66 6f 72 20 62 65 61 63 6f 6e 20 64 65 73 74 69 6e 61 74 69 6f 6e 20 5b 31 32 37 2e 30 2e 30 2e 31 5d}

	condition:
		1 of them
}

rule EQGRP_userscript : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file userscript.FW"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"

	strings:
		$x1 = {41 72 65 20 79 6f 75 20 73 75 72 65 3f 20 44 6f 6e 27 74 20 66 6f 72 67 65 74 20 74 68 61 74 20 4e 45 54 53 43 52 45 45 4e 20 66 69 72 65 77 61 6c 6c 73 20 72 65 71 75 69 72 65 20 42 41 4e 41 4e 41 4c 49 41 52 21 21 20}

	condition:
		1 of them
}

rule EQGRP_BBALL_M50FW08_2201 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"

	strings:
		$s1 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s2 = {4c 4f 41 44 45 44}
		$s3 = {70 61 67 65 54 61 62 6c 65 2e 63}
		$s4 = {5f 73 74 61 72 74 5f 74 65 78 74}
		$s5 = {68 61 6e 64 6c 65 72 5f 72 65 61 64 42 49 4f 53}
		$s6 = {4b 45 45 50 47 4f 49 4e 47}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 40KB and 5 of ( $s* ) )
}

rule EQGRP_BUSURPER_3001_724 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"

	strings:
		$s1 = {49 4d 50 4c 41 4e 54}
		$s2 = {4b 45 45 50 47 4f 49 4e 47}
		$s3 = {75 70 67 72 61 64 65 5f 69 6d 70 6c 61 6e 74}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}

rule EQGRP_workit : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file workit.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"

	strings:
		$s1 = {6d 61 63 64 65 66 20 69 6e 69 74 20 3e 20 2f 74 6d 70 2f 2e 6e 65 74 72 63 3b}
		$s2 = {2f 75 73 72 2f 62 69 6e 2f 77 67 65 74 20 68 74 74 70 3a 2f 2f}
		$s3 = {48 4f 4d 45 3d 2f 74 6d 70 20 66 74 70}
		$s4 = {20 3e 3e 20 2f 74 6d 70 2f 2e 6e 65 74 72 63 3b}
		$s5 = {2f 75 73 72 2f 72 61 70 69 64 73 74 72 65 61 6d 2f 62 69 6e 2f 74 66 74 70}
		$s6 = {63 72 65 61 74 65 64 20 73 68 65 6c 6c 5f 63 6f 6d 6d 61 6e 64 3a}
		$s7 = {72 6d 20 2d 66 20 2f 74 6d 70 2f 2e 6e 65 74 72 63 3b}
		$s8 = {65 63 68 6f 20 71 75 69 74 20 3e 3e 20 2f 74 6d 70 2f 2e 6e 65 74 72 63 3b}
		$s9 = {65 63 68 6f 20 62 69 6e 61 72 79 20 3e 3e 20 2f 74 6d 70 2f 2e 6e 65 74 72 63 3b}
		$s10 = {63 68 6d 6f 64 20 36 30 30 20 2f 74 6d 70 2f 2e 6e 65 74 72 63 3b}
		$s11 = {63 72 65 61 74 65 64 20 63 6c 69 5f 63 6f 6d 6d 61 6e 64 3a}

	condition:
		6 of them
}

rule EQGRP_tinyhttp_setup : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"

	strings:
		$x1 = {66 69 72 65 66 6f 78 20 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 38 30 30 30 2f 24 5f 6e 61 6d 65}
		$x2 = {57 68 61 74 20 69 73 20 74 68 65 20 6e 61 6d 65 20 6f 66 20 79 6f 75 72 20 69 6d 70 6c 61 6e 74 3a}
		$x3 = {6b 69 6c 6c 61 6c 6c 20 74 68 74 74 70 64}
		$x4 = {63 6f 70 79 20 68 74 74 70 3a 2f 2f 3c 49 50 3e 3a 38 30 2f 24 5f 6e 61 6d 65 20 66 6c 61 73 68 3a 2f 24 5f 6e 61 6d 65}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 2KB and 1 of ( $x* ) ) or ( all of them )
}

rule EQGRP_shellcode : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file shellcode.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ac9decb971dd44127a6ca0d35ac153951f0735bb4df422733046098eca8f8b7f"

	strings:
		$s1 = {65 78 65 63 75 74 65 5f 70 6f 73 74 20 3d 20 27 5c 78 65 38 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 35 64 5c 78 62 65 5c 78 65 66 5c 78 62 65 5c 78 61 64 5c 78 64 65 5c 78 38 39 5c 78 66 37 5c 78 38 39 5c 78 65 63 5c 78 32 39 5c 78 66 34 5c 78 62 38 5c 78 30 33 5c 78 30 30 5c 78 30 30 5c 78 30 30}
		$s2 = {74 69 6e 79 5f 65 78 65 63 20 3d 20 27 5c 78 37 66 5c 78 34 35 5c 78 34 63 5c 78 34 36 5c 78 30 31 5c 78 30 31 5c 78 30 31 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 32 5c 78 30 30 5c 78 30 33 5c 78 30 30 5c 78 30 31 5c 78 30 30 5c 78 30 30}
		$s3 = {61 75 74 68 5f 69 64 20 3d 20 27 5c 78 33 31 5c 78 63 30 5c 78 62 30 5c 78 30 33 5c 78 33 31 5c 78 64 62 5c 78 38 39 5c 78 65 31 5c 78 33 31 5c 78 64 32 5c 78 62 36 5c 78 66 30 5c 78 62 32 5c 78 30 64 5c 78 63 64 5c 78 38 30 5c 78 33 64 5c 78 66 66 5c 78 66 66 5c 78 66 66 5c 78 66 66 5c 78 37 35 5c 78 30 37}
		$c1 = { e8 00 00 00 00 5d be ef be ad de 89 f7 89 ec 29 f4 b8 03 00 00 00 }
		$c3 = { 31 c0 b0 03 31 db 89 e1 31 d2 b6 f0 b2 0d cd 80 3d ff ff ff ff 75 07 }

	condition:
		1 of them
}

rule EQGRP_EPBA : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file EPBA.script"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"

	strings:
		$x1 = {2e 2f 65 70 69 63 62 61 6e 61 6e 61 5f 32 2e 30 2e 30 2e 31 2e 70 79 20 2d 74 20 31 32 37 2e 30 2e 30 2e 31 20 2d 2d 70 72 6f 74 6f 3d 73 73 68 20 2d 2d 75 73 65 72 6e 61 6d 65 3d 63 69 73 63 6f 20 2d 2d 70 61 73 73 77 6f 72 64 3d 63 69 73 63 6f 20 2d 2d 74 61 72 67 65 74 5f 76 65 72 73 3d 61 73 61 38 30 34 20 2d 2d 6d 65 6d 3d 4e 41 20 2d 70 20 32 32 20}
		$x2 = {2d 74 20 54 41 52 47 45 54 5f 49 50 2c 20 2d 2d 74 61 72 67 65 74 5f 69 70 3d 54 41 52 47 45 54 5f 49 50 20 2d 2d 20 45 69 74 68 65 72 20 31 32 37 2e 30 2e 30 2e 31 20 6f 72 20 57 69 6e 20 4f 70 73 20 49 50}
		$x3 = {2e 2f 62 72 69 64 65 2d 31 31 30 30 20 2d 2d 6c 70 20 31 32 37 2e 30 2e 30 2e 31 20 2d 2d 69 6d 70 6c 61 6e 74 20 31 32 37 2e 30 2e 30 2e 31 20 2d 2d 73 70 6f 72 74 20 52 48 50 20 2d 2d 64 70 6f 72 74 20 52 48 50}
		$x4 = {2d 2d 74 61 72 67 65 74 5f 76 65 72 73 3d 54 41 52 47 45 54 5f 56 45 52 53 20 20 20 20 74 61 72 67 65 74 20 50 69 78 20 76 65 72 73 69 6f 6e 20 28 70 69 78 37 31 32 2c 20 61 73 61 38 30 34 29 20 28 52 45 51 55 49 52 45 44 29}
		$x5 = {2d 70 20 44 45 53 54 5f 50 4f 52 54 2c 20 2d 2d 64 65 73 74 5f 70 6f 72 74 3d 44 45 53 54 5f 50 4f 52 54 20 64 65 66 61 75 6c 74 73 3a 20 74 65 6c 6e 65 74 3d 32 33 2c 20 73 73 68 3d 32 32 20 28 6f 70 74 69 6f 6e 61 6c 29 20 2d 20 43 68 61 6e 67 65 20 74 6f 20 4c 4f 43 41 4c 20 72 65 64 69 72 65 63 74 20 70 6f 72 74}
		$x6 = {74 68 69 73 20 6f 70 65 72 61 74 69 6f 6e 20 69 73 20 63 6f 6d 70 6c 65 74 65 2c 20 42 61 6e 61 6e 61 47 6c 65 65 20 77 69 6c 6c}
		$x7 = {63 64 20 2f 63 75 72 72 65 6e 74 2f 62 69 6e 2f 46 57 2f 42 47 58 58 58 58 2f 49 6e 73 74 61 6c 6c 2f 4c 50}

	condition:
		( uint16( 0 ) == 0x2023 and filesize < 7KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule EQGRP_BPIE : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"

	strings:
		$s1 = {70 72 6f 66 50 72 6f 63 65 73 73 50 61 63 6b 65 74}
		$s2 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s3 = {67 65 74 54 69 6d 65 53 6c 6f 74 43 6d 64 48 61 6e 64 6c 65 72}
		$s4 = {67 65 74 49 70 49 70 43 6d 64 48 61 6e 64 6c 65 72}
		$s5 = {4c 4f 41 44 45 44}
		$s6 = {70 72 6f 66 53 74 61 72 74 53 63 61 6e}
		$s7 = {74 6d 70 44 61 74 61 2e 31}
		$s8 = {72 65 73 65 74 43 6d 64 48 61 6e 64 6c 65 72}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 70KB and 6 of ( $s* ) )
}

rule EQGRP_jetplow_SH : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file jetplow.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"

	strings:
		$s1 = {63 64 20 2f 63 75 72 72 65 6e 74 2f 62 69 6e 2f 46 57 2f 42 41 4e 41 4e 41 47 4c 45 45 2f 24 62 67 76 65 72 2f 49 6e 73 74 61 6c 6c 2f 4c 50 2f 6a 65 74 70 6c 6f 77}
		$s2 = {2a 2a 2a 2a 2a 20 50 6c 65 61 73 65 20 70 6c 61 63 65 20 79 6f 75 72 20 55 41 20 69 6e 20 2f 63 75 72 72 65 6e 74 2f 62 69 6e 2f 46 57 2f 4f 50 53 20 2a 2a 2a 2a 2a}
		$s3 = {6c 6e 20 2d 73 20 2e 2e 2f 6a 70 2f 6f 72 69 67 5f 63 6f 64 65 2e 62 69 6e 20 6f 72 69 67 5f 63 6f 64 65 5f 70 69 78 47 65 6e 2e 62 69 6e}
		$s4 = {2a 2a 2a 2a 2a 20 20 20 20 20 20 20 20 20 20 20 20 20 57 65 6c 63 6f 6d 65 20 74 6f 20 4a 65 74 50 6c 6f 77 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2a 2a 2a 2a 2a}

	condition:
		1 of them
}

rule EQGRP_BBANJO : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"

	strings:
		$s1 = {67 65 74 5f 6c 73 6c 5f 69 6e 74 65 72 66 61 63 65 73}
		$s2 = {65 6e 63 72 79 70 74 46 43 34 50 61 79 6c 6f 61 64}
		$s3 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s4 = {62 65 61 63 6f 6e 5f 67 65 74 63 6f 6e 66 69 67}
		$s5 = {4c 4f 41 44 45 44}
		$s6 = {46 6f 72 6d 42 65 61 63 6f 6e 50 61 63 6b 65 74}
		$s7 = {62 65 61 63 6f 6e 5f 72 65 63 6f 6e 66 69 67 75 72 65}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 50KB and all of them )
}

rule EQGRP_BPATROL_2201 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"

	strings:
		$s1 = {64 75 6d 70 43 6f 6e 66 69 67}
		$s2 = {67 65 74 73 74 61 74 75 73 48 61 6e 64 6c 65 72}
		$s3 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s4 = {78 74 72 61 63 74 64 61 74 61}
		$s5 = {4b 45 45 50 47 4f 49 4e 47}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 40KB and all of them )
}

rule EQGRP_extrabacon : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"

	strings:
		$x1 = {54 6f 20 64 69 73 61 62 6c 65 20 70 61 73 73 77 6f 72 64 20 63 68 65 63 6b 69 6e 67 20 6f 6e 20 74 61 72 67 65 74 3a}
		$x2 = {5b 2d 5d 20 74 61 72 67 65 74 20 69 73 20 72 75 6e 6e 69 6e 67}
		$x3 = {5b 2d 5d 20 70 72 6f 62 6c 65 6d 20 69 6d 70 6f 72 74 69 6e 67 20 76 65 72 73 69 6f 6e 2d 73 70 65 63 69 66 69 63 20 73 68 65 6c 6c 63 6f 64 65 20 66 72 6f 6d}
		$x4 = {5b 2b 5d 20 69 6d 70 6f 72 74 69 6e 67 20 76 65 72 73 69 6f 6e 2d 73 70 65 63 69 66 69 63 20 73 68 65 6c 6c 63 6f 64 65}
		$s5 = {5b 2d 5d 20 75 6e 73 75 70 70 6f 72 74 65 64 20 74 61 72 67 65 74 20 76 65 72 73 69 6f 6e 2c 20 61 62 6f 72 74}

	condition:
		1 of them
}

rule EQGRP_sploit_py : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file sploit.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

	strings:
		$x1 = {74 68 65 20 2d 2d 73 70 6f 6f 66 20 6f 70 74 69 6f 6e 20 72 65 71 75 69 72 65 73 20 33 20 6f 72 20 34 20 66 69 65 6c 64 73 20 61 73 20 66 6f 6c 6c 6f 77 73 20 72 65 64 69 72 5f 69 70}
		$x2 = {5b 2d 5d 20 74 69 6d 65 6f 75 74 20 77 61 69 74 69 6e 67 20 66 6f 72 20 72 65 73 70 6f 6e 73 65 20 2d 20 74 61 72 67 65 74 20 6d 61 79 20 68 61 76 65 20 63 72 61 73 68 65 64}
		$x3 = {5b 2d 5d 20 6e 6f 20 72 65 73 70 6f 6e 73 65 20 66 72 6f 6d 20 68 65 61 6c 74 68 20 63 68 65 63 6b 20 2d 20 74 61 72 67 65 74 20 6d 61 79 20 68 61 76 65 20 63 72 61 73 68 65 64}

	condition:
		1 of them
}

rule EQGRP_uninstallPBD : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"

	strings:
		$s1 = {6d 65 6d 73 65 74 20 30 30 65 39 61 30 35 63 20 34 20 33 38 38 34 35 62 38 38}
		$s2 = {5f 68 69 64 65 63 6d 64}
		$s3 = {6d 65 6d 73 65 74 20 30 31 33 61 62 64 30 34 20 31 20 30 64}

	condition:
		all of them
}

rule EQGRP_BICECREAM : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BICECREAM-2140"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"

	strings:
		$s1 = {43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 74 61 72 67 65 74 20 64 65 76 69 63 65 3a 20 25 73 3a 25 64 2e 20 50 6c 65 61 73 65 20 63 68 65 63 6b 20 49 50 20 61 64 64 72 65 73 73 2e}
		$s2 = {63 6f 6d 6d 61 6e 64 20 64 61 74 61 20 73 69 7a 65 20 69 73 20 69 6e 76 61 6c 69 64 20 66 6f 72 20 61 6e 20 65 78 65 63 20 63 6d 64}
		$s3 = {41 20 73 63 72 69 70 74 20 77 61 73 20 73 70 65 63 69 66 69 65 64 20 62 75 74 20 74 61 72 67 65 74 20 69 73 20 6e 6f 74 20 61 20 50 50 43 34 30 35 2d 62 61 73 65 64 20 4e 65 74 53 63 72 65 65 6e 20 28 4e 53 35 58 54 2c 20 4e 53 32 35 2c 20 61 6e 64 20 4e 53 35 30 29 2e 20 45 78 65 63 75 74 69 6e 67 20 73 63 72 69 70 74 73 20 69 73 20 73 75 70 70 6f 72 74 65 64 20 62 75 74 20 6d 61}
		$s4 = {45 78 65 63 75 74 65 20 30 78 25 30 38 78 20 77 69 74 68 20 61 72 67 73 20 28 25 30 38 78 2c 20 25 30 38 78 2c 20 25 30 38 78 2c 20 25 30 38 78 29 3a 20 5b 79 2f 6e 5d}
		$s5 = {45 78 65 63 75 74 65 20 30 78 25 30 38 78 20 77 69 74 68 20 61 72 67 73 20 28 25 30 38 78 2c 20 25 30 38 78 2c 20 25 30 38 78 29 3a 20 5b 79 2f 6e 5d}
		$s6 = {5b 25 64 5d 20 45 78 65 63 75 74 65 20 63 6f 64 65 2e}
		$s7 = {45 78 65 63 75 74 65 20 30 78 25 30 38 78 20 77 69 74 68 20 61 72 67 73 20 28 25 30 38 78 29 3a 20 5b 79 2f 6e 5d}
		$s8 = {64 75 6d 70 5f 76 61 6c 75 65 5f 4c 48 41 53 48 5f 44 4f 41 4c 4c 5f 41 52 47}
		$s9 = {45 67 67 63 6f 64 65 20 69 73 20 63 6f 6d 70 6c 65 74 65 2e 20 50 61 73 73 20 65 78 65 63 75 74 69 6f 6e 20 74 6f 20 69 74 3f 20 5b 79 2f 6e 5d}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}

rule EQGRP_create_http_injection : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file create_http_injection.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"

	strings:
		$x1 = {72 65 71 75 69 72 65 64 20 62 79 20 53 45 43 4f 4e 44 44 41 54 45}
		$s1 = {68 65 6c 70 3d 27 4f 75 74 70 75 74 20 66 69 6c 65 20 6e 61 6d 65 20 28 6f 70 74 69 6f 6e 61 6c 29 2e 20 42 79 20 64 65 66 61 75 6c 74 20 74 68 65 20 72 65 73 75 6c 74 69 6e 67 20 64 61 74 61 20 69 73 20 77 72 69 74 74 65 6e 20 74 6f 20 73 74 64 6f 75 74 2e 27 29}
		$s2 = {64 61 74 61 20 3d 20 27 3c 68 74 6d 6c 3e 3c 62 6f 64 79 20 6f 6e 6c 6f 61 64 3d 22 6c 6f 63 61 74 69 6f 6e 2e 72 65 6c 6f 61 64 28 74 72 75 65 29 22 3e 3c 69 66 72 61 6d 65 20 73 72 63 3d 22 25 73 22 20 68 65 69 67 68 74 3d 22 31 22 20 77 69 64 74 68 3d 22 31 22 20 73 63 72 6f 6c 6c 69 6e 67 3d 22 6e 6f 22 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 22}
		$s3 = {76 65 72 73 69 6f 6e 3d 27 25 70 72 6f 67 20 31 2e 30 27 2c}
		$s4 = {75 73 61 67 65 3d 27 25 70 72 6f 67 20 5b 20 2e 2e 2e 20 6f 70 74 69 6f 6e 73 20 2e 2e 2e 20 5d 20 75 72 6c 27 2c}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 3KB and ( $x1 or 2 of them ) ) or ( all of them )
}

rule EQGRP_BFLEA_2201 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"

	strings:
		$s1 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s2 = {4c 4f 41 44 45 44}
		$s3 = {72 65 61 64 46 6c 61 73 68 48 61 6e 64 6c 65 72}
		$s4 = {4b 45 45 50 47 4f 49 4e 47}
		$s5 = {66 6c 61 73 68 52 74 6e 73 50 69 78 36 78 2e 63}
		$s6 = {66 69 78 5f 69 70 5f 63 6b 73 75 6d 5f 69 6e 63 72}
		$s7 = {77 72 69 74 65 46 6c 61 73 68 48 61 6e 64 6c 65 72}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}

rule EQGRP_BpfCreator_RHEL4 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"

	strings:
		$s1 = {75 73 61 67 65 20 25 73 20 22 3c 74 63 70 64 75 6d 70 20 70 63 61 70 20 73 74 72 69 6e 67 3e 22 20 3c 6f 75 74 66 69 6c 65 3e}
		$s2 = {65 72 72 6f 72 20 72 65 61 64 69 6e 67 20 64 75 6d 70 20 66 69 6c 65 3a 20 25 73}
		$s3 = {74 72 75 6e 63 61 74 65 64 20 64 75 6d 70 20 66 69 6c 65 3b 20 74 72 69 65 64 20 74 6f 20 72 65 61 64 20 25 75 20 63 61 70 74 75 72 65 64 20 62 79 74 65 73 2c 20 6f 6e 6c 79 20 67 6f 74 20 25 6c 75}
		$s4 = {25 73 3a 20 6c 69 6e 6b 2d 6c 61 79 65 72 20 74 79 70 65 20 25 64 20 69 73 6e 27 74 20 73 75 70 70 6f 72 74 65 64 20 69 6e 20 73 61 76 65 66 69 6c 65 73}
		$s5 = {44 4c 54 20 25 64 20 69 73 20 6e 6f 74 20 6f 6e 65 20 6f 66 20 74 68 65 20 44 4c 54 73 20 73 75 70 70 6f 72 74 65 64 20 62 79 20 74 68 69 73 20 64 65 76 69 63 65}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 2000KB and all of them )
}

rule EQGRP_StoreFc : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file StoreFc.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"

	strings:
		$x1 = {55 73 61 67 65 3a 20 53 74 6f 72 65 46 63 2e 70 79 20 2d 2d 63 6f 6e 66 69 67 46 69 6c 65 3d 3c 70 61 74 68 20 74 6f 20 78 6d 6c 20 66 69 6c 65 3e 20 2d 2d 69 6d 70 6c 61 6e 74 46 69 6c 65 3d 3c 70 61 74 68 20 74 6f 20 42 69 6e 53 74 6f 72 65 20 69 6d 70 6c 61 6e 74 3e 20 5b 2d 2d 6f 75 74 70 75 74 46 69 6c 65 3d 3c 66 69 6c 65 20 74 6f 20 77 72 69 74 65 20 74 68 65 20 63 6f 6e 66}
		$x2 = {72 61 69 73 65 20 45 78 63 65 70 74 69 6f 6e 2c 20 22 4d 75 73 74 20 73 75 70 70 6c 79 20 62 6f 74 68 20 61 20 63 6f 6e 66 69 67 20 66 69 6c 65 20 61 6e 64 20 69 6d 70 6c 61 6e 74 20 66 69 6c 65 2e 22}
		$x3 = {54 68 69 73 20 69 73 20 77 72 61 70 70 65 72 20 66 6f 72 20 53 74 6f 72 65 2e 70 79 20 74 68 61 74 20 46 45 4c 4f 4e 59 43 52 4f 57 42 41 52 20 77 69 6c 6c 20 75 73 65 2e 20 54 68 69 73}

	condition:
		1 of them
}

rule EQGRP_hexdump : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file hexdump.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"

	strings:
		$s1 = {64 65 66 20 68 65 78 64 75 6d 70 28 78 2c 6c 65 61 64 3d 22 5b 2b 5d 20 22 2c 6f 75 74 3d 73 79 73 2e 73 74 64 6f 75 74 29 3a}
		$s2 = {70 72 69 6e 74 20 3e 3e 6f 75 74 2c 20 22 25 73 25 30 34 78 20 20 22 20 25 20 28 6c 65 61 64 2c 69 29 2c}
		$s3 = {70 72 69 6e 74 20 3e 3e 6f 75 74 2c 20 22 25 30 32 58 22 20 25 20 6f 72 64 28 78 5b 69 2b 6a 5d 29 2c}
		$s4 = {70 72 69 6e 74 20 3e 3e 6f 75 74 2c 20 73 61 6e 65 28 78 5b 69 3a 69 2b 31 36 5d 29}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 1KB and 2 of ( $s* ) ) or ( all of them )
}

rule EQGRP_BBALL : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"

	strings:
		$s1 = {43 6f 6d 70 6f 6e 65 6e 74 73 2f 4d 6f 64 75 6c 65 73 2f 42 69 6f 73 4d 6f 64 75 6c 65 2f 49 6d 70 6c 61 6e 74 2f 45 32 38 46 36 2f 2e 2e 2f 65 32 38 66 36 34 30 6a 33 5f 61 73 6d 2e 53}
		$s2 = {2e 67 6f 74 5f 6c 6f 61 64 65 72}
		$s3 = {68 61 6e 64 6c 65 72 5f 72 65 61 64 42 49 4f 53}
		$s4 = {63 6d 6f 73 52 65 61 64 42 79 74 65}
		$s5 = {4b 45 45 50 47 4f 49 4e 47}
		$s6 = {63 68 65 63 6b 73 75 6d 41 72 65 61 43 6f 6e 66 69 72 6d 65 64 2e 30}
		$s7 = {77 72 69 74 65 53 70 65 65 64 50 6c 6f 77 2e 63}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 40KB and 4 of ( $s* ) ) or ( all of them )
}

rule EQGRP_BARPUNCH_BPICKER : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

	strings:
		$x1 = {2d 2d 63 6d 64 20 25 78 20 2d 2d 69 64 6b 65 79 20 25 73 20 2d 2d 73 70 6f 72 74 20 25 69 20 2d 2d 64 70 6f 72 74 20 25 69 20 2d 2d 6c 70 20 25 73 20 2d 2d 69 6d 70 6c 61 6e 74 20 25 73 20 2d 2d 62 73 69 7a 65 20 25 68 75 20 2d 2d 6c 6f 67 64 69 72 20 25 73 20 2d 2d 6c 70 74 69 6d 65 6f 75 74 20 25 75}
		$x2 = {25 73 20 2d 63 20 3c 63 6d 64 74 79 70 65 3e 20 2d 6c 20 3c 6c 70 3e 20 2d 69 20 3c 69 6d 70 6c 61 6e 74 3e 20 2d 6b 20 3c 69 6b 65 79 3e 20 2d 73 20 3c 70 6f 72 74 3e 20 2d 64 20 3c 70 6f 72 74 3e 20 5b 6f 70 65 72 61 74 69 6f 6e 5d 20 5b 6f 70 74 69 6f 6e 73 5d}
		$x3 = {2a 20 5b 25 6c 75 5d 20 30 78 25 78 20 69 73 20 6d 61 72 6b 65 64 20 61 73 20 73 74 61 74 65 6c 65 73 73 20 28 74 68 65 20 6d 6f 64 75 6c 65 20 77 69 6c 6c 20 62 65 20 70 65 72 73 69 73 74 65 64 20 77 69 74 68 6f 75 74 20 69 74 73 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 29}
		$x4 = {25 73 20 76 65 72 73 69 6f 6e 20 25 73 20 61 6c 72 65 61 64 79 20 68 61 73 20 70 65 72 73 69 73 74 65 6e 63 65 20 69 6e 73 74 61 6c 6c 65 64 2e 20 49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 2c}
		$x5 = {54 68 65 20 61 63 74 69 76 65 20 6d 6f 64 75 6c 65 28 73 29 20 6f 6e 20 74 68 65 20 74 61 72 67 65 74 20 61 72 65 20 6e 6f 74 20 6d 65 61 6e 74 20 74 6f 20 62 65 20 70 65 72 73 69 73 74 65 64}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 6000KB and 1 of them ) or ( 3 of them )
}

rule EQGRP_Implants_Gen6 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash7 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$s1 = {4c 50 2e 63 3a 70 69 78 53 65 63 75 72 69 74 79 20 2d 20 49 6d 70 72 6f 70 65 72 20 6e 75 6d 62 65 72 20 6f 66 20 62 79 74 65 73 20 72 65 61 64 20 69 6e 20 53 65 63 75 72 69 74 79 2f 49 6e 74 65 72 66 61 63 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e}
		$s2 = {4c 50 2e 63 3a 70 69 78 53 65 63 75 72 69 74 79 20 2d 20 4e 6f 74 20 69 6e 20 53 65 73 73 69 6f 6e}
		$s3 = {67 65 74 4d 6f 64 49 6e 74 65 72 66 61 63 65 5f 5f 70 72 65 6c 6f 61 64 65 64 4d 6f 64 75 6c 65 73}
		$s4 = {73 68 6f 77 43 6f 6d 6d 61 6e 64 73}
		$s5 = {72 65 61 64 4d 6f 64 75 6c 65 49 6e 74 65 72 66 61 63 65}
		$s6 = {57 72 61 70 70 69 6e 67 5f 4e 6f 74 5f 4e 65 63 65 73 73 61 72 79 5f 4f 72 5f 57 72 61 70 70 69 6e 67 5f 4f 6b}
		$s7 = {47 65 74 5f 43 4d 44 5f 4c 69 73 74}
		$s8 = {4c 50 5f 4c 69 73 74 65 6e 32}
		$s9 = {6b 69 6c 6c 43 6d 64 4c 69 73 74}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 6000KB and all of them )
}

rule EQGRP_Implants_Gen5 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash8 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$x1 = {4d 6f 64 75 6c 65 20 61 6e 64 20 49 6d 70 6c 61 6e 74 20 76 65 72 73 69 6f 6e 73 20 64 6f 20 6e 6f 74 20 6d 61 74 63 68 2e 20 20 54 68 69 73 20 6d 6f 64 75 6c 65 20 69 73 20 6e 6f 74 20 63 6f 6d 70 61 74 69 62 6c 65 20 77 69 74 68 20 74 68 65 20 74 61 72 67 65 74 20 69 6d 70 6c 61 6e 74}
		$s1 = {25 73 2f 42 46 5f 52 45 41 44 5f 25 30 38 78 5f 25 30 34 64 25 30 32 64 25 30 32 64 5f 25 30 32 64 25 30 32 64 25 30 32 64 2e 6c 6f 67}
		$s2 = {25 73 2f 42 46 5f 25 30 34 64 25 30 32 64 25 30 32 64 2e 6c 6f 67}
		$s3 = {25 73 2f 42 46 5f 52 45 41 44 5f 25 30 38 78 5f 25 30 34 64 25 30 32 64 25 30 32 64 5f 25 30 32 64 25 30 32 64 25 30 32 64 2e 62 69 6e}

	condition:
		( uint16( 0 ) == 0x457f and 1 of ( $x* ) ) or ( all of them )
}

rule EQGRP_pandarock : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files pandarock_v1.11.1.1.bin, pit"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "1214e282ac7258e616ebd76f912d4b2455d1b415b7216823caa3fc0d09045a5f"
		hash2 = "c8a151df7605cb48feb8be2ab43ec965b561d2b6e2a837d645fdf6a6191ab5fe"

	strings:
		$x1 = {2a 20 4e 6f 74 20 61 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 65 78 65 63 75 74 65 20 22 25 73 22 20 63 6f 6d 6d 61 6e 64}
		$x2 = {54 45 52 4d 49 4e 41 54 49 4e 47 20 53 43 52 49 50 54 20 28 63 6f 6d 6d 61 6e 64 20 65 72 72 6f 72 20 6f 72 20 22 71 75 69 74 22 20 65 6e 63 6f 75 6e 74 65 72 65 64 29}
		$x3 = {65 78 65 63 75 74 65 20 63 6f 64 65 20 69 6e 20 3c 66 69 6c 65 3e 20 70 61 73 73 69 6e 67 20 3c 61 72 67 58 3e 20 28 48 45 58 29}
		$x4 = {2a 20 55 73 65 20 61 72 72 6f 77 20 6b 65 79 73 20 74 6f 20 73 63 72 6f 6c 6c 20 74 68 72 6f 75 67 68 20 63 6f 6d 6d 61 6e 64 20 68 69 73 74 6f 72 79}
		$s1 = {70 69 74 43 6d 64 5f 70 72 6f 63 65 73 73 43 6d 64 4c 69 6e 65}
		$s2 = {65 78 65 63 75 74 65 20 61 6c 6c 20 63 6f 6d 6d 61 6e 64 73 20 69 6e 20 3c 66 69 6c 65 3e}
		$s3 = {5f 5f 70 72 6f 63 65 73 73 53 68 65 6c 6c 43 6d 64}
		$s4 = {70 69 74 54 61 72 67 65 74 5f 67 65 74 44 73 74 50 6f 72 74}
		$s5 = {5f 5f 70 72 6f 63 65 73 73 53 65 74 54 61 72 67 65 74 49 70}
		$o1 = {4c 6f 67 67 69 6e 67 20 63 6f 6d 6d 61 6e 64 73 20 61 6e 64 20 6f 75 74 70 75 74 20 2d 20 4f 4e}
		$o2 = {54 68 69 73 20 63 6f 6d 6d 61 6e 64 20 69 73 20 74 6f 6f 20 64 61 6e 67 65 72 6f 75 73 2e 20 20 49 66 20 79 6f 75 27 64 20 6c 69 6b 65 20 74 6f 20 72 75 6e 20 69 74 2c 20 63 6f 6e 74 61 63 74 20 74 68 65 20 64 65 76 65 6c 6f 70 6d 65 6e 74 20 74 65 61 6d}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 3000KB and 1 of ( $x* ) ) or ( 4 of them ) or 1 of ( $o* )
}

rule EQGRP_BananaUsurper_writeJetPlow : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$x1 = {49 6d 70 6c 61 6e 74 20 56 65 72 73 69 6f 6e 2d 53 70 65 63 69 66 69 63 20 56 61 6c 75 65 73 3a}
		$x2 = {54 68 69 73 20 66 75 6e 63 74 69 6f 6e 20 73 68 6f 75 6c 64 20 6e 6f 74 20 62 65 20 75 73 65 64 20 77 69 74 68 20 61 20 4e 65 74 73 63 72 65 65 6e 2c 20 73 6f 6d 65 74 68 69 6e 67 20 68 61 73 20 67 6f 6e 65 20 68 6f 72 72 69 62 6c 79 20 77 72 6f 6e 67}
		$s1 = {63 72 65 61 74 65 53 65 6e 64 52 65 63 76 3a 20 72 65 63 76 27 64 20 61 6e 20 65 72 72 6f 72 20 66 72 6f 6d 20 74 68 65 20 74 61 72 67 65 74 2e}
		$s2 = {45 72 72 6f 72 3a 20 57 61 74 63 68 44 6f 67 54 69 6d 65 6f 75 74 20 72 65 61 64 20 72 65 74 75 72 6e 65 64 20 25 64 20 69 6e 73 74 65 61 64 20 6f 66 20 34}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 2000KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule EQGRP_Implants_Gen4 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash3 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash4 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"

	strings:
		$s1 = {43 6f 6d 6d 61 6e 64 20 68 61 73 20 6e 6f 74 20 79 65 74 20 62 65 65 6e 20 63 6f 64 65 64}
		$s2 = {42 65 61 63 6f 6e 20 44 6f 6d 61 69 6e 20 20 3a 20 77 77 77 2e 25 73 2e 63 6f 6d}
		$s3 = {54 68 69 73 20 63 6f 6d 6d 61 6e 64 20 63 61 6e 20 6f 6e 6c 79 20 62 65 20 72 75 6e 20 6f 6e 20 61 20 50 49 58 2f 41 53 41}
		$s4 = {57 61 72 6e 69 6e 67 21 20 42 61 64 20 6f 72 20 6d 69 73 73 69 6e 67 20 46 6c 61 73 68 20 76 61 6c 75 65 73 20 28 69 6e 20 73 65 63 74 69 6f 6e 20 32 20 6f 66 20 2e 64 61 74 20 66 69 6c 65 29}
		$s5 = {50 72 69 6e 74 69 6e 67 20 74 68 65 20 69 6e 74 65 72 66 61 63 65 20 69 6e 66 6f 20 61 6e 64 20 73 65 63 75 72 69 74 79 20 6c 65 76 65 6c 73 2e 20 50 49 58 20 4f 4e 4c 59 2e}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 3000KB and 3 of them ) or ( all of them )
}

rule EQGRP_Implants_Gen3 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

	strings:
		$x1 = {69 6e 63 6f 6d 70 6c 65 74 65 20 61 6e 64 20 6d 75 73 74 20 62 65 20 72 65 6d 6f 76 65 64 20 6d 61 6e 75 61 6c 6c 79 2e 29}
		$s1 = {25 73 3a 20 72 65 63 76 27 64 20 61 6e 20 65 72 72 6f 72 20 66 72 6f 6d 20 74 68 65 20 74 61 72 67 65 74 2e}
		$s2 = {55 6e 61 62 6c 65 20 74 6f 20 66 65 74 63 68 20 74 68 65 20 61 64 64 72 65 73 73 20 74 6f 20 74 68 65 20 67 65 74 5f 75 70 74 69 6d 65 5f 73 65 63 73 20 66 75 6e 63 74 69 6f 6e 20 66 6f 72 20 74 68 69 73 20 4f 53 20 76 65 72 73 69 6f 6e}
		$s3 = {75 70 6c 6f 61 64 2f 61 63 74 69 76 61 74 65 2f 64 65 2d 61 63 74 69 76 61 74 65 2f 72 65 6d 6f 76 65 2f 63 6d 64 20 66 75 6e 63 74 69 6f 6e 20 66 61 69 6c 65 64}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 6000KB and 2 of them ) or ( all of them )
}

rule EQGRP_BLIAR_BLIQUER : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"

	strings:
		$x1 = {44 6f 20 79 6f 75 20 77 69 73 68 20 74 6f 20 61 63 74 69 76 61 74 65 20 74 68 65 20 69 6d 70 6c 61 6e 74 20 74 68 61 74 20 69 73 20 61 6c 72 65 61 64 79 20 6f 6e 20 74 68 65 20 66 69 72 65 77 61 6c 6c 3f 20 28 79 2f 6e 29 3a 20}
		$x2 = {54 68 65 72 65 20 69 73 20 6e 6f 20 69 6d 70 6c 61 6e 74 20 70 72 65 73 65 6e 74 20 6f 6e 20 74 68 65 20 66 69 72 65 77 61 6c 6c 2e}
		$x3 = {49 6d 70 6c 61 6e 74 20 56 65 72 73 69 6f 6e 20 3a 25 6c 78 25 6c 78 25 6c 78}
		$x4 = {59 6f 75 20 6d 61 79 20 6e 6f 77 20 63 6f 6e 6e 65 63 74 20 74 6f 20 74 68 65 20 69 6d 70 6c 61 6e 74 20 75 73 69 6e 67 20 74 68 65 20 70 62 64 20 69 64 6b 65 79}
		$x5 = {4e 6f 20 72 65 70 6c 79 20 66 72 6f 6d 20 70 65 72 73 69 73 74 61 6e 74 20 62 61 63 6b 20 64 6f 6f 72 2e}
		$x6 = {72 6d 20 2d 72 66 20 70 62 64 2e 77 63 3b 20 77 63 20 2d 63 20 25 73 20 3e 20 70 62 64 2e 77 63}
		$p1 = {50 42 44 5f 47 65 74 56 65 72 73 69 6f 6e}
		$p2 = {70 62 64 2f 70 62 64 45 6e 63 72 79 70 74 2e 62 69 6e}
		$p3 = {70 62 64 2f 70 62 64 47 65 74 56 65 72 73 69 6f 6e 2e 70 6b 74}
		$p4 = {70 62 64 2f 70 62 64 53 74 61 72 74 57 72 69 74 65 2e 62 69 6e}
		$p5 = {70 62 64 2f 70 62 64 5f 73 65 74 4e 65 77 48 6f 6f 6b 50 74 2e 70 6b 74}
		$p6 = {70 62 64 2f 70 62 64 5f 55 70 6c 6f 61 64 5f 53 69 6e 67 6c 65 50 6b 74 2e 70 6b 74}
		$s1 = {55 6e 61 62 6c 65 20 74 6f 20 66 65 74 63 68 20 68 6f 6f 6b 20 61 6e 64 20 6a 6d 70 20 61 64 64 72 65 73 73 65 73 20 66 6f 72 20 74 68 69 73 20 4f 53 20 76 65 72 73 69 6f 6e}
		$s2 = {43 6f 75 6c 64 20 6e 6f 74 20 67 65 74 20 68 6f 6f 6b 20 61 6e 64 20 6a 75 6d 70 20 61 64 64 72 65 73 73 65 73}
		$s3 = {45 6e 74 65 72 20 74 68 65 20 6e 61 6d 65 20 6f 66 20 61 20 63 6c 65 61 6e 20 69 6d 70 6c 61 6e 74 20 62 69 6e 61 72 79 20 28 4e 4f 54 20 61 6e 20 69 6d 61 67 65 29 3a}
		$s4 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 61 64 20 64 61 74 20 66 69 6c 65 20 66 6f 72 20 4f 53 20 76 65 72 73 69 6f 6e 20 30 78 25 30 38 6c 78}
		$s5 = {49 6e 76 61 6c 69 64 20 69 6d 70 6c 61 6e 74 20 66 69 6c 65}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 3000KB and ( 1 of ( $x* ) or 1 of ( $p* ) ) ) or ( 3 of them )
}

rule EQGRP_sploit : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		hash2 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

	strings:
		$s1 = {70 72 69 6e 74 20 22 5b 2b 5d 20 43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 25 73 3a 25 73 22 20 25 20 28 73 65 6c 66 2e 70 61 72 61 6d 73 2e 64 73 74 5b 27 69 70 27 5d 2c 20 73 65 6c 66 2e 70 61 72 61 6d 73 2e 64 73 74 5b 27 70 6f 72 74 27 5d 29}
		$s2 = {40 6f 76 65 72 72 69 64 61 62 6c 65 28 22 4d 75 73 74 20 62 65 20 6f 76 65 72 72 69 64 65 6e 20 69 66 20 74 68 65 20 74 61 72 67 65 74 20 77 69 6c 6c 20 62 65 20 74 6f 75 63 68 65 64 2e 20 20 42 61 73 65 20 69 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 20 73 68 6f 75 6c 64 20 6e 6f 74 20 62 65 20 63 61 6c 6c 65 64 2e 22 29}
		$s3 = {40 6f 76 65 72 72 69 64 61 62 6c 65 28 22 4d 75 73 74 20 62 65 20 6f 76 65 72 72 69 64 65 6e 2e 20 20 42 61 73 65 20 69 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 20 73 68 6f 75 6c 64 20 6e 6f 74 20 62 65 20 63 61 6c 6c 65 64 2e 22 29}
		$s4 = {65 78 70 2e 6c 6f 61 64 5f 76 69 6e 66 6f 28 29}
		$s5 = {69 66 20 6e 6f 74 20 6f 6b 61 79 20 61 6e 64 20 73 65 6c 66 2e 74 65 72 6d 69 6e 61 74 65 46 6c 69 6e 67 4f 6e 45 78 63 65 70 74 69 6f 6e 3a}
		$s6 = {70 72 69 6e 74 20 22 5b 2d 5d 20 6b 65 79 62 6f 61 72 64 20 69 6e 74 65 72 72 75 70 74 20 62 65 66 6f 72 65 20 72 65 73 70 6f 6e 73 65 20 72 65 63 65 69 76 65 64 22}
		$s7 = {69 66 20 73 65 6c 66 2e 74 65 72 6d 69 6e 61 74 65 46 6c 69 6e 67 4f 6e 45 78 63 65 70 74 69 6f 6e 3a}
		$s8 = {70 72 69 6e 74 20 27 44 65 62 75 67 20 69 6e 66 6f 20 27 2c 27 3d 27 2a 34 30}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 90KB and 1 of ( $s* ) ) or ( 4 of them )
}

rule EQGRP_Implants_Gen2 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$x1 = {4d 6f 64 75 6c 65 73 20 70 65 72 73 69 73 74 65 6e 63 65 20 66 69 6c 65 20 77 72 69 74 74 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79}
		$x2 = {4d 6f 64 75 6c 65 73 20 70 65 72 73 69 73 74 65 6e 63 65 20 64 61 74 61 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 72 65 6d 6f 76 65 64}
		$x3 = {4e 6f 20 4d 6f 64 75 6c 65 73 20 61 72 65 20 61 63 74 69 76 65 20 6f 6e 20 74 68 65 20 66 69 72 65 77 61 6c 6c 2c 20 6e 6f 74 68 69 6e 67 20 74 6f 20 70 65 72 73 69 73 74}
		$s1 = {2d 2d 63 6d 64 20 25 78 20 2d 2d 69 64 6b 65 79 20 25 73 20 2d 2d 73 70 6f 72 74 20 25 69 20 2d 2d 64 70 6f 72 74 20 25 69 20 2d 2d 6c 70 20 25 73 20 2d 2d 69 6d 70 6c 61 6e 74 20 25 73 20 2d 2d 62 73 69 7a 65 20 25 68 75 20 2d 2d 6c 6f 67 64 69 72 20 25 73 20}
		$s2 = {45 72 72 6f 72 20 77 68 69 6c 65 20 61 74 74 65 6d 70 69 6e 67 20 74 6f 20 70 65 72 73 69 73 74 20 6d 6f 64 75 6c 65 73 3a}
		$s3 = {45 72 72 6f 72 20 77 68 69 6c 65 20 72 65 61 64 69 6e 67 20 69 6e 74 65 72 66 61 63 65 20 69 6e 66 6f 20 66 72 6f 6d 20 50 49 58}
		$s4 = {4c 50 2e 63 3a 70 69 78 46 72 65 65 20 2d 20 46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 72 65 73 70 6f 6e 73 65}
		$s5 = {57 41 52 4e 49 4e 47 3a 20 4c 50 20 54 69 6d 65 6f 75 74 20 73 70 65 63 69 66 69 65 64 20 28 25 6c 75 20 73 65 63 6f 6e 64 73 29 20 6c 65 73 73 20 74 68 61 6e 20 64 65 66 61 75 6c 74 20 28 25 75 20 73 65 63 6f 6e 64 73 29 2e 20 20 53 65 74 74 69 6e 67 20 64 65 66 61 75 6c 74}
		$s6 = {55 6e 61 62 6c 65 20 74 6f 20 66 65 74 63 68 20 63 6f 6e 66 69 67 20 61 64 64 72 65 73 73 20 66 6f 72 20 74 68 69 73 20 4f 53 20 76 65 72 73 69 6f 6e}
		$s7 = {4c 50 2e 63 3a 20 69 6e 74 65 72 66 61 63 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 6e 6f 74 20 61 76 61 69 6c 61 62 6c 65 20 66 6f 72 20 74 68 69 73 20 73 65 73 73 69 6f 6e}
		$s8 = {5b 25 73 3a 25 73 3a 25 64 5d 20 45 52 52 4f 52 3a 20}
		$s9 = {65 78 74 72 61 63 74 5f 66 67 62 67}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 3000KB and 1 of ( $x* ) ) or ( 5 of them )
}

rule EQGRP_Implants_Gen1 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, lpexe, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash8 = "ee3e3487a9582181892e27b4078c5a3cb47bb31fc607634468cc67753f7e61d7"
		hash9 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$s1 = {57 41 52 4e 49 4e 47 3a 20 20 53 65 73 73 69 6f 6e 20 6d 61 79 20 6e 6f 74 20 68 61 76 65 20 62 65 65 6e 20 63 6c 6f 73 65 64 21}
		$s2 = {45 58 45 43 20 50 61 63 6b 65 74 20 50 72 6f 63 65 73 73 65 64}
		$s3 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 73 65 72 74 20 74 68 65 20 63 6f 6d 6d 61 6e 64 20 69 6e 74 6f 20 63 6f 6d 6d 61 6e 64 20 6c 69 73 74 2e}
		$s4 = {53 65 6e 64 5f 50 61 63 6b 65 74 3a 20 54 72 79 69 6e 67 20 74 6f 20 73 65 6e 64 20 74 6f 6f 20 6d 75 63 68 20 64 61 74 61 2e}
		$s5 = {70 61 79 6c 6f 61 64 4c 65 6e 67 74 68 20 3e 3d 20 4d 41 58 5f 41 4c 4c 4f 57 5f 53 49 5a 45 2e}
		$s6 = {57 72 6f 6e 67 20 50 61 79 6c 6f 61 64 20 53 69 7a 65}
		$s7 = {55 6e 6b 6e 6f 77 6e 20 70 61 63 6b 65 74 20 72 65 63 65 69 76 65 64 2e 2e 2e 2e 2e 2e}
		$s8 = {52 65 74 75 72 6e 65 64 20 65 61 78 20 3d 20 25 30 38 78}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 6000KB and ( 2 of ( $s* ) ) ) or ( 5 of them )
}

rule EQGRP_eligiblebombshell_generic : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
		hash2 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"

	strings:
		$s1 = {6c 6f 67 67 69 6e 67 2e 65 72 72 6f 72 28 22 20 20 20 20 20 20 20 50 65 72 68 61 70 73 20 79 6f 75 20 73 68 6f 75 6c 64 20 72 75 6e 20 77 69 74 68 20 2d 2d 73 63 61 6e 3f 22 29}
		$s2 = {6c 6f 67 67 69 6e 67 2e 65 72 72 6f 72 28 22 45 52 52 4f 52 3a 20 4e 6f 20 65 6e 74 72 79 20 66 6f 72 20 45 54 61 67 20 5b 25 73 5d 20 69 6e 20 25 73 2e 22 20 25}
		$s3 = {22 62 65 20 73 75 70 70 6c 69 65 64 22 29}

	condition:
		( filesize < 70KB and 2 of ( $s* ) ) or ( all of them )
}

rule EQGRP_ssh_telnet_29 : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
		hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"

	strings:
		$s1 = {72 65 63 65 69 76 65 64 20 70 72 6f 6d 70 74 2c 20 77 65 27 72 65 20 69 6e}
		$s2 = {66 61 69 6c 65 64 20 74 6f 20 6c 6f 67 69 6e 2c 20 62 61 64 20 63 72 65 64 73 2c 20 61 62 6f 72 74}
		$s3 = {73 65 6e 64 69 6e 67 20 63 6f 6d 6d 61 6e 64 20 22 20 2b 20 73 74 72 28 6e 29 20 2b 20 22 2f 22 20 2b 20 73 74 72 28 74 6f 74 29 20 2b 20 22 2c 20 6c 65 6e 20 22 20 2b 20 73 74 72 28 6c 65 6e 28 63 68 75 6e 6b 29 20 2b 20}
		$s4 = {72 65 63 65 69 76 65 64 20 6e 61 74 20 2d 20 45 50 42 41 3a 20 6f 6b 2c 20 70 61 79 6c 6f 61 64 3a 20 6d 61 6e 67 6c 65 64 2c 20 64 69 64 20 6e 6f 74 20 72 75 6e}
		$s5 = {6e 6f 20 73 74 61 74 75 73 20 72 65 74 75 72 6e 65 64 20 66 72 6f 6d 20 74 61 72 67 65 74 2c 20 63 6f 75 6c 64 20 62 65 20 61 6e 20 65 78 70 6c 6f 69 74 20 66 61 69 6c 75 72 65 2c 20 6f 72 20 74 68 69 73 20 69 73 20 61 20 76 65 72 73 69 6f 6e 20 77 68 65 72 65 20 77 65 20 64 6f 6e 27 74 20 65 78 70 65 63 74 20 61 20 73 74 75 73 20 72 65 74 75 72 6e}
		$s6 = {72 65 63 65 69 76 65 64 20 61 72 70 20 2d 20 45 50 42 41 3a 20 6f 6b 2c 20 70 61 79 6c 6f 61 64 3a 20 66 61 69 6c}
		$s7 = {63 68 6f 70 70 65 64 20 3d 20 73 74 72 69 6e 67 2e 72 73 74 72 69 70 28 70 61 79 6c 6f 61 64 2c 20 22 5c 78 30 61 22 29}

	condition:
		( filesize < 10KB and 2 of them ) or ( 3 of them )
}

rule EQGRP_tinyexec : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - from files tinyexec"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"

	strings:
		$s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
		$s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }

	condition:
		uint32( 0 ) == 0x464c457f and filesize < 270 and all of them
}

rule EQGRP_callbacks : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - Callback addresses"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"

	strings:
		$s1 = {((33 30 2e 34 30 2e 35 30 2e 36 30 3a 39 33 34 32) | (33 00 30 00 2e 00 34 00 30 00 2e 00 35 00 30 00 2e 00 36 00 30 00 3a 00 39 00 33 00 34 00 32 00))}

	condition:
		1 of them
}

rule EQGRP_Extrabacon_Output : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - Extrabacon exploit output"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"

	strings:
		$s1 = {7c 23 23 23 5b 20 53 4e 4d 50 72 65 73 70 6f 6e 73 65 20 5d 23 23 23}
		$s2 = {5b 2b 5d 20 67 65 6e 65 72 61 74 69 6e 67 20 65 78 70 6c 6f 69 74 20 66 6f 72 20 65 78 65 63 20 6d 6f 64 65 20 70 61 73 73 2d 64 69 73 61 62 6c 65}
		$s3 = {5b 2b 5d 20 62 75 69 6c 64 69 6e 67 20 70 61 79 6c 6f 61 64 20 66 6f 72 20 6d 6f 64 65 20 70 61 73 73 2d 64 69 73 61 62 6c 65}
		$s4 = {5b 2b 5d 20 45 78 65 63 75 74 69 6e 67 3a 20 20 65 78 74 72 61 62 61 63 6f 6e}
		$s5 = {61 70 70 65 6e 64 65 64 20 41 41 41 41 44 4d 49 4e 41 55 54 48 5f 45 4e 41 42 4c 45 20 70 61 79 6c 6f 61 64}

	condition:
		2 of them
}

rule EQGRP_Unique_Strings : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - Unique strings"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"

	strings:
		$s1 = {2f 42 61 6e 61 6e 61 47 6c 65 65 2f 45 4c 49 47 49 42 4c 45 42 4f 4d 42}
		$s2 = {50 72 6f 74 6f 63 6f 6c 20 6d 75 73 74 20 62 65 20 65 69 74 68 65 72 20 68 74 74 70 20 6f 72 20 68 74 74 70 73 20 28 45 78 3a 20 68 74 74 70 73 3a 2f 2f 31 2e 32 2e 33 2e 34 3a 31 32 33 34 29}

	condition:
		1 of them
}

rule EQGRP_RC5_RC6_Opcode : hardened
{
	meta:
		description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
		date = "2016-08-17"

	strings:
		$s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }

	condition:
		1 of them
}

