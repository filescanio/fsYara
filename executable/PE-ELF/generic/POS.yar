rule blackpos_v2 : hardened
{
	meta:
		author = "@patrickrolsen"
		version = "0.1"
		reference = "http://blog.nuix.com/2014/09/08/blackpos-v2-new-variant-or-different-family"

	strings:
		$s1 = {55 73 61 67 65 3a 20 2d 5b 73 74 61 72 74 7c 73 74 6f 70 7c 69 6e 73 74 61 6c 6c 7c 75 6e 69 6e 73 74 61 6c 6c}
		$s2 = {5c 53 59 53 54 45 4d 33 32 5c 73 63 2e 65 78 65 20 63 6f 6e 66 69 67 20 4c 61 6e 6d 61 6e 57 6f 72 6b 73 74 61 74 69 6f 6e}
		$s3 = {74 2e 62 61 74}
		$s4 = {6d 63 66 6d 69 73 76 63}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule dump_tool : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "Related to pwdump6 and fgdump tools"

	strings:
		$s1 = {6c 73 72 65 6d 6f 72 61}
		$s2 = {73 65 72 76 70 77}
		$s3 = {66 61 69 6c 65 64 3a 20 25 64}
		$s4 = {66 67 64 75 6d 70}
		$s5 = {66 67 65 78 65 63}
		$s6 = {66 67 65 78 65 63 70 69 70 65}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* )
}

rule osql_tool : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "O/I SQL - SQL query tool"
		filetype = "EXE"
		version = "0.1"
		date = "1/30/2014"

	strings:
		$s1 = {6f 73 71 6c 5c 73 72 63}
		$s2 = {4f 53 51 4c 55 53 45 52}
		$s3 = {4f 53 51 4c 50 41 53 53 57 4f 52 44}
		$s4 = {4f 53 51 4c 53 45 52 56 45 52}

	condition:
		uint16( 0 ) == 0x5A4D and ( all of ( $s* ) )
}

rule misc_pos : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "POS Malware"
		score = 40

	strings:
		$s1 = {4b 41 50 54 4f 58 41}
		$s2 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 25 73}
		$s3 = {70 69 64 3a}
		$s4 = {25 41 44 44 25}
		$s5 = {43 4f 4d 53 50 45 43}
		$s6 = {4b 41 52 54 4f 58 41}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* )
}

rule unknown : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "Unknown POS"

	strings:
		$s1 = {61 00 2e 00 65 00 78 00 65 00}
		$s2 = {43 00 61 00 6e 00 20 00 61 00 6e 00 79 00 6f 00 6e 00 65 00 20 00 74 00 65 00 73 00 74 00}
		$s3 = {49 00 20 00 6d 00 20 00 69 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 63 00 6c 00 61 00 73 00 73 00 20 00 6e 00 6f 00 77 00}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* )
}

rule regex_pos : hardened limited
{
	meta:
		author = "@patrickrolsen"
		reference = "POS malware - Regex"

	strings:
		$n1 = {52 45 47 45 58 45 4e 44}
		$n2 = {52 65 67 45 78 70 72}
		$n3 = {72 65 67 65 78}
		$s4 = {5b 31 2d 35 5d 5b 30 2d 39 5d 7b 31 34 7d 3d 28 3f 21 31 32 30 31 7c 31 32 30 32 7c 31 32 30 33 7c 31 32 30 34 7c 31 31 7c 31 30 7c 30 39 7c 30 38 7c 30 37 7c 30 36 7c 30 35 7c 30 34 7c 30 33 7c 30 32 29 5b 30 2d 39 5d 7b 35 7d 5b 30 2d 39 5d 2a}
		$s5 = {5b 34 37 5d 5b 30 2d 39 5d 7b 31 33 7d 3d 28 3f 21 31 32 30 31 7c 31 32 30 32 7c 31 32 30 33 7c 31 32 30 34 7c 31 31 7c 31 30 7c 30 39 7c 30 38 7c 30 37 7c 30 36 7c 30 35 7c 30 34 7c 30 33 7c 30 32 29 5b 30 2d 39 5d 7b 35 7d 5b 30 2d 39 5d 2a}
		$s6 = {28 3f 3a 30 5b 30 2d 35 5d 7c 5b 36 38 5d 5b 30 2d 39 5d 29 5b 30 2d 39 5d 7b 31 31 7d 3d 28 3f 21 31 32 30 31 7c 31 32 30 32 7c 31 32 30 33 7c 31 32 30 34 7c 31 31 7c 31 30 7c 30 39 7c 30 38 7c 30 37 7c 30 36 7c 30 35 7c 30 34 7c 30 33 7c 30 32 29 5b 30 2d 39 5d 7b 35 7d 5b 30 2d 39 5d 2a}
		$s7 = {28 3f 3a 30 31 31 7c 35 5b 30 2d 39 5d 7b 32 7d 29 5b 30 2d 39 5d 7b 31 32 7d 3d 28 3f 21 31 32 30 31 7c 31 32 30 32 7c 31 32 30 33 7c 31 32 30 34 7c 31 31 7c 31 30 7c 30 39 7c 30 38 7c 30 37 7c 30 36 7c 30 35 7c 30 34 7c 30 33 7c 30 32 29 5b 30 2d 39 5d 7b 35 7d 5b 30 2d 39 5d 2a}
		$s8 = {28 3f 3a 32 31 33 31 7c 31 38 30 30 7c 33 35 5c 64 7b 33 7d 29 5c 64 7b 31 31 7d 3d 28 3f 21 31 32 30 31 7c 31 32 30 32 7c 31 32 30 33 7c 31 32 30 34 7c 31 31 7c 31 30 7c 30 39 7c 30 38 7c 30 37 7c 30 36 7c 30 35 7c 30 34 7c 30 33 7c 30 32 29 5b 30 2d 39 5d 7b 35 7d 5b 30 2d 39 5d 2a}
		$s9 = {28 5b 30 2d 39 5d 7b 31 35 2c 31 36 7d 5b 44 3d 5d 28 30 5b 37 2d 39 5d 7c 31 5b 30 2d 35 5d 29 28 28 30 5b 31 2d 39 5d 29 7c 28 31 5b 30 2d 32 5d 29 29 5b 30 2d 39 5d 7b 38 2c 33 30 7d 29}
		$s10 = {28 28 62 7c 42 29 5b 30 2d 39 5d 7b 31 33 2c 31 39 7d 5c 5e 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 33 30 7d 5c 2f 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 33 30 7d 5c 5e 28 30 5b 37 2d 39 5d 7c 31 5b 30 2d 35 5d 29 28 28 30 5b 31 2d 39 5d 29 7c 28 31 5b 30 2d 32 5d 29 29 5b 30 2d 39 5c 73 5d 7b 33 2c 35 30 7d 5b 30 2d 39 5d 7b 31 7d 29}
		$s11 = {5b 30 2d 39 5d 2a 5c 5e 5b 61 2d 7a 41 2d 5a 5d 2a 2f 5b 61 2d 7a 41 2d 5a 20 5d 2a 5c 5e 5b 30 2d 39 5d 2a}
		$s12 = {5c 64 7b 31 35 2c 31 39 7d 3d 5c 64 7b 31 33 2c 7d}
		$s13 = {5c 3b 3f 5b 33 2d 39 5d 7b 31 7d 5b 30 2d 39 5d 7b 31 32 2c 31 39 7d 5b 44 3d 5c 75 30 30 36 31 5d 5b 30 2d 39 5d 7b 31 30 2c 33 30 7d 5c 3f 3f}
		$s14 = {5b 30 2d 39 5d 7b 31 32 7d 28 3f 3a 5b 30 2d 39 5d 7b 33 7d 29 3f 3d 28 3f 21 31 32 30 31 7c 31 32 30 32 7c 31 32 30 33 7c 31 32 30 34 7c 31 31 7c 31 30 7c 30 39 7c 30 38 7c 30 37 7c 30 36 7c 30 35 7c 30 34 7c 30 33 7c 30 32 29 5b 30 2d 39 5d 7b 35 7d 5b 30 2d 39 5d 2a}

	condition:
		uint16( 0 ) == 0x5A4D and 1 of ( $n* ) and 1 of ( $s* )
}

rule reg_pos : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "POS malware - RegExpr"

	strings:
		$s1 = {54 31 5f 46 4f 55 4e 44 3a 20 25 73}
		$s2 = {69 64 3d 25 73 26 6c 6f 67 3d 25 73}
		$s3 = {5c 64 7b 31 35 2c 31 39 7d 3d 5c 64 7b 31 33 2c 7d}

	condition:
		uint16( 0 ) == 0x5A4D and 2 of ( $s* )
}

rule sets_pos : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "POS malware - Sets"

	strings:
		$s1 = {47 45 54 20 2f 73 65 74 73 2e 74 78 74}

	condition:
		uint16( 0 ) == 0x5A4D and $s1
}

rule monitor_tool_pos : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "POS malware - Monitoring Tool??"

	strings:
		$s1 = {52 43 50 54 20 54 4f}
		$s2 = {4d 41 49 4c 20 46 52 4f 4d}
		$s3 = {41 55 54 48 20 4c 4f 47 49 4e}
		$s4 = {52 65 70 6c 79 2d 54 6f}
		$s5 = {58 2d 4d 61 69 6c 65 72}
		$s6 = {63 72 79 70 74 6f}
		$s7 = {74 00 65 00 73 00 74 00 33 00 33 00 35 00 2e 00 74 00 78 00 74 00}
		$s8 = {2f 63 20 64 65 6c}

	condition:
		uint16( 0 ) == 0x5A4D and 7 of ( $s* )
}

rule pstgdump_2 : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "pstgdump"

	strings:
		$s1 = {66 67 64 75 6d 70 5c 70 73 74 67 64 75 6d 70}
		$s2 = {70 73 74 67 64 75 6d 70}
		$s3 = {4f 75 74 6c 6f 6f 6b}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule keyfinder_tool : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "Magical Jelly Bean KeyFinder"

	strings:
		$s1 = {63 68 67 78 70 2e 76 62 73}
		$s2 = {6f 66 66 69 63 65 6b 65 79 2e 65 78 65}
		$s3 = {66 69 6e 64 6b 65 79 2e 65 78 65}
		$s4 = {78 70 6b 65 79 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5A4D and 2 of ( $s* )
}

rule memdump_diablo : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "Process Memory Dumper - DiabloHorn"

	strings:
		$s1 = {44 69 61 62 6c 6f 48 6f 72 6e}
		$s2 = {50 72 6f 63 65 73 73 20 4d 65 6d 6f 72 79 20 44 75 6d 70 65 72}
		$s3 = {70 69 64 2d 25 73 2e 64 6d 70}
		$s4 = {50 69 64 20 25 64 20 69 6e 20 6e 6f 74 20 61 63 65 73 73 69 62 6c 65}
		$s5 = {6d 65 6d 64 75 6d 70 2e 65 78 65}
		$s6 = {25 73 2d 25 64 2e 64 6d 70}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* )
}

rule blazingtools : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "Blazing Tools - http://www.blazingtools.com (Keyloggers)"

	strings:
		$s1 = {62 6c 61 7a 69 6e 67 74 6f 6f 6c 73 2e 63 6f 6d}
		$s2 = {4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00}
		$s3 = {53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 73 00}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule sysocmgr : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "System stand-alone Optional Component Manager - http://support.microsoft.com/kb/222444"

	strings:
		$s1 = {53 00 59 00 53 00 4f 00 43 00 4d 00 47 00 52 00 2e 00 45 00 58 00 45 00}
		$s2 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 73 00 74 00 61 00 6e 00 64 00 2d 00 61 00 6c 00 6f 00 6e 00 65 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 43 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule lacy_keylogger : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "Appears to be a form of keylogger."

	strings:
		$s1 = {4c 00 61 00 63 00 79 00 2e 00 65 00 78 00 65 00}
		$s2 = {42 00 6c 00 64 00 67 00 20 00 43 00 68 00 69 00 76 00 65 00 20 00 44 00 75 00 65 00 6c 00 20 00 52 00 69 00 70 00 20 00 51 00 75 00 65 00 72 00 79 00}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule searchinject : hardened limited
{
	meta:
		author = "@patrickrolsen"
		reference = "Usage: SearchInject <PID1>[PID2][PID3] - It loads Searcher.dll (appears to be hard coded)"

	strings:
		$s1 = {53 65 61 72 63 68 49 6e 6a 65 63 74}
		$s2 = {69 6e 6a 65 63 74 20 62 61 73 65 3a}
		$s3 = {53 65 61 72 63 68 65 72 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule heistenberg_pos : hardened
{
	meta:
		author = "@patrickrolsen"
		reference = "POS Malware"

	strings:
		$s1 = {4b 41 52 54 4f 58 41}
		$s2 = {64 6d 70 7a 2e 6c 6f 67}
		$s3 = {2f 61 70 69 2f 70 72 6f 63 65 73 73 2e 70 68 70 3f 78 79 3d}
		$s4 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 50 43 49 43 6f 6d 70 6c 69 61 6e 74}
		$s6 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 25 73}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* )
}

rule pos_jack : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		version = "0.1"
		reference = "http://blog.spiderlabs.com/2014/02/jackpos-the-house-always-wins.html"
		date = "2/22/2014"

	strings:
		$pdb1 = {5c 7a 69 65 64 70 69 72 61 74 65 2e 7a 69 65 64 70 69 72 61 74 65 2d 50 43 5c}
		$pdb2 = {5c 73 6f 70 5c 73 6f 70 5c}

	condition:
		uint16( 0 ) == 0x5A4D and 1 of ( $pdb* )
}

rule pos_memory_scrapper_ : hardened limited
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware Memory Scraper"
		version = "0.3"
		description = "POS Memory Scraper"
		date = "01/30/2014"

	strings:
		$s1 = {6b 61 72 74 6f 78 61}
		$s2 = {43 43 32 20 72 65 67 69 6f 6e 3a}
		$s3 = {43 43 20 6d 65 6d 72 65 67 69 6f 6e 3a}
		$s4 = {74 61 72 67 65 74 20 70 69 64 3a}
		$s5 = {73 63 61 6e 20 61 6c 6c 20 70 72 6f 63 65 73 73 65 73 3a}
		$s6 = {3c 70 69 64 3e 20 3c 50 41 54 54 45 52 4e 3e}
		$s7 = {4b 41 50 54 4f 58 41}
		$s8 = {41 54 54 45 52 4e}
		$s9 = {5c 73 76 68 73 74 25 70}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* )
}

rule pos_malwre_dexter_stardust : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Dexter Malware - StarDust Variant"
		version = "0.1"
		description = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
		reference = "16b596de4c0e4d2acdfdd6632c80c070, 2afaa709ef5260184cbda8b521b076e1, and e3dd1dc82ddcfaf410372ae7e6b2f658"
		date = "12/30/2013"

	strings:
		$s1 = {63 65 68 5f 33 5c 2e 5c 63 65 68 5f 34 5c 2e 2e 5c 63 65 68 5f 36}
		$s2 = {59 61 74 6f 65 64 33 66 65 33 72 65 78 32 33 30 33 30 61 6d 33 39 34 39 37 34 30 33}
		$s3 = {50 6f 6f 37 6c 6f 32 37 36 36 37 30 31 37 33 71 75 61 69 31 36 35 36 38 75 6e 74 6f 31 38 32 38 4f 6c 65 6f 39 65 64 73 39 36 30 30 36 6e 6f 73 79 73 75 6d 70 37 68 6f 76 65 31 39}
		$s4 = {43 6f 6d 6d 6f 6e 46 69 6c 65 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule pos_malware_project_hook : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Project Hook"
		version = "0.1"
		description = "Table 1 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
		reference = "759154d20849a25315c4970fe37eac59"
		date = "12/30/2013"

	strings:
		$s1 = {43 61 6c 6c 49 6d 61 67 65 2e 65 78 65}
		$s2 = {42 75 72 70 53 77 69 6d}
		$s3 = {57 6f 72 6b 5c 50 72 6f 6a 65 63 74 5c 4c 6f 61 64}
		$s4 = {57 6f 72 74 48 69 73 6e 61 6c}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule pdb_strings_Rescator : hardened limited
{
	meta:
		author = "@patrickrolsen"
		maltype = "Target Attack"
		version = "0.3"
		description = "Rescator PDB strings within binaries"
		date = "01/30/2014"

	strings:
		$pdb1 = {5c 50 72 6f 6a 65 63 74 73 5c 52 65 73 63 61 74 6f 72}

	condition:
		uint16( 0 ) == 0x5A4D and $pdb1
}

rule pos_uploader : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		reference = "http://blogs.mcafee.com/mcafee-labs/analyzing-the-target-point-of-sale-malware"
		version = "0.1"
		description = "Testing the base64 encoded file in sys32"
		date = "01/30/2014"

	strings:
		$s1 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 25 73}
		$s2 = {66 74 70 20 2d 73 3a 25 73}
		$s3 = {64 61 74 61 5f 25 64 5f 25 64 5f 25 64 5f 25 64 5f 25 64 2e 74 78 74}
		$s4 = {5c 75 70 6c 6f 61 64 65 72 5c}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $s* )
}

rule winxml_dll : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		reference = "ce0296e2d77ec3bb112e270fc260f274"
		version = "0.1"
		description = "Testing the base64 encoded file in sys32"
		date = "01/30/2014"

	strings:
		$s1 = {5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 78 6d 6c 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5A4D and ( all of ( $s* ) )
}

rule pos_chewbacca : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		reference = "https://www.securelist.com/en/blog/208214185/ChewBacca_a_new_episode_of_Tor_based_Malware"
		hashes = "21f8b9d9a6fa3a0cd3a3f0644636bf09, 28bc48ac4a92bde15945afc0cee0bd54"
		version = "0.2"
		description = "Testing the base64 encoded file in sys32"
		date = "01/30/2014"

	strings:
		$s1 = {74 6f 72 20 2d 66 20 3c 74 6f 72 72 63 3e}
		$s2 = {74 6f 72 5f}
		$s3 = {75 6d 65 6d 73 63 61 6e}
		$s4 = {43 48 45 57 42 41 43}

	condition:
		uint16( 0 ) == 0x5A4D and ( all of ( $s* ) )
}

