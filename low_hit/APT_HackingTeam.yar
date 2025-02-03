rule bin_ndisk : hardened
{
	meta:
		description = "Hacking Team Disclosure Sample - file ndisk.sys"
		author = "Florian Roth"
		reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
		date = "2015-07-07"
		hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"

	strings:
		$s1 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 25 00 64 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 6e 00 64 00 69 00 73 00 6b 00 2e 00 73 00 79 00 73 00}
		$s2 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 25 00 64 00 5c 00 45 00 6e 00 75 00 6d 00 5c 00 52 00 6f 00 6f 00 74 00 5c 00 4c 00 45 00 47 00 41 00 43 00 59 00 5f 00 4e 00 44 00 49 00 53 00 4b 00 2e 00 53 00 59 00 53 00}
		$s3 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 44 00 65 00 65 00 70 00 46 00 72 00 7a 00}
		$s4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 20 00 44 00 69 00 73 00 6b 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}
		$s5 = {6e 00 64 00 69 00 73 00 6b 00 2e 00 73 00 79 00 73 00}
		$s6 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4d 00 53 00 48 00 34 00 44 00 45 00 56 00 31 00}
		$s7 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 53 00 48 00 34 00 44 00 45 00 56 00 31 00}
		$s8 = {62 00 75 00 69 00 6c 00 74 00 20 00 62 00 79 00 3a 00 20 00 57 00 69 00 6e 00 44 00 44 00 4b 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and 6 of them
}

rule Hackingteam_Elevator_DLL : hardened
{
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.dll"
		author = "Florian Roth"
		reference = "http://t.co/EG0qtVcKLh"
		date = "2015-07-07"
		hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"

	strings:
		$s1 = {5c 73 79 73 6e 61 74 69 76 65 5c 43 49 2e 64 6c 6c}
		$s2 = {73 65 74 78 20 54 4f 52 5f 43 4f 4e 54 52 4f 4c 5f 50 41 53 53 57 4f 52 44}
		$s3 = {6d 69 74 6d 70 72 6f 78 79 30}
		$s4 = {5c 69 6e 73 65 72 74 5f 63 65 72 74 2e 65 78 65}
		$s5 = {65 6c 65 76 61 74 6f 72 2e 64 6c 6c}
		$s6 = {43 52 54 44 4c 4c 2e 44 4c 4c}
		$s7 = {66 61 69 6c 20 61 64 64 69 6e 67 20 63 65 72 74}
		$s8 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 46 69 6c 65}
		$s9 = {66 61 69 6c 20 61 64 64 69 6e 67 20 63 65 72 74 3a 20 25 73}
		$s10 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 20 66 61 69 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 6 of them
}

rule HackingTeam_Elevator_EXE : hardened
{
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.exe"
		author = "Florian Roth"
		reference = "Hacking Team Disclosure elevator.c"
		date = "2015-07-07"
		hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
		hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"
		hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"

	strings:
		$x1 = {43 52 54 44 4c 4c 2e 44 4c 4c}
		$x2 = {5c 73 79 73 6e 61 74 69 76 65 5c 43 49 2e 64 6c 6c}
		$x3 = {5c 53 79 73 74 65 6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 43 49 2e 64 6c 6c}
		$x4 = {43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 53 79 73 6e 61 74 69 76 65 5c 5c 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65}
		$s1 = {5b 2a 5d 20 74 72 61 76 65 72 73 69 6e 67 20 70 72 6f 63 65 73 73 65 73}
		$s2 = {5f 67 65 74 6b 70 72 6f 63 65 73 73}
		$s3 = {5b 2a 5d 20 4c 6f 61 64 65 72 43 6f 6e 66 69 67 20 25 70}
		$s4 = {6c 6f 61 64 65 72 2e 6f 62 6a}
		$s5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 35 2e 30 3b 20 53 4c 43 43 32 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 35 2e 33 30 37 32 39 3b 20 2e 4e 45 54 20 43 4c 52 20 33}
		$s6 = {5b 2a 5d 20 74 6f 6b 65 6e 20 72 65 73 74 6f 72 65}
		$s7 = {65 6c 65 76 61 74 6f 72 2e 6f 62 6a}
		$s8 = {5f 67 65 74 65 78 70 6f 72 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of ( $x* ) and 3 of ( $s* )
}

rule RCS_Backdoor : hardened
{
	meta:
		description = "Hacking Team RCS Backdoor"
		author = "botherder https://github.com/botherder"

	strings:
		$filter1 = {24 64 65 62 75 67 33}
		$filter2 = {24 6c 6f 67 32}
		$filter3 = {65 72 72 6f 72 32}
		$debug1 = /\- (C)hecking components/ wide ascii
		$debug2 = /\- (A)ctivating hiding system/ wide ascii
		$debug3 = /(f)ully operational/ wide ascii
		$log1 = /\- Browser activity \(FF\)/ wide ascii
		$log2 = /\- Browser activity \(IE\)/ wide ascii
		$error1 = /\[Unable to deploy\]/ wide ascii
		$error2 = /\[The system is already monitored\]/ wide ascii

	condition:
		(2 of ( $debug* ) or 2 of ( $log* ) or all of ( $error* ) ) and not any of ( $filter* )
}

rule RCS_Scout : hardened
{
	meta:
		description = "Hacking Team RCS Scout"
		author = "botherder https://github.com/botherder"

	strings:
		$filter1 = {24 65 6e 67 69 6e 65 35}
		$filter2 = {24 73 74 61 72 74 34}
		$filter3 = {24 75 70 64 32}
		$filter4 = {24 6c 6f 6f 6b 6d 61 36}
		$engine1 = /(E)ngine started/ wide ascii
		$engine2 = /(R)unning in background/ wide ascii
		$engine3 = /(L)ocking doors/ wide ascii
		$engine4 = /(R)otors engaged/ wide ascii
		$engine5 = /(I)\'m going to start it/ wide ascii
		$start1 = /Starting upgrade\!/ wide ascii
		$start2 = /(I)\'m going to start the program/ wide ascii
		$start3 = /(i)s it ok\?/ wide ascii
		$start4 = /(C)lick to start the program/ wide ascii
		$upd1 = /(U)pdJob/ wide ascii
		$upd2 = /(U)pdTimer/ wide ascii
		$lookma1 = /(O)wning PCI bus/ wide
		$lookma2 = /(F)ormatting bios/ wide
		$lookma3 = /(P)lease insert a disk in drive A:/ wide
		$lookma4 = /(U)pdating CPU microcode/ wide
		$lookma5 = /(N)ot sure what's happening/ wide
		$lookma6 = /(L)ook ma, no thread id\! \\\\o\// wide

	condition:
		( all of ( $engine* ) or all of ( $start* ) or all of ( $upd* ) or 4 of ( $lookma* ) ) and not any of ( $filter* )
}

