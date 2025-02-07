rule RUAG_Tavdig_Malformed_Executable : hardened
{
	meta:
		description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60

	condition:
		uint16( 0 ) == 0x5a4d and uint32( uint32( 0x3C ) ) == 0x0000AD0B
}

rule RUAG_Bot_Config_File : hardened
{
	meta:
		description = "Detects a specific config file used by malware in RUAG APT case"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60

	strings:
		$s1 = {5b 43 4f 4e 46 49 47 5d}
		$s2 = {6e 61 6d 65 20 3d 20}
		$s3 = {65 78 65 20 3d 20 63 6d 64 2e 65 78 65}

	condition:
		$s1 at 0 and $s2 and $s3 and filesize < 160
}

rule RUAG_Cobra_Malware : hardened
{
	meta:
		description = "Detects a malware mentioned in the RUAG Case called Carbon/Cobra"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60

	strings:
		$s1 = {5c 43 6f 62 72 61 5c 52 65 6c 65 61 73 65 5c 43 6f 62 72 61 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and $s1
}

rule RUAG_Cobra_Config_File : hardened
{
	meta:
		description = "Detects a config text file used by malware Cobra in RUAG case"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60

	strings:
		$h1 = {5b 4e 41 4d 45 5d}
		$s1 = {6f 62 6a 65 63 74 5f 69 64 3d}
		$s2 = {5b 54 49 4d 45 5d}
		$s3 = {6c 61 73 74 63 6f 6e 6e 65 63 74}
		$s4 = {5b 43 57 5f 4c 4f 43 41 4c 5d}
		$s5 = {73 79 73 74 65 6d 5f 70 69 70 65}
		$s6 = {75 73 65 72 5f 70 69 70 65}
		$s7 = {5b 54 52 41 4e 53 50 4f 52 54 5d}
		$s8 = {72 75 6e 5f 74 61 73 6b 5f 73 79 73 74 65 6d}
		$s9 = {5b 57 4f 52 4b 44 41 54 41 5d}
		$s10 = {61 64 64 72 65 73 73 31}

	condition:
		$h1 at 0 and 8 of ( $s* ) and filesize < 5KB
}

rule RUAG_Exfil_Config_File : hardened
{
	meta:
		description = "Detects a config text file used in data exfiltration in RUAG case"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60

	strings:
		$h1 = {5b 54 52 41 4e 53 50 4f 52 54 5d}
		$s1 = {73 79 73 74 65 6d 5f 70 69 70 65}
		$s2 = {73 70 73 74 61 74 75 73}
		$s3 = {61 64 61 70 74 61 62 6c 65}
		$s4 = {70 6f 73 74 5f 66 72 61 67}
		$s5 = {70 66 73 67 72 6f 77 70 65 72 69 6f 64}

	condition:
		$h1 at 0 and all of ( $s* ) and filesize < 1KB
}

import "pe"

rule WaterBug_turla_dll : hardened
{
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla DLL"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://www.symantec.com/connect/blogs/turla-spying-tool-targets-governments-and-diplomats"

	strings:
		$a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/

	condition:
		pe.exports( "ee" ) and $a
}

rule turla_dropper : hardened
{
	meta:
		maltype = "turla dropper"
		ref = "https://github.com/reed1713"
		reference = "http://info.baesystemsdetica.com/rs/baesystems/images/snake_whitepaper.pdf"
		date = "3/13/2014"
		description = "This sample was pulled from the bae systems snake campaign report. The Turla dropper creates a file in teh temp dir and registers an auto start service call \"RPC Endpoint Locator\"."

	strings:
		$type = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid = {34 36 38 38}
		$data = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 72 73 79 73 2e 65 78 65}
		$type1 = {53 65 72 76 69 63 65 20 43 6f 6e 74 72 6f 6c 20 4d 61 6e 61 67 65 72}
		$eventid1 = {37 30 33 36}
		$data1 = {52 50 43 20 45 6e 64 70 6f 69 6e 74 20 4c 6f 63 61 74 6f 72}
		$data2 = {72 75 6e 6e 69 6e 67}
		$type2 = {53 65 72 76 69 63 65 20 43 6f 6e 74 72 6f 6c 20 4d 61 6e 61 67 65 72}
		$eventid2 = {37 30 34 35}
		$data3 = {52 50 43 20 45 6e 64 70 6f 69 6e 74 20 4c 6f 63 61 74 6f 72}
		$data4 = {75 73 65 72 20 6d 6f 64 65 20 73 65 72 76 69 63 65}
		$data5 = {61 75 74 6f 20 73 74 61 72 74}

	condition:
		($type and $eventid and $data ) or ( $type1 and $eventid1 and $data1 and $data2 and $type2 and $eventid2 and $data3 and $data4 and $data5 )
}

