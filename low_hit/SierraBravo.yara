import "pe"

rule SierraBravo_Two : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$smbComNegotiationPacketGen = { 66 C7 ?? 0E 07 C8 [0-32] C7 ?? 39 D4 00 00 80 [0-32] 66 C7 ?? 25 FF 00 [0-32] 66 C7 ?? 27 A4 00 [0-32]	66 C7 ?? 29 04 41 [0-32] 66 C7 ?? 2B 32 00}
		$lib = {21 65 6d 43 46 67 76 37 58 63 38 49 74 61 56 47 4e 30 62 4d 66}
		$api1 = {21 63 74 52 48 46 45 58 35 6d 39 4a 6e 5a 64 44 66 70 4b}
		$api2 = {21 65 6d 43 46 67 76 37 58 63 38 49 74 61 56 47 4e 30 62 4d 66}
		$api3 = {21 56 57 42 65 42 78 59 78 31 6e 7a 72 43 6b 42 4c 47 51 4f}
		$pwd = {69 61 6d 73 6f 72 72 79 21 40 31 32 33 34 35 36 37}

	condition:
		$smbComNegotiationPacketGen in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) ) or ( $pwd in ( ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".data" ) ] . raw_data_size ) ) and ( $lib in ( ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".data" ) ] . raw_data_size ) ) or $api1 in ( ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".data" ) ] . raw_data_size ) ) or $api2 in ( ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".data" ) ] . raw_data_size ) ) or $api3 in ( ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".data" ) ] . raw_data_size ) ) ) )
}

import "pe"

rule SierraBravo_One : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$spreaderSetup = {68 7E 66 04 80 5? E8 [4] 6A 32 89 B4 [5] C7 84 [5] 01 00 00 00 C7 44 [2] 03 00 00 00 C7 44 [2] 00 00 00 00 }

	condition:
		$spreaderSetup in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

rule SierraBravo_packed : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = {63 6d 64 2e 65 78 65 20 2f 63 20 22 6e 65 74 20 73 68 61 72 65 20 61 64 6d 69 6e 24 20 2f 64 22}
		$ = {4d 41 49 4c 20 46 52 4f 4d 3a 3c}
		$ = {2e 70 65 74 69 74 65}
		$ = {53 75 62 6a 65 63 74 3a 20 25 73 7c 25 73 7c 25 73}

	condition:
		3 of them
}

