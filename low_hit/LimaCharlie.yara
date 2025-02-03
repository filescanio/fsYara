import "pe"

rule LimaCharlie : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_x86 = "6ee6ae79ee1502a11ece81e971a54f189a271be9ec700101a2bd7a21198b94c7"
		Source_x64 = "90ace24eb132c776a6d5bb0451437db21e84601495a2165d75f520af637e71e8"

	strings:
		$misspelling = {44 00 65 00 66 00 75 00 61 00 6c 00 74 00 20 00 53 00 6c 00 65 00 65 00 70 00 20 00 3d 00 20 00 25 00 64 00}
		$x86 = {FF ?? 74 5? 5? 8F ?? 48 01 00 00 85 C0 5? 8F ?? 44 01 00 00 75 ?? F6 [2] 01 74}
		$x64 = {48 [2] 70 48 [2] 60 01 00 00 48 [2] 68 01 00 00 48 85 C0 75 ?? F6 [2] 01 74}

	condition:
		$x86 in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) ) or $x64 in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) ) or $misspelling
}

