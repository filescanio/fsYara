import "pe"

rule RomeoAlfa : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "fba0b8bdc1be44d100ac31b864830fcc9d056f1f5ab5486384e09bd088256dd0.file2.bin"

	strings:
		$zeroIPLoader = {68 [4] 56 E8 [4] 83 C6 28 83 C4 08 81 FE [4] 7C E?}
		$sleeper = {5? 8B [3] 85 ?? 7E ?? 5? 8B 3D [4]  68 [4] FF ??  4? 75 ??	5? 5? C3 }
		$xercesc = {78 65 72 63 65 73 63}

	condition:
		($sleeper in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) ) or $zeroIPLoader in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) ) ) and not $xercesc
}

