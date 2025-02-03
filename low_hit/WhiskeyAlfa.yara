import "pe"

rule WhiskeyAlfa : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1c66e67a8531e3ff1c64ae57e6edfde7bef2352d.ex_"

	strings:
		$randomBuffer = {E8 [4] B1 ?? F6 E9 88 [3] 4? 81 ?? 00 00 01 00 7C}
		$mbrDiskInfo = {89 ?? 09 C7 ?? 65 00 00 02 00 C7 ?? 15 04 00 00 00 C6 ?? 08 08 C7 ?? 04 00 02 00 00 89 ?? 89 ?? 0D C7 ?? 11 01 00 00 00 89 ?? 69 89 ?? 19 B8 01 00 00 00}
		$mbrReplacement_Decoded = { B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 }
		$mbrReplacement_Encoded = { E7 10 E3 53 9E 40 AD 91 D3 A9 D7 2F A0 E1 D3 EC 36 2F D2 56 53 57 D0 06 51 53 D0 06 57 53 }
		$licKey = {39 39 45 32 34 32 38 43 43 41 34 33 30 39 43 36 38 41 41 46 38 43 36 31 36 45 46 33 33 30 36 35 38 32 41 36 34 35 31 33 45 35 35 43 37 38 36 41 38 36 34 42 43 38 33 44 41 46 45 30 43 37 38 35 38 35 42 36 39 32 30 34 37 32 37 33 42 30 45 35 35 32 37 35 31 30 32 43 36 36 34 43 35 32 31 37 45 37 36 42 38 45 36 37 46 33 35 46 43 45 33 38 35 45 34 33 32 38 45 45 31 41 44 31 33 39 45 41 36 41 41 32 36 33 34 35 43 34 46 39 33 30 30 30 44 42 42 43 37 45 46 31 35 37 39 44 34 46}

	condition:
		$licKey or $mbrReplacement_Decoded or $mbrReplacement_Encoded or $randomBuffer in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) ) or $mbrDiskInfo in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

