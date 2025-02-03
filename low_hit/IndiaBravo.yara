rule IndiaBravo_PapaAlfa : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = {70 00 6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 6d 00 73 00 69 00}
		$ = {73 63 76 72 69 74 30 30 31 2e 62 61 74}

	condition:
		all of them
}

import "pe"

rule IndiaBravo_RomeoCharlie : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "58ad28ac4fb911abb6a20382456c4ad6fe5c8ee5.ex_"
		Status = "Signature is too loose to be useful."

	strings:
		$a = {50 68 7E 66 04 80 8B 8D [4] 51 FF 15 [4] 83 F8 FF 75}
		$b1 = {78 63 31 32 33 34 36 35 2d 65 66 66 66 2d 38 37 63 63 2d 33 37 61 62 63 64 65 66 39}
		$b2 = {5b 00 43 00 68 00 65 00 63 00 6b 00 5d 00 20 00 2d 00 20 00 50 00 4f 00 52 00 54 00 20 00 45 00 52 00 52 00 4f 00 52 00 2e 00 2e 00 2e 00}
		$b3 = {25 73 64 2e 65 25 73 63 20 6e 25 73 73 68 25 73 72 65 77 61 25 73 20 61 64 25 73 20 70 6f 25 73 6f 70 25 73 69 6e 67 20 54 25 73 20 25 64}

	condition:
		2 of ( $b* ) or $a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule IndiaBravo_RomeoBravo : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "6e3db4da27f12eaba005217eba7cd9133bc258c97fe44605d12e20a556775009"

	strings:
		$a = {E8 [4] 68 [2] 00 00 68 [4] A3 [4]	89 15 [4] E8 [4] 83 C4 08 8D [3] 6A 00 5? 68 [2] 00 00 	68 [4] 5? FF 15 [4] 5? 	FF 15}
		$b1 = {74 00 6d 00 73 00 63 00 6f 00 6d 00 70 00 67 00 2e 00 6d 00 73 00 69 00}
		$b2 = {63 76 72 69 74 30 30 30 2e 62 61 74}

	condition:
		2 of ( $b* ) or $a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

rule IndiaBravo_generic : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$extractDll = {5b 00 32 00 5d 00 20 00 2d 00 20 00 45 00 78 00 74 00 72 00 61 00 63 00 74 00 20 00 44 00 6c 00 6c 00 2e 00 2e 00 2e 00}
		$createSvc = {5b 00 33 00 5d 00 20 00 2d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 53 00 56 00 43 00 2e 00 2e 00 2e 00}

	condition:
		all of them
}

