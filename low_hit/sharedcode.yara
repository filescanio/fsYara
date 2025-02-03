import "pe"

rule Caracachs : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
		$a = {B? 10 00 00 00 8B ?? C1 ?? 10 81 ?? FF 7F 00 00 03 ?? 8B ?? 8B ?? 83 ?? 0F 2B ?? D3 ?? 8B ?? D3 ?? 0B ?? 	89 ?? 	}

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule StringDotSimplified : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
		$a = {	F3 AB 	80 ?? 00 	74 ?? 	8A 02 	3C 2E 	74 ?? 	3C 20 	74 ?? 	88 06 	46 }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule FakeTLS_ServerHelloGetSelectedCipher : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
		$a = {	24 10 	0C 10 	89 ?? 	66 8? [3] 66 3? 00 C0 73 ?? 66 2? 35 00 66 F7 ?? 1B ?? 	2? 80 0? 00 01 00 00 8B ?? 5? }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule XORDecodeA7 : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
		$a = {	8A [2] 	8B ??	34 A7 	46 88 ?? 83 ?? FF 33 ?? 4? F2 AE F7 ?? 	4? 3B ?? }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule DynamicAPILoading : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
		$a = {	83 C4 ?? 5? 5? 	FF 15 [4] 68 [4] A3 [4]	E8 [4]	83 C4 ?? 5? 5? 	FF 15 [4] 68 [4] A3 [4]	E8 [4] 83 C4 ?? 5?  5? 	FF 15 [4] 68 [4] A3 [4]	E8}

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule DNSCalcStyleEncodeAndDecode : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "975522bc3e07f7aa2c4a5457e6cc16c49a148b9f731134b8971983225835577e"

	strings:
		$a = {8A ?? 80 ?? ?? 80 ?? ?? 88 ?? 4? 4? 75 ?? }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule GenerateTLSClientHelloPacket_Test : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
		$a = {25 07 00 00 80 79 ?? 4? 	83 ?? F8 4? }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule RC4SboxKeyGen : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin"

	strings:
		$a = {	8A [3] 	8B ?? 	81 ?? 0F 00 00 80 79 ?? 4? 83 ?? F0 4? 	}

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule RandomTimestampGenerator : sharedcode hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin joanap baseline sample"

	strings:
		$a = {	66 81 [3] FE FF FF [1-4] 99 B9 0C 00 00 00 F7 [1-4] 42 	66 89 [3]  FF D6 99 B9 1C 00 00 00 F7 [1-4] 42 	66 89 [3] FF D6 99 B9 17 00 00 00 F7 [1-4] 42 66 89 [3] FF D6 99 B9 3B 00 00 00 F7 [1-4] 42 66 89 [3] FF D6 99 	B9 3B 00 00 00 	F7 }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

import "pe"

rule CPUInfoExtraction : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd10010_296fcc9d611ca1b8f8288192d6d854cf4072853010cc65cb0c7f958626999fbd.bin"

	strings:
		$a = {68 00 00 00 80 8B ?? 8B ?? 04 89 [3] 8B ?? 08 89 [3] 8B ?? 0C 8D [3] 89 [5] 5? 8B ?? 89 [5] E8 [4] 8B ?? 8B ?? 	3D 00 00 00 80 8B ?? 04 }

	condition:
		$a in ( ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset ) .. ( pe.sections [ pe.section_index ( ".text" ) ] . raw_data_offset + pe.sections [ pe.section_index ( ".text" ) ] . raw_data_size ) )
}

