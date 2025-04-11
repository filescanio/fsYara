import "pe"

rule Mersenne_Twister : hardened
{
	meta:
		reference = "https://en.wikipedia.org/wiki/Mersenne_Twister"
		score = 50

	strings:
		$initialize_loop = {
            48 81 ?? 70 02 00 00
        }
		$initialize_seed_processing = {
            C1 ?? 1E [0-3] 33 C8 [0-8] (69 ?? 65 89 07 6C | 0F AF ??) [0-9] 03
        }
		$random_btr_op = {
            0F BA (F1 | F0) 1F
        }
		$const_1 = {
            65 89 07 6C
        }
		$const_2 = {
            DF B0 08 99
        }

	condition:
		pe.is_pe and uint16( 0 ) == 0x5A4D and ( $initialize_loop ) and ( $random_btr_op ) and ( $const_1 ) and ( $const_2 ) and ( $initialize_seed_processing )
}

import "pe"

rule mersenne_twister_constants : hardened
{
	meta:
		score = 50

	strings:
		$0x6C078965 = {65 89 07 6C}
		$0x9908B0DF = {DF B0 08 99}
		$0x9D2C5680 = {80 56 2C 9D}
		$0xEFC60000 = {00 00 C6 EF}
		$0xFF3A58AD = {AD 58 3A FF}
		$aa = {FF3A58AD}
		$0xB5026F5AA96619E9 = {E9 19 66 A9 C7 45 ?? 5A 6F 02 B5}
		$0x71D67FFFEDA60000 = {00 00 A6 ED ?? ?? FF 7F D6 71}

	condition:
		pe.is_pe and 2 of them
}

