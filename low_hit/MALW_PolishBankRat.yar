rule PolishBankRAT_srservice_xorloop : hardened
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Finds the custom xor decode loop for <PolishBankRAT_srservice>"

	strings:
		$loop = { 48 8B CD E8 60 FF FF FF 48 FF C3 32 44 1E FF 48 FF CF 88 43 FF }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $loop
}

rule PolishBankRAT_fdsvc_xor_loop : hardened
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Finds the custom xor decode loop for <PolishBankRAT_fdsvc>"

	strings:
		$loop = {0F B6 42 FF 48 8D 52 FF 30 42 01 FF CF 75 F1}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $loop
}

rule PolishBankRAT_fdsvc_decode2 : hardened
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Find a constant used as part of a payload decoding function in PolishBankRAT_fdsvc"

	strings:
		$part1 = {A6 EB 96}
		$part2 = {61 B2 E2 EF}
		$part3 = {0D CB E8 C4}
		$part4 = {5A F1 66 9C}
		$part5 = {A4 80 CD 9A}
		$part6 = {F1 2F 46 25}
		$part7 = {2F DB 16 26}
		$part8 = {4B C4 3F 3C}
		$str1 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule decoded_PolishBankRAT_fdsvc_strings : hardened
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Finds hard coded strings in PolishBankRAT_fdsvc"

	strings:
		$str1 = {((73 73 79 6c 6b 61) | (73 00 73 00 79 00 6c 00 6b 00 61 00))}
		$str2 = {((75 73 74 61 6e 61 76 6c 69 76 61 74) | (75 00 73 00 74 00 61 00 6e 00 61 00 76 00 6c 00 69 00 76 00 61 00 74 00))}
		$str3 = {((70 6f 6c 75 63 68 69 74) | (70 00 6f 00 6c 00 75 00 63 00 68 00 69 00 74 00))}
		$str4 = {((70 65 72 65 73 6c 61 74) | (70 00 65 00 72 00 65 00 73 00 6c 00 61 00 74 00))}
		$str5 = {((64 65 72 7a 68 61 74) | (64 00 65 00 72 00 7a 00 68 00 61 00 74 00))}
		$str6 = {((76 79 6b 68 6f 64 69 74) | (76 00 79 00 6b 00 68 00 6f 00 64 00 69 00 74 00))}
		$str7 = {((4e 61 63 68 61 6c 6f) | (4e 00 61 00 63 00 68 00 61 00 6c 00 6f 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and 4 of ( $str* )
}

