rule malware_sakula_xorloop : hardened
{
	meta:
		description = "XOR loops from Sakula malware"
		author = "David Cannings"
		md5 = "fc6497fe708dbda9355139721b6181e7"
		date = "2016-06-13"
		modified = "2023-01-27"
		id = "9349b7e4-560c-5d8b-94d9-cbb9fd09e132"

	strings:
		$opcodes_decode_loop01 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }
		$opcodes_decode_loop02 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }

	condition:
		uint16( 0 ) == 0x5A4D and any of ( $opcodes* )
}

rule malware_sakula_memory : hardened
{
	meta:
		description = "Sakula malware - strings after unpacking (memory rule)"
		author = "David Cannings"
		md5 = "b3852b9e7f2b8954be447121bb6b65c3"
		id = "328e3707-d11d-5b7f-bec4-18a42a2c658b"

	strings:
		$str01 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 22 25 73 22}
		$str02 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 20 22 25 73 22 20 50 6c 61 79 20 22 25 73 22}
		$str03 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 2b 28 63 6f 6d 70 61 74 69 62 6c 65 3b 2b 4d 53 49 45 2b 38 2e 30 3b 2b 57 69 6e 64 6f 77 73 2b 4e 54 2b 35 2e 31 3b 2b 53 56 31 29}
		$str04 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6d 64 2e 65 78 65 20 2f 63 20 63 6d 64 2e 65 78 65 20 2f 63 20 63 6d 64 2e 65 78 65 20 2f 63 20 63 6d 64 2e 65 78 65 20 2f 63 20 63 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22}
		$str05 = {53 65 6c 66 20 50 72 6f 63 65 73 73 20 49 64 3a 25 64}
		$str06 = {25 64 5f 25 64 5f 25 64 5f 25 73}
		$str07 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 53 4c 43 43 32 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 35 2e 33 30 37 32 39 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 30 2e 33 30 37 32 39 3b 20 4d 65 64 69 61 20 43 65 6e 74 65 72 20 50 43 20 36 2e 30 29}
		$str08 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 20 22 25 73 22 20 41 63 74 69 76 65 51 76 61 77 20 22 25 73 22}
		$opcodes01 = { 83 F9 00 74 0E 31 C0 8A 03 D0 C0 34 ?? 88 03 49 43 EB ED }
		$opcodes02 = { 31 C0 8A 04 13 32 01 83 F8 00 75 0E 83 FA 00 74 04 49 4A }

	condition:
		4 of them
}

rule malware_sakula_shellcode : hardened
{
	meta:
		description = "Sakula shellcode - taken from decoded setup.msi but may not be unique enough to identify Sakula"
		author = "David Cannings"
		id = "147e4894-7877-5367-9f6b-588eb7f0379a"

	strings:
		$opcodes01 = { 55 89 E5 E8 00 00 00 00 58 83 C0 06 C9 C3 }
		$opcodes02 = { 8B 5E 3C 8B 5C 1E 78 8B 4C 1E 20 53 8B 5C 1E 24 01 F3 }

	condition:
		any of them
}

