rule SUSP_XORed_Mozilla : hardened limited
{
	meta:
		description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
		author = "Florian Roth"
		reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
		date = "2019-10-28"
		modified = "2023-11-25"
		score = 65
		id = "af7fc551-0d4e-589e-9152-95d9c4ab03bf"

	strings:
		$xo1 = {((4d 6f 7a 69 6c 6c 61 2f 35 2e 30) | (4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00))}
		$fp1 = {53 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 20 00 4c 00 61 00 62 00 73 00}
		$fp2 = {3c 66 69 6c 74 65 72 20 6f 62 6a 65 63 74 20 61 74}

	condition:
		$xo1 and not 1 of ( $fp* ) and not uint32( 0 ) == 0x434d5953
}

rule SUSP_XORed_MSDOS_Stub_Message : hardened limited
{
	meta:
		description = "Detects suspicious XORed MSDOS stub message"
		author = "Florian Roth"
		reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
		date = "2019-10-28"
		modified = "2023-10-11"
		score = 55
		id = "9ab52434-9162-5fd5-bf34-8b163f6aeec4"

	strings:
		$xo1 = {((54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65) | (54 00 68 00 69 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 72 00 75 00 6e 00 20 00 69 00 6e 00 20 00 44 00 4f 00 53 00 20 00 6d 00 6f 00 64 00 65 00))}
		$xo2 = {((54 68 69 73 20 70 72 6f 67 72 61 6d 20 6d 75 73 74 20 62 65 20 72 75 6e 20 75 6e 64 65 72 20 57 69 6e 33 32) | (54 00 68 00 69 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 6d 00 75 00 73 00 74 00 20 00 62 00 65 00 20 00 72 00 75 00 6e 00 20 00 75 00 6e 00 64 00 65 00 72 00 20 00 57 00 69 00 6e 00 33 00 32 00))}
		$fp1 = {((41 56 41 53 54 20 53 6f 66 74 77 61 72 65) | (41 00 56 00 41 00 53 00 54 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00))}
		$fp2 = {((41 56 47 20 4e 65 74 68 65 72 6c 61 6e 64 73) | (41 00 56 00 47 00 20 00 4e 00 65 00 74 00 68 00 65 00 72 00 6c 00 61 00 6e 00 64 00 73 00))}
		$fp3 = {((41 56 47 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73) | (41 00 56 00 47 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00))}
		$fp4 = {4d 00 61 00 6c 00 69 00 63 00 69 00 6f 00 75 00 73 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 52 00 65 00 6d 00 6f 00 76 00 61 00 6c 00 20 00 54 00 6f 00 6f 00 6c 00}
		$fp5 = {((4d 63 41 66 65 65 20 4c 61 62 73) | (4d 00 63 00 41 00 66 00 65 00 65 00 20 00 4c 00 61 00 62 00 73 00))}
		$fp6 = {((4b 61 73 70 65 72 73 6b 79 20 4c 61 62) | (4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 20 00 4c 00 61 00 62 00))}
		$fp7 = {((3c 70 72 6f 70 65 72 74 69 65 73 6d 61 70 3e) | (3c 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 6d 00 61 00 70 00 3e 00))}
		$fp10 = {41 00 76 00 69 00 72 00 61 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00}
		$fp11 = {73 00 79 00 6e 00 74 00 65 00 76 00 6f 00 20 00 47 00 6d 00 62 00 48 00}
		$fp13 = {53 6f 70 68 6f 73 43 6c 65 61 6e}
		$fp14 = {53 00 6f 00 70 00 68 00 6f 00 73 00 48 00 6f 00 6d 00 65 00 43 00 6c 00 65 00 61 00 6e 00}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* ) and not uint16( 0 ) == 0xb0b0 and not uint16( 0 ) == 0x5953
}

