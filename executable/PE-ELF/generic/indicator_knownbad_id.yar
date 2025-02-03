rule INDICATOR_KB_ID_BazarLoader : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects Bazar executables with specific email addresses found in the code signing certificate"

	strings:
		$s1 = {((73 6b 61 72 61 62 65 79 6c 6c 63 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 6b 00 61 00 72 00 61 00 62 00 65 00 79 00 6c 00 6c 00 63 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((61 64 6d 69 6e 40 69 6e 74 65 6c 6c 2d 69 74 2e 72 75) | (61 00 64 00 6d 00 69 00 6e 00 40 00 69 00 6e 00 74 00 65 00 6c 00 6c 00 2d 00 69 00 74 00 2e 00 72 00 75 00))}
		$s3 = {((73 75 70 70 6f 72 74 40 70 72 6f 2d 6b 6f 6e 2e 72 75) | (73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 70 00 72 00 6f 00 2d 00 6b 00 6f 00 6e 00 2e 00 72 00 75 00))}

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule INDICATOR_KB_ID_QakBot : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects QakBot executables with specific email addresses found in the code signing certificate"

	strings:
		$s1 = {((68 75 74 74 65 72 2e 73 39 34 40 79 61 68 6f 6f 2e 63 6f 6d) | (68 00 75 00 74 00 74 00 65 00 72 00 2e 00 73 00 39 00 34 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((61 6e 64 72 65 6a 2e 76 72 65 61 72 40 61 6f 6c 2e 63 6f 6d) | (61 00 6e 00 64 00 72 00 65 00 6a 00 2e 00 76 00 72 00 65 00 61 00 72 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((6b 6c 61 75 73 2e 70 65 64 65 72 73 65 6e 40 61 6f 6c 2e 63 6f 6d) | (6b 00 6c 00 61 00 75 00 73 00 2e 00 70 00 65 00 64 00 65 00 72 00 73 00 65 00 6e 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((61 2e 73 70 65 6e 64 6c 40 61 6f 6c 2e 63 6f 6d) | (61 00 2e 00 73 00 70 00 65 00 6e 00 64 00 6c 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((6d 6a 65 6d 65 63 40 61 6f 6c 2e 63 6f 6d) | (6d 00 6a 00 65 00 6d 00 65 00 63 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((72 6f 62 65 72 74 2e 73 69 6a 61 6e 65 63 40 79 61 68 6f 6f 2e 63 6f 6d) | (72 00 6f 00 62 00 65 00 72 00 74 00 2e 00 73 00 69 00 6a 00 61 00 6e 00 65 00 63 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((6d 69 74 6a 61 2e 76 69 64 6f 76 69 40 61 6f 6c 2e 63 6f 6d) | (6d 00 69 00 74 00 6a 00 61 00 2e 00 76 00 69 00 64 00 6f 00 76 00 69 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule INDICATOR_KB_ID_Amadey : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects Amadey executables with specific email addresses found in the code signing certificate"

	strings:
		$s1 = {((74 6f 63 68 6b 61 2e 64 69 72 65 63 74 6f 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (74 00 6f 00 63 00 68 00 6b 00 61 00 2e 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule INDICATOR_KB_ID_UNK01 : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects Amadey executables with specific email addresses found in the code signing certificate"
		hash1 = "37d08a64868c35c5bae8f5155cc669486590951ea80dd9da61ec38defb89a146"

	strings:
		$s1 = {((65 74 69 65 6e 6e 65 40 74 65 74 72 61 63 65 72 6f 75 73 2e 62 72) | (65 00 74 00 69 00 65 00 6e 00 6e 00 65 00 40 00 74 00 65 00 74 00 72 00 61 00 63 00 65 00 72 00 6f 00 75 00 73 00 2e 00 62 00 72 00))}

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule INDICATOR_KB_ID_Ransomware_LockerGoga : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with LockerGoga ransomware"

	strings:
		$s1 = {((61 62 62 73 63 68 65 76 69 73 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (61 00 62 00 62 00 73 00 63 00 68 00 65 00 76 00 69 00 73 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((61 70 65 72 79 77 73 71 61 72 6f 63 69 40 6f 32 2e 70 6c) | (61 00 70 00 65 00 72 00 79 00 77 00 73 00 71 00 61 00 72 00 6f 00 63 00 69 00 40 00 6f 00 32 00 2e 00 70 00 6c 00))}
		$s3 = {((61 73 75 78 69 64 6f 72 75 72 61 65 70 31 39 39 39 40 6f 32 2e 70 6c) | (61 00 73 00 75 00 78 00 69 00 64 00 6f 00 72 00 75 00 72 00 61 00 65 00 70 00 31 00 39 00 39 00 39 00 40 00 6f 00 32 00 2e 00 70 00 6c 00))}
		$s4 = {((64 68 61 72 6d 61 70 61 72 72 61 63 6b 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (64 00 68 00 61 00 72 00 6d 00 61 00 70 00 61 00 72 00 72 00 61 00 63 00 6b 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((69 6a 75 71 6f 64 69 73 75 6e 6f 76 69 62 39 38 40 6f 32 2e 70 6c) | (69 00 6a 00 75 00 71 00 6f 00 64 00 69 00 73 00 75 00 6e 00 6f 00 76 00 69 00 62 00 39 00 38 00 40 00 6f 00 32 00 2e 00 70 00 6c 00))}
		$s6 = {((6d 61 79 61 72 63 68 65 6e 6f 74 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6d 00 61 00 79 00 61 00 72 00 63 00 68 00 65 00 6e 00 6f 00 74 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((6d 69 6b 6c 6c 69 6d 69 74 65 64 73 40 67 6d 61 69 6c 2e 63 6f 6d 30) | (6d 00 69 00 6b 00 6c 00 6c 00 69 00 6d 00 69 00 74 00 65 00 64 00 73 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 30 00))}
		$s8 = {((70 68 61 6e 74 68 61 76 6f 6e 67 73 61 6e 65 76 65 79 61 68 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (70 00 68 00 61 00 6e 00 74 00 68 00 61 00 76 00 6f 00 6e 00 67 00 73 00 61 00 6e 00 65 00 76 00 65 00 79 00 61 00 68 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s9 = {((71 69 63 69 66 6f 6d 75 65 6a 69 6a 69 6b 61 40 6f 32 2e 70 6c) | (71 00 69 00 63 00 69 00 66 00 6f 00 6d 00 75 00 65 00 6a 00 69 00 6a 00 69 00 6b 00 61 00 40 00 6f 00 32 00 2e 00 70 00 6c 00))}
		$s10 = {((72 65 7a 61 77 79 72 65 65 64 69 70 69 31 39 39 38 40 6f 32 2e 70 6c) | (72 00 65 00 7a 00 61 00 77 00 79 00 72 00 65 00 65 00 64 00 69 00 70 00 69 00 31 00 39 00 39 00 38 00 40 00 6f 00 32 00 2e 00 70 00 6c 00))}
		$s11 = {((73 61 79 61 6e 77 61 6c 73 77 6f 72 74 68 39 36 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (73 00 61 00 79 00 61 00 6e 00 77 00 61 00 6c 00 73 00 77 00 6f 00 72 00 74 00 68 00 39 00 36 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s12 = {((73 75 7a 75 6d 63 70 68 65 72 73 6f 6e 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (73 00 75 00 7a 00 75 00 6d 00 63 00 70 00 68 00 65 00 72 00 73 00 6f 00 6e 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s13 = {((77 79 61 74 74 70 65 74 74 69 67 72 65 77 38 39 32 32 35 35 35 40 6d 61 69 6c 2e 63 6f 6d) | (77 00 79 00 61 00 74 00 74 00 70 00 65 00 74 00 74 00 69 00 67 00 72 00 65 00 77 00 38 00 39 00 32 00 32 00 35 00 35 00 35 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_GoldenAxe : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with GoldenAxe ransomware"

	strings:
		$s1 = {((78 78 62 61 63 6b 40 6b 65 65 6d 61 69 6c 2e 6d 65) | (78 00 78 00 62 00 61 00 63 00 6b 00 40 00 6b 00 65 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 6d 00 65 00))}
		$s2 = {((64 61 72 6b 75 73 6d 62 61 63 6b 75 70 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (64 00 61 00 72 00 6b 00 75 00 73 00 6d 00 62 00 61 00 63 00 6b 00 75 00 70 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_GetCrypt : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with GetCrypt ransomware"

	strings:
		$s1 = {((67 65 74 63 72 79 70 74 40 63 6f 63 6b 2e 6c 69) | (67 00 65 00 74 00 63 00 72 00 79 00 70 00 74 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s2 = {((63 72 79 70 74 67 65 74 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (63 00 72 00 79 00 70 00 74 00 67 00 65 00 74 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((63 72 79 70 74 67 65 74 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (63 00 72 00 79 00 70 00 74 00 67 00 65 00 74 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((6f 66 66 74 69 74 61 6e 40 70 6d 2e 6d 65) | (6f 00 66 00 66 00 74 00 69 00 74 00 61 00 6e 00 40 00 70 00 6d 00 2e 00 6d 00 65 00))}
		$s5 = {((6f 66 66 74 69 74 61 6e 40 63 6f 63 6b 2e 6c 69) | (6f 00 66 00 66 00 74 00 69 00 74 00 61 00 6e 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s6 = {((75 6e 34 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (75 00 6e 00 34 00 32 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_CryptoMix : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with CryptoMix ransomware"

	strings:
		$s1 = {((70 6f 72 74 73 74 61 74 72 65 6c 65 61 31 39 38 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 6f 6d) | (70 00 6f 00 72 00 74 00 73 00 74 00 61 00 74 00 72 00 65 00 6c 00 65 00 61 00 31 00 39 00 38 00 32 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 6d 00))}
		$s2 = {((75 6e 6c 6f 63 6b 40 65 71 61 6c 74 65 63 68 2e 73 75) | (75 00 6e 00 6c 00 6f 00 63 00 6b 00 40 00 65 00 71 00 61 00 6c 00 74 00 65 00 63 00 68 00 2e 00 73 00 75 00))}
		$s3 = {((75 6e 6c 6f 63 6b 40 72 6f 79 61 6c 6d 61 69 6c 2e 73 75) | (75 00 6e 00 6c 00 6f 00 63 00 6b 00 40 00 72 00 6f 00 79 00 61 00 6c 00 6d 00 61 00 69 00 6c 00 2e 00 73 00 75 00))}
		$s4 = {((61 64 65 78 73 69 6e 32 37 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (61 00 64 00 65 00 78 00 73 00 69 00 6e 00 32 00 37 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((6e 62 61 63 74 6f 63 65 70 6e 79 6f 75 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6e 00 62 00 61 00 63 00 74 00 6f 00 63 00 65 00 70 00 6e 00 79 00 6f 00 75 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((6e 75 6e 6c 6f 63 6b 40 65 71 61 6c 74 65 63 68 2e 73 75) | (6e 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 40 00 65 00 71 00 61 00 6c 00 74 00 65 00 63 00 68 00 2e 00 73 00 75 00))}
		$s7 = {((6e 73 6e 6c 6f 63 6b 40 72 6f 79 61 6c 6d 61 69 6c 2e 73 75) | (6e 00 73 00 6e 00 6c 00 6f 00 63 00 6b 00 40 00 72 00 6f 00 79 00 61 00 6c 00 6d 00 61 00 69 00 6c 00 2e 00 73 00 75 00))}
		$s8 = {((63 65 72 73 69 61 63 73 6f 66 61 6c 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (63 00 65 00 72 00 73 00 69 00 61 00 63 00 73 00 6f 00 66 00 61 00 6c 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Buran : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Buran ransomware"

	strings:
		$s1 = {((72 65 63 6f 76 65 72 79 5f 73 65 72 76 65 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 5f 00 73 00 65 00 72 00 76 00 65 00 72 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((72 65 63 6f 76 65 72 79 31 73 65 72 76 65 72 40 63 6f 63 6b 2e 6c 69) | (72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 31 00 73 00 65 00 72 00 76 00 65 00 72 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s3 = {((70 6f 6c 73 73 68 31 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (70 00 6f 00 6c 00 73 00 73 00 68 00 31 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((70 6f 6c 73 73 68 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (70 00 6f 00 6c 00 73 00 73 00 68 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((62 75 72 61 6e 73 75 70 70 6f 72 74 40 65 78 70 6c 6f 69 74 2e 69 6d) | (62 00 75 00 72 00 61 00 6e 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 2e 00 69 00 6d 00))}
		$s6 = {((62 75 72 61 6e 73 75 70 70 6f 72 74 40 78 6d 70 70 2e 6a 70) | (62 00 75 00 72 00 61 00 6e 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 78 00 6d 00 70 00 70 00 2e 00 6a 00 70 00))}
		$s7 = {((6a 61 63 6b 73 74 65 61 6d 32 30 31 38 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6a 00 61 00 63 00 6b 00 73 00 74 00 65 00 61 00 6d 00 32 00 30 00 31 00 38 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s8 = {((6e 6f 74 65 73 74 65 61 6d 32 30 31 38 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (6e 00 6f 00 74 00 65 00 73 00 74 00 65 00 61 00 6d 00 32 00 30 00 31 00 38 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_RansomwareEXX : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with RansomwareEXX Linux ransomware"

	strings:
		$s1 = {((66 72 61 6e 63 65 2e 65 69 67 73 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (66 00 72 00 61 00 6e 00 63 00 65 00 2e 00 65 00 69 00 67 00 73 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Phobos : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Phobos ransomware"

	strings:
		$s1 = {((68 65 6c 70 72 65 63 6f 76 65 72 40 66 6f 78 6d 61 69 6c 2e 63 6f 6d) | (68 00 65 00 6c 00 70 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 40 00 66 00 6f 00 78 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((72 65 63 6f 76 65 72 68 65 6c 70 32 30 32 30 40 74 68 65 73 65 63 75 72 65 2e 62 69 7a) | (72 00 65 00 63 00 6f 00 76 00 65 00 72 00 68 00 65 00 6c 00 70 00 32 00 30 00 32 00 30 00 40 00 74 00 68 00 65 00 73 00 65 00 63 00 75 00 72 00 65 00 2e 00 62 00 69 00 7a 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Epsilon : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Epsilon ransomware"

	strings:
		$s1 = {((6e 65 66 74 65 74 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (6e 00 65 00 66 00 74 00 65 00 74 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Thanos : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Thanos ransomware"

	strings:
		$s1 = {((6d 79 2d 63 6f 6e 74 61 63 74 2d 65 6d 61 69 6c 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6d 00 79 00 2d 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 2d 00 65 00 6d 00 61 00 69 00 6c 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((67 65 74 2d 6d 79 2d 64 61 74 61 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (67 00 65 00 74 00 2d 00 6d 00 79 00 2d 00 64 00 61 00 74 00 61 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Vovalex : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Vovalex ransomware"

	strings:
		$s1 = {((76 6f 76 61 6e 61 6e 64 6c 65 78 75 73 40 63 6f 63 6b 2e 6c 69) | (76 00 6f 00 76 00 61 00 6e 00 61 00 6e 00 64 00 6c 00 65 00 78 00 75 00 73 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_AlumniLocker : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with AlumniLocker ransomware"

	strings:
		$s1 = {((61 6c 75 6d 6e 69 6c 6f 63 6b 65 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (61 00 6c 00 75 00 6d 00 6e 00 69 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_DoejoCrypt : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with DoejoCrypt ransomware"

	strings:
		$s1 = {((6b 6f 6e 65 64 69 65 79 70 40 61 69 72 6d 61 69 6c 2e 63 63) | (6b 00 6f 00 6e 00 65 00 64 00 69 00 65 00 79 00 70 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}
		$s2 = {((75 65 6e 77 6f 6e 6b 65 6e 40 6d 65 6d 61 69 6c 2e 63 6f 6d) | (75 00 65 00 6e 00 77 00 6f 00 6e 00 6b 00 65 00 6e 00 40 00 6d 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Purge : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Purge ransomware"

	strings:
		$s1 = {((72 73 63 6c 40 64 72 2e 63 6f 6d) | (72 00 73 00 63 00 6c 00 40 00 64 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((72 73 63 6c 40 75 73 61 2e 63 6f 6d) | (72 00 73 00 63 00 6c 00 40 00 75 00 73 00 61 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Zeoticus : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Zeoticus ransomware"

	strings:
		$s1 = {((61 6e 6f 62 74 61 6e 69 75 6d 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (61 00 6e 00 6f 00 62 00 74 00 61 00 6e 00 69 00 75 00 6d 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((61 6e 6f 62 74 61 6e 69 75 6d 40 63 6f 63 6b 2e 6c 69) | (61 00 6e 00 6f 00 62 00 74 00 61 00 6e 00 69 00 75 00 6d 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_JobCryptor : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with JobCryptor ransomware"

	strings:
		$s1 = {((6f 6c 61 67 67 6f 75 6e 65 32 33 35 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68) | (6f 00 6c 00 61 00 67 00 67 00 6f 00 75 00 6e 00 65 00 32 00 33 00 35 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 68 00))}
		$s2 = {((6f 75 61 72 64 69 61 31 31 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (6f 00 75 00 61 00 72 00 64 00 69 00 61 00 31 00 31 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((6c 61 67 67 6f 75 6e 65 6f 31 31 40 67 6d 61 69 6c 2e 63 6f 6d) | (6c 00 61 00 67 00 67 00 6f 00 75 00 6e 00 65 00 6f 00 31 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Cuba : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with JobCryptor ransomware"

	strings:
		$s1 = {((68 65 6c 70 61 64 6d 69 6e 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (68 00 65 00 6c 00 70 00 61 00 64 00 6d 00 69 00 6e 00 32 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((68 65 6c 70 61 64 6d 69 6e 32 40 63 6f 63 6b 2e 6c 69) | (68 00 65 00 6c 00 70 00 61 00 64 00 6d 00 69 00 6e 00 32 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s3 = {((6d 66 72 61 40 63 6f 63 6b 2e 6c 69) | (6d 00 66 00 72 00 61 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s4 = {((61 64 6d 69 6e 40 63 75 62 61 2d 73 75 70 70 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 63 00 75 00 62 00 61 00 2d 00 73 00 75 00 70 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((63 75 62 61 5f 73 75 70 70 6f 72 74 40 65 78 70 6c 6f 69 74 2e 69 6d) | (63 00 75 00 62 00 61 00 5f 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 2e 00 69 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Hello : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Hello / WickrMe ransomware"

	strings:
		$s1 = {((65 6d 6d 69 6e 67 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (65 00 6d 00 6d 00 69 00 6e 00 67 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((61 6d 70 62 65 6c 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (61 00 6d 00 70 00 62 00 65 00 6c 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((61 73 61 75 72 69 62 65 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (61 00 73 00 61 00 75 00 72 00 69 00 62 00 65 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((63 61 6e 64 69 65 74 6f 64 64 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (63 00 61 00 6e 00 64 00 69 00 65 00 74 00 6f 00 64 00 64 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((6b 65 6c 6c 79 72 65 69 66 66 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (6b 00 65 00 6c 00 6c 00 79 00 72 00 65 00 69 00 66 00 66 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((6b 65 76 69 6e 64 65 6c 6f 61 63 68 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6b 00 65 00 76 00 69 00 6e 00 64 00 65 00 6c 00 6f 00 61 00 63 00 68 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((73 68 65 69 6c 61 62 65 61 73 6c 65 79 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (73 00 68 00 65 00 69 00 6c 00 61 00 62 00 65 00 61 00 73 00 6c 00 65 00 79 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_UnlockYourFiles : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with UnlockYourFiles ransomware"

	strings:
		$s1 = {((34 6c 6f 6b 33 72 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (34 00 6c 00 6f 00 6b 00 33 00 72 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((34 6c 6f 6b 33 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (34 00 6c 00 6f 00 6b 00 33 00 72 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_DarkSide : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with DarkSide ransomware"
		hash1 = "bafa2efff234303166d663f967037dae43701e7d63d914efc8c894b3e5be9408"

	strings:
		$s1 = {((62 72 65 61 74 68 63 6f 6a 75 6e 6b 74 61 62 31 39 38 37 40 79 61 68 6f 6f 2e 63 6f 6d) | (62 00 72 00 65 00 61 00 74 00 68 00 63 00 6f 00 6a 00 75 00 6e 00 6b 00 74 00 61 00 62 00 31 00 39 00 38 00 37 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Spyro : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Spyro ransomware"

	strings:
		$s1 = {((62 6c 61 63 6b 73 70 79 72 6f 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (62 00 6c 00 61 00 63 00 6b 00 73 00 70 00 79 00 72 00 6f 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((62 6c 61 63 6b 73 70 79 72 6f 40 6d 61 69 6c 66 65 6e 63 65 2e 63 6f 6d) | (62 00 6c 00 61 00 63 00 6b 00 73 00 70 00 79 00 72 00 6f 00 40 00 6d 00 61 00 69 00 6c 00 66 00 65 00 6e 00 63 00 65 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Ryzerlo : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Ryzerlo / HiddenTear / RSJON ransomware"

	strings:
		$s1 = {((64 61 72 6b 6a 6f 6e 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (64 00 61 00 72 00 6b 00 6a 00 6f 00 6e 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_PYSA : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with PYSA / Mespinoza ransomware"

	strings:
		$s1 = {((6c 75 65 62 65 67 67 38 30 32 34 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (6c 00 75 00 65 00 62 00 65 00 67 00 67 00 38 00 30 00 32 00 34 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s2 = {((6d 61 79 61 6b 69 6e 67 67 77 33 37 33 32 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (6d 00 61 00 79 00 61 00 6b 00 69 00 6e 00 67 00 67 00 77 00 33 00 37 00 33 00 32 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s3 = {((6c 61 75 72 69 61 62 6f 72 6e 68 61 74 37 37 32 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6c 00 61 00 75 00 72 00 69 00 61 00 62 00 6f 00 72 00 6e 00 68 00 61 00 74 00 37 00 37 00 32 00 32 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((44 65 62 6f 72 61 68 54 72 61 73 6b 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (44 00 65 00 62 00 6f 00 72 00 61 00 68 00 54 00 72 00 61 00 73 00 6b 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s5 = {((41 6c 69 73 6f 6e 52 6f 62 6c 65 73 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (41 00 6c 00 69 00 73 00 6f 00 6e 00 52 00 6f 00 62 00 6c 00 65 00 73 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s6 = {((4e 61 74 61 6e 53 63 68 75 6c 74 7a 36 37 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (4e 00 61 00 74 00 61 00 6e 00 53 00 63 00 68 00 75 00 6c 00 74 00 7a 00 36 00 37 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((6a 6f 6e 69 6b 65 6d 70 70 69 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (6a 00 6f 00 6e 00 69 00 6b 00 65 00 6d 00 70 00 70 00 69 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s8 = {((6c 61 6e 65 72 6f 73 61 6c 69 65 34 39 30 30 33 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (6c 00 61 00 6e 00 65 00 72 00 6f 00 73 00 61 00 6c 00 69 00 65 00 34 00 39 00 30 00 30 00 33 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s9 = {((62 65 72 6e 61 6c 6d 61 72 67 61 72 65 74 36 34 35 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (62 00 65 00 72 00 6e 00 61 00 6c 00 6d 00 61 00 72 00 67 00 61 00 72 00 65 00 74 00 36 00 34 00 35 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s10 = {((63 61 72 6c 68 75 62 62 61 72 64 32 30 32 31 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (63 00 61 00 72 00 6c 00 68 00 75 00 62 00 62 00 61 00 72 00 64 00 32 00 30 00 32 00 31 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$u1 = {((68 74 74 70 3a 2f 2f 70 79 73 61 32 62 69 74 63) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 79 00 73 00 61 00 32 00 62 00 69 00 74 00 63 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_MedusaLocker : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with MedusaLocker ransomware"

	strings:
		$s1 = {((69 74 68 65 6c 70 6e 65 74 77 6f 72 6b 40 64 65 63 6f 72 6f 75 73 2e 63 79 6f 75) | (69 00 74 00 68 00 65 00 6c 00 70 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 40 00 64 00 65 00 63 00 6f 00 72 00 6f 00 75 00 73 00 2e 00 63 00 79 00 6f 00 75 00))}
		$s2 = {((69 74 68 65 6c 70 6e 65 74 77 6f 72 6b 40 77 68 6f 6c 65 6e 65 73 73 2e 62 75 73 69 6e 65 73 73) | (69 00 74 00 68 00 65 00 6c 00 70 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 40 00 77 00 68 00 6f 00 6c 00 65 00 6e 00 65 00 73 00 73 00 2e 00 62 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00))}
		$s3 = {((69 74 68 65 6c 70 6e 65 74 77 6f 72 6b 40) | (69 00 74 00 68 00 65 00 6c 00 70 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 40 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_RanzyLocker : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with RanzyLocker ransomware"

	strings:
		$s1 = {((65 76 69 6c 75 73 65 72 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (65 00 76 00 69 00 6c 00 75 00 73 00 65 00 72 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((65 76 69 6c 70 72 30 74 6f 6e 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (65 00 76 00 69 00 6c 00 70 00 72 00 30 00 74 00 6f 00 6e 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_AlKhal : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with AlKhal ransomware"

	strings:
		$s1 = {((61 6c 6b 68 61 6c 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (61 00 6c 00 6b 00 68 00 61 00 6c 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((63 79 72 69 6c 67 61 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (63 00 79 00 72 00 69 00 6c 00 67 00 61 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_DECAF : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with DECAF ransomware"

	strings:
		$s1 = {((32 32 65 62 36 38 37 34 37 35 66 32 63 35 63 61 33 30 62 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (32 00 32 00 65 00 62 00 36 00 38 00 37 00 34 00 37 00 35 00 66 00 32 00 63 00 35 00 63 00 61 00 33 00 30 00 62 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = { 4d 49 49 42 43 67 4b 43 41 51 45 41 71 34 6b 31
                48 64 62 31 54 48 72 7a 42 42 65 4f 31 38 34 6b
                6e 43 62 42 4b 72 30 33 61 70 66 58 71 6c 4f 6b
                53 64 74 48 53 4a 67 66 79 49 71 4a 50 47 78 6c
                0a 2f 63 46 69 73 4a 6d 56 58 52 33 2f 74 34 65
                39 46 62 4c 73 45 49 75 54 70 39 50 4a 54 63 69
                6f 6d 48 66 72 35 43 67 43 51 7a 68 6e 41 5a 30
                41 76 6a 47 42 61 57 50 36 4b 70 43 79 66 44 6e
                73 0a 79 62 72 75 79 4b 71 79 67 61 57 70 5a 53
                41 6e 7a 52 64 42 2b 54 41 6b 75 35 69 71 79 38
                71 31 56 77 6e 4e 35 37 51 42 6c 74 72 6f 30 59
                4a 5a 38 65 6e 4b 5a 52 54 6c 63 7a 6d 74 6a 65
                4f 70 0a 42 2f 78 75 54 4f 75 44 6a 6d 55 53 4e
                69 47 79 69 6a 57 42 56 66 59 6b 37 73 56 58 6c
                2f 6c 51 38 74 61 58 72 33 36 78 50 57 68 4d 49
                47 30 45 71 52 56 72 46 56 2b 63 61 76 53 37 5a
                34 76 61 0a 79 58 6d 63 66 35 35 4e 6b 70 4d 47
                4b 4b 59 38 75 71 76 77 62 34 61 4c 49 4b 61 62
                65 6b 32 6e 55 57 42 67 4e 67 53 4f 74 71 42 4c
                4c 4c 32 41 32 62 59 2f 35 73 30 47 4a 2f 56 56
                2b 45 6d 49 0a 58 37 2f 7a 49 2b 46 63 65 55 2b
                64 63 4e 58 2f 69 72 30 75 6a 50 34 79 73 34 6d
                2f 6a 6a 5a 44 34 77 49 44 41 51 41 42 }

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Babuk : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Babuk ransomware"

	strings:
		$s1 = {((6d 69 74 6e 69 63 6b 64 40 63 74 65 6d 70 6c 61 72 2e 63 6f 6d) | (6d 00 69 00 74 00 6e 00 69 00 63 00 6b 00 64 00 40 00 63 00 74 00 65 00 6d 00 70 00 6c 00 61 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((7a 61 72 38 62 40 74 75 74 61 2e 69 6f) | (7a 00 61 00 72 00 38 00 62 00 40 00 74 00 75 00 74 00 61 00 2e 00 69 00 6f 00))}
		$s3 = {((72 65 63 6f 76 65 72 33 30 30 64 6f 6c 6c 61 72 73 40 67 6d 61 69 6c 2e 63 6f 6d) | (72 00 65 00 63 00 6f 00 76 00 65 00 72 00 33 00 30 00 30 00 64 00 6f 00 6c 00 6c 00 61 00 72 00 73 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((73 75 70 70 6f 72 74 2e 33 33 33 30 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 75 00 70 00 70 00 6f 00 72 00 74 00 2e 00 33 00 33 00 33 00 30 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((64 65 63 72 79 70 74 64 65 6c 74 61 40 67 6d 61 69 6c 2e 63 6f 6d) | (64 00 65 00 63 00 72 00 79 00 70 00 74 00 64 00 65 00 6c 00 74 00 61 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((70 79 6f 74 72 6d 61 6b 73 69 6d 40 67 6d 61 69 6c 2e 63 6f 6d) | (70 00 79 00 6f 00 74 00 72 00 6d 00 61 00 6b 00 73 00 69 00 6d 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((72 65 74 72 69 65 76 65 64 61 74 61 33 30 30 40 67 6d 61 69 6c 2e 63 6f 6d) | (72 00 65 00 74 00 72 00 69 00 65 00 76 00 65 00 64 00 61 00 74 00 61 00 33 00 30 00 30 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s8 = {((33 4a 47 33 36 4b 59 36 61 62 5a 54 6e 48 42 64 51 43 6f 6e 31 68 68 65 43 33 57 61 32 62 64 79 71 73) | (33 00 4a 00 47 00 33 00 36 00 4b 00 59 00 36 00 61 00 62 00 5a 00 54 00 6e 00 48 00 42 00 64 00 51 00 43 00 6f 00 6e 00 31 00 68 00 68 00 65 00 43 00 33 00 57 00 61 00 32 00 62 00 64 00 79 00 71 00 73 00))}
		$s9 = {((34 36 7a 64 5a 56 52 6a 6d 39 58 4a 68 64 6a 70 69 70 77 74 59 44 59 35 31 4e 4b 62 44 37 34 62 66 45 66 66 78 6d 62 71 50 6a 77 48 36 65 66 54 59 72 74 76 62 55 35 45 74 34 41 4b 43 72 65 39 4d 65 69 71 74 69 52 35 31 4c 76 67 32 58 38 64 58 76 31 74 50 37 6e 78 4c 61 45 48 4b 4b 51) | (34 00 36 00 7a 00 64 00 5a 00 56 00 52 00 6a 00 6d 00 39 00 58 00 4a 00 68 00 64 00 6a 00 70 00 69 00 70 00 77 00 74 00 59 00 44 00 59 00 35 00 31 00 4e 00 4b 00 62 00 44 00 37 00 34 00 62 00 66 00 45 00 66 00 66 00 78 00 6d 00 62 00 71 00 50 00 6a 00 77 00 48 00 36 00 65 00 66 00 54 00 59 00 72 00 74 00 76 00 62 00 55 00 35 00 45 00 74 00 34 00 41 00 4b 00 43 00 72 00 65 00 39 00 4d 00 65 00 69 00 71 00 74 00 69 00 52 00 35 00 31 00 4c 00 76 00 67 00 32 00 58 00 38 00 64 00 58 00 76 00 31 00 74 00 50 00 37 00 6e 00 78 00 4c 00 61 00 45 00 48 00 4b 00 4b 00 51 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Rapid : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Rapid ransomware"

	strings:
		$s1 = {((6a 69 6d 6d 79 6e 65 79 74 72 6f 6e 40 74 75 74 61 2e 69 6f) | (6a 00 69 00 6d 00 6d 00 79 00 6e 00 65 00 79 00 74 00 72 00 6f 00 6e 00 40 00 74 00 75 00 74 00 61 00 2e 00 69 00 6f 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Satana : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Satana ransomware"

	strings:
		$s1 = {((61 64 61 6d 61 64 61 6d 40 61 75 73 69 2e 63 6f 6d) | (61 00 64 00 61 00 6d 00 61 00 64 00 61 00 6d 00 40 00 61 00 75 00 73 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((58 73 72 52 32 68 65 32 5a 38 75 6e 35 79 73 47 57 6e 4a 31 77 76 65 5a 52 50 52 53 39 36 58 45 6f 58) | (58 00 73 00 72 00 52 00 32 00 68 00 65 00 32 00 5a 00 38 00 75 00 6e 00 35 00 79 00 73 00 47 00 57 00 6e 00 4a 00 31 00 77 00 76 00 65 00 5a 00 52 00 50 00 52 00 53 00 39 00 36 00 58 00 45 00 6f 00 58 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Zeppelin : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Zeppelin ransomware"

	strings:
		$s1 = {((6b 64 38 65 62 79 30 40 69 6e 62 6f 78 68 75 62 2e 6e 65 74) | (6b 00 64 00 38 00 65 00 62 00 79 00 30 00 40 00 69 00 6e 00 62 00 6f 00 78 00 68 00 75 00 62 00 2e 00 6e 00 65 00 74 00))}
		$s2 = {((6b 64 38 65 62 79 30 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (6b 00 64 00 38 00 65 00 62 00 79 00 30 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s3 = {((6b 64 38 65 62 79 30 40 6e 75 6b 65 2e 61 66 72 69 63 61) | (6b 00 64 00 38 00 65 00 62 00 79 00 30 00 40 00 6e 00 75 00 6b 00 65 00 2e 00 61 00 66 00 72 00 69 00 63 00 61 00))}
		$s4 = {((75 73 70 65 78 31 40 63 6f 63 6b 2e 6c 69) | (75 00 73 00 70 00 65 00 78 00 31 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s5 = {((75 73 70 65 78 32 40 63 6f 63 6b 2e 6c 69) | (75 00 73 00 70 00 65 00 78 00 32 00 40 00 63 00 6f 00 63 00 6b 00 2e 00 6c 00 69 00))}
		$s6 = {((43 68 69 6e 61 2e 48 65 6c 70 65 72 40 61 6f 6c 2e 63 6f 6d) | (43 00 68 00 69 00 6e 00 61 00 2e 00 48 00 65 00 6c 00 70 00 65 00 72 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_STOP : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with STOP ransomware"

	strings:
		$s1 = {((67 6f 72 65 6e 74 6f 73 40 62 69 74 6d 65 73 73 61 67 65 2e 63 68) | (67 00 6f 00 72 00 65 00 6e 00 74 00 6f 00 73 00 40 00 62 00 69 00 74 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 2e 00 63 00 68 00))}
		$s2 = {((67 6f 72 65 6e 74 6f 73 32 40 66 69 72 65 6d 61 69 6c 2e 63 63) | (67 00 6f 00 72 00 65 00 6e 00 74 00 6f 00 73 00 32 00 40 00 66 00 69 00 72 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}
		$s3 = {((6d 61 6e 61 67 65 72 40 6d 61 69 6c 74 65 6d 70 2e 63 68) | (6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 40 00 6d 00 61 00 69 00 6c 00 74 00 65 00 6d 00 70 00 2e 00 63 00 68 00))}
		$s4 = {((68 65 6c 70 72 65 73 74 6f 72 65 6d 61 6e 61 67 65 72 40 61 69 72 6d 61 69 6c 2e 63 63) | (68 00 65 00 6c 00 70 00 72 00 65 00 73 00 74 00 6f 00 72 00 65 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}
		$s5 = {((73 75 70 70 6f 72 74 68 65 6c 70 40 61 69 72 6d 61 69 6c 2e 63 63) | (73 00 75 00 70 00 70 00 6f 00 72 00 74 00 68 00 65 00 6c 00 70 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}
		$s6 = {((6d 61 6e 61 67 65 72 68 65 6c 70 65 72 40 61 69 72 6d 61 69 6c 2e 63 63) | (6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 68 00 65 00 6c 00 70 00 65 00 72 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}
		$s7 = {((68 65 6c 70 74 65 61 6d 40 6d 61 69 6c 2e 63 68) | (68 00 65 00 6c 00 70 00 74 00 65 00 61 00 6d 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 68 00))}
		$s8 = {((68 65 6c 70 6d 61 6e 61 67 65 72 40 61 69 72 6d 61 69 6c 2e 63 63) | (68 00 65 00 6c 00 70 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}
		$s9 = {((73 75 70 70 6f 72 74 40 73 79 73 6d 61 69 6c 2e 63 68) | (73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 73 00 79 00 73 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 68 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Diavol : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Diavol ransomware"

	strings:
		$s1 = {((2f 6e 6f 69 6e 6f 2e 35 66 77 73 36 75 71 76 35 62 79 74 74 67 32 72 2f 2f 3a 73 70 74 74 68) | (2f 00 6e 00 6f 00 69 00 6e 00 6f 00 2e 00 35 00 66 00 77 00 73 00 36 00 75 00 71 00 76 00 35 00 62 00 79 00 74 00 74 00 67 00 32 00 72 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00))}
		$s2 = {((68 74 74 70 73 3a 2f 2f 72 32 67 74 74 79 62 35 76 71 75 36 73 77 66 35 2e 6f 6e 69 6f 6e 2f) | (68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 72 00 32 00 67 00 74 00 74 00 79 00 62 00 35 00 76 00 71 00 75 00 36 00 73 00 77 00 66 00 35 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Chaos : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Chaos ransomware"
		score = 60

	strings:
		$s1 = {((61 6e 65 6e 6f 6d 6f 75 73 33 31 40 67 6d 61 69 6c 2e 63 6f 6d) | (61 00 6e 00 65 00 6e 00 6f 00 6d 00 6f 00 75 00 73 00 33 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((64 61 65 6e 67 73 6f 63 69 65 74 79 74 65 61 6d 40 67 6d 61 69 6c 2e 63 6f 6d) | (64 00 61 00 65 00 6e 00 67 00 73 00 6f 00 63 00 69 00 65 00 74 00 79 00 74 00 65 00 61 00 6d 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((52 61 6e 73 48 65 6c 70 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (52 00 61 00 6e 00 73 00 48 00 65 00 6c 00 70 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((31 38 76 68 42 70 67 50 68 5a 72 6a 4a 6b 62 75 54 32 5a 79 55 58 41 6e 4a 61 76 61 4a 63 54 77 45 64) | (31 00 38 00 76 00 68 00 42 00 70 00 67 00 50 00 68 00 5a 00 72 00 6a 00 4a 00 6b 00 62 00 75 00 54 00 32 00 5a 00 79 00 55 00 58 00 41 00 6e 00 4a 00 61 00 76 00 61 00 4a 00 63 00 54 00 77 00 45 00 64 00))}
		$s5 = {((62 63 31 71 6c 6e 7a 63 65 70 34 6c 34 61 63 30 74 74 64 72 71 37 61 77 78 65 76 39 65 68 75 34 36 35 66 32 76 70 74 39 78 30) | (62 00 63 00 31 00 71 00 6c 00 6e 00 7a 00 63 00 65 00 70 00 34 00 6c 00 34 00 61 00 63 00 30 00 74 00 74 00 64 00 72 00 71 00 37 00 61 00 77 00 78 00 65 00 76 00 39 00 65 00 68 00 75 00 34 00 36 00 35 00 66 00 32 00 76 00 70 00 74 00 39 00 78 00 30 00))}
		$s6 = {((38 41 46 74 50 6e 72 65 5a 70 32 38 78 6f 65 74 55 79 4b 69 51 76 56 74 77 72 6f 76 39 50 74 45 62 4d 79 76 63 7a 64 4e 5a 70 42 4e 34 35 45 55 62 45 73 72 45 38 78 59 56 70 34 4e 4e 71 50 72 74 78 4e 6a 51 77 6e 33 50 62 57 33 46 47 31 36 45 50 59 63 50 70 4b 7a 4d 55 37 38 78 4e 36) | (38 00 41 00 46 00 74 00 50 00 6e 00 72 00 65 00 5a 00 70 00 32 00 38 00 78 00 6f 00 65 00 74 00 55 00 79 00 4b 00 69 00 51 00 76 00 56 00 74 00 77 00 72 00 6f 00 76 00 39 00 50 00 74 00 45 00 62 00 4d 00 79 00 76 00 63 00 7a 00 64 00 4e 00 5a 00 70 00 42 00 4e 00 34 00 35 00 45 00 55 00 62 00 45 00 73 00 72 00 45 00 38 00 78 00 59 00 56 00 70 00 34 00 4e 00 4e 00 71 00 50 00 72 00 74 00 78 00 4e 00 6a 00 51 00 77 00 6e 00 33 00 50 00 62 00 57 00 33 00 46 00 47 00 31 00 36 00 45 00 50 00 59 00 63 00 50 00 70 00 4b 00 7a 00 4d 00 55 00 37 00 38 00 78 00 4e 00 36 00))}
		$s7 = {((62 63 31 71 75 36 74 68 61 72 77 61 77 77 6e 79 32 38 7a 39 66 6a 36 6e 72 78 67 35 63 71 66 74 61 65 70 39 61 70 36 7a 32 76) | (62 00 63 00 31 00 71 00 75 00 36 00 74 00 68 00 61 00 72 00 77 00 61 00 77 00 77 00 6e 00 79 00 32 00 38 00 7a 00 39 00 66 00 6a 00 36 00 6e 00 72 00 78 00 67 00 35 00 63 00 71 00 66 00 74 00 61 00 65 00 70 00 39 00 61 00 70 00 36 00 7a 00 32 00 76 00))}
		$s8 = {((62 61 6d 62 6f 6c 69 6e 61 32 30 32 31 40 76 69 72 67 69 6c 69 6f 2e 69 74) | (62 00 61 00 6d 00 62 00 6f 00 6c 00 69 00 6e 00 61 00 32 00 30 00 32 00 31 00 40 00 76 00 69 00 72 00 67 00 69 00 6c 00 69 00 6f 00 2e 00 69 00 74 00))}
		$s9 = {((31 45 6f 79 75 76 63 58 64 41 51 51 76 53 74 6b 6f 4a 5a 33 38 76 64 47 6d 38 34 53 74 44 37 77 6a 6d) | (31 00 45 00 6f 00 79 00 75 00 76 00 63 00 58 00 64 00 41 00 51 00 51 00 76 00 53 00 74 00 6b 00 6f 00 4a 00 5a 00 33 00 38 00 76 00 64 00 47 00 6d 00 38 00 34 00 53 00 74 00 44 00 37 00 77 00 6a 00 6d 00))}
		$s10 = {((31 47 33 39 35 50 4a 73 38 63 69 71 76 58 50 5a 45 59 62 31 4c 66 55 47 50 69 78 39 68 39 6e 33 6f 51) | (31 00 47 00 33 00 39 00 35 00 50 00 4a 00 73 00 38 00 63 00 69 00 71 00 76 00 58 00 50 00 5a 00 45 00 59 00 62 00 31 00 4c 00 66 00 55 00 47 00 50 00 69 00 78 00 39 00 68 00 39 00 6e 00 33 00 6f 00 51 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Maze : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Maze ransomware"

	strings:
		$s1 = {((67 65 74 6d 79 66 69 6c 65 73 62 61 63 6b 40 61 69 72 6d 61 69 6c 2e 63 63) | (67 00 65 00 74 00 6d 00 79 00 66 00 69 00 6c 00 65 00 73 00 62 00 61 00 63 00 6b 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_LokiLocker : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with LokiLocker ransomware"

	strings:
		$s1 = {((55 6e 6c 6f 63 6b 70 6c 73 2e 64 72 30 31 40 79 61 68 6f 6f 2e 63 6f 6d) | (55 00 6e 00 6c 00 6f 00 63 00 6b 00 70 00 6c 00 73 00 2e 00 64 00 72 00 30 00 31 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_BlackCat : hardened
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with BlackCat ransomware"

	strings:
		$pk1 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 30 42 30 6e 69 39 74 79 4b 48 53 4a 6d 55 36 67 63 31 69 52 77 4e 54 6b 6c 59 6f 63 52 4b 6d 4c 50 55 79 4f 74 68 55 49 48 6e 5a 48 77 4c 31 4d 32 70 4b 6c 4d 42 77 58 78 38 31 62 62 6f 56 53 36 43 66 38 59 61 43 6f 57 57 31 62 43 6d 4c 77 50 58 34 32 31 73 47 32 32 78 6b 6d 74 4d 79 2f 53 66 69 47 38 6a 61 59 74 59 69 41 37 72 37 68 4f 64 49 55 6e 4a 67 52 6f 36 76 44 76 4e 61 66 5a 6c 53 44 33 32 74 46 56 56 6a 75 58 38 45 63 37 39 71 6a 32 46 4d 37 2f 4d 6d 4e 63 73 65 55 67 70 49 51 61 45 41 43 75 5a 63 53 7a 4d 4b 2b 6a 5a 41 34 42 4c 54 39 62 35 41 6b 6b 65 63 32 68 50 4f 58 47 54 50 6d 67 61 58 6a 4c 39 45 4a 45 2b 30 72 68 4e 5a 63 6d 2f 6d 36 78 65 34 2f 53 35 65 4c 32 6b 53 43 56 73 4e 55 65 47 38 78 57 75 53 4f 32 6b 44 52 53 38 78 59 33 72 74 4a 4f 43 4e 45 64 71 5a 70 31 72 78 7a 54 6b 68 67 6a 33 68 48 71 72 37 41 6f 46 41 6b 78 4e 62 6c 51 35 33 38 4a 63 64 46 35 2b 43 47 49 4e 78 63 6b 41 2f 6c 64 6d 50 37 77 51 64 39 32 74 6d 46 6b 32 76 63 6c 32 57 65 51 79 6b 46 77 4d 4d 36 4c 36 4d 73 51 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 30 00 42 00 30 00 6e 00 69 00 39 00 74 00 79 00 4b 00 48 00 53 00 4a 00 6d 00 55 00 36 00 67 00 63 00 31 00 69 00 52 00 77 00 4e 00 54 00 6b 00 6c 00 59 00 6f 00 63 00 52 00 4b 00 6d 00 4c 00 50 00 55 00 79 00 4f 00 74 00 68 00 55 00 49 00 48 00 6e 00 5a 00 48 00 77 00 4c 00 31 00 4d 00 32 00 70 00 4b 00 6c 00 4d 00 42 00 77 00 58 00 78 00 38 00 31 00 62 00 62 00 6f 00 56 00 53 00 36 00 43 00 66 00 38 00 59 00 61 00 43 00 6f 00 57 00 57 00 31 00 62 00 43 00 6d 00 4c 00 77 00 50 00 58 00 34 00 32 00 31 00 73 00 47 00 32 00 32 00 78 00 6b 00 6d 00 74 00 4d 00 79 00 2f 00 53 00 66 00 69 00 47 00 38 00 6a 00 61 00 59 00 74 00 59 00 69 00 41 00 37 00 72 00 37 00 68 00 4f 00 64 00 49 00 55 00 6e 00 4a 00 67 00 52 00 6f 00 36 00 76 00 44 00 76 00 4e 00 61 00 66 00 5a 00 6c 00 53 00 44 00 33 00 32 00 74 00 46 00 56 00 56 00 6a 00 75 00 58 00 38 00 45 00 63 00 37 00 39 00 71 00 6a 00 32 00 46 00 4d 00 37 00 2f 00 4d 00 6d 00 4e 00 63 00 73 00 65 00 55 00 67 00 70 00 49 00 51 00 61 00 45 00 41 00 43 00 75 00 5a 00 63 00 53 00 7a 00 4d 00 4b 00 2b 00 6a 00 5a 00 41 00 34 00 42 00 4c 00 54 00 39 00 62 00 35 00 41 00 6b 00 6b 00 65 00 63 00 32 00 68 00 50 00 4f 00 58 00 47 00 54 00 50 00 6d 00 67 00 61 00 58 00 6a 00 4c 00 39 00 45 00 4a 00 45 00 2b 00 30 00 72 00 68 00 4e 00 5a 00 63 00 6d 00 2f 00 6d 00 36 00 78 00 65 00 34 00 2f 00 53 00 35 00 65 00 4c 00 32 00 6b 00 53 00 43 00 56 00 73 00 4e 00 55 00 65 00 47 00 38 00 78 00 57 00 75 00 53 00 4f 00 32 00 6b 00 44 00 52 00 53 00 38 00 78 00 59 00 33 00 72 00 74 00 4a 00 4f 00 43 00 4e 00 45 00 64 00 71 00 5a 00 70 00 31 00 72 00 78 00 7a 00 54 00 6b 00 68 00 67 00 6a 00 33 00 68 00 48 00 71 00 72 00 37 00 41 00 6f 00 46 00 41 00 6b 00 78 00 4e 00 62 00 6c 00 51 00 35 00 33 00 38 00 4a 00 63 00 64 00 46 00 35 00 2b 00 43 00 47 00 49 00 4e 00 78 00 63 00 6b 00 41 00 2f 00 6c 00 64 00 6d 00 50 00 37 00 77 00 51 00 64 00 39 00 32 00 74 00 6d 00 46 00 6b 00 32 00 76 00 63 00 6c 00 32 00 57 00 65 00 51 00 79 00 6b 00 46 00 77 00 4d 00 4d 00 36 00 4c 00 36 00 4d 00 73 00 51 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk2 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 34 39 67 7a 4a 77 50 39 55 77 45 75 59 51 5a 54 31 63 64 67 53 70 78 47 36 7a 38 54 56 4e 4c 50 66 53 34 51 77 64 33 76 70 57 48 45 4f 41 75 76 69 38 4a 47 56 45 70 48 50 47 5a 6e 72 44 31 51 46 6f 44 4c 53 54 76 61 33 50 5a 34 6d 71 74 49 56 4f 37 39 47 4f 59 62 35 75 51 6b 50 37 4c 64 4a 47 57 62 4c 41 6a 55 47 70 74 56 47 6d 42 36 37 6a 4b 4f 4f 4c 4c 72 6a 6d 75 42 44 48 70 4a 58 53 4f 47 47 2f 76 77 35 76 61 6a 72 34 4d 68 4e 6e 73 76 6f 42 4c 50 4f 43 30 41 4f 7a 50 4d 36 47 42 44 67 4b 64 43 39 7a 64 55 47 4e 45 72 65 41 6a 4f 52 34 6e 65 71 77 5a 32 6a 66 59 6c 35 6b 35 65 33 65 52 46 38 36 68 6d 57 68 47 58 4a 51 61 55 31 75 54 6d 44 4a 77 67 51 49 7a 6d 55 5a 4b 6f 2b 59 43 66 41 48 62 45 62 53 41 34 48 68 73 75 6d 4a 66 77 30 4d 4a 4e 37 52 66 4b 50 45 51 6b 45 56 76 52 49 42 69 62 48 6e 4a 75 49 70 31 62 78 6b 33 49 47 50 7a 54 43 62 79 51 4c 48 4d 56 4c 7a 38 77 67 45 6c 45 65 78 75 38 2f 61 4f 33 46 54 36 77 34 75 50 59 33 71 44 2b 72 32 57 2b 72 69 37 78 49 64 45 4e 2f 70 54 7a 36 54 42 4b 76 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 34 00 39 00 67 00 7a 00 4a 00 77 00 50 00 39 00 55 00 77 00 45 00 75 00 59 00 51 00 5a 00 54 00 31 00 63 00 64 00 67 00 53 00 70 00 78 00 47 00 36 00 7a 00 38 00 54 00 56 00 4e 00 4c 00 50 00 66 00 53 00 34 00 51 00 77 00 64 00 33 00 76 00 70 00 57 00 48 00 45 00 4f 00 41 00 75 00 76 00 69 00 38 00 4a 00 47 00 56 00 45 00 70 00 48 00 50 00 47 00 5a 00 6e 00 72 00 44 00 31 00 51 00 46 00 6f 00 44 00 4c 00 53 00 54 00 76 00 61 00 33 00 50 00 5a 00 34 00 6d 00 71 00 74 00 49 00 56 00 4f 00 37 00 39 00 47 00 4f 00 59 00 62 00 35 00 75 00 51 00 6b 00 50 00 37 00 4c 00 64 00 4a 00 47 00 57 00 62 00 4c 00 41 00 6a 00 55 00 47 00 70 00 74 00 56 00 47 00 6d 00 42 00 36 00 37 00 6a 00 4b 00 4f 00 4f 00 4c 00 4c 00 72 00 6a 00 6d 00 75 00 42 00 44 00 48 00 70 00 4a 00 58 00 53 00 4f 00 47 00 47 00 2f 00 76 00 77 00 35 00 76 00 61 00 6a 00 72 00 34 00 4d 00 68 00 4e 00 6e 00 73 00 76 00 6f 00 42 00 4c 00 50 00 4f 00 43 00 30 00 41 00 4f 00 7a 00 50 00 4d 00 36 00 47 00 42 00 44 00 67 00 4b 00 64 00 43 00 39 00 7a 00 64 00 55 00 47 00 4e 00 45 00 72 00 65 00 41 00 6a 00 4f 00 52 00 34 00 6e 00 65 00 71 00 77 00 5a 00 32 00 6a 00 66 00 59 00 6c 00 35 00 6b 00 35 00 65 00 33 00 65 00 52 00 46 00 38 00 36 00 68 00 6d 00 57 00 68 00 47 00 58 00 4a 00 51 00 61 00 55 00 31 00 75 00 54 00 6d 00 44 00 4a 00 77 00 67 00 51 00 49 00 7a 00 6d 00 55 00 5a 00 4b 00 6f 00 2b 00 59 00 43 00 66 00 41 00 48 00 62 00 45 00 62 00 53 00 41 00 34 00 48 00 68 00 73 00 75 00 6d 00 4a 00 66 00 77 00 30 00 4d 00 4a 00 4e 00 37 00 52 00 66 00 4b 00 50 00 45 00 51 00 6b 00 45 00 56 00 76 00 52 00 49 00 42 00 69 00 62 00 48 00 6e 00 4a 00 75 00 49 00 70 00 31 00 62 00 78 00 6b 00 33 00 49 00 47 00 50 00 7a 00 54 00 43 00 62 00 79 00 51 00 4c 00 48 00 4d 00 56 00 4c 00 7a 00 38 00 77 00 67 00 45 00 6c 00 45 00 65 00 78 00 75 00 38 00 2f 00 61 00 4f 00 33 00 46 00 54 00 36 00 77 00 34 00 75 00 50 00 59 00 33 00 71 00 44 00 2b 00 72 00 32 00 57 00 2b 00 72 00 69 00 37 00 78 00 49 00 64 00 45 00 4e 00 2f 00 70 00 54 00 7a 00 36 00 54 00 42 00 4b 00 76 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk3 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 38 74 4b 50 4e 46 43 62 55 35 55 6e 72 39 6a 78 6c 54 6b 34 52 6d 55 64 56 68 63 52 79 64 4a 46 74 73 36 68 4d 70 4c 7a 63 41 58 49 52 32 79 78 69 4e 43 30 51 69 46 34 55 6f 76 41 49 70 47 77 58 36 6b 78 4f 57 37 6b 4f 61 4f 76 41 42 4a 51 50 36 51 45 4e 4d 4e 53 67 30 33 30 56 6c 4c 6f 54 50 2b 6e 64 66 46 77 49 74 2b 58 2b 52 55 66 6c 47 34 55 57 50 45 38 79 75 2b 6b 7a 47 70 43 77 70 37 55 6a 58 2b 68 44 2f 53 70 46 62 53 46 52 52 68 33 42 76 4c 33 76 45 71 30 34 44 7a 45 30 41 7a 69 66 45 42 45 34 79 78 4b 70 4c 73 72 4d 73 58 79 5a 7a 57 79 39 4e 7a 61 38 4e 54 4f 32 6a 72 42 78 6f 45 56 4d 32 78 43 4c 6b 55 4c 70 30 77 5a 45 50 44 77 67 65 4b 47 6b 6f 78 4d 7a 71 61 76 56 57 42 43 2b 56 78 69 30 61 74 4b 73 74 62 6f 37 2f 54 6c 6f 4e 65 6e 50 61 67 6c 2f 65 55 45 72 6b 39 43 38 74 54 36 37 7a 4b 67 62 45 68 33 54 46 74 52 45 67 61 78 61 2f 79 72 6a 42 76 4e 34 38 42 55 38 4a 47 47 78 4c 78 79 34 41 65 47 46 30 76 4f 55 64 44 30 57 6b 4a 73 57 59 7a 4c 56 67 32 31 41 70 67 4a 61 43 44 72 35 7a 44 50 75 51 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 38 00 74 00 4b 00 50 00 4e 00 46 00 43 00 62 00 55 00 35 00 55 00 6e 00 72 00 39 00 6a 00 78 00 6c 00 54 00 6b 00 34 00 52 00 6d 00 55 00 64 00 56 00 68 00 63 00 52 00 79 00 64 00 4a 00 46 00 74 00 73 00 36 00 68 00 4d 00 70 00 4c 00 7a 00 63 00 41 00 58 00 49 00 52 00 32 00 79 00 78 00 69 00 4e 00 43 00 30 00 51 00 69 00 46 00 34 00 55 00 6f 00 76 00 41 00 49 00 70 00 47 00 77 00 58 00 36 00 6b 00 78 00 4f 00 57 00 37 00 6b 00 4f 00 61 00 4f 00 76 00 41 00 42 00 4a 00 51 00 50 00 36 00 51 00 45 00 4e 00 4d 00 4e 00 53 00 67 00 30 00 33 00 30 00 56 00 6c 00 4c 00 6f 00 54 00 50 00 2b 00 6e 00 64 00 66 00 46 00 77 00 49 00 74 00 2b 00 58 00 2b 00 52 00 55 00 66 00 6c 00 47 00 34 00 55 00 57 00 50 00 45 00 38 00 79 00 75 00 2b 00 6b 00 7a 00 47 00 70 00 43 00 77 00 70 00 37 00 55 00 6a 00 58 00 2b 00 68 00 44 00 2f 00 53 00 70 00 46 00 62 00 53 00 46 00 52 00 52 00 68 00 33 00 42 00 76 00 4c 00 33 00 76 00 45 00 71 00 30 00 34 00 44 00 7a 00 45 00 30 00 41 00 7a 00 69 00 66 00 45 00 42 00 45 00 34 00 79 00 78 00 4b 00 70 00 4c 00 73 00 72 00 4d 00 73 00 58 00 79 00 5a 00 7a 00 57 00 79 00 39 00 4e 00 7a 00 61 00 38 00 4e 00 54 00 4f 00 32 00 6a 00 72 00 42 00 78 00 6f 00 45 00 56 00 4d 00 32 00 78 00 43 00 4c 00 6b 00 55 00 4c 00 70 00 30 00 77 00 5a 00 45 00 50 00 44 00 77 00 67 00 65 00 4b 00 47 00 6b 00 6f 00 78 00 4d 00 7a 00 71 00 61 00 76 00 56 00 57 00 42 00 43 00 2b 00 56 00 78 00 69 00 30 00 61 00 74 00 4b 00 73 00 74 00 62 00 6f 00 37 00 2f 00 54 00 6c 00 6f 00 4e 00 65 00 6e 00 50 00 61 00 67 00 6c 00 2f 00 65 00 55 00 45 00 72 00 6b 00 39 00 43 00 38 00 74 00 54 00 36 00 37 00 7a 00 4b 00 67 00 62 00 45 00 68 00 33 00 54 00 46 00 74 00 52 00 45 00 67 00 61 00 78 00 61 00 2f 00 79 00 72 00 6a 00 42 00 76 00 4e 00 34 00 38 00 42 00 55 00 38 00 4a 00 47 00 47 00 78 00 4c 00 78 00 79 00 34 00 41 00 65 00 47 00 46 00 30 00 76 00 4f 00 55 00 64 00 44 00 30 00 57 00 6b 00 4a 00 73 00 57 00 59 00 7a 00 4c 00 56 00 67 00 32 00 31 00 41 00 70 00 67 00 4a 00 61 00 43 00 44 00 72 00 35 00 7a 00 44 00 50 00 75 00 51 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk4 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 70 77 33 74 57 64 4d 61 57 4a 76 4e 66 32 4d 65 6a 79 35 48 30 59 36 6b 75 6a 2b 6c 73 74 4e 70 77 46 79 69 73 6d 47 44 45 59 68 57 4b 50 70 73 39 63 36 38 78 6c 2b 38 34 6f 36 75 4c 4b 66 71 50 7a 4e 76 4c 6e 53 78 6c 56 61 36 44 69 74 63 4a 47 65 4b 4a 45 51 6b 7a 4e 2b 43 31 65 31 4b 73 66 7a 4d 36 33 6a 48 79 62 52 45 42 32 68 73 2b 64 48 62 71 42 71 34 64 62 61 6d 49 51 63 54 72 72 72 34 6d 4b 7a 75 48 4a 37 61 6f 6b 34 6d 6c 70 52 78 32 55 6e 31 58 4f 4a 61 6f 64 6f 56 37 78 4f 48 4f 37 75 69 35 76 36 75 4b 33 39 4d 4a 33 72 76 69 74 53 45 42 76 76 35 6f 49 30 57 44 6c 70 33 49 46 6d 74 64 36 55 4d 36 72 32 6e 79 67 59 31 6e 63 41 55 75 61 73 61 6c 5a 67 46 31 56 61 7a 37 56 58 4f 57 79 58 32 52 65 51 48 62 59 57 57 52 43 52 31 71 79 4b 4d 51 63 42 74 6a 54 35 50 4f 58 78 39 42 38 65 6b 31 70 6e 55 34 70 36 35 6b 47 65 39 4d 37 39 34 42 68 68 68 32 30 47 4e 32 34 67 59 35 61 2b 7a 77 58 77 73 74 61 4e 54 4f 39 6c 75 77 64 34 78 6a 6a 52 51 41 56 73 44 67 6a 72 6a 6b 7a 74 69 32 37 47 31 31 49 43 6e 36 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 70 00 77 00 33 00 74 00 57 00 64 00 4d 00 61 00 57 00 4a 00 76 00 4e 00 66 00 32 00 4d 00 65 00 6a 00 79 00 35 00 48 00 30 00 59 00 36 00 6b 00 75 00 6a 00 2b 00 6c 00 73 00 74 00 4e 00 70 00 77 00 46 00 79 00 69 00 73 00 6d 00 47 00 44 00 45 00 59 00 68 00 57 00 4b 00 50 00 70 00 73 00 39 00 63 00 36 00 38 00 78 00 6c 00 2b 00 38 00 34 00 6f 00 36 00 75 00 4c 00 4b 00 66 00 71 00 50 00 7a 00 4e 00 76 00 4c 00 6e 00 53 00 78 00 6c 00 56 00 61 00 36 00 44 00 69 00 74 00 63 00 4a 00 47 00 65 00 4b 00 4a 00 45 00 51 00 6b 00 7a 00 4e 00 2b 00 43 00 31 00 65 00 31 00 4b 00 73 00 66 00 7a 00 4d 00 36 00 33 00 6a 00 48 00 79 00 62 00 52 00 45 00 42 00 32 00 68 00 73 00 2b 00 64 00 48 00 62 00 71 00 42 00 71 00 34 00 64 00 62 00 61 00 6d 00 49 00 51 00 63 00 54 00 72 00 72 00 72 00 34 00 6d 00 4b 00 7a 00 75 00 48 00 4a 00 37 00 61 00 6f 00 6b 00 34 00 6d 00 6c 00 70 00 52 00 78 00 32 00 55 00 6e 00 31 00 58 00 4f 00 4a 00 61 00 6f 00 64 00 6f 00 56 00 37 00 78 00 4f 00 48 00 4f 00 37 00 75 00 69 00 35 00 76 00 36 00 75 00 4b 00 33 00 39 00 4d 00 4a 00 33 00 72 00 76 00 69 00 74 00 53 00 45 00 42 00 76 00 76 00 35 00 6f 00 49 00 30 00 57 00 44 00 6c 00 70 00 33 00 49 00 46 00 6d 00 74 00 64 00 36 00 55 00 4d 00 36 00 72 00 32 00 6e 00 79 00 67 00 59 00 31 00 6e 00 63 00 41 00 55 00 75 00 61 00 73 00 61 00 6c 00 5a 00 67 00 46 00 31 00 56 00 61 00 7a 00 37 00 56 00 58 00 4f 00 57 00 79 00 58 00 32 00 52 00 65 00 51 00 48 00 62 00 59 00 57 00 57 00 52 00 43 00 52 00 31 00 71 00 79 00 4b 00 4d 00 51 00 63 00 42 00 74 00 6a 00 54 00 35 00 50 00 4f 00 58 00 78 00 39 00 42 00 38 00 65 00 6b 00 31 00 70 00 6e 00 55 00 34 00 70 00 36 00 35 00 6b 00 47 00 65 00 39 00 4d 00 37 00 39 00 34 00 42 00 68 00 68 00 68 00 32 00 30 00 47 00 4e 00 32 00 34 00 67 00 59 00 35 00 61 00 2b 00 7a 00 77 00 58 00 77 00 73 00 74 00 61 00 4e 00 54 00 4f 00 39 00 6c 00 75 00 77 00 64 00 34 00 78 00 6a 00 6a 00 52 00 51 00 41 00 56 00 73 00 44 00 67 00 6a 00 72 00 6a 00 6b 00 7a 00 74 00 69 00 32 00 37 00 47 00 31 00 31 00 49 00 43 00 6e 00 36 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk5 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 71 38 6b 6a 35 4c 51 4a 6e 67 50 73 59 37 41 68 54 61 4a 73 55 58 63 35 46 72 53 47 65 4b 53 35 67 77 35 50 49 71 6b 32 51 50 4d 39 54 59 36 2b 75 73 38 54 52 52 7a 57 5a 37 72 47 6b 31 7a 6e 73 32 6b 6c 70 7a 70 52 4d 55 7a 4c 49 71 42 38 6c 70 43 6b 4a 6a 71 6b 4f 55 47 66 67 71 73 2b 48 4e 34 56 49 4f 70 6f 4a 67 46 59 38 39 37 78 73 74 4a 43 78 54 63 2b 38 70 59 51 45 73 53 71 43 6c 78 4a 6c 6c 73 63 55 30 6f 6b 6b 4c 53 51 71 6e 64 49 52 32 47 7a 6e 6c 67 33 71 66 63 77 79 6e 63 4a 41 46 42 49 6e 79 71 4d 2b 4c 34 6b 62 77 43 51 5a 36 78 35 48 4e 69 4c 65 32 6c 4a 6e 38 52 50 32 61 44 69 4d 49 2b 52 53 31 75 4c 59 72 6f 6e 32 47 37 72 78 44 54 55 51 6e 78 54 68 4d 74 67 4c 41 65 6b 6f 38 75 6c 61 42 33 54 70 42 30 67 34 6c 6d 48 43 65 6e 6b 45 5a 65 42 4e 73 38 31 39 38 36 2b 4d 6a 48 6e 76 37 4b 6b 69 73 63 5a 37 5a 72 65 7a 4b 6a 4e 61 49 78 52 73 38 42 41 63 44 39 79 2b 51 39 51 51 78 43 76 5a 4d 53 30 31 49 54 4e 58 63 67 69 49 74 62 41 34 64 73 47 71 31 66 50 4a 34 32 79 42 6b 6b 69 49 6f 64 73 45 51 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 71 00 38 00 6b 00 6a 00 35 00 4c 00 51 00 4a 00 6e 00 67 00 50 00 73 00 59 00 37 00 41 00 68 00 54 00 61 00 4a 00 73 00 55 00 58 00 63 00 35 00 46 00 72 00 53 00 47 00 65 00 4b 00 53 00 35 00 67 00 77 00 35 00 50 00 49 00 71 00 6b 00 32 00 51 00 50 00 4d 00 39 00 54 00 59 00 36 00 2b 00 75 00 73 00 38 00 54 00 52 00 52 00 7a 00 57 00 5a 00 37 00 72 00 47 00 6b 00 31 00 7a 00 6e 00 73 00 32 00 6b 00 6c 00 70 00 7a 00 70 00 52 00 4d 00 55 00 7a 00 4c 00 49 00 71 00 42 00 38 00 6c 00 70 00 43 00 6b 00 4a 00 6a 00 71 00 6b 00 4f 00 55 00 47 00 66 00 67 00 71 00 73 00 2b 00 48 00 4e 00 34 00 56 00 49 00 4f 00 70 00 6f 00 4a 00 67 00 46 00 59 00 38 00 39 00 37 00 78 00 73 00 74 00 4a 00 43 00 78 00 54 00 63 00 2b 00 38 00 70 00 59 00 51 00 45 00 73 00 53 00 71 00 43 00 6c 00 78 00 4a 00 6c 00 6c 00 73 00 63 00 55 00 30 00 6f 00 6b 00 6b 00 4c 00 53 00 51 00 71 00 6e 00 64 00 49 00 52 00 32 00 47 00 7a 00 6e 00 6c 00 67 00 33 00 71 00 66 00 63 00 77 00 79 00 6e 00 63 00 4a 00 41 00 46 00 42 00 49 00 6e 00 79 00 71 00 4d 00 2b 00 4c 00 34 00 6b 00 62 00 77 00 43 00 51 00 5a 00 36 00 78 00 35 00 48 00 4e 00 69 00 4c 00 65 00 32 00 6c 00 4a 00 6e 00 38 00 52 00 50 00 32 00 61 00 44 00 69 00 4d 00 49 00 2b 00 52 00 53 00 31 00 75 00 4c 00 59 00 72 00 6f 00 6e 00 32 00 47 00 37 00 72 00 78 00 44 00 54 00 55 00 51 00 6e 00 78 00 54 00 68 00 4d 00 74 00 67 00 4c 00 41 00 65 00 6b 00 6f 00 38 00 75 00 6c 00 61 00 42 00 33 00 54 00 70 00 42 00 30 00 67 00 34 00 6c 00 6d 00 48 00 43 00 65 00 6e 00 6b 00 45 00 5a 00 65 00 42 00 4e 00 73 00 38 00 31 00 39 00 38 00 36 00 2b 00 4d 00 6a 00 48 00 6e 00 76 00 37 00 4b 00 6b 00 69 00 73 00 63 00 5a 00 37 00 5a 00 72 00 65 00 7a 00 4b 00 6a 00 4e 00 61 00 49 00 78 00 52 00 73 00 38 00 42 00 41 00 63 00 44 00 39 00 79 00 2b 00 51 00 39 00 51 00 51 00 78 00 43 00 76 00 5a 00 4d 00 53 00 30 00 31 00 49 00 54 00 4e 00 58 00 63 00 67 00 69 00 49 00 74 00 62 00 41 00 34 00 64 00 73 00 47 00 71 00 31 00 66 00 50 00 4a 00 34 00 32 00 79 00 42 00 6b 00 6b 00 69 00 49 00 6f 00 64 00 73 00 45 00 51 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk6 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 71 45 6f 79 74 4e 72 4d 5a 52 6f 71 79 49 73 46 70 63 6a 69 71 56 57 70 75 56 2b 63 43 39 6a 53 31 75 6d 58 4e 67 2f 41 6e 4a 46 2f 78 45 37 4c 4f 4e 41 6d 62 31 70 38 44 73 78 31 69 67 49 55 64 36 35 49 58 66 46 55 78 6d 4a 6a 46 4f 35 68 66 38 4c 49 42 7a 76 6a 55 62 42 6c 6c 34 6c 62 53 67 47 54 41 55 48 61 33 4a 62 6d 72 2f 69 6d 6c 65 36 51 66 74 6d 59 33 32 4a 37 64 44 62 34 57 75 4a 55 4f 78 2b 76 4c 4e 54 30 49 37 32 43 45 53 69 79 6f 74 53 7a 77 67 76 4c 77 6a 79 75 62 54 6d 7a 54 4a 4d 6b 71 76 69 59 4f 63 67 44 6a 34 35 4e 56 4f 78 36 36 39 63 47 36 46 57 45 61 4a 6f 33 50 55 5a 7a 52 78 39 4c 53 36 70 6b 4f 6e 38 74 57 2b 57 34 4e 7a 6d 48 4d 63 72 6d 61 2b 4c 4f 61 6b 61 6e 37 4e 55 36 4b 68 76 35 48 66 35 41 52 4e 73 41 41 2b 4b 76 44 66 50 31 57 58 4a 2f 56 73 4c 58 6a 36 78 38 53 64 58 30 76 32 69 53 2b 79 35 38 65 68 55 55 6d 6c 78 63 38 48 4e 73 59 64 4f 47 46 77 72 77 59 58 39 7a 4c 79 4a 44 65 64 73 62 50 67 30 32 63 34 41 45 34 4b 58 74 38 76 48 34 2b 6a 34 6c 56 46 74 72 75 53 79 34 76 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 71 00 45 00 6f 00 79 00 74 00 4e 00 72 00 4d 00 5a 00 52 00 6f 00 71 00 79 00 49 00 73 00 46 00 70 00 63 00 6a 00 69 00 71 00 56 00 57 00 70 00 75 00 56 00 2b 00 63 00 43 00 39 00 6a 00 53 00 31 00 75 00 6d 00 58 00 4e 00 67 00 2f 00 41 00 6e 00 4a 00 46 00 2f 00 78 00 45 00 37 00 4c 00 4f 00 4e 00 41 00 6d 00 62 00 31 00 70 00 38 00 44 00 73 00 78 00 31 00 69 00 67 00 49 00 55 00 64 00 36 00 35 00 49 00 58 00 66 00 46 00 55 00 78 00 6d 00 4a 00 6a 00 46 00 4f 00 35 00 68 00 66 00 38 00 4c 00 49 00 42 00 7a 00 76 00 6a 00 55 00 62 00 42 00 6c 00 6c 00 34 00 6c 00 62 00 53 00 67 00 47 00 54 00 41 00 55 00 48 00 61 00 33 00 4a 00 62 00 6d 00 72 00 2f 00 69 00 6d 00 6c 00 65 00 36 00 51 00 66 00 74 00 6d 00 59 00 33 00 32 00 4a 00 37 00 64 00 44 00 62 00 34 00 57 00 75 00 4a 00 55 00 4f 00 78 00 2b 00 76 00 4c 00 4e 00 54 00 30 00 49 00 37 00 32 00 43 00 45 00 53 00 69 00 79 00 6f 00 74 00 53 00 7a 00 77 00 67 00 76 00 4c 00 77 00 6a 00 79 00 75 00 62 00 54 00 6d 00 7a 00 54 00 4a 00 4d 00 6b 00 71 00 76 00 69 00 59 00 4f 00 63 00 67 00 44 00 6a 00 34 00 35 00 4e 00 56 00 4f 00 78 00 36 00 36 00 39 00 63 00 47 00 36 00 46 00 57 00 45 00 61 00 4a 00 6f 00 33 00 50 00 55 00 5a 00 7a 00 52 00 78 00 39 00 4c 00 53 00 36 00 70 00 6b 00 4f 00 6e 00 38 00 74 00 57 00 2b 00 57 00 34 00 4e 00 7a 00 6d 00 48 00 4d 00 63 00 72 00 6d 00 61 00 2b 00 4c 00 4f 00 61 00 6b 00 61 00 6e 00 37 00 4e 00 55 00 36 00 4b 00 68 00 76 00 35 00 48 00 66 00 35 00 41 00 52 00 4e 00 73 00 41 00 41 00 2b 00 4b 00 76 00 44 00 66 00 50 00 31 00 57 00 58 00 4a 00 2f 00 56 00 73 00 4c 00 58 00 6a 00 36 00 78 00 38 00 53 00 64 00 58 00 30 00 76 00 32 00 69 00 53 00 2b 00 79 00 35 00 38 00 65 00 68 00 55 00 55 00 6d 00 6c 00 78 00 63 00 38 00 48 00 4e 00 73 00 59 00 64 00 4f 00 47 00 46 00 77 00 72 00 77 00 59 00 58 00 39 00 7a 00 4c 00 79 00 4a 00 44 00 65 00 64 00 73 00 62 00 50 00 67 00 30 00 32 00 63 00 34 00 41 00 45 00 34 00 4b 00 58 00 74 00 38 00 76 00 48 00 34 00 2b 00 6a 00 34 00 6c 00 56 00 46 00 74 00 72 00 75 00 53 00 79 00 34 00 76 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk7 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 74 39 75 59 6b 48 7a 61 69 7a 4e 58 67 2f 53 31 31 6e 63 54 54 4c 79 62 6b 4d 74 71 72 4b 57 38 67 67 36 54 79 7a 62 47 57 6e 52 4e 52 4f 6c 39 4f 2b 6c 31 56 5a 42 4c 47 30 78 69 4d 74 31 6d 5a 62 75 53 74 6c 38 4c 74 33 6c 31 76 6c 6b 4d 61 39 32 6b 67 4c 6a 4e 2b 55 66 4b 6d 71 33 4b 68 42 45 68 65 4e 32 75 4d 6d 52 30 57 70 77 56 38 33 6b 63 65 56 52 6d 7a 72 35 6c 75 67 34 52 79 51 2f 78 41 36 2f 4f 58 4b 34 4e 70 74 44 49 54 34 4c 36 43 55 54 42 57 4d 79 6b 32 6d 6d 59 30 43 71 39 48 79 79 72 6a 64 6e 48 65 41 58 57 41 63 51 47 46 45 61 63 37 57 34 6a 54 6a 4f 4e 5a 71 49 2b 6c 67 53 63 50 65 77 53 2b 63 50 46 6e 7a 31 68 41 44 30 49 41 71 7a 6a 35 58 32 6d 5a 56 53 66 46 47 52 33 74 44 6f 49 65 34 32 6a 77 35 77 62 36 57 32 79 69 38 7a 62 33 6d 67 4b 72 47 74 54 42 62 77 30 50 70 6a 30 55 67 4b 72 6d 64 4e 35 69 46 6d 66 55 51 48 4c 45 7a 4b 41 61 6b 44 67 67 4c 63 42 74 72 57 31 6f 35 2b 34 57 4d 61 5a 4f 4c 77 38 6d 61 55 35 62 79 76 6a 58 75 33 46 33 69 33 47 64 51 65 38 53 4b 54 59 63 56 4b 35 4f 51 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 74 00 39 00 75 00 59 00 6b 00 48 00 7a 00 61 00 69 00 7a 00 4e 00 58 00 67 00 2f 00 53 00 31 00 31 00 6e 00 63 00 54 00 54 00 4c 00 79 00 62 00 6b 00 4d 00 74 00 71 00 72 00 4b 00 57 00 38 00 67 00 67 00 36 00 54 00 79 00 7a 00 62 00 47 00 57 00 6e 00 52 00 4e 00 52 00 4f 00 6c 00 39 00 4f 00 2b 00 6c 00 31 00 56 00 5a 00 42 00 4c 00 47 00 30 00 78 00 69 00 4d 00 74 00 31 00 6d 00 5a 00 62 00 75 00 53 00 74 00 6c 00 38 00 4c 00 74 00 33 00 6c 00 31 00 76 00 6c 00 6b 00 4d 00 61 00 39 00 32 00 6b 00 67 00 4c 00 6a 00 4e 00 2b 00 55 00 66 00 4b 00 6d 00 71 00 33 00 4b 00 68 00 42 00 45 00 68 00 65 00 4e 00 32 00 75 00 4d 00 6d 00 52 00 30 00 57 00 70 00 77 00 56 00 38 00 33 00 6b 00 63 00 65 00 56 00 52 00 6d 00 7a 00 72 00 35 00 6c 00 75 00 67 00 34 00 52 00 79 00 51 00 2f 00 78 00 41 00 36 00 2f 00 4f 00 58 00 4b 00 34 00 4e 00 70 00 74 00 44 00 49 00 54 00 34 00 4c 00 36 00 43 00 55 00 54 00 42 00 57 00 4d 00 79 00 6b 00 32 00 6d 00 6d 00 59 00 30 00 43 00 71 00 39 00 48 00 79 00 79 00 72 00 6a 00 64 00 6e 00 48 00 65 00 41 00 58 00 57 00 41 00 63 00 51 00 47 00 46 00 45 00 61 00 63 00 37 00 57 00 34 00 6a 00 54 00 6a 00 4f 00 4e 00 5a 00 71 00 49 00 2b 00 6c 00 67 00 53 00 63 00 50 00 65 00 77 00 53 00 2b 00 63 00 50 00 46 00 6e 00 7a 00 31 00 68 00 41 00 44 00 30 00 49 00 41 00 71 00 7a 00 6a 00 35 00 58 00 32 00 6d 00 5a 00 56 00 53 00 66 00 46 00 47 00 52 00 33 00 74 00 44 00 6f 00 49 00 65 00 34 00 32 00 6a 00 77 00 35 00 77 00 62 00 36 00 57 00 32 00 79 00 69 00 38 00 7a 00 62 00 33 00 6d 00 67 00 4b 00 72 00 47 00 74 00 54 00 42 00 62 00 77 00 30 00 50 00 70 00 6a 00 30 00 55 00 67 00 4b 00 72 00 6d 00 64 00 4e 00 35 00 69 00 46 00 6d 00 66 00 55 00 51 00 48 00 4c 00 45 00 7a 00 4b 00 41 00 61 00 6b 00 44 00 67 00 67 00 4c 00 63 00 42 00 74 00 72 00 57 00 31 00 6f 00 35 00 2b 00 34 00 57 00 4d 00 61 00 5a 00 4f 00 4c 00 77 00 38 00 6d 00 61 00 55 00 35 00 62 00 79 00 76 00 6a 00 58 00 75 00 33 00 46 00 33 00 69 00 33 00 47 00 64 00 51 00 65 00 38 00 53 00 4b 00 54 00 59 00 63 00 56 00 4b 00 35 00 4f 00 51 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk8 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 75 67 71 5a 34 41 54 45 39 2b 39 46 71 75 6e 75 6e 57 2f 44 42 76 47 6f 73 6e 55 58 2f 62 4e 78 51 7a 4d 59 55 6d 45 31 34 47 4a 49 62 4e 61 36 76 77 59 53 4e 58 4f 6c 47 30 39 6d 76 64 41 71 5a 71 44 33 6c 58 69 68 57 44 6a 79 32 35 2b 67 7a 71 53 65 53 2b 46 73 32 71 4e 79 54 64 66 47 50 41 38 69 75 32 78 78 35 52 52 55 58 4b 4c 47 46 54 68 78 74 49 7a 67 33 66 6f 68 41 4b 33 2b 4c 78 4a 56 68 78 74 75 49 54 41 54 33 38 49 48 61 63 63 37 64 56 4c 48 73 72 64 64 75 34 55 44 6a 69 48 47 46 64 76 58 6a 42 35 35 4e 77 65 35 63 75 31 42 59 79 6c 48 73 41 52 4d 59 79 63 42 41 32 46 77 4c 50 35 37 63 4b 76 63 32 2f 43 33 4f 58 42 41 46 36 71 62 73 56 58 42 63 79 46 68 72 4b 4f 4f 59 41 2f 2b 35 49 6a 46 66 45 68 67 48 79 32 46 4c 48 52 66 38 6c 6d 50 51 50 62 53 6c 72 4d 36 64 6b 2b 57 34 44 35 4b 56 71 4f 50 78 2f 65 46 70 30 67 65 55 4a 4a 6c 6d 6c 72 65 33 66 6c 49 32 39 71 57 53 32 30 62 6b 47 71 41 45 7a 39 6a 30 37 79 36 39 48 47 59 4e 39 4e 74 37 2b 44 52 67 42 77 72 70 4e 6f 2f 45 6b 5a 6b 75 61 53 54 74 51 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 75 00 67 00 71 00 5a 00 34 00 41 00 54 00 45 00 39 00 2b 00 39 00 46 00 71 00 75 00 6e 00 75 00 6e 00 57 00 2f 00 44 00 42 00 76 00 47 00 6f 00 73 00 6e 00 55 00 58 00 2f 00 62 00 4e 00 78 00 51 00 7a 00 4d 00 59 00 55 00 6d 00 45 00 31 00 34 00 47 00 4a 00 49 00 62 00 4e 00 61 00 36 00 76 00 77 00 59 00 53 00 4e 00 58 00 4f 00 6c 00 47 00 30 00 39 00 6d 00 76 00 64 00 41 00 71 00 5a 00 71 00 44 00 33 00 6c 00 58 00 69 00 68 00 57 00 44 00 6a 00 79 00 32 00 35 00 2b 00 67 00 7a 00 71 00 53 00 65 00 53 00 2b 00 46 00 73 00 32 00 71 00 4e 00 79 00 54 00 64 00 66 00 47 00 50 00 41 00 38 00 69 00 75 00 32 00 78 00 78 00 35 00 52 00 52 00 55 00 58 00 4b 00 4c 00 47 00 46 00 54 00 68 00 78 00 74 00 49 00 7a 00 67 00 33 00 66 00 6f 00 68 00 41 00 4b 00 33 00 2b 00 4c 00 78 00 4a 00 56 00 68 00 78 00 74 00 75 00 49 00 54 00 41 00 54 00 33 00 38 00 49 00 48 00 61 00 63 00 63 00 37 00 64 00 56 00 4c 00 48 00 73 00 72 00 64 00 64 00 75 00 34 00 55 00 44 00 6a 00 69 00 48 00 47 00 46 00 64 00 76 00 58 00 6a 00 42 00 35 00 35 00 4e 00 77 00 65 00 35 00 63 00 75 00 31 00 42 00 59 00 79 00 6c 00 48 00 73 00 41 00 52 00 4d 00 59 00 79 00 63 00 42 00 41 00 32 00 46 00 77 00 4c 00 50 00 35 00 37 00 63 00 4b 00 76 00 63 00 32 00 2f 00 43 00 33 00 4f 00 58 00 42 00 41 00 46 00 36 00 71 00 62 00 73 00 56 00 58 00 42 00 63 00 79 00 46 00 68 00 72 00 4b 00 4f 00 4f 00 59 00 41 00 2f 00 2b 00 35 00 49 00 6a 00 46 00 66 00 45 00 68 00 67 00 48 00 79 00 32 00 46 00 4c 00 48 00 52 00 66 00 38 00 6c 00 6d 00 50 00 51 00 50 00 62 00 53 00 6c 00 72 00 4d 00 36 00 64 00 6b 00 2b 00 57 00 34 00 44 00 35 00 4b 00 56 00 71 00 4f 00 50 00 78 00 2f 00 65 00 46 00 70 00 30 00 67 00 65 00 55 00 4a 00 4a 00 6c 00 6d 00 6c 00 72 00 65 00 33 00 66 00 6c 00 49 00 32 00 39 00 71 00 57 00 53 00 32 00 30 00 62 00 6b 00 47 00 71 00 41 00 45 00 7a 00 39 00 6a 00 30 00 37 00 79 00 36 00 39 00 48 00 47 00 59 00 4e 00 39 00 4e 00 74 00 37 00 2b 00 44 00 52 00 67 00 42 00 77 00 72 00 70 00 4e 00 6f 00 2f 00 45 00 6b 00 5a 00 6b 00 75 00 61 00 53 00 54 00 74 00 51 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk9 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 75 75 41 51 6c 6e 6f 77 53 47 61 53 69 32 58 67 6e 77 61 48 51 41 46 5a 36 65 37 43 30 53 77 70 41 79 79 4c 54 6e 63 4a 34 6c 35 63 77 46 62 4d 2b 6d 77 6e 56 2b 69 56 33 61 2b 65 72 74 38 57 71 4f 6d 57 31 61 4b 4f 43 6a 54 50 58 72 58 4e 6f 69 72 51 67 62 6f 56 70 4c 66 68 49 49 54 31 75 4f 4f 73 73 34 4f 38 6c 6f 64 52 78 67 42 36 51 72 4c 43 49 37 50 59 4d 5a 2b 38 56 67 49 64 45 50 50 7a 73 6a 6d 54 46 4c 78 46 63 37 44 45 52 78 6e 53 6a 68 47 64 52 51 49 6a 5a 4e 6a 6d 37 62 47 53 63 4a 44 30 4d 61 79 44 4c 39 4b 54 6b 56 64 4a 74 43 2b 43 39 6e 35 64 77 45 77 67 36 58 74 51 62 77 4c 44 65 61 47 5a 61 42 79 4f 67 42 2f 7a 52 36 74 6c 63 50 51 43 4e 55 39 72 6a 31 71 66 63 56 72 49 2f 64 46 57 34 62 72 2f 4e 6e 4a 62 71 72 48 37 31 34 7a 2b 64 76 43 61 31 38 49 4a 54 63 75 33 6b 57 37 34 43 41 69 6c 76 48 72 6c 35 71 46 44 64 38 43 43 51 68 6a 4c 72 6a 51 44 50 78 41 6f 43 62 61 39 61 58 4b 72 36 64 77 74 33 34 2f 4d 55 30 74 56 52 54 59 6a 7a 4d 41 78 52 34 79 54 68 33 6f 45 6a 56 54 2b 48 69 66 76 56 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 75 00 75 00 41 00 51 00 6c 00 6e 00 6f 00 77 00 53 00 47 00 61 00 53 00 69 00 32 00 58 00 67 00 6e 00 77 00 61 00 48 00 51 00 41 00 46 00 5a 00 36 00 65 00 37 00 43 00 30 00 53 00 77 00 70 00 41 00 79 00 79 00 4c 00 54 00 6e 00 63 00 4a 00 34 00 6c 00 35 00 63 00 77 00 46 00 62 00 4d 00 2b 00 6d 00 77 00 6e 00 56 00 2b 00 69 00 56 00 33 00 61 00 2b 00 65 00 72 00 74 00 38 00 57 00 71 00 4f 00 6d 00 57 00 31 00 61 00 4b 00 4f 00 43 00 6a 00 54 00 50 00 58 00 72 00 58 00 4e 00 6f 00 69 00 72 00 51 00 67 00 62 00 6f 00 56 00 70 00 4c 00 66 00 68 00 49 00 49 00 54 00 31 00 75 00 4f 00 4f 00 73 00 73 00 34 00 4f 00 38 00 6c 00 6f 00 64 00 52 00 78 00 67 00 42 00 36 00 51 00 72 00 4c 00 43 00 49 00 37 00 50 00 59 00 4d 00 5a 00 2b 00 38 00 56 00 67 00 49 00 64 00 45 00 50 00 50 00 7a 00 73 00 6a 00 6d 00 54 00 46 00 4c 00 78 00 46 00 63 00 37 00 44 00 45 00 52 00 78 00 6e 00 53 00 6a 00 68 00 47 00 64 00 52 00 51 00 49 00 6a 00 5a 00 4e 00 6a 00 6d 00 37 00 62 00 47 00 53 00 63 00 4a 00 44 00 30 00 4d 00 61 00 79 00 44 00 4c 00 39 00 4b 00 54 00 6b 00 56 00 64 00 4a 00 74 00 43 00 2b 00 43 00 39 00 6e 00 35 00 64 00 77 00 45 00 77 00 67 00 36 00 58 00 74 00 51 00 62 00 77 00 4c 00 44 00 65 00 61 00 47 00 5a 00 61 00 42 00 79 00 4f 00 67 00 42 00 2f 00 7a 00 52 00 36 00 74 00 6c 00 63 00 50 00 51 00 43 00 4e 00 55 00 39 00 72 00 6a 00 31 00 71 00 66 00 63 00 56 00 72 00 49 00 2f 00 64 00 46 00 57 00 34 00 62 00 72 00 2f 00 4e 00 6e 00 4a 00 62 00 71 00 72 00 48 00 37 00 31 00 34 00 7a 00 2b 00 64 00 76 00 43 00 61 00 31 00 38 00 49 00 4a 00 54 00 63 00 75 00 33 00 6b 00 57 00 37 00 34 00 43 00 41 00 69 00 6c 00 76 00 48 00 72 00 6c 00 35 00 71 00 46 00 44 00 64 00 38 00 43 00 43 00 51 00 68 00 6a 00 4c 00 72 00 6a 00 51 00 44 00 50 00 78 00 41 00 6f 00 43 00 62 00 61 00 39 00 61 00 58 00 4b 00 72 00 36 00 64 00 77 00 74 00 33 00 34 00 2f 00 4d 00 55 00 30 00 74 00 56 00 52 00 54 00 59 00 6a 00 7a 00 4d 00 41 00 78 00 52 00 34 00 79 00 54 00 68 00 33 00 6f 00 45 00 6a 00 56 00 54 00 2b 00 48 00 69 00 66 00 76 00 56 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk10 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 77 63 50 6a 6e 50 6c 38 62 49 31 41 30 69 75 64 58 37 30 46 4b 6b 54 6a 6e 4c 6a 48 79 65 74 48 4e 32 6b 41 49 63 79 4f 47 31 30 4b 38 76 6d 36 37 6e 2f 4d 61 39 6d 41 6e 6f 44 67 67 44 33 44 36 55 74 41 62 77 6a 76 48 77 50 57 31 6d 39 57 46 2b 4d 72 6e 42 58 6d 42 69 7a 45 30 4a 70 77 4f 4c 74 56 46 63 48 65 56 4c 4a 58 6c 59 6e 2f 43 35 52 4e 5a 7a 69 54 43 77 6a 61 75 48 36 54 6c 54 37 4d 6f 2f 6f 48 66 67 37 6e 58 34 49 58 45 75 61 65 41 5a 7a 38 67 39 69 6f 65 4a 31 4c 79 64 69 39 5a 5a 4d 31 67 6d 64 4e 6b 38 4b 75 4b 52 30 7a 72 72 4a 36 4d 4d 41 47 72 68 4d 74 62 6c 4c 46 56 77 74 4d 6e 37 49 6c 4e 6a 54 2f 42 67 53 4c 34 70 44 79 4e 61 2b 2b 77 49 35 50 34 52 32 72 4d 79 6b 4a 77 47 75 2f 37 6f 32 6b 4b 45 32 49 46 69 6d 74 46 44 79 5a 35 61 2b 43 58 34 36 63 64 4b 74 37 75 6f 35 65 4b 46 69 71 66 2f 6a 54 65 73 39 2f 79 35 41 67 6f 53 36 39 6d 74 34 66 52 76 57 46 68 50 37 71 48 58 52 4f 32 67 47 38 58 41 63 2b 39 73 75 68 69 75 56 55 57 5a 54 41 75 33 78 58 7a 35 56 73 6d 42 74 6b 38 70 7a 63 70 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 77 00 63 00 50 00 6a 00 6e 00 50 00 6c 00 38 00 62 00 49 00 31 00 41 00 30 00 69 00 75 00 64 00 58 00 37 00 30 00 46 00 4b 00 6b 00 54 00 6a 00 6e 00 4c 00 6a 00 48 00 79 00 65 00 74 00 48 00 4e 00 32 00 6b 00 41 00 49 00 63 00 79 00 4f 00 47 00 31 00 30 00 4b 00 38 00 76 00 6d 00 36 00 37 00 6e 00 2f 00 4d 00 61 00 39 00 6d 00 41 00 6e 00 6f 00 44 00 67 00 67 00 44 00 33 00 44 00 36 00 55 00 74 00 41 00 62 00 77 00 6a 00 76 00 48 00 77 00 50 00 57 00 31 00 6d 00 39 00 57 00 46 00 2b 00 4d 00 72 00 6e 00 42 00 58 00 6d 00 42 00 69 00 7a 00 45 00 30 00 4a 00 70 00 77 00 4f 00 4c 00 74 00 56 00 46 00 63 00 48 00 65 00 56 00 4c 00 4a 00 58 00 6c 00 59 00 6e 00 2f 00 43 00 35 00 52 00 4e 00 5a 00 7a 00 69 00 54 00 43 00 77 00 6a 00 61 00 75 00 48 00 36 00 54 00 6c 00 54 00 37 00 4d 00 6f 00 2f 00 6f 00 48 00 66 00 67 00 37 00 6e 00 58 00 34 00 49 00 58 00 45 00 75 00 61 00 65 00 41 00 5a 00 7a 00 38 00 67 00 39 00 69 00 6f 00 65 00 4a 00 31 00 4c 00 79 00 64 00 69 00 39 00 5a 00 5a 00 4d 00 31 00 67 00 6d 00 64 00 4e 00 6b 00 38 00 4b 00 75 00 4b 00 52 00 30 00 7a 00 72 00 72 00 4a 00 36 00 4d 00 4d 00 41 00 47 00 72 00 68 00 4d 00 74 00 62 00 6c 00 4c 00 46 00 56 00 77 00 74 00 4d 00 6e 00 37 00 49 00 6c 00 4e 00 6a 00 54 00 2f 00 42 00 67 00 53 00 4c 00 34 00 70 00 44 00 79 00 4e 00 61 00 2b 00 2b 00 77 00 49 00 35 00 50 00 34 00 52 00 32 00 72 00 4d 00 79 00 6b 00 4a 00 77 00 47 00 75 00 2f 00 37 00 6f 00 32 00 6b 00 4b 00 45 00 32 00 49 00 46 00 69 00 6d 00 74 00 46 00 44 00 79 00 5a 00 35 00 61 00 2b 00 43 00 58 00 34 00 36 00 63 00 64 00 4b 00 74 00 37 00 75 00 6f 00 35 00 65 00 4b 00 46 00 69 00 71 00 66 00 2f 00 6a 00 54 00 65 00 73 00 39 00 2f 00 79 00 35 00 41 00 67 00 6f 00 53 00 36 00 39 00 6d 00 74 00 34 00 66 00 52 00 76 00 57 00 46 00 68 00 50 00 37 00 71 00 48 00 58 00 52 00 4f 00 32 00 67 00 47 00 38 00 58 00 41 00 63 00 2b 00 39 00 73 00 75 00 68 00 69 00 75 00 56 00 55 00 57 00 5a 00 54 00 41 00 75 00 33 00 78 00 58 00 7a 00 35 00 56 00 73 00 6d 00 42 00 74 00 6b 00 38 00 70 00 7a 00 63 00 70 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk11 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 77 4d 51 58 46 4d 74 59 66 36 30 4b 72 62 55 56 77 4e 56 6f 50 68 68 72 43 54 4e 4d 59 33 5a 76 2b 2f 57 55 4c 5a 52 5a 66 4a 34 64 4d 68 59 6f 7a 44 78 74 52 56 64 74 42 44 4b 74 75 59 75 48 43 47 4c 75 2f 59 6d 66 39 77 4b 46 46 58 67 56 48 33 45 6e 37 71 49 31 73 55 32 55 64 6a 4e 52 34 30 38 36 58 38 6f 53 54 4d 55 6e 2f 47 77 45 41 45 49 5a 41 48 74 53 46 75 6b 36 41 58 63 58 57 2b 65 4f 30 79 78 50 46 2b 6c 74 35 41 5a 63 4e 6e 4a 6f 63 57 42 56 5a 38 52 57 47 76 73 51 64 74 47 67 74 5a 61 6c 74 74 41 79 6e 52 4f 43 34 52 55 47 6b 76 44 31 68 31 73 73 4d 74 65 48 57 6e 65 46 4c 70 66 7a 53 50 47 6c 62 75 30 73 30 63 65 6d 73 72 54 50 6d 68 65 78 47 49 65 6e 75 70 2f 59 6a 4e 64 6d 68 62 66 76 76 59 45 39 6b 5a 66 50 65 62 47 74 5a 48 77 36 6f 51 58 57 63 47 37 73 41 6c 76 6b 47 63 69 4a 6c 33 45 6f 39 46 7a 6e 4e 6a 30 4b 2b 76 38 57 51 57 35 4c 2f 55 62 6f 73 5a 61 59 56 4a 62 78 6c 62 74 79 53 76 71 55 71 5a 62 6b 4c 4b 73 6d 70 39 31 74 72 39 62 76 54 69 44 4d 5a 75 58 5a 53 37 69 48 56 71 63 68 55 51 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 77 00 4d 00 51 00 58 00 46 00 4d 00 74 00 59 00 66 00 36 00 30 00 4b 00 72 00 62 00 55 00 56 00 77 00 4e 00 56 00 6f 00 50 00 68 00 68 00 72 00 43 00 54 00 4e 00 4d 00 59 00 33 00 5a 00 76 00 2b 00 2f 00 57 00 55 00 4c 00 5a 00 52 00 5a 00 66 00 4a 00 34 00 64 00 4d 00 68 00 59 00 6f 00 7a 00 44 00 78 00 74 00 52 00 56 00 64 00 74 00 42 00 44 00 4b 00 74 00 75 00 59 00 75 00 48 00 43 00 47 00 4c 00 75 00 2f 00 59 00 6d 00 66 00 39 00 77 00 4b 00 46 00 46 00 58 00 67 00 56 00 48 00 33 00 45 00 6e 00 37 00 71 00 49 00 31 00 73 00 55 00 32 00 55 00 64 00 6a 00 4e 00 52 00 34 00 30 00 38 00 36 00 58 00 38 00 6f 00 53 00 54 00 4d 00 55 00 6e 00 2f 00 47 00 77 00 45 00 41 00 45 00 49 00 5a 00 41 00 48 00 74 00 53 00 46 00 75 00 6b 00 36 00 41 00 58 00 63 00 58 00 57 00 2b 00 65 00 4f 00 30 00 79 00 78 00 50 00 46 00 2b 00 6c 00 74 00 35 00 41 00 5a 00 63 00 4e 00 6e 00 4a 00 6f 00 63 00 57 00 42 00 56 00 5a 00 38 00 52 00 57 00 47 00 76 00 73 00 51 00 64 00 74 00 47 00 67 00 74 00 5a 00 61 00 6c 00 74 00 74 00 41 00 79 00 6e 00 52 00 4f 00 43 00 34 00 52 00 55 00 47 00 6b 00 76 00 44 00 31 00 68 00 31 00 73 00 73 00 4d 00 74 00 65 00 48 00 57 00 6e 00 65 00 46 00 4c 00 70 00 66 00 7a 00 53 00 50 00 47 00 6c 00 62 00 75 00 30 00 73 00 30 00 63 00 65 00 6d 00 73 00 72 00 54 00 50 00 6d 00 68 00 65 00 78 00 47 00 49 00 65 00 6e 00 75 00 70 00 2f 00 59 00 6a 00 4e 00 64 00 6d 00 68 00 62 00 66 00 76 00 76 00 59 00 45 00 39 00 6b 00 5a 00 66 00 50 00 65 00 62 00 47 00 74 00 5a 00 48 00 77 00 36 00 6f 00 51 00 58 00 57 00 63 00 47 00 37 00 73 00 41 00 6c 00 76 00 6b 00 47 00 63 00 69 00 4a 00 6c 00 33 00 45 00 6f 00 39 00 46 00 7a 00 6e 00 4e 00 6a 00 30 00 4b 00 2b 00 76 00 38 00 57 00 51 00 57 00 35 00 4c 00 2f 00 55 00 62 00 6f 00 73 00 5a 00 61 00 59 00 56 00 4a 00 62 00 78 00 6c 00 62 00 74 00 79 00 53 00 76 00 71 00 55 00 71 00 5a 00 62 00 6b 00 4c 00 4b 00 73 00 6d 00 70 00 39 00 31 00 74 00 72 00 39 00 62 00 76 00 54 00 69 00 44 00 4d 00 5a 00 75 00 58 00 5a 00 53 00 37 00 69 00 48 00 56 00 71 00 63 00 68 00 55 00 51 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$pk12 = {((4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 78 62 4b 56 78 77 59 65 34 50 70 6e 50 6d 30 58 74 75 71 53 68 44 71 46 57 43 46 52 42 77 30 74 59 6f 32 76 6d 4c 77 56 50 6c 77 61 2b 30 2b 6f 78 38 2b 6e 46 30 6d 7a 57 43 33 5a 5a 54 32 58 6b 47 53 6f 64 73 7a 6f 73 4f 6f 6f 63 66 4b 41 77 4f 6a 51 6e 41 2b 34 2f 48 6f 6b 6c 34 68 67 47 36 4b 38 4f 37 77 57 75 57 6c 76 67 6f 34 66 6b 63 5a 53 68 79 32 63 4d 59 39 46 61 43 36 65 34 62 4d 66 75 72 6c 44 46 74 37 4f 56 72 4b 4b 57 41 79 45 47 76 34 39 45 74 71 36 4c 4e 6f 79 6c 35 64 64 4d 2f 58 6d 73 70 47 35 32 67 73 63 52 6f 49 63 4f 54 77 42 4c 34 62 44 38 6e 56 63 61 6d 5a 58 71 45 34 6a 32 6d 53 36 32 48 69 63 51 36 71 39 59 67 52 56 73 31 50 4c 62 67 56 50 62 67 38 63 32 72 46 7a 70 4e 31 65 38 77 5a 64 50 74 76 79 47 4f 4e 30 6d 33 43 6d 78 73 59 61 36 33 79 69 61 6e 62 6e 42 41 53 34 57 6e 78 45 6e 6f 49 37 65 43 5a 5a 4e 6b 62 6c 72 2b 6b 5a 42 34 4a 39 57 61 72 35 56 59 48 75 39 6c 46 77 34 58 57 65 75 48 67 65 74 2f 52 6e 38 6f 47 43 4a 4f 4d 48 6b 5a 4d 7a 32 33 4e 70 55 56 61 58 39 68 74 51 41 77 49 44 41 51 41 42) | (4d 00 49 00 49 00 42 00 49 00 6a 00 41 00 4e 00 42 00 67 00 6b 00 71 00 68 00 6b 00 69 00 47 00 39 00 77 00 30 00 42 00 41 00 51 00 45 00 46 00 41 00 41 00 4f 00 43 00 41 00 51 00 38 00 41 00 4d 00 49 00 49 00 42 00 43 00 67 00 4b 00 43 00 41 00 51 00 45 00 41 00 78 00 62 00 4b 00 56 00 78 00 77 00 59 00 65 00 34 00 50 00 70 00 6e 00 50 00 6d 00 30 00 58 00 74 00 75 00 71 00 53 00 68 00 44 00 71 00 46 00 57 00 43 00 46 00 52 00 42 00 77 00 30 00 74 00 59 00 6f 00 32 00 76 00 6d 00 4c 00 77 00 56 00 50 00 6c 00 77 00 61 00 2b 00 30 00 2b 00 6f 00 78 00 38 00 2b 00 6e 00 46 00 30 00 6d 00 7a 00 57 00 43 00 33 00 5a 00 5a 00 54 00 32 00 58 00 6b 00 47 00 53 00 6f 00 64 00 73 00 7a 00 6f 00 73 00 4f 00 6f 00 6f 00 63 00 66 00 4b 00 41 00 77 00 4f 00 6a 00 51 00 6e 00 41 00 2b 00 34 00 2f 00 48 00 6f 00 6b 00 6c 00 34 00 68 00 67 00 47 00 36 00 4b 00 38 00 4f 00 37 00 77 00 57 00 75 00 57 00 6c 00 76 00 67 00 6f 00 34 00 66 00 6b 00 63 00 5a 00 53 00 68 00 79 00 32 00 63 00 4d 00 59 00 39 00 46 00 61 00 43 00 36 00 65 00 34 00 62 00 4d 00 66 00 75 00 72 00 6c 00 44 00 46 00 74 00 37 00 4f 00 56 00 72 00 4b 00 4b 00 57 00 41 00 79 00 45 00 47 00 76 00 34 00 39 00 45 00 74 00 71 00 36 00 4c 00 4e 00 6f 00 79 00 6c 00 35 00 64 00 64 00 4d 00 2f 00 58 00 6d 00 73 00 70 00 47 00 35 00 32 00 67 00 73 00 63 00 52 00 6f 00 49 00 63 00 4f 00 54 00 77 00 42 00 4c 00 34 00 62 00 44 00 38 00 6e 00 56 00 63 00 61 00 6d 00 5a 00 58 00 71 00 45 00 34 00 6a 00 32 00 6d 00 53 00 36 00 32 00 48 00 69 00 63 00 51 00 36 00 71 00 39 00 59 00 67 00 52 00 56 00 73 00 31 00 50 00 4c 00 62 00 67 00 56 00 50 00 62 00 67 00 38 00 63 00 32 00 72 00 46 00 7a 00 70 00 4e 00 31 00 65 00 38 00 77 00 5a 00 64 00 50 00 74 00 76 00 79 00 47 00 4f 00 4e 00 30 00 6d 00 33 00 43 00 6d 00 78 00 73 00 59 00 61 00 36 00 33 00 79 00 69 00 61 00 6e 00 62 00 6e 00 42 00 41 00 53 00 34 00 57 00 6e 00 78 00 45 00 6e 00 6f 00 49 00 37 00 65 00 43 00 5a 00 5a 00 4e 00 6b 00 62 00 6c 00 72 00 2b 00 6b 00 5a 00 42 00 34 00 4a 00 39 00 57 00 61 00 72 00 35 00 56 00 59 00 48 00 75 00 39 00 6c 00 46 00 77 00 34 00 58 00 57 00 65 00 75 00 48 00 67 00 65 00 74 00 2f 00 52 00 6e 00 38 00 6f 00 47 00 43 00 4a 00 4f 00 4d 00 48 00 6b 00 5a 00 4d 00 7a 00 32 00 33 00 4e 00 70 00 55 00 56 00 61 00 58 00 39 00 68 00 74 00 51 00 41 00 77 00 49 00 44 00 41 00 51 00 41 00 42 00))}
		$url1 = {((3a 2f 2f 7a 75 6a 67 7a 62 75 35 79 36 34 78 62 6d 76 63 34 32 61 64 64 70 34 6c 78 6b 6f 6f 73 62 34 74 73 6c 66 35 6d 65 68 6e 68 37 70 76 71 6a 70 77 78 6e 35 67 6f 6b 79 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 7a 00 75 00 6a 00 67 00 7a 00 62 00 75 00 35 00 79 00 36 00 34 00 78 00 62 00 6d 00 76 00 63 00 34 00 32 00 61 00 64 00 64 00 70 00 34 00 6c 00 78 00 6b 00 6f 00 6f 00 73 00 62 00 34 00 74 00 73 00 6c 00 66 00 35 00 6d 00 65 00 68 00 6e 00 68 00 37 00 70 00 76 00 71 00 6a 00 70 00 77 00 78 00 6e 00 35 00 67 00 6f 00 6b 00 79 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url2 = {((3a 2f 2f 61 6c 70 68 76 6d 6d 6d 32 37 6f 33 61 62 6f 33 72 32 6d 6c 6d 6a 72 70 64 6d 7a 6c 65 33 72 79 6b 61 6a 71 63 35 78 73 6a 37 6a 37 65 6a 6b 73 62 70 73 61 33 36 61 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 61 00 6c 00 70 00 68 00 76 00 6d 00 6d 00 6d 00 32 00 37 00 6f 00 33 00 61 00 62 00 6f 00 33 00 72 00 32 00 6d 00 6c 00 6d 00 6a 00 72 00 70 00 64 00 6d 00 7a 00 6c 00 65 00 33 00 72 00 79 00 6b 00 61 00 6a 00 71 00 63 00 35 00 78 00 73 00 6a 00 37 00 6a 00 37 00 65 00 6a 00 6b 00 73 00 62 00 70 00 73 00 61 00 33 00 36 00 61 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url3 = {((3a 2f 2f 32 63 75 71 67 65 65 72 6a 64 62 61 32 72 68 64 69 76 69 65 7a 6f 64 70 75 33 6c 63 34 71 7a 32 73 6a 66 34 71 69 6e 36 66 37 73 74 64 32 65 76 6c 65 71 6c 7a 6a 69 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 32 00 63 00 75 00 71 00 67 00 65 00 65 00 72 00 6a 00 64 00 62 00 61 00 32 00 72 00 68 00 64 00 69 00 76 00 69 00 65 00 7a 00 6f 00 64 00 70 00 75 00 33 00 6c 00 63 00 34 00 71 00 7a 00 32 00 73 00 6a 00 66 00 34 00 71 00 69 00 6e 00 36 00 66 00 37 00 73 00 74 00 64 00 32 00 65 00 76 00 6c 00 65 00 71 00 6c 00 7a 00 6a 00 69 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url4 = {((3a 2f 2f 61 6f 63 7a 70 70 6f 78 6d 66 71 71 74 68 74 77 6c 77 69 34 66 6d 7a 6c 72 76 36 61 6f 72 33 69 73 6e 36 66 66 61 69 69 63 35 35 77 72 66 75 6d 78 73 6c 78 33 76 79 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 61 00 6f 00 63 00 7a 00 70 00 70 00 6f 00 78 00 6d 00 66 00 71 00 71 00 74 00 68 00 74 00 77 00 6c 00 77 00 69 00 34 00 66 00 6d 00 7a 00 6c 00 72 00 76 00 36 00 61 00 6f 00 72 00 33 00 69 00 73 00 6e 00 36 00 66 00 66 00 61 00 69 00 69 00 63 00 35 00 35 00 77 00 72 00 66 00 75 00 6d 00 78 00 73 00 6c 00 78 00 33 00 76 00 79 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url5 = {((3a 2f 2f 62 34 74 77 71 61 32 6d 76 6f 62 33 73 36 75 76 75 79 66 72 61 35 78 6b 33 71 67 70 73 32 76 35 6b 6b 74 37 6b 32 71 6e 62 37 72 70 64 75 33 6a 34 66 6b 6e 74 65 61 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 62 00 34 00 74 00 77 00 71 00 61 00 32 00 6d 00 76 00 6f 00 62 00 33 00 73 00 36 00 75 00 76 00 75 00 79 00 66 00 72 00 61 00 35 00 78 00 6b 00 33 00 71 00 67 00 70 00 73 00 32 00 76 00 35 00 6b 00 6b 00 74 00 37 00 6b 00 32 00 71 00 6e 00 62 00 37 00 72 00 70 00 64 00 75 00 33 00 6a 00 34 00 66 00 6b 00 6e 00 74 00 65 00 61 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url6 = {((3a 2f 2f 62 36 76 34 6f 6a 73 37 6a 66 76 66 74 76 63 6f 61 67 6a 78 70 37 71 7a 33 33 79 65 6c 6a 79 64 71 79 36 61 66 7a 73 68 32 36 76 71 62 7a 63 6a 77 7a 34 62 33 7a 61 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 62 00 36 00 76 00 34 00 6f 00 6a 00 73 00 37 00 6a 00 66 00 76 00 66 00 74 00 76 00 63 00 6f 00 61 00 67 00 6a 00 78 00 70 00 37 00 71 00 7a 00 33 00 33 00 79 00 65 00 6c 00 6a 00 79 00 64 00 71 00 79 00 36 00 61 00 66 00 7a 00 73 00 68 00 32 00 36 00 76 00 71 00 62 00 7a 00 63 00 6a 00 77 00 7a 00 34 00 62 00 33 00 7a 00 61 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url7 = {((3a 2f 2f 68 74 6e 70 61 66 7a 62 76 64 64 72 32 6c 6c 73 74 77 62 6a 6f 75 75 70 64 64 66 6c 71 6d 37 79 37 63 72 37 74 63 63 68 62 65 6f 36 72 6d 78 70 71 6f 78 63 62 71 71 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 68 00 74 00 6e 00 70 00 61 00 66 00 7a 00 62 00 76 00 64 00 64 00 72 00 32 00 6c 00 6c 00 73 00 74 00 77 00 62 00 6a 00 6f 00 75 00 75 00 70 00 64 00 64 00 66 00 6c 00 71 00 6d 00 37 00 79 00 37 00 63 00 72 00 37 00 74 00 63 00 63 00 68 00 62 00 65 00 6f 00 36 00 72 00 6d 00 78 00 70 00 71 00 6f 00 78 00 63 00 62 00 71 00 71 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url8 = {((3a 2f 2f 69 64 37 73 65 65 78 6a 6e 34 62 6f 6a 6e 35 72 76 6f 34 6c 77 63 6a 67 75 66 6a 7a 37 67 6b 69 73 61 69 64 63 6b 61 75 78 33 75 76 6a 63 37 6c 37 78 72 73 69 71 61 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 69 00 64 00 37 00 73 00 65 00 65 00 78 00 6a 00 6e 00 34 00 62 00 6f 00 6a 00 6e 00 35 00 72 00 76 00 6f 00 34 00 6c 00 77 00 63 00 6a 00 67 00 75 00 66 00 6a 00 7a 00 37 00 67 00 6b 00 69 00 73 00 61 00 69 00 64 00 63 00 6b 00 61 00 75 00 78 00 33 00 75 00 76 00 6a 00 63 00 37 00 6c 00 37 00 78 00 72 00 73 00 69 00 71 00 61 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url9 = {((3a 2f 2f 6d 75 37 35 6c 74 76 33 6c 78 64 32 34 64 62 79 75 36 67 74 76 6d 6e 77 79 62 65 63 69 67 73 35 61 75 6b 69 37 66 63 65 73 34 33 37 78 76 76 66 6c 7a 76 61 32 6e 71 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 6d 00 75 00 37 00 35 00 6c 00 74 00 76 00 33 00 6c 00 78 00 64 00 32 00 34 00 64 00 62 00 79 00 75 00 36 00 67 00 74 00 76 00 6d 00 6e 00 77 00 79 00 62 00 65 00 63 00 69 00 67 00 73 00 35 00 61 00 75 00 6b 00 69 00 37 00 66 00 63 00 65 00 73 00 34 00 33 00 37 00 78 00 76 00 76 00 66 00 6c 00 7a 00 76 00 61 00 32 00 6e 00 71 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url10 = {((3a 2f 2f 6f 64 66 33 64 74 33 34 74 6b 71 6e 64 77 35 68 32 6c 35 67 74 32 67 77 77 64 33 6a 63 74 35 72 77 77 6a 75 73 62 64 33 76 6c 69 6e 32 6a 75 65 79 76 32 71 6b 67 69 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 6f 00 64 00 66 00 33 00 64 00 74 00 33 00 34 00 74 00 6b 00 71 00 6e 00 64 00 77 00 35 00 68 00 32 00 6c 00 35 00 67 00 74 00 32 00 67 00 77 00 77 00 64 00 33 00 6a 00 63 00 74 00 35 00 72 00 77 00 77 00 6a 00 75 00 73 00 62 00 64 00 33 00 76 00 6c 00 69 00 6e 00 32 00 6a 00 75 00 65 00 79 00 76 00 32 00 71 00 6b 00 67 00 69 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url11 = {((3a 2f 2f 72 66 6f 73 75 73 6c 36 71 64 6d 34 7a 68 6f 71 62 71 6e 6a 78 61 6c 6f 70 72 6c 64 32 71 7a 33 35 75 37 37 68 34 61 61 70 34 36 72 68 77 6b 6f 75 65 6a 73 6f 6f 71 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 72 00 66 00 6f 00 73 00 75 00 73 00 6c 00 36 00 71 00 64 00 6d 00 34 00 7a 00 68 00 6f 00 71 00 62 00 71 00 6e 00 6a 00 78 00 61 00 6c 00 6f 00 70 00 72 00 6c 00 64 00 32 00 71 00 7a 00 33 00 35 00 75 00 37 00 37 00 68 00 34 00 61 00 61 00 70 00 34 00 36 00 72 00 68 00 77 00 6b 00 6f 00 75 00 65 00 6a 00 73 00 6f 00 6f 00 71 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url12 = {((3a 2f 2f 73 74 79 35 72 34 68 68 62 35 6f 69 68 62 71 32 6d 77 65 76 72 6f 66 64 69 71 62 67 65 73 69 36 36 72 76 78 72 35 73 72 35 37 33 78 67 76 74 75 76 72 34 63 73 35 79 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 73 00 74 00 79 00 35 00 72 00 34 00 68 00 68 00 62 00 35 00 6f 00 69 00 68 00 62 00 71 00 32 00 6d 00 77 00 65 00 76 00 72 00 6f 00 66 00 64 00 69 00 71 00 62 00 67 00 65 00 73 00 69 00 36 00 36 00 72 00 76 00 78 00 72 00 35 00 73 00 72 00 35 00 37 00 33 00 78 00 67 00 76 00 74 00 75 00 76 00 72 00 34 00 63 00 73 00 35 00 79 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url13 = {((3a 2f 2f 78 71 6f 79 6b 65 6d 6d 63 69 76 77 74 70 78 68 33 61 36 70 75 33 77 37 73 73 74 72 32 79 37 68 61 70 78 64 69 76 34 63 61 61 78 69 64 75 72 6d 77 77 62 6a 78 32 69 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 78 00 71 00 6f 00 79 00 6b 00 65 00 6d 00 6d 00 63 00 69 00 76 00 77 00 74 00 70 00 78 00 68 00 33 00 61 00 36 00 70 00 75 00 33 00 77 00 37 00 73 00 73 00 74 00 72 00 32 00 79 00 37 00 68 00 61 00 70 00 78 00 64 00 69 00 76 00 34 00 63 00 61 00 61 00 78 00 69 00 64 00 75 00 72 00 6d 00 77 00 77 00 62 00 6a 00 78 00 32 00 69 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}
		$url14 = {((3a 2f 2f 79 34 37 32 32 73 73 36 34 76 65 6c 35 68 6d 70 68 37 35 74 65 37 6c 78 32 78 35 78 7a 34 36 33 33 32 32 79 70 6a 69 72 6d 35 79 74 78 76 69 69 6a 74 64 70 79 62 69 64 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 79 00 34 00 37 00 32 00 32 00 73 00 73 00 36 00 34 00 76 00 65 00 6c 00 35 00 68 00 6d 00 70 00 68 00 37 00 35 00 74 00 65 00 37 00 6c 00 78 00 32 00 78 00 35 00 78 00 7a 00 34 00 36 00 33 00 33 00 32 00 32 00 79 00 70 00 6a 00 69 00 72 00 6d 00 35 00 79 00 74 00 78 00 76 00 69 00 69 00 6a 00 74 00 64 00 70 00 79 00 62 00 69 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}

	condition:
		(1 of ( $pk* ) and 1 of ( $url* ) )
}

rule INDICATOR_KB_ID_Ransomware_Koxic : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with LokiLocker ransomware"

	strings:
		$s1 = {((77 69 6c 68 65 6c 6d 6b 6f 78 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (77 00 69 00 6c 00 68 00 65 00 6c 00 6d 00 6b 00 6f 00 78 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((46 33 43 37 37 37 44 32 32 41 30 36 38 36 30 35 35 41 33 35 35 38 39 31 37 33 31 35 36 37 36 44 36 30 37 30 32 36 42 36 38 30 44 41 35 43 38 44 33 44 34 44 38 38 37 30 31 37 41 32 41 38 34 34 46 35 34 36 41 45 35 39 46 35 39 46) | (46 00 33 00 43 00 37 00 37 00 37 00 44 00 32 00 32 00 41 00 30 00 36 00 38 00 36 00 30 00 35 00 35 00 41 00 33 00 35 00 35 00 38 00 39 00 31 00 37 00 33 00 31 00 35 00 36 00 37 00 36 00 44 00 36 00 30 00 37 00 30 00 32 00 36 00 42 00 36 00 38 00 30 00 44 00 41 00 35 00 43 00 38 00 44 00 33 00 44 00 34 00 44 00 38 00 38 00 37 00 30 00 31 00 37 00 41 00 32 00 41 00 38 00 34 00 34 00 46 00 35 00 34 00 36 00 41 00 45 00 35 00 39 00 46 00 35 00 39 00 46 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Ryuk : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Ryuk ransomware"

	strings:
		$s1 = {((57 61 79 6e 65 45 76 65 6e 73 6f 6e 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (57 00 61 00 79 00 6e 00 65 00 45 00 76 00 65 00 6e 00 73 00 6f 00 6e 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((57 61 79 6e 65 45 76 65 6e 73 6f 6e 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (57 00 61 00 79 00 6e 00 65 00 45 00 76 00 65 00 6e 00 73 00 6f 00 6e 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((31 34 68 56 4b 6d 37 46 74 32 72 78 44 42 46 54 4e 6b 6b 52 43 33 6b 47 73 74 4d 47 70 32 41 34 68 6b) | (31 00 34 00 68 00 56 00 4b 00 6d 00 37 00 46 00 74 00 32 00 72 00 78 00 44 00 42 00 46 00 54 00 4e 00 6b 00 6b 00 52 00 43 00 33 00 6b 00 47 00 73 00 74 00 4d 00 47 00 70 00 32 00 41 00 34 00 68 00 6b 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_LockDown : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with LockDown / cantopen ransomware"

	strings:
		$s1 = {((43 43 57 68 69 74 65 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (43 00 43 00 57 00 68 00 69 00 74 00 65 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s2 = {((62 63 31 71 36 75 67 30 76 72 78 7a 36 36 64 35 36 34 71 7a 6e 63 6c 75 39 79 79 79 76 6e 36 7a 75 72 73 6b 65 7a 6d 74 36 34) | (62 00 63 00 31 00 71 00 36 00 75 00 67 00 30 00 76 00 72 00 78 00 7a 00 36 00 36 00 64 00 35 00 36 00 34 00 71 00 7a 00 6e 00 63 00 6c 00 75 00 39 00 79 00 79 00 79 00 76 00 6e 00 36 00 7a 00 75 00 72 00 73 00 6b 00 65 00 7a 00 6d 00 74 00 36 00 34 00))}

	condition:
		any of them
}

rule INDICATOR_KB_LNK_BOI_MAC : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Windows Shortcut .lnk files with previously known bad Birth Object ID and MAC address combination"

	strings:
		$boi1 = { 2C ED AC EC 94 7A E8 11 9F DE 00 0C 29 A1 A9 40 }
		$boi2 = { 3F 54 89 18 46 CB E8 11 BD 0E 08 00 27 6D D5 D9 }
		$boi3 = { DE 63 02 FE 57 A2 E8 11 92 E8 5C F3 70 8B 16 F2 }
		$boi4 = { C2 CC 13 98 18 B9 E2 41 82 40 54 A8 AD E2 0A 9A }
		$boi5 = { C4 9D 3A D4 C2 29 3D 47 A9 20 EE A4 D8 A7 D8 7D }
		$boi6 = { E4 51 EC 20 66 61 EA 11 85 CD B2 FC 36 31 EE 21 }
		$boi7 = { 6E DD CE 86 0F 07 90 4B AF 18 38 2F 97 FB 53 62 }
		$boi8 = { 25 41 87 AE F1 D2 EA 11 93 97 00 50 56 C0 00 08 }
		$boi9 = { C4 9D 3A D4 C2 29 3D 47 A9 20 EE A4 D8 A7 D8 7D }
		$boi10 = { 5C 46 EC 05 A6 60 EB 11 85 EB 8C 16 45 31 19 7F }
		$boi11 = { 30 8B 17 86 9B 35 C5 40 A7 9D 48 5C D6 3D F3 5C }
		$boi12 = { E5 21 1D 04 9D A4 E9 11 A9 37 00 0C 29 0F 29 89 }
		$boi13 = { 34 5F AC 8A 4E CE ED 4D 8E 55 83 8E EA 24 B3 4E }
		$boi14 = { 49 77 25 3B D6 E1 EB 11 9C BB 00 D8 61 85 FD 9F }
		$mac1 = { 00 0C 29 A1 A9 40 }
		$mac2 = { 08 00 27 6D D5 D9 }
		$mac3 = { 5C F3 70 8B 16 F2 }
		$mac4 = { 00 0C 29 5A 39 04 }
		$mac5 = { B2 FC 36 31 EE 21 }
		$mac6 = { 00 50 56 C0 00 08 }
		$mac7 = { 8C 16 45 31 19 7F }
		$mac8 = { 00 0C 29 0F 29 89 }
		$mac9 = { 00 D8 61 85 FD 9F }

	condition:
		uint16( 0 ) == 0x004c and uint32( 4 ) == 0x00021401 and filesize < 3KB and ( 1 of ( $boi* ) and 1 of ( $mac* ) )
}

rule INDICATOR_KB_ID_PowerShellSMTPKeyLogger : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects email accounts used for exfiltration observed in PowerShellSMTPKeyLogger"

	strings:
		$s1 = {((74 69 6e 79 74 69 6d 31 30 31 31 30 31 31 30 40 67 6d 61 69 6c 2e 63 6f 6d) | (74 00 69 00 6e 00 79 00 74 00 69 00 6d 00 31 00 30 00 31 00 31 00 30 00 31 00 31 00 30 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((6e 6f 72 65 70 6c 61 79 2e 69 6e 66 6f 2e 30 31 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 6f 00 72 00 65 00 70 00 6c 00 61 00 79 00 2e 00 69 00 6e 00 66 00 6f 00 2e 00 30 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((6b 72 7a 61 72 70 6f 6e 40 6d 61 69 6c 2e 63 6f 6d) | (6b 00 72 00 7a 00 61 00 72 00 70 00 6f 00 6e 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((6d 2e 73 75 6d 61 72 65 65 2e 32 30 31 39 40 67 6d 61 69 6c 2e 63 6f 6d) | (6d 00 2e 00 73 00 75 00 6d 00 61 00 72 00 65 00 65 00 2e 00 32 00 30 00 31 00 39 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((6a 6f 65 7a 61 6f 6e 6c 79 40 6d 61 69 6c 2e 63 6f 6d) | (6a 00 6f 00 65 00 7a 00 61 00 6f 00 6e 00 6c 00 79 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((73 65 74 69 61 61 64 69 6e 32 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 65 00 74 00 69 00 61 00 61 00 64 00 69 00 6e 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((6e 61 73 74 61 69 6e 2e 61 6e 6e 61 73 38 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 61 00 73 00 74 00 61 00 69 00 6e 00 2e 00 61 00 6e 00 6e 00 61 00 73 00 38 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s8 = {((66 65 66 2e 66 65 64 65 72 66 69 63 6f 40 67 6d 61 69 6c 2e 63 6f 6d) | (66 00 65 00 66 00 2e 00 66 00 65 00 64 00 65 00 72 00 66 00 69 00 63 00 6f 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s9 = {((69 6d 61 63 61 74 61 6e 64 61 64 6f 67 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (69 00 6d 00 61 00 63 00 61 00 74 00 61 00 6e 00 64 00 61 00 64 00 6f 00 67 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s10 = {((76 61 72 75 6e 2e 73 61 32 30 30 37 40 67 6d 61 69 6c 2e 63 6f 6d) | (76 00 61 00 72 00 75 00 6e 00 2e 00 73 00 61 00 32 00 30 00 30 00 37 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s11 = {((74 68 65 66 6f 67 5f 36 36 40 79 61 68 6f 6f 2e 63 6f 6d) | (74 00 68 00 65 00 66 00 6f 00 67 00 5f 00 36 00 36 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$s12 = {((61 62 64 75 6c 6c 61 2e 61 62 6f 75 73 61 69 66 40 67 6d 61 69 6c 2e 63 6f 6d) | (61 00 62 00 64 00 75 00 6c 00 6c 00 61 00 2e 00 61 00 62 00 6f 00 75 00 73 00 61 00 69 00 66 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s13 = {((6e 61 73 74 61 69 6e 2e 61 6e 6e 61 73 32 30 31 39 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 61 00 73 00 74 00 61 00 69 00 6e 00 2e 00 61 00 6e 00 6e 00 61 00 73 00 32 00 30 00 31 00 39 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s14 = {((64 65 66 65 6e 73 61 75 73 65 72 31 40 67 6d 61 69 6c 2e 63 6f 6d) | (64 00 65 00 66 00 65 00 6e 00 73 00 61 00 75 00 73 00 65 00 72 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s15 = {((64 65 66 65 6e 73 61 75 73 65 72 32 40 67 6d 61 69 6c 2e 63 6f 6d) | (64 00 65 00 66 00 65 00 6e 00 73 00 61 00 75 00 73 00 65 00 72 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s16 = {((6e 61 75 6a 69 65 6e 75 73 74 72 69 74 69 73 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 61 00 75 00 6a 00 69 00 65 00 6e 00 75 00 73 00 74 00 72 00 69 00 74 00 69 00 73 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s17 = {((67 65 72 61 73 6b 61 7a 6b 61 73 40 67 6d 61 69 6c 2e 63 6f 6d) | (67 00 65 00 72 00 61 00 73 00 6b 00 61 00 7a 00 6b 00 61 00 73 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s18 = {((6d 65 72 74 69 73 6e 69 65 74 67 61 79 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d) | (6d 00 65 00 72 00 74 00 69 00 73 00 6e 00 69 00 65 00 74 00 67 00 61 00 79 00 40 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s19 = {((6d 65 72 74 61 6b 64 61 67 30 36 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d) | (6d 00 65 00 72 00 74 00 61 00 6b 00 64 00 61 00 67 00 30 00 36 00 40 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s20 = {((62 61 6c 62 6c 6c 6c 61 32 33 38 40 67 6d 61 69 6c 2e 63 6f 6d) | (62 00 61 00 6c 00 62 00 6c 00 6c 00 6c 00 61 00 32 00 33 00 38 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s21 = {((63 68 72 69 73 74 69 61 6e 2e 76 6f 72 68 6f 66 65 72 40 79 61 68 6f 6f 2e 64 65) | (63 00 68 00 72 00 69 00 73 00 74 00 69 00 61 00 6e 00 2e 00 76 00 6f 00 72 00 68 00 6f 00 66 00 65 00 72 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 64 00 65 00))}
		$s22 = {((65 73 74 75 64 75 70 79 40 67 6d 61 69 6c 2e 63 6f 6d) | (65 00 73 00 74 00 75 00 64 00 75 00 70 00 79 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s23 = {((6c 6f 6c 6d 61 63 74 65 75 72 31 40 67 6d 61 69 6c 2e 63 6f 6d) | (6c 00 6f 00 6c 00 6d 00 61 00 63 00 74 00 65 00 75 00 72 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s24 = {((6c 6f 6c 6d 61 63 74 65 75 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (6c 00 6f 00 6c 00 6d 00 61 00 63 00 74 00 65 00 75 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s25 = {((6f 75 68 6f 6f 2e 66 61 62 69 6f 40 67 6d 61 69 6c 2e 63 6f 6d) | (6f 00 75 00 68 00 6f 00 6f 00 2e 00 66 00 61 00 62 00 69 00 6f 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s36 = {((79 65 6e 67 68 65 6c 65 40 67 6d 61 69 6c 2e 63 6f 6d) | (79 00 65 00 6e 00 67 00 68 00 65 00 6c 00 65 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s37 = {((6d 72 34 32 68 61 63 6b 65 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (6d 00 72 00 34 00 32 00 68 00 61 00 63 00 6b 00 65 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s38 = {((67 6f 75 74 68 61 6d 73 30 32 34 40 67 6d 61 69 6c 2e 63 6f 6d) | (67 00 6f 00 75 00 74 00 68 00 61 00 6d 00 73 00 30 00 32 00 34 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s39 = {((61 6d 65 79 63 73 67 6f 40 67 6d 61 69 6c 2e 63 6f 6d) | (61 00 6d 00 65 00 79 00 63 00 73 00 67 00 6f 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s40 = {((6a 6f 73 65 6c 75 73 6f 76 40 67 6d 61 69 6c 2e 63 6f 6d) | (6a 00 6f 00 73 00 65 00 6c 00 75 00 73 00 6f 00 76 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s41 = {((6a 6f 73 65 6c 75 69 73 73 6f 76 40 67 6d 61 69 6c 2e 63 6f 6d) | (6a 00 6f 00 73 00 65 00 6c 00 75 00 69 00 73 00 73 00 6f 00 76 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s42 = {((74 6f 6e 69 74 72 61 76 65 6c 73 37 40 67 6d 61 69 6c 2e 63 6f 6d) | (74 00 6f 00 6e 00 69 00 74 00 72 00 61 00 76 00 65 00 6c 00 73 00 37 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s43 = {((6a 61 61 6e 75 73 70 61 61 6e 40 67 6d 61 69 6c 2e 63 6f 6d) | (6a 00 61 00 61 00 6e 00 75 00 73 00 70 00 61 00 61 00 6e 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s44 = {((70 61 73 74 61 6b 74 75 75 40 67 6d 61 69 6c 2e 63 6f 6d) | (70 00 61 00 73 00 74 00 61 00 6b 00 74 00 75 00 75 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s45 = {((61 63 68 79 75 74 68 61 2e 6e 72 31 30 40 67 6d 61 69 6c 2e 63 6f 6d) | (61 00 63 00 68 00 79 00 75 00 74 00 68 00 61 00 2e 00 6e 00 72 00 31 00 30 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s46 = {((6e 69 6b 61 6c 67 72 61 69 64 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 69 00 6b 00 61 00 6c 00 67 00 72 00 61 00 69 00 64 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s47 = {((75 73 65 72 31 40 6d 61 69 6c 2e 63 6f 6d) | (75 00 73 00 65 00 72 00 31 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s48 = {((64 65 6d 6f 63 79 62 65 72 40 6b 65 72 6d 65 75 72 2e 63 6f 6d) | (64 00 65 00 6d 00 6f 00 63 00 79 00 62 00 65 00 72 00 40 00 6b 00 65 00 72 00 6d 00 65 00 75 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$s49 = {((6c 6f 67 67 6b 65 79 65 6d 69 73 6f 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (6c 00 6f 00 67 00 67 00 6b 00 65 00 79 00 65 00 6d 00 69 00 73 00 6f 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s50 = {((6c 6f 67 67 6b 65 79 72 65 63 65 70 74 6f 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (6c 00 6f 00 67 00 67 00 6b 00 65 00 79 00 72 00 65 00 63 00 65 00 70 00 74 00 6f 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s51 = {((74 6f 6f 70 6d 6f 6f 76 65 31 32 33 40 67 6d 61 69 6c 2e 63 6f 6d) | (74 00 6f 00 6f 00 70 00 6d 00 6f 00 6f 00 76 00 65 00 31 00 32 00 33 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s52 = {((74 6f 6f 70 6d 6f 6f 76 65 73 75 40 6d 61 69 6c 2e 63 6f 6d) | (74 00 6f 00 6f 00 70 00 6d 00 6f 00 6f 00 76 00 65 00 73 00 75 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s53 = {((64 6f 6d 69 2e 70 65 6e 74 65 73 74 69 6e 67 40 67 6d 61 69 6c 2e 63 6f 6d) | (64 00 6f 00 6d 00 69 00 2e 00 70 00 65 00 6e 00 74 00 65 00 73 00 74 00 69 00 6e 00 67 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_PowerShellWiFiStealer : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects email accounts used for exfiltration observed in PowerShellWiFiStealer"

	strings:
		$s1 = {((68 61 6a 64 65 62 65 62 72 65 69 64 65 6b 72 65 69 64 65 40 67 6d 61 69 6c 2e 63 6f 6d) | (68 00 61 00 6a 00 64 00 65 00 62 00 65 00 62 00 72 00 65 00 69 00 64 00 65 00 6b 00 72 00 65 00 69 00 64 00 65 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((75 73 62 40 70 74 65 72 6f 62 6f 74 2e 6e 65 74) | (75 00 73 00 62 00 40 00 70 00 74 00 65 00 72 00 6f 00 62 00 6f 00 74 00 2e 00 6e 00 65 00 74 00))}
		$s3 = {((75 6d 61 69 72 64 61 64 61 62 65 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (75 00 6d 00 61 00 69 00 72 00 64 00 61 00 64 00 61 00 62 00 65 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s4 = {((6d 72 75 6d 61 69 72 6f 6b 40 67 6d 61 69 6c 2e 63 6f 6d) | (6d 00 72 00 75 00 6d 00 61 00 69 00 72 00 6f 00 6b 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s5 = {((63 72 65 64 73 65 6e 64 65 72 62 6f 74 40 67 6d 61 69 6c 2e 63 6f 6d) | (63 00 72 00 65 00 64 00 73 00 65 00 6e 00 64 00 65 00 72 00 62 00 6f 00 74 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((65 61 73 79 77 61 72 65 79 74 62 40 67 6d 61 69 6c 2e 63 6f 6d) | (65 00 61 00 73 00 79 00 77 00 61 00 72 00 65 00 79 00 74 00 62 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_PowerShellCookieStealer : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects email accounts used for exfiltration observed in PowerShellCookieStealer"

	strings:
		$s1 = {((73 65 6e 6d 6e 30 77 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 65 00 6e 00 6d 00 6e 00 30 00 77 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((6d 6f 68 61 6d 65 64 2e 74 72 61 62 65 6c 73 69 2e 65 6e 61 32 40 67 6d 61 69 6c 2e 63 6f 6d) | (6d 00 6f 00 68 00 61 00 6d 00 65 00 64 00 2e 00 74 00 72 00 61 00 62 00 65 00 6c 00 73 00 69 00 2e 00 65 00 6e 00 61 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Infostealer : hardened limited
{
	meta:
		author = "ditekshen"
		description = "Detects exfiltration email addresses correlated from various infostealers. The same email may be observed in multiple families."
		reference = "https://github.com/ditekshen/is-wos"

	strings:
		$account1 = {((32 30 32 30 40 77 65 62 73 69 74 65 2d 70 72 61 63 74 69 73 65 2e 73 69 74 65) | (32 00 30 00 32 00 30 00 40 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2d 00 70 00 72 00 61 00 63 00 74 00 69 00 73 00 65 00 2e 00 73 00 69 00 74 00 65 00))}
		$account2 = {((61 62 69 64 73 68 61 68 40 63 6f 6d 73 61 74 73 2e 6e 65 74 2e 70 6b) | (61 00 62 00 69 00 64 00 73 00 68 00 61 00 68 00 40 00 63 00 6f 00 6d 00 73 00 61 00 74 00 73 00 2e 00 6e 00 65 00 74 00 2e 00 70 00 6b 00))}
		$account3 = {((61 62 6c 65 66 61 63 65 32 30 32 30 40 6f 72 69 67 69 6e 6c 6f 67 65 72 2e 63 6f 6d) | (61 00 62 00 6c 00 65 00 66 00 61 00 63 00 65 00 32 00 30 00 32 00 30 00 40 00 6f 00 72 00 69 00 67 00 69 00 6e 00 6c 00 6f 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account4 = {((61 62 6f 79 6f 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (61 00 62 00 6f 00 79 00 6f 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account5 = {((61 62 6f 79 6f 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (61 00 62 00 6f 00 79 00 6f 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account6 = {((61 62 6f 79 5f 6f 72 69 67 69 6e 40 6f 72 69 67 69 6e 6c 6f 67 65 72 2e 63 6f 6d) | (61 00 62 00 6f 00 79 00 5f 00 6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 6f 00 72 00 69 00 67 00 69 00 6e 00 6c 00 6f 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account7 = {((61 62 73 30 30 30 30 31 40 6e 65 64 74 65 6b 2e 63 6f 6d 2e 61 75) | (61 00 62 00 73 00 30 00 30 00 30 00 30 00 31 00 40 00 6e 00 65 00 64 00 74 00 65 00 6b 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 75 00))}
		$account8 = {((61 62 75 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (61 00 62 00 75 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account9 = {((61 63 63 6f 75 6e 74 61 6e 74 40 6d 65 64 6f 65 72 6d 77 2e 6f 72 67) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 61 00 6e 00 74 00 40 00 6d 00 65 00 64 00 6f 00 65 00 72 00 6d 00 77 00 2e 00 6f 00 72 00 67 00))}
		$account10 = {((61 63 63 6f 75 6e 74 2e 69 6e 66 6f 31 30 30 30 40 79 61 6e 64 65 78 2e 63 6f 6d) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 2e 00 69 00 6e 00 66 00 6f 00 31 00 30 00 30 00 30 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account11 = {((61 63 63 6f 75 6e 74 69 6e 67 40 61 6d 65 72 69 63 61 6e 74 72 65 76 61 6c 65 72 69 6e 63 2e 63 6f 6d) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 69 00 6e 00 67 00 40 00 61 00 6d 00 65 00 72 00 69 00 63 00 61 00 6e 00 74 00 72 00 65 00 76 00 61 00 6c 00 65 00 72 00 69 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account12 = {((61 63 63 6f 75 6e 74 69 6e 67 2e 64 75 62 61 69 40 76 69 70 70 61 72 6b 69 6e 67 63 6f 6e 74 72 6f 6c 2e 63 6f 6d) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 69 00 6e 00 67 00 2e 00 64 00 75 00 62 00 61 00 69 00 40 00 76 00 69 00 70 00 70 00 61 00 72 00 6b 00 69 00 6e 00 67 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account13 = {((61 63 63 6f 75 6e 74 73 32 40 6f 69 6c 65 78 69 6e 64 69 61 2e 63 6f 6d) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 32 00 40 00 6f 00 69 00 6c 00 65 00 78 00 69 00 6e 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account14 = {((61 63 63 6f 75 6e 74 73 40 66 72 69 65 6e 64 73 68 69 70 73 2d 6b 65 2e 69 63 75) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 40 00 66 00 72 00 69 00 65 00 6e 00 64 00 73 00 68 00 69 00 70 00 73 00 2d 00 6b 00 65 00 2e 00 69 00 63 00 75 00))}
		$account15 = {((61 63 63 6f 75 6e 74 73 40 68 69 74 65 63 68 6e 6f 63 72 61 74 73 2e 63 6f 6d) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 40 00 68 00 69 00 74 00 65 00 63 00 68 00 6e 00 6f 00 63 00 72 00 61 00 74 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account16 = {((61 63 63 6f 75 6e 74 73 40 69 73 6c 61 6e 64 6b 69 6e 67 70 6f 6f 6c 73 2e 63 6f 6d) | (61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 40 00 69 00 73 00 6c 00 61 00 6e 00 64 00 6b 00 69 00 6e 00 67 00 70 00 6f 00 6f 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account17 = {((61 63 63 74 31 40 64 77 64 6c 2e 63 6f 6d 2e 62 64) | (61 00 63 00 63 00 74 00 31 00 40 00 64 00 77 00 64 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 64 00))}
		$account18 = {((61 63 69 64 2d 6f 72 69 67 69 6e 40 61 67 61 76 65 63 6f 6d 71 75 69 73 74 61 2e 63 6f 6d) | (61 00 63 00 69 00 64 00 2d 00 6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 61 00 67 00 61 00 76 00 65 00 63 00 6f 00 6d 00 71 00 75 00 69 00 73 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account19 = {((61 63 6b 73 6f 6e 6a 6f 67 6f 64 6f 31 32 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (61 00 63 00 6b 00 73 00 6f 00 6e 00 6a 00 6f 00 67 00 6f 00 64 00 6f 00 31 00 32 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account20 = {((61 64 6d 69 6e 31 40 68 61 76 65 75 73 65 61 72 6f 74 65 63 68 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 31 00 40 00 68 00 61 00 76 00 65 00 75 00 73 00 65 00 61 00 72 00 6f 00 74 00 65 00 63 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account21 = {((61 64 6d 69 6e 40 62 61 7a 63 69 70 72 6f 64 75 63 74 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 62 00 61 00 7a 00 63 00 69 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account22 = {((61 64 6d 69 6e 40 63 61 69 72 6f 77 61 79 73 2e 6d 65) | (61 00 64 00 6d 00 69 00 6e 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 6d 00 65 00))}
		$account23 = {((61 64 6d 69 6e 40 65 76 61 70 69 6d 70 63 6f 6c 74 64 2e 70 77) | (61 00 64 00 6d 00 69 00 6e 00 40 00 65 00 76 00 61 00 70 00 69 00 6d 00 70 00 63 00 6f 00 6c 00 74 00 64 00 2e 00 70 00 77 00))}
		$account24 = {((61 64 6d 69 6e 40 66 6f 72 65 78 63 6f 69 6e 73 74 72 61 64 65 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 66 00 6f 00 72 00 65 00 78 00 63 00 6f 00 69 00 6e 00 73 00 74 00 72 00 61 00 64 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account25 = {((61 64 6d 69 6e 40 67 65 2d 6c 6e 64 75 73 74 72 79 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 67 00 65 00 2d 00 6c 00 6e 00 64 00 75 00 73 00 74 00 72 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account26 = {((61 64 6d 69 6e 69 73 74 72 61 63 69 6f 6e 40 61 64 61 2e 6f 72 67 2e 64 6f) | (61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 63 00 69 00 6f 00 6e 00 40 00 61 00 64 00 61 00 2e 00 6f 00 72 00 67 00 2e 00 64 00 6f 00))}
		$account27 = {((61 64 6d 69 6e 69 73 74 72 61 74 6f 72 40 64 61 63 68 61 6e 71 2e 63 63) | (61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 40 00 64 00 61 00 63 00 68 00 61 00 6e 00 71 00 2e 00 63 00 63 00))}
		$account28 = {((61 64 6d 69 6e 40 6c 6f 67 37 30 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 6c 00 6f 00 67 00 37 00 30 00 2e 00 63 00 6f 00 6d 00))}
		$account29 = {((61 2e 65 6c 61 79 61 6e 40 61 62 75 6f 64 61 68 62 72 6f 73 2e 63 6f 6d) | (61 00 2e 00 65 00 6c 00 61 00 79 00 61 00 6e 00 40 00 61 00 62 00 75 00 6f 00 64 00 61 00 68 00 62 00 72 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account30 = {((61 68 6d 61 64 69 40 67 68 65 79 74 61 72 65 6e 63 61 72 70 65 74 2e 63 6f 6d) | (61 00 68 00 6d 00 61 00 64 00 69 00 40 00 67 00 68 00 65 00 79 00 74 00 61 00 72 00 65 00 6e 00 63 00 61 00 72 00 70 00 65 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account31 = {((61 6c 62 61 6e 65 6c 6c 6f 2e 6e 40 6c 61 74 72 69 76 65 6e 65 74 65 63 61 76 69 2e 63 6f 6d) | (61 00 6c 00 62 00 61 00 6e 00 65 00 6c 00 6c 00 6f 00 2e 00 6e 00 40 00 6c 00 61 00 74 00 72 00 69 00 76 00 65 00 6e 00 65 00 74 00 65 00 63 00 61 00 76 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account32 = {((61 6c 65 78 69 73 40 61 63 6d 65 63 61 72 70 2e 63 6f 6d) | (61 00 6c 00 65 00 78 00 69 00 73 00 40 00 61 00 63 00 6d 00 65 00 63 00 61 00 72 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account33 = {((61 6c 5f 67 68 61 6d 61 7a 40 62 65 73 63 6f 2e 63 6f 6d 2e 73 61) | (61 00 6c 00 5f 00 67 00 68 00 61 00 6d 00 61 00 7a 00 40 00 62 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 73 00 61 00))}
		$account34 = {((41 6c 69 62 61 62 61 6c 6f 67 73 36 35 37 40 79 61 6e 64 65 78 2e 63 6f 6d) | (41 00 6c 00 69 00 62 00 61 00 62 00 61 00 6c 00 6f 00 67 00 73 00 36 00 35 00 37 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account35 = {((61 6c 69 6d 61 74 61 74 61 40 69 6e 6e 6f 76 65 63 65 72 61 2e 63 6f 6d) | (61 00 6c 00 69 00 6d 00 61 00 74 00 61 00 74 00 61 00 40 00 69 00 6e 00 6e 00 6f 00 76 00 65 00 63 00 65 00 72 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account36 = {((61 6c 76 69 6e 2e 6b 77 65 6b 40 61 67 69 66 72 65 69 71 68 74 2e 63 6f 6d) | (61 00 6c 00 76 00 69 00 6e 00 2e 00 6b 00 77 00 65 00 6b 00 40 00 61 00 67 00 69 00 66 00 72 00 65 00 69 00 71 00 68 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account37 = {((61 6d 61 6e 69 40 6a 6b 61 6d 61 6e 69 2e 78 79 7a) | (61 00 6d 00 61 00 6e 00 69 00 40 00 6a 00 6b 00 61 00 6d 00 61 00 6e 00 69 00 2e 00 78 00 79 00 7a 00))}
		$account38 = {((61 6d 61 6e 69 40 70 6c 61 74 69 6e 73 68 69 70 73 2e 6e 65 74) | (61 00 6d 00 61 00 6e 00 69 00 40 00 70 00 6c 00 61 00 74 00 69 00 6e 00 73 00 68 00 69 00 70 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account39 = {((61 6d 61 72 61 40 69 6b 65 32 30 32 30 2e 78 79 7a) | (61 00 6d 00 61 00 72 00 61 00 40 00 69 00 6b 00 65 00 32 00 30 00 32 00 30 00 2e 00 78 00 79 00 7a 00))}
		$account40 = {((61 6d 70 61 6c 6c 40 61 6d 70 61 69 6c 2e 63 6f 6d) | (61 00 6d 00 70 00 61 00 6c 00 6c 00 40 00 61 00 6d 00 70 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account41 = {((61 6e 64 65 72 73 6f 6e 40 66 6c 73 72 6e 69 64 74 68 2e 63 6f 6d) | (61 00 6e 00 64 00 65 00 72 00 73 00 6f 00 6e 00 40 00 66 00 6c 00 73 00 72 00 6e 00 69 00 64 00 74 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account42 = {((61 6e 64 72 65 73 2e 76 65 72 64 65 40 75 73 2d 64 75 72 61 67 73 2e 63 6f 6d) | (61 00 6e 00 64 00 72 00 65 00 73 00 2e 00 76 00 65 00 72 00 64 00 65 00 40 00 75 00 73 00 2d 00 64 00 75 00 72 00 61 00 67 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account43 = {((61 6e 67 65 72 40 63 61 6e 76 61 6e 61 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (61 00 6e 00 67 00 65 00 72 00 40 00 63 00 61 00 6e 00 76 00 61 00 6e 00 61 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account44 = {((61 6e 67 6f 6c 6b 61 72 2e 6d 69 6c 69 6e 64 40 6e 65 74 61 6c 6b 61 72 2e 63 6f 2e 69 6e) | (61 00 6e 00 67 00 6f 00 6c 00 6b 00 61 00 72 00 2e 00 6d 00 69 00 6c 00 69 00 6e 00 64 00 40 00 6e 00 65 00 74 00 61 00 6c 00 6b 00 61 00 72 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account45 = {((61 6e 6e 77 69 6c 73 6f 40 79 61 6e 64 65 78 2e 63 6f 6d) | (61 00 6e 00 6e 00 77 00 69 00 6c 00 73 00 6f 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account46 = {((61 70 69 73 69 79 6c 6f 40 69 6e 6e 6f 76 65 63 65 72 61 2e 63 6f 6d) | (61 00 70 00 69 00 73 00 69 00 79 00 6c 00 6f 00 40 00 69 00 6e 00 6e 00 6f 00 76 00 65 00 63 00 65 00 72 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account47 = {((61 72 61 62 69 6f 65 70 40 61 72 61 62 69 61 6e 77 65 62 64 65 73 69 67 6e 65 72 2e 63 6f 6d) | (61 00 72 00 61 00 62 00 69 00 6f 00 65 00 70 00 40 00 61 00 72 00 61 00 62 00 69 00 61 00 6e 00 77 00 65 00 62 00 64 00 65 00 73 00 69 00 67 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account48 = {((61 72 61 66 40 63 72 6f 77 6e 63 6f 6e 74 61 69 6e 65 72 62 64 2e 69 63 75) | (61 00 72 00 61 00 66 00 40 00 63 00 72 00 6f 00 77 00 6e 00 63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 62 00 64 00 2e 00 69 00 63 00 75 00))}
		$account49 = {((61 72 6d 61 6e 69 40 6e 6f 76 61 61 2d 73 68 69 70 2e 63 6f 6d) | (61 00 72 00 6d 00 61 00 6e 00 69 00 40 00 6e 00 6f 00 76 00 61 00 61 00 2d 00 73 00 68 00 69 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account50 = {((61 72 6d 61 6e 69 40 70 6c 61 74 69 6e 73 68 69 70 73 2e 6e 65 74) | (61 00 72 00 6d 00 61 00 6e 00 69 00 40 00 70 00 6c 00 61 00 74 00 69 00 6e 00 73 00 68 00 69 00 70 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account51 = {((61 73 68 61 61 6d 62 72 6f 73 65 40 73 75 72 79 61 74 72 61 76 65 6c 73 2e 63 6f 6d) | (61 00 73 00 68 00 61 00 61 00 6d 00 62 00 72 00 6f 00 73 00 65 00 40 00 73 00 75 00 72 00 79 00 61 00 74 00 72 00 61 00 76 00 65 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account52 = {((61 73 68 6c 65 79 5f 68 61 79 77 6f 6f 64 40 62 61 70 6c 68 76 61 63 2d 75 6b 2e 63 6f 6d) | (61 00 73 00 68 00 6c 00 65 00 79 00 5f 00 68 00 61 00 79 00 77 00 6f 00 6f 00 64 00 40 00 62 00 61 00 70 00 6c 00 68 00 76 00 61 00 63 00 2d 00 75 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account53 = {((61 75 74 68 40 64 65 65 70 73 61 65 65 6d 69 72 61 74 65 73 2e 63 6f 6d) | (61 00 75 00 74 00 68 00 40 00 64 00 65 00 65 00 70 00 73 00 61 00 65 00 65 00 6d 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account54 = {((62 61 72 6f 64 61 40 75 6c 74 72 61 66 69 6c 74 65 72 69 6e 64 69 61 2e 63 6f 6d) | (62 00 61 00 72 00 6f 00 64 00 61 00 40 00 75 00 6c 00 74 00 72 00 61 00 66 00 69 00 6c 00 74 00 65 00 72 00 69 00 6e 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account55 = {((62 62 73 74 61 72 40 65 78 70 6c 6f 69 74 73 2e 73 69 74 65) | (62 00 62 00 73 00 74 00 61 00 72 00 40 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 73 00 2e 00 73 00 69 00 74 00 65 00))}
		$account56 = {((62 64 40 61 64 69 74 79 61 70 72 69 6e 74 65 72 73 2e 63 6f 6d) | (62 00 64 00 40 00 61 00 64 00 69 00 74 00 79 00 61 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account57 = {((62 65 6c 6c 61 6c 69 63 65 38 39 37 40 67 6d 61 69 6c 2e 63 6f 6d) | (62 00 65 00 6c 00 6c 00 61 00 6c 00 69 00 63 00 65 00 38 00 39 00 37 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account58 = {((62 65 6e 69 40 64 64 69 6d 6e 65 70 61 6c 2e 63 6f 6d) | (62 00 65 00 6e 00 69 00 40 00 64 00 64 00 69 00 6d 00 6e 00 65 00 70 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account59 = {((62 65 73 74 2d 73 75 63 63 65 73 73 40 70 75 72 65 2d 65 6e 65 72 67 79 2e 73 69 74 65) | (62 00 65 00 73 00 74 00 2d 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 40 00 70 00 75 00 72 00 65 00 2d 00 65 00 6e 00 65 00 72 00 67 00 79 00 2e 00 73 00 69 00 74 00 65 00))}
		$account60 = {((62 69 6c 6c 69 6f 6e 73 40 63 61 69 72 6f 77 61 79 73 2e 6d 65) | (62 00 69 00 6c 00 6c 00 69 00 6f 00 6e 00 73 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 6d 00 65 00))}
		$account61 = {((62 69 6c 6c 69 6f 6e 76 61 69 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (62 00 69 00 6c 00 6c 00 69 00 6f 00 6e 00 76 00 61 00 69 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account62 = {((62 69 6e 75 40 6d 65 74 61 6c 66 61 62 6d 65 2e 69 63 75) | (62 00 69 00 6e 00 75 00 40 00 6d 00 65 00 74 00 61 00 6c 00 66 00 61 00 62 00 6d 00 65 00 2e 00 69 00 63 00 75 00))}
		$account63 = {((62 69 6e 75 40 6d 65 74 61 6c 66 61 62 6e 65 2e 63 6f 6d) | (62 00 69 00 6e 00 75 00 40 00 6d 00 65 00 74 00 61 00 6c 00 66 00 61 00 62 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account64 = {((62 6c 65 73 73 69 6e 67 40 65 6e 65 72 67 69 73 74 78 2e 63 6f 6d) | (62 00 6c 00 65 00 73 00 73 00 69 00 6e 00 67 00 40 00 65 00 6e 00 65 00 72 00 67 00 69 00 73 00 74 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account65 = {((62 6c 72 40 73 61 68 61 72 61 65 78 70 72 65 73 73 2e 63 6f 6d) | (62 00 6c 00 72 00 40 00 73 00 61 00 68 00 61 00 72 00 61 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account66 = {((62 6f 62 40 6d 65 74 61 6c 66 61 62 6d 65 2e 69 63 75) | (62 00 6f 00 62 00 40 00 6d 00 65 00 74 00 61 00 6c 00 66 00 61 00 62 00 6d 00 65 00 2e 00 69 00 63 00 75 00))}
		$account67 = {((62 6f 73 73 77 65 6c 6c 40 67 75 69 61 72 61 70 69 64 6f 70 75 62 6c 69 63 69 64 61 64 65 2e 63 6f 6d 2e 62 72) | (62 00 6f 00 73 00 73 00 77 00 65 00 6c 00 6c 00 40 00 67 00 75 00 69 00 61 00 72 00 61 00 70 00 69 00 64 00 6f 00 70 00 75 00 62 00 6c 00 69 00 63 00 69 00 64 00 61 00 64 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00))}
		$account68 = {((62 6f 78 62 6c 65 73 73 69 6e 67 73 37 37 34 34 40 79 61 6e 64 65 78 2e 63 6f 6d) | (62 00 6f 00 78 00 62 00 6c 00 65 00 73 00 73 00 69 00 6e 00 67 00 73 00 37 00 37 00 34 00 34 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account69 = {((62 6f 79 6d 6f 75 73 65 40 79 61 6e 64 65 78 2e 63 6f 6d) | (62 00 6f 00 79 00 6d 00 6f 00 75 00 73 00 65 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account70 = {((62 72 61 6a 65 73 68 40 63 72 6f 70 63 68 65 6d 69 63 61 6c 73 2e 63 6f 2e 69 6e) | (62 00 72 00 61 00 6a 00 65 00 73 00 68 00 40 00 63 00 72 00 6f 00 70 00 63 00 68 00 65 00 6d 00 69 00 63 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account71 = {((62 72 69 67 68 74 40 70 61 69 67 65 6c 65 63 74 72 69 63 2e 63 6f 6d) | (62 00 72 00 69 00 67 00 68 00 74 00 40 00 70 00 61 00 69 00 67 00 65 00 6c 00 65 00 63 00 74 00 72 00 69 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account72 = {((62 72 69 6e 67 34 40 75 6e 69 76 65 72 73 61 6c 69 6e 6b 73 2e 6e 65 74) | (62 00 72 00 69 00 6e 00 67 00 34 00 40 00 75 00 6e 00 69 00 76 00 65 00 72 00 73 00 61 00 6c 00 69 00 6e 00 6b 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account73 = {((62 72 69 6e 67 40 6b 61 67 61 62 6f 2e 6e 65 74) | (62 00 72 00 69 00 6e 00 67 00 40 00 6b 00 61 00 67 00 61 00 62 00 6f 00 2e 00 6e 00 65 00 74 00))}
		$account74 = {((62 72 69 6e 67 6c 6f 67 73 40 6b 61 73 73 6f 68 6f 6d 65 2e 63 6f 6d 2e 74 72) | (62 00 72 00 69 00 6e 00 67 00 6c 00 6f 00 67 00 73 00 40 00 6b 00 61 00 73 00 73 00 6f 00 68 00 6f 00 6d 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 74 00 72 00))}
		$account75 = {((62 72 6f 6f 79 75 31 40 6c 61 72 62 61 78 70 6f 2e 63 6f 6d) | (62 00 72 00 6f 00 6f 00 79 00 75 00 31 00 40 00 6c 00 61 00 72 00 62 00 61 00 78 00 70 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account76 = {((62 72 6f 6f 79 75 40 6c 61 72 62 61 78 70 6f 2e 63 6f 6d) | (62 00 72 00 6f 00 6f 00 79 00 75 00 40 00 6c 00 61 00 72 00 62 00 61 00 78 00 70 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account77 = {((62 72 75 6e 6f 6c 75 67 6e 61 6e 69 40 61 72 72 6d 65 74 2e 69 6e) | (62 00 72 00 75 00 6e 00 6f 00 6c 00 75 00 67 00 6e 00 61 00 6e 00 69 00 40 00 61 00 72 00 72 00 6d 00 65 00 74 00 2e 00 69 00 6e 00))}
		$account78 = {((62 2e 73 74 6f 6a 61 6e 6f 76 40 6f 70 73 74 69 6e 61 67 70 65 74 72 6f 76 2e 67 6f 76 2e 6d 6b) | (62 00 2e 00 73 00 74 00 6f 00 6a 00 61 00 6e 00 6f 00 76 00 40 00 6f 00 70 00 73 00 74 00 69 00 6e 00 61 00 67 00 70 00 65 00 74 00 72 00 6f 00 76 00 2e 00 67 00 6f 00 76 00 2e 00 6d 00 6b 00))}
		$account79 = {((42 75 72 6e 61 40 66 69 6c 65 6c 6f 67 2e 69 6e 66 6f) | (42 00 75 00 72 00 6e 00 61 00 40 00 66 00 69 00 6c 00 65 00 6c 00 6f 00 67 00 2e 00 69 00 6e 00 66 00 6f 00))}
		$account80 = {((63 61 61 2d 63 68 65 72 72 79 68 75 61 6e 67 40 70 61 69 72 73 69 67 73 2e 63 6f 6d) | (63 00 61 00 61 00 2d 00 63 00 68 00 65 00 72 00 72 00 79 00 68 00 75 00 61 00 6e 00 67 00 40 00 70 00 61 00 69 00 72 00 73 00 69 00 67 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account81 = {((63 61 67 6c 61 72 40 6c 69 64 79 61 74 72 69 6b 6f 2d 63 6f 6d 2e 6d 65) | (63 00 61 00 67 00 6c 00 61 00 72 00 40 00 6c 00 69 00 64 00 79 00 61 00 74 00 72 00 69 00 6b 00 6f 00 2d 00 63 00 6f 00 6d 00 2e 00 6d 00 65 00))}
		$account82 = {((63 61 67 6c 61 72 40 6c 69 64 79 61 74 72 69 6b 6f 2d 74 72 2e 70 77) | (63 00 61 00 67 00 6c 00 61 00 72 00 40 00 6c 00 69 00 64 00 79 00 61 00 74 00 72 00 69 00 6b 00 6f 00 2d 00 74 00 72 00 2e 00 70 00 77 00))}
		$account83 = {((63 61 6e 64 6f 6c 6b 61 72 2e 70 40 74 65 63 6e 69 63 61 73 72 65 75 6e 69 64 61 73 2d 65 73 2e 63 6f) | (63 00 61 00 6e 00 64 00 6f 00 6c 00 6b 00 61 00 72 00 2e 00 70 00 40 00 74 00 65 00 63 00 6e 00 69 00 63 00 61 00 73 00 72 00 65 00 75 00 6e 00 69 00 64 00 61 00 73 00 2d 00 65 00 73 00 2e 00 63 00 6f 00))}
		$account84 = {((63 61 72 6f 6c 79 6e 65 40 64 61 6e 64 6f 70 75 62 2e 6d 75) | (63 00 61 00 72 00 6f 00 6c 00 79 00 6e 00 65 00 40 00 64 00 61 00 6e 00 64 00 6f 00 70 00 75 00 62 00 2e 00 6d 00 75 00))}
		$account85 = {((63 65 6c 61 6c 40 6c 69 64 79 61 74 72 69 6b 6f 2d 63 6f 6d 2e 6d 65) | (63 00 65 00 6c 00 61 00 6c 00 40 00 6c 00 69 00 64 00 79 00 61 00 74 00 72 00 69 00 6b 00 6f 00 2d 00 63 00 6f 00 6d 00 2e 00 6d 00 65 00))}
		$account86 = {((63 65 73 61 72 40 65 63 6f 2d 6d 61 6e 69 61 2e 65 73) | (63 00 65 00 73 00 61 00 72 00 40 00 65 00 63 00 6f 00 2d 00 6d 00 61 00 6e 00 69 00 61 00 2e 00 65 00 73 00))}
		$account87 = {((63 68 61 6c 6c 61 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (63 00 68 00 61 00 6c 00 6c 00 61 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account88 = {((63 68 61 6e 6b 65 79 40 73 61 6c 61 73 61 72 6c 61 6d 6c 6e 61 74 65 73 2e 63 6f 6d) | (63 00 68 00 61 00 6e 00 6b 00 65 00 79 00 40 00 73 00 61 00 6c 00 61 00 73 00 61 00 72 00 6c 00 61 00 6d 00 6c 00 6e 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account89 = {((63 68 61 72 69 66 2e 79 61 73 73 69 6e 40 63 72 6f 6e 69 6d 65 74 2e 6d 65) | (63 00 68 00 61 00 72 00 69 00 66 00 2e 00 79 00 61 00 73 00 73 00 69 00 6e 00 40 00 63 00 72 00 6f 00 6e 00 69 00 6d 00 65 00 74 00 2e 00 6d 00 65 00))}
		$account90 = {((63 68 61 72 6c 65 73 78 6d 6f 6e 69 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 68 00 61 00 72 00 6c 00 65 00 73 00 78 00 6d 00 6f 00 6e 00 69 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account91 = {((63 68 65 6c 6c 61 70 61 6e 64 69 61 6e 40 69 6e 73 6f 6f 72 79 61 65 78 70 72 65 73 73 63 61 72 67 6f 2e 63 6f 6d) | (63 00 68 00 65 00 6c 00 6c 00 61 00 70 00 61 00 6e 00 64 00 69 00 61 00 6e 00 40 00 69 00 6e 00 73 00 6f 00 6f 00 72 00 79 00 61 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 63 00 61 00 72 00 67 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account92 = {((63 68 69 64 65 72 61 40 72 61 6e 6b 79 77 69 73 65 2e 63 6f 6d) | (63 00 68 00 69 00 64 00 65 00 72 00 61 00 40 00 72 00 61 00 6e 00 6b 00 79 00 77 00 69 00 73 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account93 = {((63 68 69 2e 65 62 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 68 00 69 00 2e 00 65 00 62 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account94 = {((63 68 69 40 6a 69 61 2d 69 6c 64 61 2e 63 6f 6d) | (63 00 68 00 69 00 40 00 6a 00 69 00 61 00 2d 00 69 00 6c 00 64 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account95 = {((63 68 69 6a 69 6f 6b 65 6a 61 63 6b 73 6f 6e 31 32 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 68 00 69 00 6a 00 69 00 6f 00 6b 00 65 00 6a 00 61 00 63 00 6b 00 73 00 6f 00 6e 00 31 00 32 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account96 = {((63 68 69 6d 61 40 6f 73 63 61 72 75 6c 65 2e 78 79 7a) | (63 00 68 00 69 00 6d 00 61 00 40 00 6f 00 73 00 63 00 61 00 72 00 75 00 6c 00 65 00 2e 00 78 00 79 00 7a 00))}
		$account97 = {((63 68 69 6d 61 40 70 6c 61 74 69 6e 73 68 69 70 73 2e 6e 65 74) | (63 00 68 00 69 00 6d 00 61 00 40 00 70 00 6c 00 61 00 74 00 69 00 6e 00 73 00 68 00 69 00 70 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account98 = {((63 68 69 6e 61 6c 6f 67 67 65 72 73 40 6a 75 69 6c 69 2d 74 77 2e 63 6f 6d) | (63 00 68 00 69 00 6e 00 61 00 6c 00 6f 00 67 00 67 00 65 00 72 00 73 00 40 00 6a 00 75 00 69 00 6c 00 69 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account99 = {((63 68 69 6e 61 70 65 61 63 65 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 68 00 69 00 6e 00 61 00 70 00 65 00 61 00 63 00 65 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account100 = {((63 68 69 6e 61 74 75 65 64 64 79 40 79 61 6e 64 65 78 2e 72 75) | (63 00 68 00 69 00 6e 00 61 00 74 00 75 00 65 00 64 00 64 00 79 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account101 = {((63 68 72 69 73 74 65 6c 6c 65 2e 62 65 72 74 65 6c 6c 65 40 6d 65 72 72 73 65 6e 2e 63 6f 6d) | (63 00 68 00 72 00 69 00 73 00 74 00 65 00 6c 00 6c 00 65 00 2e 00 62 00 65 00 72 00 74 00 65 00 6c 00 6c 00 65 00 40 00 6d 00 65 00 72 00 72 00 73 00 65 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account102 = {((63 68 72 69 73 74 69 61 6e 2e 66 65 72 72 65 74 74 69 40 66 6f 78 2d 69 74 2e 6d 65) | (63 00 68 00 72 00 69 00 73 00 74 00 69 00 61 00 6e 00 2e 00 66 00 65 00 72 00 72 00 65 00 74 00 74 00 69 00 40 00 66 00 6f 00 78 00 2d 00 69 00 74 00 2e 00 6d 00 65 00))}
		$account103 = {((63 68 75 6b 69 65 62 72 6f 40 69 6e 74 61 72 73 63 61 6e 2e 6f 72 67) | (63 00 68 00 75 00 6b 00 69 00 65 00 62 00 72 00 6f 00 40 00 69 00 6e 00 74 00 61 00 72 00 73 00 63 00 61 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account104 = {((63 6a 6d 79 67 75 79 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 6a 00 6d 00 79 00 67 00 75 00 79 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account105 = {((63 6b 40 62 63 6f 6e 64 75 63 74 74 2e 69 63 75) | (63 00 6b 00 40 00 62 00 63 00 6f 00 6e 00 64 00 75 00 63 00 74 00 74 00 2e 00 69 00 63 00 75 00))}
		$account106 = {((63 6b 40 6b 69 6e 67 6d 65 7a 7a 2e 78 79 7a) | (63 00 6b 00 40 00 6b 00 69 00 6e 00 67 00 6d 00 65 00 7a 00 7a 00 2e 00 78 00 79 00 7a 00))}
		$account107 = {((63 6b 40 6b 69 6e 67 7a 6d 65 7a 2e 78 79 7a) | (63 00 6b 00 40 00 6b 00 69 00 6e 00 67 00 7a 00 6d 00 65 00 7a 00 2e 00 78 00 79 00 7a 00))}
		$account108 = {((63 6b 40 6e 78 74 6c 65 76 65 6c 2e 78 79 7a) | (63 00 6b 00 40 00 6e 00 78 00 74 00 6c 00 65 00 76 00 65 00 6c 00 2e 00 78 00 79 00 7a 00))}
		$account109 = {((63 6b 40 73 6f 6e 6f 66 67 72 61 63 65 2e 77 65 62 73 69 74 65) | (63 00 6b 00 40 00 73 00 6f 00 6e 00 6f 00 66 00 67 00 72 00 61 00 63 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account111 = {((63 6c 61 69 72 65 6d 6f 6f 6e 33 33 33 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 6c 00 61 00 69 00 72 00 65 00 6d 00 6f 00 6f 00 6e 00 33 00 33 00 33 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account112 = {((63 6c 61 72 6b 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (63 00 6c 00 61 00 72 00 6b 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account113 = {((63 6f 6d 6d 31 40 64 77 64 6c 2e 63 6f 6d 2e 62 64) | (63 00 6f 00 6d 00 6d 00 31 00 40 00 64 00 77 00 64 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 64 00))}
		$account114 = {((63 6f 6d 2e 6d 61 6e 61 67 65 72 40 6d 7a 72 6e 62 64 2e 63 6f 6d) | (63 00 6f 00 6d 00 2e 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 40 00 6d 00 7a 00 72 00 6e 00 62 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account115 = {((63 6f 6e 66 69 72 6d 65 64 40 67 72 61 64 75 61 74 65 2e 6f 72 67) | (63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 65 00 64 00 40 00 67 00 72 00 61 00 64 00 75 00 61 00 74 00 65 00 2e 00 6f 00 72 00 67 00))}
		$account116 = {((63 6f 6e 74 61 62 69 6c 69 64 61 64 40 69 6e 74 65 72 65 78 70 72 65 73 73 2e 75 73) | (63 00 6f 00 6e 00 74 00 61 00 62 00 69 00 6c 00 69 00 64 00 61 00 64 00 40 00 69 00 6e 00 74 00 65 00 72 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 2e 00 75 00 73 00))}
		$account117 = {((63 6f 6e 74 61 63 74 40 61 73 73 6f 63 68 61 6d 2e 69 63 75) | (63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 40 00 61 00 73 00 73 00 6f 00 63 00 68 00 61 00 6d 00 2e 00 69 00 63 00 75 00))}
		$account118 = {((63 6f 6e 74 61 63 74 40 65 75 72 61 6d 74 65 63 2e 70 77) | (63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 40 00 65 00 75 00 72 00 61 00 6d 00 74 00 65 00 63 00 2e 00 70 00 77 00))}
		$account119 = {((63 6f 6e 74 61 63 74 40 67 63 63 6f 2e 64 7a) | (63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 40 00 67 00 63 00 63 00 6f 00 2e 00 64 00 7a 00))}
		$account120 = {((43 6f 6e 74 61 63 74 40 78 63 68 69 31 2e 78 79 7a) | (43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 40 00 78 00 63 00 68 00 69 00 31 00 2e 00 78 00 79 00 7a 00))}
		$account121 = {((63 2e 72 61 6e 6e 6f 6e 65 40 6d 65 63 68 61 74 72 6f 6e 2d 67 6d 62 68 2e 67 61) | (63 00 2e 00 72 00 61 00 6e 00 6e 00 6f 00 6e 00 65 00 40 00 6d 00 65 00 63 00 68 00 61 00 74 00 72 00 6f 00 6e 00 2d 00 67 00 6d 00 62 00 68 00 2e 00 67 00 61 00))}
		$account122 = {((63 72 6d 2e 73 61 6c 40 73 75 70 72 61 6a 69 74 2e 6d 65) | (63 00 72 00 6d 00 2e 00 73 00 61 00 6c 00 40 00 73 00 75 00 70 00 72 00 61 00 6a 00 69 00 74 00 2e 00 6d 00 65 00))}
		$account123 = {((63 72 6f 77 6e 73 40 6b 65 6e 6e 79 63 6f 72 70 69 6e 67 2e 63 6f 6d) | (63 00 72 00 6f 00 77 00 6e 00 73 00 40 00 6b 00 65 00 6e 00 6e 00 79 00 63 00 6f 00 72 00 70 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account124 = {((63 72 75 69 7a 6a 61 6d 65 73 40 79 61 6e 64 65 78 2e 72 75) | (63 00 72 00 75 00 69 00 7a 00 6a 00 61 00 6d 00 65 00 73 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account125 = {((63 73 6f 40 64 72 6e 67 65 74 75 2e 63 6f 2e 7a 61) | (63 00 73 00 6f 00 40 00 64 00 72 00 6e 00 67 00 65 00 74 00 75 00 2e 00 63 00 6f 00 2e 00 7a 00 61 00))}
		$account126 = {((63 73 70 75 72 69 40 73 65 61 72 63 68 6e 65 74 2e 63 6f 2e 69 6e) | (63 00 73 00 70 00 75 00 72 00 69 00 40 00 73 00 65 00 61 00 72 00 63 00 68 00 6e 00 65 00 74 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account127 = {((63 75 70 6a 75 6c 40 79 61 6e 64 65 78 2e 63 6f 6d) | (63 00 75 00 70 00 6a 00 75 00 6c 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account128 = {((63 76 40 62 61 6e 64 61 69 63 68 65 6d 69 63 61 6c 2e 63 6f 6d) | (63 00 76 00 40 00 62 00 61 00 6e 00 64 00 61 00 69 00 63 00 68 00 65 00 6d 00 69 00 63 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account129 = {((64 61 62 6f 40 61 6e 64 69 6e 67 2d 74 77 2e 63 6f 6d) | (64 00 61 00 62 00 6f 00 40 00 61 00 6e 00 64 00 69 00 6e 00 67 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account130 = {((64 61 65 73 68 69 6e 70 68 61 72 6d 40 6b 6f 72 65 61 6d 61 69 6c 2e 63 6f 6d) | (64 00 61 00 65 00 73 00 68 00 69 00 6e 00 70 00 68 00 61 00 72 00 6d 00 40 00 6b 00 6f 00 72 00 65 00 61 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account131 = {((64 61 6c 66 61 72 6f 40 68 69 6c 6d 61 72 63 68 65 65 7a 65 2e 63 6f 6d) | (64 00 61 00 6c 00 66 00 61 00 72 00 6f 00 40 00 68 00 69 00 6c 00 6d 00 61 00 72 00 63 00 68 00 65 00 65 00 7a 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account132 = {((64 61 76 65 31 40 65 6d 6d 61 6e 6e 61 72 2e 63 6f 6d) | (64 00 61 00 76 00 65 00 31 00 40 00 65 00 6d 00 6d 00 61 00 6e 00 6e 00 61 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account133 = {((64 61 76 65 40 65 6d 6d 61 6e 6e 61 72 2e 63 6f 6d) | (64 00 61 00 76 00 65 00 40 00 65 00 6d 00 6d 00 61 00 6e 00 6e 00 61 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account134 = {((64 61 76 69 64 40 64 61 6d 69 65 6e 7a 79 2e 78 79 7a) | (64 00 61 00 76 00 69 00 64 00 40 00 64 00 61 00 6d 00 69 00 65 00 6e 00 7a 00 79 00 2e 00 78 00 79 00 7a 00))}
		$account135 = {((64 62 32 40 62 6c 61 63 6b 73 65 61 2e 72 65 64) | (64 00 62 00 32 00 40 00 62 00 6c 00 61 00 63 00 6b 00 73 00 65 00 61 00 2e 00 72 00 65 00 64 00))}
		$account136 = {((64 63 61 69 63 65 64 6f 40 69 67 69 68 6d 2e 69 63 75) | (64 00 63 00 61 00 69 00 63 00 65 00 64 00 6f 00 40 00 69 00 67 00 69 00 68 00 6d 00 2e 00 69 00 63 00 75 00))}
		$account137 = {((64 64 64 40 70 65 68 6c 65 64 69 6e 65 6b 61 6d 2e 63 6f 6d) | (64 00 64 00 64 00 40 00 70 00 65 00 68 00 6c 00 65 00 64 00 69 00 6e 00 65 00 6b 00 61 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account138 = {((64 65 66 61 75 6c 74 40 65 73 70 69 72 61 6c 72 65 6c 6f 6a 6f 61 72 69 61 2e 63 6f 6d) | (64 00 65 00 66 00 61 00 75 00 6c 00 74 00 40 00 65 00 73 00 70 00 69 00 72 00 61 00 6c 00 72 00 65 00 6c 00 6f 00 6a 00 6f 00 61 00 72 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account139 = {((64 65 73 74 69 6e 79 40 61 6c 74 72 69 69 2e 63 6f 6d) | (64 00 65 00 73 00 74 00 69 00 6e 00 79 00 40 00 61 00 6c 00 74 00 72 00 69 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account140 = {((64 68 61 64 6a 61 7a 69 40 61 64 65 6e 65 72 71 79 65 75 72 6f 70 65 2e 63 6f 2e 75 6b) | (64 00 68 00 61 00 64 00 6a 00 61 00 7a 00 69 00 40 00 61 00 64 00 65 00 6e 00 65 00 72 00 71 00 79 00 65 00 75 00 72 00 6f 00 70 00 65 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00))}
		$account141 = {((64 68 72 75 76 40 6f 78 73 65 2e 69 6e) | (64 00 68 00 72 00 75 00 76 00 40 00 6f 00 78 00 73 00 65 00 2e 00 69 00 6e 00))}
		$account142 = {((64 69 72 65 63 74 6f 72 40 65 6c 73 65 6d 69 6c 6c 65 72 6f 2e 6f 72 67 2e 62 6f) | (64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 40 00 65 00 6c 00 73 00 65 00 6d 00 69 00 6c 00 6c 00 65 00 72 00 6f 00 2e 00 6f 00 72 00 67 00 2e 00 62 00 6f 00))}
		$account143 = {((64 69 72 65 63 74 6f 72 40 6d 65 64 6f 72 6d 77 2e 6f 72 67) | (64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 40 00 6d 00 65 00 64 00 6f 00 72 00 6d 00 77 00 2e 00 6f 00 72 00 67 00))}
		$account144 = {((64 69 73 70 61 74 63 68 2e 6c 6b 6f 40 70 65 72 66 65 63 74 67 65 6e 65 72 61 74 6f 72 73 2e 63 6f 6d) | (64 00 69 00 73 00 70 00 61 00 74 00 63 00 68 00 2e 00 6c 00 6b 00 6f 00 40 00 70 00 65 00 72 00 66 00 65 00 63 00 74 00 67 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account145 = {((64 6f 63 73 40 68 64 74 72 61 6e 73 2e 6d 65) | (64 00 6f 00 63 00 73 00 40 00 68 00 64 00 74 00 72 00 61 00 6e 00 73 00 2e 00 6d 00 65 00))}
		$account146 = {((64 6f 63 75 6d 65 6e 74 73 40 6d 79 67 6f 6c 64 65 6e 61 65 67 6c 65 2e 63 6f 6d) | (64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 40 00 6d 00 79 00 67 00 6f 00 6c 00 64 00 65 00 6e 00 61 00 65 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account147 = {((64 6f 67 64 6f 6c 6c 61 72 73 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (64 00 6f 00 67 00 64 00 6f 00 6c 00 6c 00 61 00 72 00 73 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account148 = {((64 6f 67 67 79 40 6b 69 6e 67 6d 65 7a 7a 2e 78 79 7a) | (64 00 6f 00 67 00 67 00 79 00 40 00 6b 00 69 00 6e 00 67 00 6d 00 65 00 7a 00 7a 00 2e 00 78 00 79 00 7a 00))}
		$account149 = {((64 6f 67 6d 61 6e 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (64 00 6f 00 67 00 6d 00 61 00 6e 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account150 = {((64 6f 6d 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (64 00 6f 00 6d 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account151 = {((64 6f 6e 67 61 33 40 64 6f 6e 67 61 73 65 69 6d 63 6f 6e 2e 63 6f 6d) | (64 00 6f 00 6e 00 67 00 61 00 33 00 40 00 64 00 6f 00 6e 00 67 00 61 00 73 00 65 00 69 00 6d 00 63 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account152 = {((64 6f 6e 40 70 6c 61 74 69 6e 73 68 69 70 73 2e 6e 65 74) | (64 00 6f 00 6e 00 40 00 70 00 6c 00 61 00 74 00 69 00 6e 00 73 00 68 00 69 00 70 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account153 = {((64 6f 6e 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (64 00 6f 00 6e 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account154 = {((64 6f 72 65 65 6e 2e 6d 75 68 65 62 77 61 40 6d 69 63 72 6f 68 61 65 6d 2d 75 67 2e 63 6f) | (64 00 6f 00 72 00 65 00 65 00 6e 00 2e 00 6d 00 75 00 68 00 65 00 62 00 77 00 61 00 40 00 6d 00 69 00 63 00 72 00 6f 00 68 00 61 00 65 00 6d 00 2d 00 75 00 67 00 2e 00 63 00 6f 00))}
		$account155 = {((64 72 65 61 6d 40 64 73 74 65 63 2e 6d 78) | (64 00 72 00 65 00 61 00 6d 00 40 00 64 00 73 00 74 00 65 00 63 00 2e 00 6d 00 78 00))}
		$account156 = {((64 75 74 63 68 40 64 75 74 63 68 77 6f 72 6c 64 2e 73 70 61 63 65) | (64 00 75 00 74 00 63 00 68 00 40 00 64 00 75 00 74 00 63 00 68 00 77 00 6f 00 72 00 6c 00 64 00 2e 00 73 00 70 00 61 00 63 00 65 00))}
		$account157 = {((65 61 40 6c 69 74 74 6c 65 69 74 61 6c 79 2e 63 6f 2e 69 6e) | (65 00 61 00 40 00 6c 00 69 00 74 00 74 00 6c 00 65 00 69 00 74 00 61 00 6c 00 79 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account158 = {((65 62 61 73 65 40 6e 6f 76 61 61 2d 73 68 69 70 2e 63 6f 6d) | (65 00 62 00 61 00 73 00 65 00 40 00 6e 00 6f 00 76 00 61 00 61 00 2d 00 73 00 68 00 69 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account159 = {((65 2e 66 61 73 63 69 61 6e 69 40 77 61 6c 74 61 72 74 6f 73 74 6f 2e 63 6f 6d) | (65 00 2e 00 66 00 61 00 73 00 63 00 69 00 61 00 6e 00 69 00 40 00 77 00 61 00 6c 00 74 00 61 00 72 00 74 00 6f 00 73 00 74 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account160 = {((65 69 6c 65 65 6e 40 62 6c 6f 77 74 61 63 2d 74 77 2e 63 6f 6d) | (65 00 69 00 6c 00 65 00 65 00 6e 00 40 00 62 00 6c 00 6f 00 77 00 74 00 61 00 63 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account161 = {((65 6c 62 65 72 40 77 74 73 65 6c 65 2e 6e 65 74) | (65 00 6c 00 62 00 65 00 72 00 40 00 77 00 74 00 73 00 65 00 6c 00 65 00 2e 00 6e 00 65 00 74 00))}
		$account162 = {((65 6c 65 6b 75 73 32 30 32 30 40 61 65 72 6f 74 61 63 63 74 76 6e 2e 63 6f 6d) | (65 00 6c 00 65 00 6b 00 75 00 73 00 32 00 30 00 32 00 30 00 40 00 61 00 65 00 72 00 6f 00 74 00 61 00 63 00 63 00 74 00 76 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account163 = {((65 6c 68 61 6e 64 61 73 79 61 40 70 70 65 2d 65 67 2e 63 6f 6d) | (65 00 6c 00 68 00 61 00 6e 00 64 00 61 00 73 00 79 00 61 00 40 00 70 00 70 00 65 00 2d 00 65 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account164 = {((65 6c 6d 61 6c 69 40 62 69 6b 6f 73 73 6f 66 74 2e 6d 65) | (65 00 6c 00 6d 00 61 00 6c 00 69 00 40 00 62 00 69 00 6b 00 6f 00 73 00 73 00 6f 00 66 00 74 00 2e 00 6d 00 65 00))}
		$account165 = {((65 6c 76 69 65 6d 61 72 71 75 65 7a 40 6f 6e 74 69 6d 65 2e 63 6f 6d 2e 70 68) | (65 00 6c 00 76 00 69 00 65 00 6d 00 61 00 72 00 71 00 75 00 65 00 7a 00 40 00 6f 00 6e 00 74 00 69 00 6d 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 70 00 68 00))}
		$account166 = {((65 6d 69 6e 67 6c 65 73 40 69 6c 63 6c 61 77 2e 63 6f 6d 2e 70 68) | (65 00 6d 00 69 00 6e 00 67 00 6c 00 65 00 73 00 40 00 69 00 6c 00 63 00 6c 00 61 00 77 00 2e 00 63 00 6f 00 6d 00 2e 00 70 00 68 00))}
		$account167 = {((65 6d 40 69 6e 70 61 72 6b 2e 72 73) | (65 00 6d 00 40 00 69 00 6e 00 70 00 61 00 72 00 6b 00 2e 00 72 00 73 00))}
		$account168 = {((65 6d 6d 61 40 67 61 72 6e 69 73 68 6d 61 73 74 65 72 2e 63 6f 6d) | (65 00 6d 00 6d 00 61 00 40 00 67 00 61 00 72 00 6e 00 69 00 73 00 68 00 6d 00 61 00 73 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account169 = {((65 6e 71 75 69 72 79 40 77 61 6d 61 6e 2e 69 6e) | (65 00 6e 00 71 00 75 00 69 00 72 00 79 00 40 00 77 00 61 00 6d 00 61 00 6e 00 2e 00 69 00 6e 00))}
		$account170 = {((65 2e 70 65 7a 7a 6c 69 40 67 69 69 76 69 6e 2e 63 6f 6d) | (65 00 2e 00 70 00 65 00 7a 00 7a 00 6c 00 69 00 40 00 67 00 69 00 69 00 76 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account171 = {((65 2e 70 65 7a 7a 6f 6c 69 40 67 69 69 76 69 6e 2e 63 6f 6d) | (65 00 2e 00 70 00 65 00 7a 00 7a 00 6f 00 6c 00 69 00 40 00 67 00 69 00 69 00 76 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account172 = {((65 73 69 6d 65 37 37 40 79 61 6e 64 65 78 2e 63 6f 6d) | (65 00 73 00 69 00 6d 00 65 00 37 00 37 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account173 = {((65 75 72 6f 74 6f 6f 6c 7a 40 72 65 74 75 72 6e 74 6f 6c 7a 2e 63 6f 6d) | (65 00 75 00 72 00 6f 00 74 00 6f 00 6f 00 6c 00 7a 00 40 00 72 00 65 00 74 00 75 00 72 00 6e 00 74 00 6f 00 6c 00 7a 00 2e 00 63 00 6f 00 6d 00))}
		$account174 = {((65 76 65 72 73 6f 6e 40 61 67 70 6d 65 61 74 73 2e 63 6f 6d) | (65 00 76 00 65 00 72 00 73 00 6f 00 6e 00 40 00 61 00 67 00 70 00 6d 00 65 00 61 00 74 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account175 = {((65 78 70 6f 72 74 40 61 6d 65 74 65 78 65 67 79 70 74 73 2e 69 6e 66 6f) | (65 00 78 00 70 00 6f 00 72 00 74 00 40 00 61 00 6d 00 65 00 74 00 65 00 78 00 65 00 67 00 79 00 70 00 74 00 73 00 2e 00 69 00 6e 00 66 00 6f 00))}
		$account176 = {((65 78 70 6f 72 74 40 62 72 69 73 74 6f 6c 2d 66 69 72 65 2e 63 6f) | (65 00 78 00 70 00 6f 00 72 00 74 00 40 00 62 00 72 00 69 00 73 00 74 00 6f 00 6c 00 2d 00 66 00 69 00 72 00 65 00 2e 00 63 00 6f 00))}
		$account177 = {((65 7a 65 40 62 75 72 73 74 73 74 72 65 61 6d 77 71 31 2e 77 65 62 73 69 74 65) | (65 00 7a 00 65 00 40 00 62 00 75 00 72 00 73 00 74 00 73 00 74 00 72 00 65 00 61 00 6d 00 77 00 71 00 31 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account178 = {((65 7a 65 40 6d 69 6b 65 74 6f 6e 79 2d 74 77 2e 63 6f 6d) | (65 00 7a 00 65 00 40 00 6d 00 69 00 6b 00 65 00 74 00 6f 00 6e 00 79 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account179 = {((66 61 6c 6c 69 6e 40 64 61 6d 6c 6c 61 6b 69 6d 79 61 2e 63 6f 6d) | (66 00 61 00 6c 00 6c 00 69 00 6e 00 40 00 64 00 61 00 6d 00 6c 00 6c 00 61 00 6b 00 69 00 6d 00 79 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account180 = {((66 61 6c 74 65 6c 65 63 6f 6d 40 66 61 6c 74 65 6c 65 63 6f 6d 2e 63 6f 6d) | (66 00 61 00 6c 00 74 00 65 00 6c 00 65 00 63 00 6f 00 6d 00 40 00 66 00 61 00 6c 00 74 00 65 00 6c 00 65 00 63 00 6f 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account181 = {((66 61 72 75 71 40 65 61 67 6c 65 65 79 65 61 70 70 61 72 65 6c 73 2e 63 6f 6d) | (66 00 61 00 72 00 75 00 71 00 40 00 65 00 61 00 67 00 6c 00 65 00 65 00 79 00 65 00 61 00 70 00 70 00 61 00 72 00 65 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account182 = {((66 65 63 6f 40 69 6b 65 32 30 32 30 2e 78 79 7a) | (66 00 65 00 63 00 6f 00 40 00 69 00 6b 00 65 00 32 00 30 00 32 00 30 00 2e 00 78 00 79 00 7a 00))}
		$account183 = {((66 66 61 6e 67 66 61 6e 67 40 79 61 6e 64 65 78 2e 63 6f 6d) | (66 00 66 00 61 00 6e 00 67 00 66 00 61 00 6e 00 67 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account184 = {((66 66 66 66 66 66 66 67 67 67 64 40 79 61 6e 64 65 78 2e 63 6f 6d) | (66 00 66 00 66 00 66 00 66 00 66 00 66 00 67 00 67 00 67 00 64 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account185 = {((66 69 64 6f 40 65 64 69 66 6c 65 72 2e 78 79 7a) | (66 00 69 00 64 00 6f 00 40 00 65 00 64 00 69 00 66 00 6c 00 65 00 72 00 2e 00 78 00 79 00 7a 00))}
		$account186 = {((66 69 64 6f 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (66 00 69 00 64 00 6f 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account187 = {((66 69 6e 61 6e 63 65 40 65 6e 6d 61 72 6b 2e 63 6f 6d 2e 6d 79) | (66 00 69 00 6e 00 61 00 6e 00 63 00 65 00 40 00 65 00 6e 00 6d 00 61 00 72 00 6b 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 79 00))}
		$account188 = {((66 69 6e 61 6e 63 65 40 6d 61 6e 75 6e 67 67 61 6c 6b 61 72 6f 73 65 72 69 2e 63 6f 6d) | (66 00 69 00 6e 00 61 00 6e 00 63 00 65 00 40 00 6d 00 61 00 6e 00 75 00 6e 00 67 00 67 00 61 00 6c 00 6b 00 61 00 72 00 6f 00 73 00 65 00 72 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account189 = {((66 69 6e 61 6e 63 65 40 73 75 70 72 65 6d 65 2d 73 67 2e 69 63 75) | (66 00 69 00 6e 00 61 00 6e 00 63 00 65 00 40 00 73 00 75 00 70 00 72 00 65 00 6d 00 65 00 2d 00 73 00 67 00 2e 00 69 00 63 00 75 00))}
		$account190 = {((66 69 6e 61 6e 63 65 40 77 6f 77 77 6f 77 2e 63 6f 6d 2e 73 67) | (66 00 69 00 6e 00 61 00 6e 00 63 00 65 00 40 00 77 00 6f 00 77 00 77 00 6f 00 77 00 2e 00 63 00 6f 00 6d 00 2e 00 73 00 67 00))}
		$account191 = {((66 6c 65 74 63 68 65 72 6a 6f 68 6e 73 67 74 40 67 6d 61 69 6c 2e 63 6f 6d) | (66 00 6c 00 65 00 74 00 63 00 68 00 65 00 72 00 6a 00 6f 00 68 00 6e 00 73 00 67 00 74 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account192 = {((66 6c 6f 40 6e 6f 76 61 61 2d 73 68 69 70 2e 63 6f 6d) | (66 00 6c 00 6f 00 40 00 6e 00 6f 00 76 00 61 00 61 00 2d 00 73 00 68 00 69 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account193 = {((66 6c 6f 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (66 00 6c 00 6f 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account194 = {((66 72 61 6e 63 69 73 40 62 75 72 73 74 73 74 72 65 61 6d 77 71 31 2e 77 65 62 73 69 74 65) | (66 00 72 00 61 00 6e 00 63 00 69 00 73 00 40 00 62 00 75 00 72 00 73 00 74 00 73 00 74 00 72 00 65 00 61 00 6d 00 77 00 71 00 31 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account195 = {((66 72 61 6e 6b 2e 67 6f 74 40 79 61 6e 64 65 78 2e 72 75) | (66 00 72 00 61 00 6e 00 6b 00 2e 00 67 00 6f 00 74 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account196 = {((66 72 61 6e 6b 76 61 6e 64 65 72 6c 6f 6f 70 40 73 77 61 6e 6e 62 65 72 67 2e 63 6f 6d) | (66 00 72 00 61 00 6e 00 6b 00 76 00 61 00 6e 00 64 00 65 00 72 00 6c 00 6f 00 6f 00 70 00 40 00 73 00 77 00 61 00 6e 00 6e 00 62 00 65 00 72 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account197 = {((66 72 65 73 68 63 6c 69 6e 74 6f 6e 38 32 36 39 40 79 61 6e 64 65 78 2e 63 6f 6d) | (66 00 72 00 65 00 73 00 68 00 63 00 6c 00 69 00 6e 00 74 00 6f 00 6e 00 38 00 32 00 36 00 39 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account198 = {((66 72 65 73 68 2e 69 74 61 6c 69 61 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (66 00 72 00 65 00 73 00 68 00 2e 00 69 00 74 00 61 00 6c 00 69 00 61 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account199 = {((66 74 69 40 61 6c 6c 74 6f 70 6c 69 67 68 74 69 6e 67 2e 69 63 75) | (66 00 74 00 69 00 40 00 61 00 6c 00 6c 00 74 00 6f 00 70 00 6c 00 69 00 67 00 68 00 74 00 69 00 6e 00 67 00 2e 00 69 00 63 00 75 00))}
		$account200 = {((66 75 63 6b 6f 66 66 40 6a 70 6d 65 2e 6f 72 67 2e 69 6e) | (66 00 75 00 63 00 6b 00 6f 00 66 00 66 00 40 00 6a 00 70 00 6d 00 65 00 2e 00 6f 00 72 00 67 00 2e 00 69 00 6e 00))}
		$account201 = {((66 78 78 78 66 75 7a 40 79 61 6e 64 65 78 2e 63 6f 6d) | (66 00 78 00 78 00 78 00 66 00 75 00 7a 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account202 = {((67 61 62 61 6e 64 74 65 65 40 67 6d 61 69 6c 2e 63 6f 6d) | (67 00 61 00 62 00 61 00 6e 00 64 00 74 00 65 00 65 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account203 = {((67 61 6d 7a 79 40 61 6c 6c 69 61 64 69 6e 74 6c 2e 63 6f 6d) | (67 00 61 00 6d 00 7a 00 79 00 40 00 61 00 6c 00 6c 00 69 00 61 00 64 00 69 00 6e 00 74 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account204 = {((67 61 72 61 6e 67 40 70 6c 61 74 69 6e 73 68 69 70 73 2e 6e 65 74) | (67 00 61 00 72 00 61 00 6e 00 67 00 40 00 70 00 6c 00 61 00 74 00 69 00 6e 00 73 00 68 00 69 00 70 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account205 = {((67 61 76 69 6e 40 6a 61 6e 64 72 65 67 6f 6e 2e 63 6f 6d) | (67 00 61 00 76 00 69 00 6e 00 40 00 6a 00 61 00 6e 00 64 00 72 00 65 00 67 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account206 = {((67 61 79 61 74 68 72 69 40 67 63 73 2e 63 6f 2e 69 6e) | (67 00 61 00 79 00 61 00 74 00 68 00 72 00 69 00 40 00 67 00 63 00 73 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account207 = {((67 2e 63 61 76 69 74 65 6c 6c 69 40 73 69 63 69 6d 2e 69 63 75) | (67 00 2e 00 63 00 61 00 76 00 69 00 74 00 65 00 6c 00 6c 00 69 00 40 00 73 00 69 00 63 00 69 00 6d 00 2e 00 69 00 63 00 75 00))}
		$account208 = {((67 65 6e 61 72 61 6c 31 31 32 32 40 79 61 6e 64 65 78 2e 72 75) | (67 00 65 00 6e 00 61 00 72 00 61 00 6c 00 31 00 31 00 32 00 32 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account209 = {((67 65 6e 75 78 70 63 40 79 61 6e 64 65 78 2e 63 6f 6d) | (67 00 65 00 6e 00 75 00 78 00 70 00 63 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account210 = {((67 65 6f 66 66 2e 66 61 72 6e 73 77 6f 72 74 68 40 68 6f 6c 64 6c 6e 67 72 65 64 6c 69 63 68 2e 63 6f 6d) | (67 00 65 00 6f 00 66 00 66 00 2e 00 66 00 61 00 72 00 6e 00 73 00 77 00 6f 00 72 00 74 00 68 00 40 00 68 00 6f 00 6c 00 64 00 6c 00 6e 00 67 00 72 00 65 00 64 00 6c 00 69 00 63 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account211 = {((67 65 72 65 6e 63 69 61 40 67 72 6f 75 70 6f 69 6e 6b 61 66 6f 6f 64 73 2e 63 6f 6d) | (67 00 65 00 72 00 65 00 6e 00 63 00 69 00 61 00 40 00 67 00 72 00 6f 00 75 00 70 00 6f 00 69 00 6e 00 6b 00 61 00 66 00 6f 00 6f 00 64 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account212 = {((67 65 73 74 69 6f 6e 65 73 6f 6c 6c 65 63 69 74 69 40 70 65 63 2d 77 61 72 72 61 6e 74 67 72 6f 75 70 2e 69 63 75) | (67 00 65 00 73 00 74 00 69 00 6f 00 6e 00 65 00 73 00 6f 00 6c 00 6c 00 65 00 63 00 69 00 74 00 69 00 40 00 70 00 65 00 63 00 2d 00 77 00 61 00 72 00 72 00 61 00 6e 00 74 00 67 00 72 00 6f 00 75 00 70 00 2e 00 69 00 63 00 75 00))}
		$account213 = {((67 6c 6f 62 61 6c 73 40 62 74 63 6f 6e 72 6e 65 63 74 2e 63 6f 6d) | (67 00 6c 00 6f 00 62 00 61 00 6c 00 73 00 40 00 62 00 74 00 63 00 6f 00 6e 00 72 00 6e 00 65 00 63 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account214 = {((67 6c 6f 77 68 75 62 40 79 61 6e 64 65 78 2e 63 6f 6d) | (67 00 6c 00 6f 00 77 00 68 00 75 00 62 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account215 = {((67 6f 64 69 65 40 63 6a 63 75 72 72 65 6e 74 2e 63 6f 6d) | (67 00 6f 00 64 00 69 00 65 00 40 00 63 00 6a 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account216 = {((67 6f 64 77 69 69 6c 6c 40 73 65 72 76 69 63 65 63 6f 6e 73 75 74 61 6e 74 2e 63 6f 6d) | (67 00 6f 00 64 00 77 00 69 00 69 00 6c 00 6c 00 40 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 63 00 6f 00 6e 00 73 00 75 00 74 00 61 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account217 = {((67 2e 6f 69 6b 6f 6e 6f 6d 6f 70 6f 75 6c 6f 73 40 6b 6f 72 64 65 6c 6f 73 2d 67 72 2e 63 6f) | (67 00 2e 00 6f 00 69 00 6b 00 6f 00 6e 00 6f 00 6d 00 6f 00 70 00 6f 00 75 00 6c 00 6f 00 73 00 40 00 6b 00 6f 00 72 00 64 00 65 00 6c 00 6f 00 73 00 2d 00 67 00 72 00 2e 00 63 00 6f 00))}
		$account218 = {((67 6f 6c 64 40 70 72 69 73 6d 69 6e 64 69 61 2e 69 6e) | (67 00 6f 00 6c 00 64 00 40 00 70 00 72 00 69 00 73 00 6d 00 69 00 6e 00 64 00 69 00 61 00 2e 00 69 00 6e 00))}
		$account219 = {((47 6f 6f 64 6c 75 63 6b 32 6b 32 30 40 79 61 6e 64 65 78 2e 63 6f 6d) | (47 00 6f 00 6f 00 64 00 6c 00 75 00 63 00 6b 00 32 00 6b 00 32 00 30 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account220 = {((67 6f 76 65 72 6e 6f 72 40 74 6f 74 61 6c 6c 79 61 6e 6f 6e 79 6d 6f 75 73 2e 63 6f 6d) | (67 00 6f 00 76 00 65 00 72 00 6e 00 6f 00 72 00 40 00 74 00 6f 00 74 00 61 00 6c 00 6c 00 79 00 61 00 6e 00 6f 00 6e 00 79 00 6d 00 6f 00 75 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account221 = {((67 6f 7a 6d 61 6e 68 65 6e 40 6e 61 2d 73 75 70 65 72 68 72 64 2e 63 6f 6d) | (67 00 6f 00 7a 00 6d 00 61 00 6e 00 68 00 65 00 6e 00 40 00 6e 00 61 00 2d 00 73 00 75 00 70 00 65 00 72 00 68 00 72 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account222 = {((67 72 61 63 65 5f 70 61 6e 40 74 72 61 69 6e 67 6c 65 2d 63 6e 2e 63 6f 6d) | (67 00 72 00 61 00 63 00 65 00 5f 00 70 00 61 00 6e 00 40 00 74 00 72 00 61 00 69 00 6e 00 67 00 6c 00 65 00 2d 00 63 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account223 = {((67 72 61 6e 74 33 40 6c 65 6c 74 62 61 6e 6b 2e 63 6f 6d) | (67 00 72 00 61 00 6e 00 74 00 33 00 40 00 6c 00 65 00 6c 00 74 00 62 00 61 00 6e 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account224 = {((67 72 65 65 6e 70 61 72 6b 40 69 62 63 2e 62 79) | (67 00 72 00 65 00 65 00 6e 00 70 00 61 00 72 00 6b 00 40 00 69 00 62 00 63 00 2e 00 62 00 79 00))}
		$account225 = {((67 73 61 6d 75 65 6c 40 6e 61 74 69 6f 6e 61 6c 70 6f 72 74 73 65 72 76 69 63 65 73 2e 63 61 6d) | (67 00 73 00 61 00 6d 00 75 00 65 00 6c 00 40 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 70 00 6f 00 72 00 74 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 63 00 61 00 6d 00))}
		$account226 = {((67 75 6c 64 65 6e 40 63 6f 72 69 6e 6f 78 2e 63 6f 6d 2e 74 72) | (67 00 75 00 6c 00 64 00 65 00 6e 00 40 00 63 00 6f 00 72 00 69 00 6e 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2e 00 74 00 72 00))}
		$account227 = {((68 61 6e 79 5f 68 65 6e 69 65 6e 40 73 70 70 70 75 6d 70 73 2e 63 6f) | (68 00 61 00 6e 00 79 00 5f 00 68 00 65 00 6e 00 69 00 65 00 6e 00 40 00 73 00 70 00 70 00 70 00 75 00 6d 00 70 00 73 00 2e 00 63 00 6f 00))}
		$account228 = {((68 65 61 6c 74 68 2e 73 61 66 65 74 79 40 73 65 61 62 65 61 63 68 61 71 75 61 70 61 72 6b 73 73 68 2e 63 6f 6d) | (68 00 65 00 61 00 6c 00 74 00 68 00 2e 00 73 00 61 00 66 00 65 00 74 00 79 00 40 00 73 00 65 00 61 00 62 00 65 00 61 00 63 00 68 00 61 00 71 00 75 00 61 00 70 00 61 00 72 00 6b 00 73 00 73 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account229 = {((68 65 62 65 72 74 40 70 72 6f 74 65 6e 67 69 6e 73 74 61 6c 61 63 6f 65 73 2e 63 6f 6d 2e 62 72) | (68 00 65 00 62 00 65 00 72 00 74 00 40 00 70 00 72 00 6f 00 74 00 65 00 6e 00 67 00 69 00 6e 00 73 00 74 00 61 00 6c 00 61 00 63 00 6f 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00))}
		$account230 = {((68 67 61 6c 76 61 6e 40 76 61 63 6f 6e 74 67 6f 2e 63 6f 6d) | (68 00 67 00 61 00 6c 00 76 00 61 00 6e 00 40 00 76 00 61 00 63 00 6f 00 6e 00 74 00 67 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account231 = {((68 2e 68 65 6e 6e 65 74 40 67 6c 6f 76 61 64 75 73 2e 63 6f 6d) | (68 00 2e 00 68 00 65 00 6e 00 6e 00 65 00 74 00 40 00 67 00 6c 00 6f 00 76 00 61 00 64 00 75 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account232 = {((68 68 68 70 70 40 65 6c 6f 65 6c 6f 6b 65 6e 64 69 2e 63 6f 6d) | (68 00 68 00 68 00 70 00 70 00 40 00 65 00 6c 00 6f 00 65 00 6c 00 6f 00 6b 00 65 00 6e 00 64 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account233 = {((68 69 74 65 6e 64 72 61 40 67 61 6c 61 78 79 70 68 61 72 6d 61 2d 63 6f 2d 6b 65 2e 70 77) | (68 00 69 00 74 00 65 00 6e 00 64 00 72 00 61 00 40 00 67 00 61 00 6c 00 61 00 78 00 79 00 70 00 68 00 61 00 72 00 6d 00 61 00 2d 00 63 00 6f 00 2d 00 6b 00 65 00 2e 00 70 00 77 00))}
		$account234 = {((68 6d 40 61 63 72 6f 61 74 69 76 65 2e 63 6f 6d) | (68 00 6d 00 40 00 61 00 63 00 72 00 6f 00 61 00 74 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account235 = {((68 6f 61 2e 76 75 40 67 6f 6f 64 6c 61 6e 64 2e 63 6f 6d 2e 76 6e) | (68 00 6f 00 61 00 2e 00 76 00 75 00 40 00 67 00 6f 00 6f 00 64 00 6c 00 61 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00 2e 00 76 00 6e 00))}
		$account236 = {((68 6f 6b 65 2e 73 61 6c 65 73 30 31 40 67 6d 61 69 6c 2e 63 6f 6d) | (68 00 6f 00 6b 00 65 00 2e 00 73 00 61 00 6c 00 65 00 73 00 30 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account237 = {((68 6f 6c 79 6d 61 6e 40 61 62 69 73 74 65 2e 62 69 7a) | (68 00 6f 00 6c 00 79 00 6d 00 61 00 6e 00 40 00 61 00 62 00 69 00 73 00 74 00 65 00 2e 00 62 00 69 00 7a 00))}
		$account238 = {((68 6f 75 73 74 6f 6e 64 61 76 69 64 73 6f 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (68 00 6f 00 75 00 73 00 74 00 6f 00 6e 00 64 00 61 00 76 00 69 00 64 00 73 00 6f 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account239 = {((68 70 40 64 65 65 70 73 61 65 65 6d 69 72 61 74 65 73 2e 63 6f 6d) | (68 00 70 00 40 00 64 00 65 00 65 00 70 00 73 00 61 00 65 00 65 00 6d 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account240 = {((68 73 65 6c 69 6d 6f 67 6c 75 40 62 6d 73 73 72 65 76 69 73 2e 63 6f 6d) | (68 00 73 00 65 00 6c 00 69 00 6d 00 6f 00 67 00 6c 00 75 00 40 00 62 00 6d 00 73 00 73 00 72 00 65 00 76 00 69 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account241 = {((68 75 61 6e 67 6a 69 61 6e 70 69 6e 67 40 63 68 69 6e 61 63 61 62 6c 65 73 2e 69 63 75) | (68 00 75 00 61 00 6e 00 67 00 6a 00 69 00 61 00 6e 00 70 00 69 00 6e 00 67 00 40 00 63 00 68 00 69 00 6e 00 61 00 63 00 61 00 62 00 6c 00 65 00 73 00 2e 00 69 00 63 00 75 00))}
		$account242 = {((68 75 6d 62 61 74 6f 30 31 40 72 65 7a 75 69 74 2e 70 72 6f) | (68 00 75 00 6d 00 62 00 61 00 74 00 6f 00 30 00 31 00 40 00 72 00 65 00 7a 00 75 00 69 00 74 00 2e 00 70 00 72 00 6f 00))}
		$account243 = {((68 75 73 73 61 6d 2e 6f 64 65 68 40 74 65 6d 69 63 6f 2d 6d 65 70 2e 63 6f 6d) | (68 00 75 00 73 00 73 00 61 00 6d 00 2e 00 6f 00 64 00 65 00 68 00 40 00 74 00 65 00 6d 00 69 00 63 00 6f 00 2d 00 6d 00 65 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account244 = {((68 79 62 72 69 64 40 61 67 61 76 65 63 6f 6d 71 75 69 73 74 61 2e 63 6f 6d) | (68 00 79 00 62 00 72 00 69 00 64 00 40 00 61 00 67 00 61 00 76 00 65 00 63 00 6f 00 6d 00 71 00 75 00 69 00 73 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account245 = {((68 79 62 72 69 64 2d 61 70 70 73 75 69 74 40 61 6c 6c 69 61 64 69 6e 74 6c 2e 63 6f 6d) | (68 00 79 00 62 00 72 00 69 00 64 00 2d 00 61 00 70 00 70 00 73 00 75 00 69 00 74 00 40 00 61 00 6c 00 6c 00 69 00 61 00 64 00 69 00 6e 00 74 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account246 = {((69 62 69 6c 65 32 40 65 69 6d 61 72 77 61 66 6f 6f 64 73 2e 63 6f 6d) | (69 00 62 00 69 00 6c 00 65 00 32 00 40 00 65 00 69 00 6d 00 61 00 72 00 77 00 61 00 66 00 6f 00 6f 00 64 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account247 = {((69 68 67 75 6e 67 6f 72 40 33 65 6e 61 6c 75 6d 69 6e 79 75 6d 2e 63 6f 6d 2e 74 72) | (69 00 68 00 67 00 75 00 6e 00 67 00 6f 00 72 00 40 00 33 00 65 00 6e 00 61 00 6c 00 75 00 6d 00 69 00 6e 00 79 00 75 00 6d 00 2e 00 63 00 6f 00 6d 00 2e 00 74 00 72 00))}
		$account248 = {((69 68 73 68 61 6d 73 61 40 69 72 6f 6e 68 61 6e 64 63 6f 2e 63 6f 6d) | (69 00 68 00 73 00 68 00 61 00 6d 00 73 00 61 00 40 00 69 00 72 00 6f 00 6e 00 68 00 61 00 6e 00 64 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account249 = {((69 6a 61 7a 40 68 73 69 73 74 65 65 6c 73 2e 63 6f 6d) | (69 00 6a 00 61 00 7a 00 40 00 68 00 73 00 69 00 73 00 74 00 65 00 65 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account250 = {((69 6b 6f 73 74 61 64 69 6e 6f 76 40 63 61 72 67 6f 61 69 72 2e 62 67) | (69 00 6b 00 6f 00 73 00 74 00 61 00 64 00 69 00 6e 00 6f 00 76 00 40 00 63 00 61 00 72 00 67 00 6f 00 61 00 69 00 72 00 2e 00 62 00 67 00))}
		$account251 = {((69 6b 70 63 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (69 00 6b 00 70 00 63 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account252 = {((69 6b 75 6b 75 40 70 6f 79 6c 6f 6e 65 2e 63 6f 6d) | (69 00 6b 00 75 00 6b 00 75 00 40 00 70 00 6f 00 79 00 6c 00 6f 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account253 = {((69 6c 61 72 69 6f 40 73 6f 62 72 65 72 6f 61 72 74 69 67 72 61 66 69 63 68 65 2e 63 6f 6d) | (69 00 6c 00 61 00 72 00 69 00 6f 00 40 00 73 00 6f 00 62 00 72 00 65 00 72 00 6f 00 61 00 72 00 74 00 69 00 67 00 72 00 61 00 66 00 69 00 63 00 68 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account254 = {((69 6d 70 6f 72 74 32 32 2e 65 78 70 6f 72 74 40 79 61 6e 64 65 78 2e 63 6f 6d) | (69 00 6d 00 70 00 6f 00 72 00 74 00 32 00 32 00 2e 00 65 00 78 00 70 00 6f 00 72 00 74 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account255 = {((69 6d 70 6f 72 74 73 40 65 61 73 74 65 6e 64 66 6f 6f 64 2d 75 6b 2e 69 63 75) | (69 00 6d 00 70 00 6f 00 72 00 74 00 73 00 40 00 65 00 61 00 73 00 74 00 65 00 6e 00 64 00 66 00 6f 00 6f 00 64 00 2d 00 75 00 6b 00 2e 00 69 00 63 00 75 00))}
		$account256 = {((69 6d 70 6f 72 74 73 40 74 65 63 68 69 6e 2e 69 63 75) | (69 00 6d 00 70 00 6f 00 72 00 74 00 73 00 40 00 74 00 65 00 63 00 68 00 69 00 6e 00 2e 00 69 00 63 00 75 00))}
		$account257 = {((69 6e 66 6f 32 33 40 68 75 61 74 65 6e 67 61 63 63 65 73 73 66 6c 6f 6f 72 2e 69 63 75) | (69 00 6e 00 66 00 6f 00 32 00 33 00 40 00 68 00 75 00 61 00 74 00 65 00 6e 00 67 00 61 00 63 00 63 00 65 00 73 00 73 00 66 00 6c 00 6f 00 6f 00 72 00 2e 00 69 00 63 00 75 00))}
		$account258 = {((69 6e 66 6f 40 61 62 75 6f 64 65 68 62 72 6f 73 2e 63 6f) | (69 00 6e 00 66 00 6f 00 40 00 61 00 62 00 75 00 6f 00 64 00 65 00 68 00 62 00 72 00 6f 00 73 00 2e 00 63 00 6f 00))}
		$account259 = {((69 6e 66 6f 40 61 66 69 6e 6f 78 64 65 73 69 67 6e 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 61 00 66 00 69 00 6e 00 6f 00 78 00 64 00 65 00 73 00 69 00 67 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account260 = {((69 6e 66 6f 40 61 67 72 69 2d 63 68 65 72 6e 69 63 61 6c 73 2e 6e 65 74) | (69 00 6e 00 66 00 6f 00 40 00 61 00 67 00 72 00 69 00 2d 00 63 00 68 00 65 00 72 00 6e 00 69 00 63 00 61 00 6c 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account261 = {((69 6e 66 6f 40 61 6d 61 7a 69 72 67 69 6e 64 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 61 00 6d 00 61 00 7a 00 69 00 72 00 67 00 69 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account262 = {((69 6e 66 6f 40 61 6d 65 72 69 63 61 6e 74 72 65 76 61 6c 65 72 69 6e 63 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 61 00 6d 00 65 00 72 00 69 00 63 00 61 00 6e 00 74 00 72 00 65 00 76 00 61 00 6c 00 65 00 72 00 69 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account263 = {((69 6e 66 6f 40 61 6d 65 74 68 69 73 68 69 70 70 69 6e 67 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 61 00 6d 00 65 00 74 00 68 00 69 00 73 00 68 00 69 00 70 00 70 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account264 = {((69 6e 66 6f 40 61 70 74 72 61 69 6e 69 6e 67 2e 62 69 7a) | (69 00 6e 00 66 00 6f 00 40 00 61 00 70 00 74 00 72 00 61 00 69 00 6e 00 69 00 6e 00 67 00 2e 00 62 00 69 00 7a 00))}
		$account265 = {((69 6e 66 6f 40 63 68 75 63 6b 73 6d 6f 64 65 2e 75 73) | (69 00 6e 00 66 00 6f 00 40 00 63 00 68 00 75 00 63 00 6b 00 73 00 6d 00 6f 00 64 00 65 00 2e 00 75 00 73 00))}
		$account266 = {((69 6e 66 6f 40 63 6f 6d 66 6f 72 74 6b 69 64 73 2e 69 6e) | (69 00 6e 00 66 00 6f 00 40 00 63 00 6f 00 6d 00 66 00 6f 00 72 00 74 00 6b 00 69 00 64 00 73 00 2e 00 69 00 6e 00))}
		$account267 = {((69 6e 66 6f 64 65 63 40 6c 65 70 74 61 2e 77 65 62 73 69 74 65) | (69 00 6e 00 66 00 6f 00 64 00 65 00 63 00 40 00 6c 00 65 00 70 00 74 00 61 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account268 = {((69 6e 66 6f 40 64 65 68 79 64 72 61 74 65 64 6f 6e 69 6f 6e 67 61 72 6c 69 63 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 64 00 65 00 68 00 79 00 64 00 72 00 61 00 74 00 65 00 64 00 6f 00 6e 00 69 00 6f 00 6e 00 67 00 61 00 72 00 6c 00 69 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account269 = {((69 6e 66 6f 40 65 78 63 65 6c 6c 65 6e 74 2e 62 61) | (69 00 6e 00 66 00 6f 00 40 00 65 00 78 00 63 00 65 00 6c 00 6c 00 65 00 6e 00 74 00 2e 00 62 00 61 00))}
		$account270 = {((69 6e 66 6f 40 66 69 72 73 74 67 72 61 64 65 63 6f 75 72 69 65 72 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 66 00 69 00 72 00 73 00 74 00 67 00 72 00 61 00 64 00 65 00 63 00 6f 00 75 00 72 00 69 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account271 = {((69 6e 66 6f 40 66 72 69 65 6e 64 73 68 69 70 73 2d 6b 65 2e 69 63 75) | (69 00 6e 00 66 00 6f 00 40 00 66 00 72 00 69 00 65 00 6e 00 64 00 73 00 68 00 69 00 70 00 73 00 2d 00 6b 00 65 00 2e 00 69 00 63 00 75 00))}
		$account272 = {((69 6e 66 6f 40 68 61 6a 61 72 74 72 61 64 69 6e 67 2e 6e 65 74) | (69 00 6e 00 66 00 6f 00 40 00 68 00 61 00 6a 00 61 00 72 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 2e 00 6e 00 65 00 74 00))}
		$account273 = {((69 6e 66 6f 40 68 69 67 68 65 73 74 67 61 6d 65 2e 75 73) | (69 00 6e 00 66 00 6f 00 40 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 67 00 61 00 6d 00 65 00 2e 00 75 00 73 00))}
		$account274 = {((69 6e 66 6f 40 68 6f 74 65 6c 62 6c 75 2e 65 73) | (69 00 6e 00 66 00 6f 00 40 00 68 00 6f 00 74 00 65 00 6c 00 62 00 6c 00 75 00 2e 00 65 00 73 00))}
		$account275 = {((69 6e 66 6f 40 68 6f 74 65 6c 6d 61 64 72 69 64 74 6f 72 72 65 76 69 65 6a 61 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 68 00 6f 00 74 00 65 00 6c 00 6d 00 61 00 64 00 72 00 69 00 64 00 74 00 6f 00 72 00 72 00 65 00 76 00 69 00 65 00 6a 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account276 = {((69 6e 66 6f 40 6a 61 63 63 6f 6e 74 72 61 63 74 69 6e 67 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 6a 00 61 00 63 00 63 00 6f 00 6e 00 74 00 72 00 61 00 63 00 74 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account277 = {((69 6e 66 6f 40 6c 65 67 61 6c 63 6f 75 6e 73 65 6c 62 64 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 6c 00 65 00 67 00 61 00 6c 00 63 00 6f 00 75 00 6e 00 73 00 65 00 6c 00 62 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account278 = {((69 6e 66 6f 40 6d 61 72 6d 61 72 69 73 66 65 72 72 79 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 6d 00 61 00 72 00 6d 00 61 00 72 00 69 00 73 00 66 00 65 00 72 00 72 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account279 = {((69 6e 66 6f 40 6d 6f 6e 64 61 73 74 75 64 69 6f 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 6d 00 6f 00 6e 00 64 00 61 00 73 00 74 00 75 00 64 00 69 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account280 = {((69 6e 66 6f 2e 70 61 6e 61 40 79 61 6e 64 65 78 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 2e 00 70 00 61 00 6e 00 61 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account281 = {((69 6e 66 6f 40 70 61 74 2e 70 73) | (69 00 6e 00 66 00 6f 00 40 00 70 00 61 00 74 00 2e 00 70 00 73 00))}
		$account282 = {((69 6e 66 6f 40 70 65 74 65 72 70 61 6e 2e 69 63 75) | (69 00 6e 00 66 00 6f 00 40 00 70 00 65 00 74 00 65 00 72 00 70 00 61 00 6e 00 2e 00 69 00 63 00 75 00))}
		$account283 = {((69 6e 66 6f 40 70 69 70 69 6e 67 7a 6f 6e 65 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 70 00 69 00 70 00 69 00 6e 00 67 00 7a 00 6f 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account284 = {((69 6e 66 6f 40 70 72 69 6d 6f 73 73 6f 66 61 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 70 00 72 00 69 00 6d 00 6f 00 73 00 73 00 6f 00 66 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account285 = {((69 6e 66 6f 40 72 61 6e 67 65 72 73 66 75 65 6c 2e 78 79 7a) | (69 00 6e 00 66 00 6f 00 40 00 72 00 61 00 6e 00 67 00 65 00 72 00 73 00 66 00 75 00 65 00 6c 00 2e 00 78 00 79 00 7a 00))}
		$account286 = {((69 6e 66 6f 40 72 69 73 68 69 63 68 65 6d 6c 63 61 6c 73 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 72 00 69 00 73 00 68 00 69 00 63 00 68 00 65 00 6d 00 6c 00 63 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account287 = {((69 6e 66 6f 72 6d 65 73 31 40 6d 61 63 63 69 6e 6f 78 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 72 00 6d 00 65 00 73 00 31 00 40 00 6d 00 61 00 63 00 63 00 69 00 6e 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account288 = {((69 6e 66 6f 40 73 61 6e 6b 61 70 61 74 72 6f 6c 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 73 00 61 00 6e 00 6b 00 61 00 70 00 61 00 74 00 72 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account289 = {((69 6e 66 6f 40 73 61 72 61 68 6d 61 72 69 6e 65 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 73 00 61 00 72 00 61 00 68 00 6d 00 61 00 72 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account290 = {((69 6e 66 6f 40 73 63 69 65 6e 74 65 63 68 2e 69 63 75) | (69 00 6e 00 66 00 6f 00 40 00 73 00 63 00 69 00 65 00 6e 00 74 00 65 00 63 00 68 00 2e 00 69 00 63 00 75 00))}
		$account291 = {((69 6e 66 6f 40 74 72 61 6e 73 6d 65 72 69 64 69 61 6e 2d 73 61 73 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 74 00 72 00 61 00 6e 00 73 00 6d 00 65 00 72 00 69 00 64 00 69 00 61 00 6e 00 2d 00 73 00 61 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account292 = {((69 6e 66 6f 40 75 6e 69 76 65 72 73 61 6c 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 2e 6b 65) | (69 00 6e 00 66 00 6f 00 40 00 75 00 6e 00 69 00 76 00 65 00 72 00 73 00 61 00 6c 00 73 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 63 00 6f 00 2e 00 6b 00 65 00))}
		$account293 = {((69 6e 66 6f 40 78 6f 70 73 65 72 76 69 63 65 73 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 78 00 6f 00 70 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account294 = {((69 6e 6b 79 75 40 64 75 62 68 65 2d 6b 72 2e 69 63 75) | (69 00 6e 00 6b 00 79 00 75 00 40 00 64 00 75 00 62 00 68 00 65 00 2d 00 6b 00 72 00 2e 00 69 00 63 00 75 00))}
		$account295 = {((69 72 65 6e 31 35 39 6b 40 79 61 6e 64 65 78 2e 63 6f 6d) | (69 00 72 00 65 00 6e 00 31 00 35 00 39 00 6b 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account296 = {((69 72 69 6e 61 2e 6d 61 63 72 6f 74 65 6b 40 79 61 6e 64 65 78 2e 72 75) | (69 00 72 00 69 00 6e 00 61 00 2e 00 6d 00 61 00 63 00 72 00 6f 00 74 00 65 00 6b 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account297 = {((69 2e 73 69 62 72 6d 69 6f 76 40 67 6d 61 69 6c 2e 63 6f 6d) | (69 00 2e 00 73 00 69 00 62 00 72 00 6d 00 69 00 6f 00 76 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account298 = {((69 73 73 61 63 40 61 6e 64 69 6e 67 2d 74 77 2e 63 6f 6d) | (69 00 73 00 73 00 61 00 63 00 40 00 61 00 6e 00 64 00 69 00 6e 00 67 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account299 = {((69 74 63 63 6f 69 74 40 69 74 65 2d 67 72 2e 63 6f 6d) | (69 00 74 00 63 00 63 00 6f 00 69 00 74 00 40 00 69 00 74 00 65 00 2d 00 67 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account300 = {((69 76 61 6e 68 6f 65 40 77 61 68 61 6e 61 2d 61 64 69 72 65 6b 73 61 2e 63 6f 2e 69 64) | (69 00 76 00 61 00 6e 00 68 00 6f 00 65 00 40 00 77 00 61 00 68 00 61 00 6e 00 61 00 2d 00 61 00 64 00 69 00 72 00 65 00 6b 00 73 00 61 00 2e 00 63 00 6f 00 2e 00 69 00 64 00))}
		$account301 = {((69 76 79 6c 65 65 40 62 6c 75 65 73 69 61 6c 2e 63 6f 6d) | (69 00 76 00 79 00 6c 00 65 00 65 00 40 00 62 00 6c 00 75 00 65 00 73 00 69 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account302 = {((69 76 79 2e 6c 69 6d 40 6c 65 61 64 65 72 61 72 74 2d 6d 79 2e 63 6f 6d) | (69 00 76 00 79 00 2e 00 6c 00 69 00 6d 00 40 00 6c 00 65 00 61 00 64 00 65 00 72 00 61 00 72 00 74 00 2d 00 6d 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account303 = {((69 79 6b 65 6c 6f 67 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (69 00 79 00 6b 00 65 00 6c 00 6f 00 67 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account304 = {((6a 61 63 71 75 65 6c 69 6e 61 2e 62 61 72 69 73 69 63 40 61 6e 74 6f 6c 69 6e 69 2e 74 6b) | (6a 00 61 00 63 00 71 00 75 00 65 00 6c 00 69 00 6e 00 61 00 2e 00 62 00 61 00 72 00 69 00 73 00 69 00 63 00 40 00 61 00 6e 00 74 00 6f 00 6c 00 69 00 6e 00 69 00 2e 00 74 00 6b 00))}
		$account305 = {((6a 61 66 66 69 6e 6d 61 72 6b 40 79 61 6e 64 65 78 2e 72 75) | (6a 00 61 00 66 00 66 00 69 00 6e 00 6d 00 61 00 72 00 6b 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account306 = {((6a 61 68 62 6c 65 73 73 40 77 6f 6e 64 65 72 2d 74 68 61 69 6c 61 6e 64 73 2e 63 6f 6d) | (6a 00 61 00 68 00 62 00 6c 00 65 00 73 00 73 00 40 00 77 00 6f 00 6e 00 64 00 65 00 72 00 2d 00 74 00 68 00 61 00 69 00 6c 00 61 00 6e 00 64 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account307 = {((6a 61 6d 65 73 2e 63 68 6f 38 32 38 32 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6a 00 61 00 6d 00 65 00 73 00 2e 00 63 00 68 00 6f 00 38 00 32 00 38 00 32 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account308 = {((6a 61 6d 65 73 68 61 6d 69 6c 74 6f 6e 37 35 34 34 40 67 6d 61 69 6c 2e 63 6f 6d) | (6a 00 61 00 6d 00 65 00 73 00 68 00 61 00 6d 00 69 00 6c 00 74 00 6f 00 6e 00 37 00 35 00 34 00 34 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account309 = {((6a 61 6d 65 73 6d 6f 6f 72 65 40 72 61 6d 73 65 79 6a 6f 6e 65 73 69 6e 63 2e 77 65 62 73 69 74 65) | (6a 00 61 00 6d 00 65 00 73 00 6d 00 6f 00 6f 00 72 00 65 00 40 00 72 00 61 00 6d 00 73 00 65 00 79 00 6a 00 6f 00 6e 00 65 00 73 00 69 00 6e 00 63 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account310 = {((6a 61 6d 69 65 2e 73 77 61 6e 40 62 65 74 68 66 65 6c 73 2e 6f 72 67) | (6a 00 61 00 6d 00 69 00 65 00 2e 00 73 00 77 00 61 00 6e 00 40 00 62 00 65 00 74 00 68 00 66 00 65 00 6c 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account311 = {((6a 61 6d 69 74 40 63 61 69 72 6f 77 61 79 73 2e 69 63 75) | (6a 00 61 00 6d 00 69 00 74 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 69 00 63 00 75 00))}
		$account312 = {((6a 61 73 6d 69 6e 65 40 63 69 6e 63 6f 2e 69 63 75) | (6a 00 61 00 73 00 6d 00 69 00 6e 00 65 00 40 00 63 00 69 00 6e 00 63 00 6f 00 2e 00 69 00 63 00 75 00))}
		$account313 = {((6a 65 66 66 40 67 74 70 2d 75 73 2e 63 6f 6d) | (6a 00 65 00 66 00 66 00 40 00 67 00 74 00 70 00 2d 00 75 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account314 = {((6a 65 72 72 79 65 64 77 61 72 64 31 40 79 61 6e 64 65 78 2e 72 75) | (6a 00 65 00 72 00 72 00 79 00 65 00 64 00 77 00 61 00 72 00 64 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account315 = {((6a 65 73 73 69 63 61 66 61 69 74 68 6a 65 73 73 69 63 61 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6a 00 65 00 73 00 73 00 69 00 63 00 61 00 66 00 61 00 69 00 74 00 68 00 6a 00 65 00 73 00 73 00 69 00 63 00 61 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account316 = {((6a 6e 40 61 63 72 6f 61 74 69 76 65 2e 63 6f 6d) | (6a 00 6e 00 40 00 61 00 63 00 72 00 6f 00 61 00 74 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account317 = {((6a 6f 68 61 6e 61 40 71 6f 6c 64 65 6e 68 69 67 68 77 61 79 2e 63 6f 6d) | (6a 00 6f 00 68 00 61 00 6e 00 61 00 40 00 71 00 6f 00 6c 00 64 00 65 00 6e 00 68 00 69 00 67 00 68 00 77 00 61 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account318 = {((6a 6f 68 6e 73 6f 6e 70 69 6b 79 75 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6a 00 6f 00 68 00 6e 00 73 00 6f 00 6e 00 70 00 69 00 6b 00 79 00 75 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account319 = {((6a 6f 6a 6f 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (6a 00 6f 00 6a 00 6f 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account320 = {((6a 6f 6a 6f 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (6a 00 6f 00 6a 00 6f 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account321 = {((6a 70 6c 6f 72 72 64 65 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (6a 00 70 00 6c 00 6f 00 72 00 72 00 64 00 65 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account322 = {((6a 70 6c 75 6e 6b 65 74 74 40 62 65 6c 6c 66 69 6c 67 68 74 2e 63 6f 6d) | (6a 00 70 00 6c 00 75 00 6e 00 6b 00 65 00 74 00 74 00 40 00 62 00 65 00 6c 00 6c 00 66 00 69 00 6c 00 67 00 68 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account323 = {((6a 75 73 74 69 6e 40 61 6c 6c 61 63 65 61 75 74 6f 70 61 72 74 73 2e 6d 65) | (6a 00 75 00 73 00 74 00 69 00 6e 00 40 00 61 00 6c 00 6c 00 61 00 63 00 65 00 61 00 75 00 74 00 6f 00 70 00 61 00 72 00 74 00 73 00 2e 00 6d 00 65 00))}
		$account324 = {((6b 61 74 68 72 69 6e 2e 63 6f 6d 61 6e 6e 73 40 6d 65 64 6f 65 72 2e 6d 65) | (6b 00 61 00 74 00 68 00 72 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 61 00 6e 00 6e 00 73 00 40 00 6d 00 65 00 64 00 6f 00 65 00 72 00 2e 00 6d 00 65 00))}
		$account325 = {((6b 61 79 2e 6a 6f 68 6e 40 6c 69 73 74 2e 72 75) | (6b 00 61 00 79 00 2e 00 6a 00 6f 00 68 00 6e 00 40 00 6c 00 69 00 73 00 74 00 2e 00 72 00 75 00))}
		$account326 = {((6b 65 6c 6a 40 73 75 6e 63 6f 6e 78 2e 63 6f 6d) | (6b 00 65 00 6c 00 6a 00 40 00 73 00 75 00 6e 00 63 00 6f 00 6e 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account327 = {((6b 65 6e 65 40 66 6c 79 78 70 6f 2e 63 6f 6d) | (6b 00 65 00 6e 00 65 00 40 00 66 00 6c 00 79 00 78 00 70 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account328 = {((6b 66 74 70 40 68 75 73 74 6c 65 33 36 30 2e 61 32 68 6f 73 74 65 64 2e 63 6f 6d) | (6b 00 66 00 74 00 70 00 40 00 68 00 75 00 73 00 74 00 6c 00 65 00 33 00 36 00 30 00 2e 00 61 00 32 00 68 00 6f 00 73 00 74 00 65 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account329 = {((6b 68 61 6c 69 64 40 62 65 73 63 6f 2e 63 6f 6d 2e 73 61) | (6b 00 68 00 61 00 6c 00 69 00 64 00 40 00 62 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 73 00 61 00))}
		$account330 = {((6b 68 61 6e 68 2e 74 6f 40 67 6f 6f 64 6c 61 6e 64 2e 63 6f 6d 2e 76 6e) | (6b 00 68 00 61 00 6e 00 68 00 2e 00 74 00 6f 00 40 00 67 00 6f 00 6f 00 64 00 6c 00 61 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00 2e 00 76 00 6e 00))}
		$account331 = {((6b 69 6e 67 73 40 64 75 74 63 68 6c 6f 67 73 2e 75 73) | (6b 00 69 00 6e 00 67 00 73 00 40 00 64 00 75 00 74 00 63 00 68 00 6c 00 6f 00 67 00 73 00 2e 00 75 00 73 00))}
		$account332 = {((6b 69 6e 67 73 6c 65 79 40 76 69 76 61 6c 64 69 2e 6e 65 74) | (6b 00 69 00 6e 00 67 00 73 00 6c 00 65 00 79 00 40 00 76 00 69 00 76 00 61 00 6c 00 64 00 69 00 2e 00 6e 00 65 00 74 00))}
		$account333 = {((6b 69 6e 6c 69 6b 40 62 69 7a 6e 65 74 76 69 67 61 74 30 72 2e 63 6f 6d) | (6b 00 69 00 6e 00 6c 00 69 00 6b 00 40 00 62 00 69 00 7a 00 6e 00 65 00 74 00 76 00 69 00 67 00 61 00 74 00 30 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account334 = {((6b 6f 6d 2e 75 70 61 6b 6f 76 6b 61 69 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6b 00 6f 00 6d 00 2e 00 75 00 70 00 61 00 6b 00 6f 00 76 00 6b 00 61 00 69 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account335 = {((6b 71 68 40 6f 6d 69 62 65 61 72 69 6e 67 2e 63 6f 6d) | (6b 00 71 00 68 00 40 00 6f 00 6d 00 69 00 62 00 65 00 61 00 72 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account336 = {((6b 2e 72 65 79 65 73 40 6f 74 74 6f 2d 62 72 61 6e 64 65 73 2d 64 65 2e 63 6f 6d) | (6b 00 2e 00 72 00 65 00 79 00 65 00 73 00 40 00 6f 00 74 00 74 00 6f 00 2d 00 62 00 72 00 61 00 6e 00 64 00 65 00 73 00 2d 00 64 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account337 = {((6b 73 68 69 74 69 6a 40 61 63 74 69 76 65 70 75 6d 70 73 2e 63 6f 6d) | (6b 00 73 00 68 00 69 00 74 00 69 00 6a 00 40 00 61 00 63 00 74 00 69 00 76 00 65 00 70 00 75 00 6d 00 70 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account338 = {((6b 73 40 6b 6f 6f 68 65 6a 69 73 61 66 65 74 79 2e 63 6f 6d) | (6b 00 73 00 40 00 6b 00 6f 00 6f 00 68 00 65 00 6a 00 69 00 73 00 61 00 66 00 65 00 74 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account339 = {((6c 33 65 62 65 6e 61 72 64 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6c 00 33 00 65 00 62 00 65 00 6e 00 61 00 72 00 64 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account340 = {((6c 61 6c 40 6d 6f 6e 74 61 6e 65 73 68 69 70 70 69 6e 67 2e 63 6f 6d) | (6c 00 61 00 6c 00 40 00 6d 00 6f 00 6e 00 74 00 61 00 6e 00 65 00 73 00 68 00 69 00 70 00 70 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account341 = {((6c 61 6e 65 79 40 63 6f 6d 65 72 6f 2e 75 73) | (6c 00 61 00 6e 00 65 00 79 00 40 00 63 00 6f 00 6d 00 65 00 72 00 6f 00 2e 00 75 00 73 00))}
		$account342 = {((6c 61 72 72 79 40 72 65 70 6f 72 74 6c 6f 67 2e 74 6f 70) | (6c 00 61 00 72 00 72 00 79 00 40 00 72 00 65 00 70 00 6f 00 72 00 74 00 6c 00 6f 00 67 00 2e 00 74 00 6f 00 70 00))}
		$account343 = {((6c 61 75 72 65 6e 74 40 61 65 72 6f 2d 63 61 62 6c 6e 2e 63 6f 6d) | (6c 00 61 00 75 00 72 00 65 00 6e 00 74 00 40 00 61 00 65 00 72 00 6f 00 2d 00 63 00 61 00 62 00 6c 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account344 = {((6c 61 77 6d 61 6e 37 30 37 30 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6c 00 61 00 77 00 6d 00 61 00 6e 00 37 00 30 00 37 00 30 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account345 = {((6c 63 68 61 6e 64 72 61 40 62 61 7a 63 69 70 72 6f 64 75 63 74 2e 63 6f 6d) | (6c 00 63 00 68 00 61 00 6e 00 64 00 72 00 61 00 40 00 62 00 61 00 7a 00 63 00 69 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account346 = {((6c 63 70 2d 73 62 40 6c 79 73 61 67 68 74 67 72 6f 75 70 2e 63 6f 6d) | (6c 00 63 00 70 00 2d 00 73 00 62 00 40 00 6c 00 79 00 73 00 61 00 67 00 68 00 74 00 67 00 72 00 6f 00 75 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account347 = {((6c 65 61 76 65 62 6f 61 72 64 40 75 73 61 6d 69 6c 69 74 61 72 79 64 65 70 74 2e 63 6f 6d) | (6c 00 65 00 61 00 76 00 65 00 62 00 6f 00 61 00 72 00 64 00 40 00 75 00 73 00 61 00 6d 00 69 00 6c 00 69 00 74 00 61 00 72 00 79 00 64 00 65 00 70 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account348 = {((6c 65 6f 40 77 7a 77 69 6e 74 6f 6e 2e 63 6f 6d) | (6c 00 65 00 6f 00 40 00 77 00 7a 00 77 00 69 00 6e 00 74 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account349 = {((6c 69 67 68 74 62 61 62 61 6d 75 73 69 63 40 67 6d 61 69 6c 2e 63 6f 6d) | (6c 00 69 00 67 00 68 00 74 00 62 00 61 00 62 00 61 00 6d 00 75 00 73 00 69 00 63 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account350 = {((6c 69 67 68 74 6d 75 73 69 63 31 32 33 34 35 40 79 61 6e 64 65 78 2e 72 75) | (6c 00 69 00 67 00 68 00 74 00 6d 00 75 00 73 00 69 00 63 00 31 00 32 00 33 00 34 00 35 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account351 = {((6c 69 6d 63 6f 72 40 6c 65 2d 62 65 6c 74 2e 63 6f 2e 7a 61) | (6c 00 69 00 6d 00 63 00 6f 00 72 00 40 00 6c 00 65 00 2d 00 62 00 65 00 6c 00 74 00 2e 00 63 00 6f 00 2e 00 7a 00 61 00))}
		$account352 = {((6c 6f 67 67 65 72 73 40 73 69 74 65 63 68 75 6b 61 6e 64 6c 72 65 6c 61 6e 64 2e 63 6f 6d) | (6c 00 6f 00 67 00 67 00 65 00 72 00 73 00 40 00 73 00 69 00 74 00 65 00 63 00 68 00 75 00 6b 00 61 00 6e 00 64 00 6c 00 72 00 65 00 6c 00 61 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account353 = {((6c 6f 67 69 73 74 69 63 73 40 67 61 6c 61 78 79 70 68 61 72 6d 61 2d 63 6f 2d 6b 65 2e 70 77) | (6c 00 6f 00 67 00 69 00 73 00 74 00 69 00 63 00 73 00 40 00 67 00 61 00 6c 00 61 00 78 00 79 00 70 00 68 00 61 00 72 00 6d 00 61 00 2d 00 63 00 6f 00 2d 00 6b 00 65 00 2e 00 70 00 77 00))}
		$account354 = {((6c 6f 67 6f 40 66 65 6e 64 61 6c 65 6c 74 64 2e 63 6f 6d) | (6c 00 6f 00 67 00 6f 00 40 00 66 00 65 00 6e 00 64 00 61 00 6c 00 65 00 6c 00 74 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account355 = {((6c 6f 67 73 32 30 32 30 40 67 74 62 65 6e 6b 2d 70 6c 63 2e 63 6f 6d) | (6c 00 6f 00 67 00 73 00 32 00 30 00 32 00 30 00 40 00 67 00 74 00 62 00 65 00 6e 00 6b 00 2d 00 70 00 6c 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account356 = {((6c 6f 67 73 64 65 74 61 69 6c 73 30 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6c 00 6f 00 67 00 73 00 64 00 65 00 74 00 61 00 69 00 6c 00 73 00 30 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account357 = {((6c 6f 67 73 40 73 2d 6c 62 65 61 75 74 79 63 61 72 65 2d 61 7a 2e 63 6f 6d) | (6c 00 6f 00 67 00 73 00 40 00 73 00 2d 00 6c 00 62 00 65 00 61 00 75 00 74 00 79 00 63 00 61 00 72 00 65 00 2d 00 61 00 7a 00 2e 00 63 00 6f 00 6d 00))}
		$account358 = {((6c 6f 67 73 40 76 69 72 71 6f 6d 65 64 69 63 61 6c 2e 63 6f 6d) | (6c 00 6f 00 67 00 73 00 40 00 76 00 69 00 72 00 71 00 6f 00 6d 00 65 00 64 00 69 00 63 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account359 = {((6c 6f 74 31 35 36 37 40 6f 6b 67 72 6f 63 65 72 2e 63 6f 2e 7a 61) | (6c 00 6f 00 74 00 31 00 35 00 36 00 37 00 40 00 6f 00 6b 00 67 00 72 00 6f 00 63 00 65 00 72 00 2e 00 63 00 6f 00 2e 00 7a 00 61 00))}
		$account360 = {((6c 6f 2e 74 65 72 65 6e 63 65 40 71 73 74 2d 68 6b 2e 63 6f 6d) | (6c 00 6f 00 2e 00 74 00 65 00 72 00 65 00 6e 00 63 00 65 00 40 00 71 00 73 00 74 00 2d 00 68 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account361 = {((6c 75 63 34 73 6d 61 69 6c 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6c 00 75 00 63 00 34 00 73 00 6d 00 61 00 69 00 6c 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account362 = {((6c 75 63 69 6e 65 64 61 75 67 6c 61 73 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6c 00 75 00 63 00 69 00 6e 00 65 00 64 00 61 00 75 00 67 00 6c 00 61 00 73 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account363 = {((6d 61 67 61 67 72 61 63 65 6d 61 6e 40 79 61 6e 64 65 78 2e 72 75) | (6d 00 61 00 67 00 61 00 67 00 72 00 61 00 63 00 65 00 6d 00 61 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account364 = {((6d 61 67 61 7a 61 40 73 61 72 64 75 6e 79 61 6b 6f 6c 74 75 6b 2e 63 6f 6d) | (6d 00 61 00 67 00 61 00 7a 00 61 00 40 00 73 00 61 00 72 00 64 00 75 00 6e 00 79 00 61 00 6b 00 6f 00 6c 00 74 00 75 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account365 = {((6d 61 68 65 73 68 40 63 70 6d 69 6e 64 69 61 2e 63 6f 2e 69 6e) | (6d 00 61 00 68 00 65 00 73 00 68 00 40 00 63 00 70 00 6d 00 69 00 6e 00 64 00 69 00 61 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account366 = {((6d 61 69 6c 40 6a 69 72 61 74 61 6e 65 2e 63 6f 6d) | (6d 00 61 00 69 00 6c 00 40 00 6a 00 69 00 72 00 61 00 74 00 61 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account367 = {((6d 61 69 6c 73 40 74 61 73 68 69 70 74 61 2e 63 6f 6d) | (6d 00 61 00 69 00 6c 00 73 00 40 00 74 00 61 00 73 00 68 00 69 00 70 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account368 = {((6d 61 6e 61 6e 40 64 65 73 6d 61 69 6e 64 69 61 6e 2e 63 6f 6d) | (6d 00 61 00 6e 00 61 00 6e 00 40 00 64 00 65 00 73 00 6d 00 61 00 69 00 6e 00 64 00 69 00 61 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account369 = {((6d 61 6e 6d 61 6e 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (6d 00 61 00 6e 00 6d 00 61 00 6e 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account370 = {((6d 61 6e 6f 66 66 69 63 69 61 6c 62 6c 65 73 73 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (6d 00 61 00 6e 00 6f 00 66 00 66 00 69 00 63 00 69 00 61 00 6c 00 62 00 6c 00 65 00 73 00 73 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account371 = {((6d 61 72 62 65 6c 6c 61 40 63 6f 70 79 72 61 70 2e 63 6f 6d) | (6d 00 61 00 72 00 62 00 65 00 6c 00 6c 00 61 00 40 00 63 00 6f 00 70 00 79 00 72 00 61 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account372 = {((6d 61 72 63 65 6c 2e 6d 65 6c 69 73 40 61 78 6f 6c 74 61 2e 63 6f 6d) | (6d 00 61 00 72 00 63 00 65 00 6c 00 2e 00 6d 00 65 00 6c 00 69 00 73 00 40 00 61 00 78 00 6f 00 6c 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account373 = {((6d 61 72 69 61 6e 61 6b 6c 6c 69 63 69 40 61 6c 62 61 6e 69 61 6e 64 61 69 6c 79 6e 65 77 73 2e 63 6f 6d) | (6d 00 61 00 72 00 69 00 61 00 6e 00 61 00 6b 00 6c 00 6c 00 69 00 63 00 69 00 40 00 61 00 6c 00 62 00 61 00 6e 00 69 00 61 00 6e 00 64 00 61 00 69 00 6c 00 79 00 6e 00 65 00 77 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account374 = {((6d 61 72 69 6e 65 40 74 68 65 72 6f 79 61 6c 73 61 6e 64 73 6b 6f 68 72 6f 6e 67 2e 63 6f 6d) | (6d 00 61 00 72 00 69 00 6e 00 65 00 40 00 74 00 68 00 65 00 72 00 6f 00 79 00 61 00 6c 00 73 00 61 00 6e 00 64 00 73 00 6b 00 6f 00 68 00 72 00 6f 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account375 = {((6d 61 72 69 73 61 40 73 74 65 6d 73 66 72 75 69 74 2d 7a 61 2e 63 6f 6d) | (6d 00 61 00 72 00 69 00 73 00 61 00 40 00 73 00 74 00 65 00 6d 00 73 00 66 00 72 00 75 00 69 00 74 00 2d 00 7a 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account376 = {((6d 61 72 74 69 6e 65 7a 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (6d 00 61 00 72 00 74 00 69 00 6e 00 65 00 7a 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account377 = {((6d 61 72 74 69 6e 7a 65 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (6d 00 61 00 72 00 74 00 69 00 6e 00 7a 00 65 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account378 = {((6d 61 73 73 69 6e 2e 6d 61 64 69 40 67 6c 30 62 65 61 63 74 69 76 65 6c 74 64 2e 63 6f 6d) | (6d 00 61 00 73 00 73 00 69 00 6e 00 2e 00 6d 00 61 00 64 00 69 00 40 00 67 00 6c 00 30 00 62 00 65 00 61 00 63 00 74 00 69 00 76 00 65 00 6c 00 74 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account379 = {((6d 61 79 2e 62 75 68 61 69 73 69 40 70 68 69 6c 6c 71 73 2e 63 6f 6d) | (6d 00 61 00 79 00 2e 00 62 00 75 00 68 00 61 00 69 00 73 00 69 00 40 00 70 00 68 00 69 00 6c 00 6c 00 71 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account380 = {((6d 61 79 40 73 63 61 6e 64 69 6e 61 76 69 61 6e 2d 63 6f 6c 6c 65 63 74 69 6f 6e 2e 63 6f 6d) | (6d 00 61 00 79 00 40 00 73 00 63 00 61 00 6e 00 64 00 69 00 6e 00 61 00 76 00 69 00 61 00 6e 00 2d 00 63 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account381 = {((6d 64 40 62 61 72 63 6c 61 72 79 73 62 61 6e 6b 2d 75 6b 2e 63 6f 6d) | (6d 00 64 00 40 00 62 00 61 00 72 00 63 00 6c 00 61 00 72 00 79 00 73 00 62 00 61 00 6e 00 6b 00 2d 00 75 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account382 = {((6d 64 78 40 64 72 6e 67 65 74 75 2e 63 6f 2e 7a 61) | (6d 00 64 00 78 00 40 00 64 00 72 00 6e 00 67 00 65 00 74 00 75 00 2e 00 63 00 6f 00 2e 00 7a 00 61 00))}
		$account383 = {((6d 65 65 6b 6d 69 6c 40 63 72 61 77 66 6f 72 64 6a 61 6d 61 69 63 61 2e 63 6f 6d) | (6d 00 65 00 65 00 6b 00 6d 00 69 00 6c 00 40 00 63 00 72 00 61 00 77 00 66 00 6f 00 72 00 64 00 6a 00 61 00 6d 00 61 00 69 00 63 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account384 = {((6d 65 6d 62 65 72 40 67 73 31 69 64 2e 6f 72 67) | (6d 00 65 00 6d 00 62 00 65 00 72 00 40 00 67 00 73 00 31 00 69 00 64 00 2e 00 6f 00 72 00 67 00))}
		$account385 = {((6d 65 6e 65 6c 6f 67 73 40 61 72 74 69 69 6e 6f 78 2e 63 6f 6d) | (6d 00 65 00 6e 00 65 00 6c 00 6f 00 67 00 73 00 40 00 61 00 72 00 74 00 69 00 69 00 6e 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account386 = {((6d 65 6e 75 40 6e 73 6d 65 6c 65 63 74 72 6f 6e 69 63 73 2e 63 6f 6d) | (6d 00 65 00 6e 00 75 00 40 00 6e 00 73 00 6d 00 65 00 6c 00 65 00 63 00 74 00 72 00 6f 00 6e 00 69 00 63 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account387 = {((6d 2e 67 6f 72 65 63 6b 61 40 63 72 69 69 74 65 6f 2e 63 6f 6d) | (6d 00 2e 00 67 00 6f 00 72 00 65 00 63 00 6b 00 61 00 40 00 63 00 72 00 69 00 69 00 74 00 65 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account388 = {((6d 69 63 68 65 6c 6c 65 6a 40 66 65 72 6e 73 74 75 72 6d 2e 63 6f 6d) | (6d 00 69 00 63 00 68 00 65 00 6c 00 6c 00 65 00 6a 00 40 00 66 00 65 00 72 00 6e 00 73 00 74 00 75 00 72 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account389 = {((6d 69 63 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (6d 00 69 00 63 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account390 = {((6d 69 67 75 65 6c 69 70 73 63 63 40 67 6d 61 69 6c 2e 63 6f 6d) | (6d 00 69 00 67 00 75 00 65 00 6c 00 69 00 70 00 73 00 63 00 63 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account391 = {((6d 69 6c 6c 69 40 65 78 70 6c 6f 69 74 73 2e 73 69 74 65) | (6d 00 69 00 6c 00 6c 00 69 00 40 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 73 00 2e 00 73 00 69 00 74 00 65 00))}
		$account392 = {((6d 69 6c 6c 6c 6f 67 73 40 69 6c 73 65 72 72 65 6e 6f 2e 63 6f 6d) | (6d 00 69 00 6c 00 6c 00 6c 00 6f 00 67 00 73 00 40 00 69 00 6c 00 73 00 65 00 72 00 72 00 65 00 6e 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account393 = {((6d 6f 62 69 40 62 6c 65 73 73 65 64 69 6e 63 2e 78 79 7a) | (6d 00 6f 00 62 00 69 00 40 00 62 00 6c 00 65 00 73 00 73 00 65 00 64 00 69 00 6e 00 63 00 2e 00 78 00 79 00 7a 00))}
		$account394 = {((6d 6f 62 69 6c 65 2e 6d 61 69 6c 65 72 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6d 00 6f 00 62 00 69 00 6c 00 65 00 2e 00 6d 00 61 00 69 00 6c 00 65 00 72 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account395 = {((6d 6f 62 69 74 65 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (6d 00 6f 00 62 00 69 00 74 00 65 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account396 = {((6d 6f 62 69 74 65 65 75 72 6f 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (6d 00 6f 00 62 00 69 00 74 00 65 00 65 00 75 00 72 00 6f 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account397 = {((6d 6f 69 6e 2e 61 6e 73 61 72 69 40 73 61 70 67 72 6f 75 70 2e 63 6f 6d 2e 70 6b) | (6d 00 6f 00 69 00 6e 00 2e 00 61 00 6e 00 73 00 61 00 72 00 69 00 40 00 73 00 61 00 70 00 67 00 72 00 6f 00 75 00 70 00 2e 00 63 00 6f 00 6d 00 2e 00 70 00 6b 00))}
		$account398 = {((6d 6f 6e 65 79 40 7a 65 6c 6c 69 63 6f 2e 63 6f 6d) | (6d 00 6f 00 6e 00 65 00 79 00 40 00 7a 00 65 00 6c 00 6c 00 69 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account399 = {((6d 6f 72 34 34 30 6e 65 79 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6d 00 6f 00 72 00 34 00 34 00 30 00 6e 00 65 00 79 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account400 = {((6d 6f 72 72 69 73 68 6f 6d 65 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6d 00 6f 00 72 00 72 00 69 00 73 00 68 00 6f 00 6d 00 65 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account401 = {((6d 70 61 40 63 61 69 72 6f 77 61 79 73 2e 6d 65) | (6d 00 70 00 61 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 6d 00 65 00))}
		$account402 = {((6d 72 6c 6f 67 67 61 40 70 68 6f 65 6e 69 78 6c 6f 67 65 72 2e 63 6f 6d) | (6d 00 72 00 6c 00 6f 00 67 00 67 00 61 00 40 00 70 00 68 00 6f 00 65 00 6e 00 69 00 78 00 6c 00 6f 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account403 = {((6d 72 2e 6d 69 6b 65 6f 72 69 67 69 6e 40 6c 6f 67 73 72 65 73 75 6c 74 62 6f 78 2e 78 79 7a) | (6d 00 72 00 2e 00 6d 00 69 00 6b 00 65 00 6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 6c 00 6f 00 67 00 73 00 72 00 65 00 73 00 75 00 6c 00 74 00 62 00 6f 00 78 00 2e 00 78 00 79 00 7a 00))}
		$account404 = {((6d 72 6d 6b 6d 31 32 33 34 40 63 72 65 61 63 69 6f 6e 65 73 6a 6c 79 72 2e 63 6f 6d) | (6d 00 72 00 6d 00 6b 00 6d 00 31 00 32 00 33 00 34 00 40 00 63 00 72 00 65 00 61 00 63 00 69 00 6f 00 6e 00 65 00 73 00 6a 00 6c 00 79 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account405 = {((6d 73 67 40 61 63 72 6f 61 74 69 76 65 2e 63 6f 6d) | (6d 00 73 00 67 00 40 00 61 00 63 00 72 00 6f 00 61 00 74 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account406 = {((6d 75 68 61 73 65 62 65 40 70 72 69 6d 6f 73 73 6f 66 61 2e 63 6f 6d) | (6d 00 75 00 68 00 61 00 73 00 65 00 62 00 65 00 40 00 70 00 72 00 69 00 6d 00 6f 00 73 00 73 00 6f 00 66 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account407 = {((6d 75 6a 65 65 62 40 6b 74 65 61 64 75 62 61 69 2e 63 6f 6d) | (6d 00 75 00 6a 00 65 00 65 00 62 00 40 00 6b 00 74 00 65 00 61 00 64 00 75 00 62 00 61 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account408 = {((6d 75 6c 6c 61 72 77 68 69 74 65 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6d 00 75 00 6c 00 6c 00 61 00 72 00 77 00 68 00 69 00 74 00 65 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account409 = {((6d 75 6c 75 61 6c 65 6d 40 64 73 73 61 64 69 73 2e 63 6f 6d) | (6d 00 75 00 6c 00 75 00 61 00 6c 00 65 00 6d 00 40 00 64 00 73 00 73 00 61 00 64 00 69 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account411 = {((6d 75 6d 62 61 69 40 73 68 72 65 65 6a 69 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (6d 00 75 00 6d 00 62 00 61 00 69 00 40 00 73 00 68 00 72 00 65 00 65 00 6a 00 69 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account412 = {((6d 75 72 74 69 40 61 6c 76 61 64 69 77 69 70 61 2e 63 6f 6d) | (6d 00 75 00 72 00 74 00 69 00 40 00 61 00 6c 00 76 00 61 00 64 00 69 00 77 00 69 00 70 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account413 = {((6e 61 63 69 40 74 75 72 6b 72 6f 6d 2e 78 79 7a) | (6e 00 61 00 63 00 69 00 40 00 74 00 75 00 72 00 6b 00 72 00 6f 00 6d 00 2e 00 78 00 79 00 7a 00))}
		$account414 = {((6e 63 68 6f 40 64 6f 72 6d 61 6b 65 62 61 2e 63 6f 6d) | (6e 00 63 00 68 00 6f 00 40 00 64 00 6f 00 72 00 6d 00 61 00 6b 00 65 00 62 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account415 = {((6e 64 40 70 61 6e 74 68 65 6f 6d 74 61 6e 6b 65 72 73 2e 63 6f 6d) | (6e 00 64 00 40 00 70 00 61 00 6e 00 74 00 68 00 65 00 6f 00 6d 00 74 00 61 00 6e 00 6b 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account416 = {((6e 64 40 77 74 61 78 74 72 61 63 74 69 6f 6e 2e 63 6f 6d) | (6e 00 64 00 40 00 77 00 74 00 61 00 78 00 74 00 72 00 61 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account417 = {((6e 65 64 6e 77 6f 6b 6f 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (6e 00 65 00 64 00 6e 00 77 00 6f 00 6b 00 6f 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account418 = {((6e 65 64 6e 77 6f 6b 6f 72 6f 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (6e 00 65 00 64 00 6e 00 77 00 6f 00 6b 00 6f 00 72 00 6f 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account419 = {((6e 65 6f 2e 79 63 77 61 6e 67 40 6d 69 6e 64 72 6f 79 2e 63 6f 6d) | (6e 00 65 00 6f 00 2e 00 79 00 63 00 77 00 61 00 6e 00 67 00 40 00 6d 00 69 00 6e 00 64 00 72 00 6f 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account420 = {((6e 65 77 62 72 61 6e 64 40 65 6d 61 69 6c 6c 6f 67 73 2e 74 6f 70) | (6e 00 65 00 77 00 62 00 72 00 61 00 6e 00 64 00 40 00 65 00 6d 00 61 00 69 00 6c 00 6c 00 6f 00 67 00 73 00 2e 00 74 00 6f 00 70 00))}
		$account421 = {((6e 65 77 62 72 61 6e 64 2d 66 69 6c 65 40 73 74 72 79 6b 65 69 72 2e 63 6f 6d) | (6e 00 65 00 77 00 62 00 72 00 61 00 6e 00 64 00 2d 00 66 00 69 00 6c 00 65 00 40 00 73 00 74 00 72 00 79 00 6b 00 65 00 69 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account422 = {((6e 69 63 68 6f 6c 61 73 40 62 74 63 6f 6e 72 6e 65 63 74 2e 63 6f 6d) | (6e 00 69 00 63 00 68 00 6f 00 6c 00 61 00 73 00 40 00 62 00 74 00 63 00 6f 00 6e 00 72 00 6e 00 65 00 63 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account423 = {((6e 69 63 6f 6c 61 73 2e 76 65 72 62 72 75 67 67 65 6e 40 73 30 75 64 61 6c 2e 63 6f 6d) | (6e 00 69 00 63 00 6f 00 6c 00 61 00 73 00 2e 00 76 00 65 00 72 00 62 00 72 00 75 00 67 00 67 00 65 00 6e 00 40 00 73 00 30 00 75 00 64 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account424 = {((6e 69 6c 65 73 68 40 66 72 69 65 6e 64 73 68 69 70 73 2d 6b 65 2e 69 63 75) | (6e 00 69 00 6c 00 65 00 73 00 68 00 40 00 66 00 72 00 69 00 65 00 6e 00 64 00 73 00 68 00 69 00 70 00 73 00 2d 00 6b 00 65 00 2e 00 69 00 63 00 75 00))}
		$account425 = {((6e 69 73 61 6e 65 6c 61 63 74 72 69 63 61 6c 73 2e 70 72 6f 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 69 00 73 00 61 00 6e 00 65 00 6c 00 61 00 63 00 74 00 72 00 69 00 63 00 61 00 6c 00 73 00 2e 00 70 00 72 00 6f 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account426 = {((6e 69 73 70 61 70 61 40 65 72 69 69 65 6c 6c 2e 63 6f 6d) | (6e 00 69 00 73 00 70 00 61 00 70 00 61 00 40 00 65 00 72 00 69 00 69 00 65 00 6c 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account427 = {((6e 74 75 6d 73 40 74 61 6c 6c 65 72 65 73 6d 61 72 74 6f 73 2e 63 6f 6d) | (6e 00 74 00 75 00 6d 00 73 00 40 00 74 00 61 00 6c 00 6c 00 65 00 72 00 65 00 73 00 6d 00 61 00 72 00 74 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account428 = {((6e 75 40 61 63 72 6f 61 74 69 76 65 2e 63 6f 6d) | (6e 00 75 00 40 00 61 00 63 00 72 00 6f 00 61 00 74 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account429 = {((6e 75 72 69 66 72 6f 73 74 35 35 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (6e 00 75 00 72 00 69 00 66 00 72 00 6f 00 73 00 74 00 35 00 35 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account430 = {((6e 75 72 73 61 68 2e 63 69 6e 63 69 40 69 6e 6f 6b 73 61 6e 2d 74 72 2e 63 6f 6d) | (6e 00 75 00 72 00 73 00 61 00 68 00 2e 00 63 00 69 00 6e 00 63 00 69 00 40 00 69 00 6e 00 6f 00 6b 00 73 00 61 00 6e 00 2d 00 74 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account431 = {((6e 77 65 6b 65 62 6f 78 73 40 66 69 73 63 61 6c 69 74 61 74 65 2e 65 75) | (6e 00 77 00 65 00 6b 00 65 00 62 00 6f 00 78 00 73 00 40 00 66 00 69 00 73 00 63 00 61 00 6c 00 69 00 74 00 61 00 74 00 65 00 2e 00 65 00 75 00))}
		$account432 = {((6e 77 65 6b 65 62 6f 78 73 40 74 65 68 6e 6f 70 61 6e 2e 72 73) | (6e 00 77 00 65 00 6b 00 65 00 62 00 6f 00 78 00 73 00 40 00 74 00 65 00 68 00 6e 00 6f 00 70 00 61 00 6e 00 2e 00 72 00 73 00))}
		$account433 = {((6e 78 40 61 63 72 6f 61 74 69 76 65 2e 63 6f 6d) | (6e 00 78 00 40 00 61 00 63 00 72 00 6f 00 61 00 74 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account434 = {((6f 62 69 65 6c 76 6f 73 6b 79 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (6f 00 62 00 69 00 65 00 6c 00 76 00 6f 00 73 00 6b 00 79 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account435 = {((6f 62 69 6e 6f 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (6f 00 62 00 69 00 6e 00 6f 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account436 = {((6f 62 69 6e 77 65 72 65 67 6f 40 74 76 6e 71 73 72 61 6d 2e 63 6f 6d) | (6f 00 62 00 69 00 6e 00 77 00 65 00 72 00 65 00 67 00 6f 00 40 00 74 00 76 00 6e 00 71 00 73 00 72 00 61 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account437 = {((6f 62 69 40 73 63 68 72 6f 64 65 72 73 62 6e 6b 2d 75 6b 2e 63 6f 6d) | (6f 00 62 00 69 00 40 00 73 00 63 00 68 00 72 00 6f 00 64 00 65 00 72 00 73 00 62 00 6e 00 6b 00 2d 00 75 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account438 = {((6f 62 6f 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (6f 00 62 00 6f 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account439 = {((6f 62 75 6d 61 6e 40 61 6b 6f 6e 75 63 68 65 6e 77 61 6d 2e 6f 72 67) | (6f 00 62 00 75 00 6d 00 61 00 6e 00 40 00 61 00 6b 00 6f 00 6e 00 75 00 63 00 68 00 65 00 6e 00 77 00 61 00 6d 00 2e 00 6f 00 72 00 67 00))}
		$account440 = {((6f 62 75 7a 73 6f 6c 69 64 63 61 73 68 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (6f 00 62 00 75 00 7a 00 73 00 6f 00 6c 00 69 00 64 00 63 00 61 00 73 00 68 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account441 = {((6f 66 63 65 6c 65 6e 64 69 6e 40 67 74 65 6c 65 63 61 62 6c 65 2e 63 6f 6d) | (6f 00 66 00 63 00 65 00 6c 00 65 00 6e 00 64 00 69 00 6e 00 40 00 67 00 74 00 65 00 6c 00 65 00 63 00 61 00 62 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account442 = {((6f 66 66 69 63 65 40 63 6f 6e 73 68 69 70 70 69 6e 67 2e 72 6f) | (6f 00 66 00 66 00 69 00 63 00 65 00 40 00 63 00 6f 00 6e 00 73 00 68 00 69 00 70 00 70 00 69 00 6e 00 67 00 2e 00 72 00 6f 00))}
		$account443 = {((6f 66 66 69 63 65 40 6d 65 64 69 75 72 67 65 2e 63 6f 6d) | (6f 00 66 00 66 00 69 00 63 00 65 00 40 00 6d 00 65 00 64 00 69 00 75 00 72 00 67 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account444 = {((6f 67 73 74 65 76 65 40 61 69 72 75 68 6f 6d 65 73 2e 63 6f 6d) | (6f 00 67 00 73 00 74 00 65 00 76 00 65 00 40 00 61 00 69 00 72 00 75 00 68 00 6f 00 6d 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account445 = {((6f 6b 69 72 69 6b 69 72 69 6a 70 40 76 69 76 61 6c 64 69 2e 6e 65 74) | (6f 00 6b 00 69 00 72 00 69 00 6b 00 69 00 72 00 69 00 6a 00 70 00 40 00 76 00 69 00 76 00 61 00 6c 00 64 00 69 00 2e 00 6e 00 65 00 74 00))}
		$account446 = {((6f 6b 69 72 69 6e 77 61 6a 65 73 75 73 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6f 00 6b 00 69 00 72 00 69 00 6e 00 77 00 61 00 6a 00 65 00 73 00 75 00 73 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account447 = {((6f 6c 61 6d 78 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (6f 00 6c 00 61 00 6d 00 78 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account448 = {((6f 6c 6d 78 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (6f 00 6c 00 6d 00 78 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account449 = {((6f 6d 61 72 2e 61 6c 68 6f 6d 73 69 40 67 70 67 6f 6c 62 61 6c 2e 63 6f 6d) | (6f 00 6d 00 61 00 72 00 2e 00 61 00 6c 00 68 00 6f 00 6d 00 73 00 69 00 40 00 67 00 70 00 67 00 6f 00 6c 00 62 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account450 = {((6f 6d 65 72 40 61 6c 66 61 6e 6f 6f 73 2e 63 6f 6d 2e 73 61) | (6f 00 6d 00 65 00 72 00 40 00 61 00 6c 00 66 00 61 00 6e 00 6f 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 73 00 61 00))}
		$account451 = {((6f 6d 65 75 64 6f 40 69 6e 74 61 72 73 63 61 6e 2e 6f 72 67) | (6f 00 6d 00 65 00 75 00 64 00 6f 00 40 00 69 00 6e 00 74 00 61 00 72 00 73 00 63 00 61 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account452 = {((6f 6d 6b 61 72 40 6a 64 63 2e 6e 65 74 2e 69 6e) | (6f 00 6d 00 6b 00 61 00 72 00 40 00 6a 00 64 00 63 00 2e 00 6e 00 65 00 74 00 2e 00 69 00 6e 00))}
		$account453 = {((6f 6d 6f 62 61 40 65 75 72 6f 63 65 6c 6c 2e 75 73) | (6f 00 6d 00 6f 00 62 00 61 00 40 00 65 00 75 00 72 00 6f 00 63 00 65 00 6c 00 6c 00 2e 00 75 00 73 00))}
		$account454 = {((6f 6e 65 40 63 6f 6e 6e 65 63 74 75 73 2d 74 72 61 64 65 2e 6e 65 74) | (6f 00 6e 00 65 00 40 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 75 00 73 00 2d 00 74 00 72 00 61 00 64 00 65 00 2e 00 6e 00 65 00 74 00))}
		$account455 = {((6f 6e 6c 69 6e 65 62 6f 78 6d 6f 6e 69 74 6f 72 31 40 74 65 68 6e 6f 70 61 6e 2e 72 73) | (6f 00 6e 00 6c 00 69 00 6e 00 65 00 62 00 6f 00 78 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 31 00 40 00 74 00 65 00 68 00 6e 00 6f 00 70 00 61 00 6e 00 2e 00 72 00 73 00))}
		$account456 = {((6f 6e 6c 69 6e 65 62 6f 78 6d 6f 6e 69 74 6f 72 40 66 69 73 63 61 6c 69 74 61 74 65 2e 65 75) | (6f 00 6e 00 6c 00 69 00 6e 00 65 00 62 00 6f 00 78 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 40 00 66 00 69 00 73 00 63 00 61 00 6c 00 69 00 74 00 61 00 74 00 65 00 2e 00 65 00 75 00))}
		$account457 = {((6f 6e 6c 69 6e 65 62 6f 78 6d 6f 6e 69 74 6f 72 40 74 65 68 6e 6f 70 61 6e 2e 72 73) | (6f 00 6e 00 6c 00 69 00 6e 00 65 00 62 00 6f 00 78 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 40 00 74 00 65 00 68 00 6e 00 6f 00 70 00 61 00 6e 00 2e 00 72 00 73 00))}
		$account459 = {((6f 6e 6c 69 6e 65 6d 6f 6e 69 74 6f 72 34 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6f 00 6e 00 6c 00 69 00 6e 00 65 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 34 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account460 = {((6f 70 65 72 61 74 69 6f 6e 40 6d 61 6e 65 78 2d 69 73 74 2e 63 66) | (6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 40 00 6d 00 61 00 6e 00 65 00 78 00 2d 00 69 00 73 00 74 00 2e 00 63 00 66 00))}
		$account461 = {((6f 70 65 72 61 74 69 6f 6e 73 40 66 61 6b 6c 79 2d 63 61 6d 62 6f 64 69 61 2e 63 6f 6d) | (6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 40 00 66 00 61 00 6b 00 6c 00 79 00 2d 00 63 00 61 00 6d 00 62 00 6f 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account462 = {((6f 72 64 65 72 73 40 73 68 72 63 2d 69 6e 64 69 61 2e 63 6f 6d) | (6f 00 72 00 64 00 65 00 72 00 73 00 40 00 73 00 68 00 72 00 63 00 2d 00 69 00 6e 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account463 = {((6f 72 69 65 67 6f 31 40 79 61 6e 64 65 78 2e 72 75) | (6f 00 72 00 69 00 65 00 67 00 6f 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account464 = {((6f 72 69 67 69 6e 34 40 63 6f 64 75 63 61 74 69 6f 6e 2e 63 6f 6d 2e 6d 79) | (6f 00 72 00 69 00 67 00 69 00 6e 00 34 00 40 00 63 00 6f 00 64 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 79 00))}
		$account465 = {((6f 72 69 67 69 6e 36 40 63 6f 64 75 63 61 74 69 6f 6e 2e 63 6f 6d 2e 6d 79) | (6f 00 72 00 69 00 67 00 69 00 6e 00 36 00 40 00 63 00 6f 00 64 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 79 00))}
		$account466 = {((6f 72 69 67 69 6e 61 6c 40 61 79 64 61 6e 67 72 6f 75 70 2e 63 6f 6d 2e 6d 79) | (6f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 40 00 61 00 79 00 64 00 61 00 6e 00 67 00 72 00 6f 00 75 00 70 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 79 00))}
		$account467 = {((6f 72 69 67 69 6e 61 6c 40 64 61 64 61 74 69 6c 65 73 2e 63 6f 6d 2e 61 75) | (6f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 40 00 64 00 61 00 64 00 61 00 74 00 69 00 6c 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 75 00))}
		$account468 = {((6f 72 69 67 69 6e 6d 6f 6e 65 79 40 61 6d 62 72 65 68 2e 63 6f 6d) | (6f 00 72 00 69 00 67 00 69 00 6e 00 6d 00 6f 00 6e 00 65 00 79 00 40 00 61 00 6d 00 62 00 72 00 65 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account469 = {((6f 72 69 67 69 6e 40 70 61 6e 70 61 74 6d 6f 73 2e 63 6f 2e 69 64) | (6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 70 00 61 00 6e 00 70 00 61 00 74 00 6d 00 6f 00 73 00 2e 00 63 00 6f 00 2e 00 69 00 64 00))}
		$account470 = {((6f 73 63 61 72 31 40 7a 65 65 6e 61 74 6c 6e 63 2e 63 6f 6d) | (6f 00 73 00 63 00 61 00 72 00 31 00 40 00 7a 00 65 00 65 00 6e 00 61 00 74 00 6c 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account471 = {((6f 74 75 70 61 79 61 63 68 69 40 63 6f 67 6e 69 74 69 6f 70 65 72 75 2e 63 6f 6d) | (6f 00 74 00 75 00 70 00 61 00 79 00 61 00 63 00 68 00 69 00 40 00 63 00 6f 00 67 00 6e 00 69 00 74 00 69 00 6f 00 70 00 65 00 72 00 75 00 2e 00 63 00 6f 00 6d 00))}
		$account472 = {((6f 75 72 70 6c 61 73 74 69 63 32 32 40 67 6d 61 69 6c 2e 63 6f 6d) | (6f 00 75 00 72 00 70 00 6c 00 61 00 73 00 74 00 69 00 63 00 32 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account473 = {((70 61 6e 6f 73 40 73 6b 65 70 73 69 73 2d 73 67 2e 69 63 75) | (70 00 61 00 6e 00 6f 00 73 00 40 00 73 00 6b 00 65 00 70 00 73 00 69 00 73 00 2d 00 73 00 67 00 2e 00 69 00 63 00 75 00))}
		$account474 = {((70 61 72 69 73 61 40 61 62 61 72 73 69 61 76 61 2e 63 6f 6d) | (70 00 61 00 72 00 69 00 73 00 61 00 40 00 61 00 62 00 61 00 72 00 73 00 69 00 61 00 76 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account475 = {((70 61 73 73 6a 6f 6e 65 73 40 79 61 6e 64 65 78 2e 63 6f 6d) | (70 00 61 00 73 00 73 00 6a 00 6f 00 6e 00 65 00 73 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account476 = {((70 61 75 6c 69 6e 65 2e 76 6f 73 74 72 6f 70 69 61 74 6f 76 61 40 79 61 6e 64 65 78 2e 63 6f 6d) | (70 00 61 00 75 00 6c 00 69 00 6e 00 65 00 2e 00 76 00 6f 00 73 00 74 00 72 00 6f 00 70 00 69 00 61 00 74 00 6f 00 76 00 61 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account477 = {((70 61 76 61 6e 40 62 65 73 63 6f 2e 63 6f 6d 2e 73 61) | (70 00 61 00 76 00 61 00 6e 00 40 00 62 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 73 00 61 00))}
		$account478 = {((70 63 73 31 40 64 65 65 70 73 61 65 65 6d 69 72 61 74 65 73 2e 63 6f 6d) | (70 00 63 00 73 00 31 00 40 00 64 00 65 00 65 00 70 00 73 00 61 00 65 00 65 00 6d 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account479 = {((70 63 73 40 64 65 65 70 73 61 65 65 6d 69 72 61 74 65 73 2e 63 6f 6d) | (70 00 63 00 73 00 40 00 64 00 65 00 65 00 70 00 73 00 61 00 65 00 65 00 6d 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account480 = {((70 65 64 72 6f 61 6c 65 78 37 31 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (70 00 65 00 64 00 72 00 6f 00 61 00 6c 00 65 00 78 00 37 00 31 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account481 = {((70 65 65 40 63 68 65 6d 73 68 69 72 65 2e 6f 72 67) | (70 00 65 00 65 00 40 00 63 00 68 00 65 00 6d 00 73 00 68 00 69 00 72 00 65 00 2e 00 6f 00 72 00 67 00))}
		$account482 = {((70 65 74 65 72 73 6f 6e 68 6f 75 73 74 6f 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (70 00 65 00 74 00 65 00 72 00 73 00 6f 00 6e 00 68 00 6f 00 75 00 73 00 74 00 6f 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account483 = {((70 68 79 6e 6f 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (70 00 68 00 79 00 6e 00 6f 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account484 = {((70 68 79 6e 6f 40 70 6c 61 74 69 6e 73 68 69 70 73 2e 6e 65 74) | (70 00 68 00 79 00 6e 00 6f 00 40 00 70 00 6c 00 61 00 74 00 69 00 6e 00 73 00 68 00 69 00 70 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account485 = {((70 69 6e 40 61 70 74 72 61 69 6e 69 6e 67 2e 62 69 7a) | (70 00 69 00 6e 00 40 00 61 00 70 00 74 00 72 00 61 00 69 00 6e 00 69 00 6e 00 67 00 2e 00 62 00 69 00 7a 00))}
		$account486 = {((70 6d 75 72 69 69 74 68 69 40 67 61 6d 6d 61 76 69 6c 6c 61 2e 6f 72 67) | (70 00 6d 00 75 00 72 00 69 00 69 00 74 00 68 00 69 00 40 00 67 00 61 00 6d 00 6d 00 61 00 76 00 69 00 6c 00 6c 00 61 00 2e 00 6f 00 72 00 67 00))}
		$account487 = {((70 2e 6f 72 69 67 69 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (70 00 2e 00 6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account488 = {((70 6f 73 74 6d 61 73 74 65 72 40 75 6e 69 74 65 64 70 61 72 63 65 6c 73 73 65 72 76 69 63 65 73 2e 63 6f 6d) | (70 00 6f 00 73 00 74 00 6d 00 61 00 73 00 74 00 65 00 72 00 40 00 75 00 6e 00 69 00 74 00 65 00 64 00 70 00 61 00 72 00 63 00 65 00 6c 00 73 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account489 = {((70 6f 76 40 72 69 61 6e 62 6f 77 6d 61 78 2e 63 6f 6d) | (70 00 6f 00 76 00 40 00 72 00 69 00 61 00 6e 00 62 00 6f 00 77 00 6d 00 61 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account490 = {((70 70 64 61 74 61 40 67 6f 6c 64 65 6e 66 61 6e 63 65 2e 63 6f 6d) | (70 00 70 00 64 00 61 00 74 00 61 00 40 00 67 00 6f 00 6c 00 64 00 65 00 6e 00 66 00 61 00 6e 00 63 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account491 = {((70 70 75 72 69 40 73 65 61 72 63 68 6e 65 74 2e 63 6f 2e 69 6e) | (70 00 70 00 75 00 72 00 69 00 40 00 73 00 65 00 61 00 72 00 63 00 68 00 6e 00 65 00 74 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account492 = {((70 72 61 63 74 69 63 65 40 77 65 62 64 65 73 69 67 6e 2d 63 6c 61 73 73 2e 73 69 74 65) | (70 00 72 00 61 00 63 00 74 00 69 00 63 00 65 00 40 00 77 00 65 00 62 00 64 00 65 00 73 00 69 00 67 00 6e 00 2d 00 63 00 6c 00 61 00 73 00 73 00 2e 00 73 00 69 00 74 00 65 00))}
		$account493 = {((70 72 61 6e 61 76 2e 70 61 74 65 6c 40 75 6c 74 72 61 66 69 6c 74 65 72 69 6e 64 69 61 2e 63 6f 6d) | (70 00 72 00 61 00 6e 00 61 00 76 00 2e 00 70 00 61 00 74 00 65 00 6c 00 40 00 75 00 6c 00 74 00 72 00 61 00 66 00 69 00 6c 00 74 00 65 00 72 00 69 00 6e 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account494 = {((70 72 61 73 68 61 6e 74 40 67 6f 70 61 6c 64 61 73 76 69 73 72 61 6d 2e 63 6f 6d) | (70 00 72 00 61 00 73 00 68 00 61 00 6e 00 74 00 40 00 67 00 6f 00 70 00 61 00 6c 00 64 00 61 00 73 00 76 00 69 00 73 00 72 00 61 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account495 = {((70 72 65 73 68 40 61 6e 64 69 6e 67 2d 74 77 2e 63 6f 6d) | (70 00 72 00 65 00 73 00 68 00 40 00 61 00 6e 00 64 00 69 00 6e 00 67 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account496 = {((70 72 65 73 70 40 65 6d 73 73 2e 75 73) | (70 00 72 00 65 00 73 00 70 00 40 00 65 00 6d 00 73 00 73 00 2e 00 75 00 73 00))}
		$account497 = {((70 72 69 6e 63 65 6c 6f 67 40 6d 61 6e 67 65 72 6f 2e 78 79 7a) | (70 00 72 00 69 00 6e 00 63 00 65 00 6c 00 6f 00 67 00 40 00 6d 00 61 00 6e 00 67 00 65 00 72 00 6f 00 2e 00 78 00 79 00 7a 00))}
		$account498 = {((70 72 6f 64 75 63 63 69 6f 6e 40 73 65 72 76 61 6c 65 63 2d 63 6f 6d 2e 6d 65) | (70 00 72 00 6f 00 64 00 75 00 63 00 63 00 69 00 6f 00 6e 00 40 00 73 00 65 00 72 00 76 00 61 00 6c 00 65 00 63 00 2d 00 63 00 6f 00 6d 00 2e 00 6d 00 65 00))}
		$account499 = {((70 72 6f 69 7a 76 6f 64 6e 6a 61 40 6e 6f 6b 61 63 68 69 2e 72 73) | (70 00 72 00 6f 00 69 00 7a 00 76 00 6f 00 64 00 6e 00 6a 00 61 00 40 00 6e 00 6f 00 6b 00 61 00 63 00 68 00 69 00 2e 00 72 00 73 00))}
		$account500 = {((70 72 6f 79 65 63 74 6f 73 40 73 61 6e 74 69 61 67 6f 67 61 72 63 69 61 2e 65 73) | (70 00 72 00 6f 00 79 00 65 00 63 00 74 00 6f 00 73 00 40 00 73 00 61 00 6e 00 74 00 69 00 61 00 67 00 6f 00 67 00 61 00 72 00 63 00 69 00 61 00 2e 00 65 00 73 00))}
		$account501 = {((70 75 6c 73 69 74 2e 63 40 73 70 69 6e 74 65 6e 67 2e 63 6f 6d) | (70 00 75 00 6c 00 73 00 69 00 74 00 2e 00 63 00 40 00 73 00 70 00 69 00 6e 00 74 00 65 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account502 = {((70 75 72 63 68 61 73 65 40 64 6a 69 6e 64 75 73 74 72 69 65 73 2e 6e 65 74) | (70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 40 00 64 00 6a 00 69 00 6e 00 64 00 75 00 73 00 74 00 72 00 69 00 65 00 73 00 2e 00 6e 00 65 00 74 00))}
		$account503 = {((70 75 72 63 68 61 73 65 40 67 6f 6d 6f 73 77 61 2e 63 6f 6d) | (70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 40 00 67 00 6f 00 6d 00 6f 00 73 00 77 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account504 = {((70 75 72 63 68 61 73 69 6e 67 40 73 69 69 63 65 67 79 70 74 2e 63 6f 6d) | (70 00 75 00 72 00 63 00 68 00 61 00 73 00 69 00 6e 00 67 00 40 00 73 00 69 00 69 00 63 00 65 00 67 00 79 00 70 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account505 = {((71 61 74 61 72 40 63 6f 6e 74 69 6e 65 6e 74 61 6c 6d 61 6e 70 6f 77 65 72 2e 63 6f 6d) | (71 00 61 00 74 00 61 00 72 00 40 00 63 00 6f 00 6e 00 74 00 69 00 6e 00 65 00 6e 00 74 00 61 00 6c 00 6d 00 61 00 6e 00 70 00 6f 00 77 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account506 = {((72 61 6d 6b 75 6d 61 72 40 61 64 76 6f 69 63 65 6d 65 64 69 61 77 6f 72 6b 73 2e 63 6f 6d) | (72 00 61 00 6d 00 6b 00 75 00 6d 00 61 00 72 00 40 00 61 00 64 00 76 00 6f 00 69 00 63 00 65 00 6d 00 65 00 64 00 69 00 61 00 77 00 6f 00 72 00 6b 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account507 = {((72 61 6e 64 79 40 72 61 79 6d 6f 6e 64 2d 6a 6f 68 6e 2e 63 6f 6d) | (72 00 61 00 6e 00 64 00 79 00 40 00 72 00 61 00 79 00 6d 00 6f 00 6e 00 64 00 2d 00 6a 00 6f 00 68 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account508 = {((72 61 6e 67 65 72 32 40 61 6d 69 73 67 6c 6f 62 61 6c 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (72 00 61 00 6e 00 67 00 65 00 72 00 32 00 40 00 61 00 6d 00 69 00 73 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account509 = {((72 61 6e 67 65 72 40 63 61 6e 76 61 6e 61 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (72 00 61 00 6e 00 67 00 65 00 72 00 40 00 63 00 61 00 6e 00 76 00 61 00 6e 00 61 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account510 = {((72 61 6e 67 65 72 5f 6c 6f 67 40 74 65 6e 64 65 72 74 72 61 64 65 66 6f 72 65 78 2e 63 6f 2e 75 6b) | (72 00 61 00 6e 00 67 00 65 00 72 00 5f 00 6c 00 6f 00 67 00 40 00 74 00 65 00 6e 00 64 00 65 00 72 00 74 00 72 00 61 00 64 00 65 00 66 00 6f 00 72 00 65 00 78 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00))}
		$account511 = {((72 61 6e 67 65 72 40 73 65 6c 74 72 61 62 61 6e 6b 2e 63 6f 6d) | (72 00 61 00 6e 00 67 00 65 00 72 00 40 00 73 00 65 00 6c 00 74 00 72 00 61 00 62 00 61 00 6e 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account512 = {((72 61 6e 67 65 72 5f 73 74 75 62 40 74 65 6e 64 65 72 74 72 61 64 65 66 6f 72 65 78 2e 63 6f 2e 75 6b) | (72 00 61 00 6e 00 67 00 65 00 72 00 5f 00 73 00 74 00 75 00 62 00 40 00 74 00 65 00 6e 00 64 00 65 00 72 00 74 00 72 00 61 00 64 00 65 00 66 00 6f 00 72 00 65 00 78 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00))}
		$account513 = {((72 61 70 68 61 65 6c 40 67 69 74 67 67 6e 2e 63 6f 6d) | (72 00 61 00 70 00 68 00 61 00 65 00 6c 00 40 00 67 00 69 00 74 00 67 00 67 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account514 = {((72 61 74 6e 61 40 61 73 6b 6f 6e 2e 63 6f 2e 69 64) | (72 00 61 00 74 00 6e 00 61 00 40 00 61 00 73 00 6b 00 6f 00 6e 00 2e 00 63 00 6f 00 2e 00 69 00 64 00))}
		$account515 = {((72 61 7a 69 6c 6f 67 73 40 72 61 7a 69 6c 6f 67 73 2e 63 6f 6d) | (72 00 61 00 7a 00 69 00 6c 00 6f 00 67 00 73 00 40 00 72 00 61 00 7a 00 69 00 6c 00 6f 00 67 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account516 = {((72 65 61 6c 6c 69 66 65 40 6a 70 6d 65 2e 6f 72 67 2e 69 6e) | (72 00 65 00 61 00 6c 00 6c 00 69 00 66 00 65 00 40 00 6a 00 70 00 6d 00 65 00 2e 00 6f 00 72 00 67 00 2e 00 69 00 6e 00))}
		$account517 = {((72 65 63 65 69 76 65 40 6d 65 64 69 63 70 72 6f 64 75 63 74 69 6f 6e 2e 67 71) | (72 00 65 00 63 00 65 00 69 00 76 00 65 00 40 00 6d 00 65 00 64 00 69 00 63 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 67 00 71 00))}
		$account518 = {((72 65 63 65 70 74 69 6f 6e 40 63 72 65 73 74 70 61 6b 2e 63 6f 6d) | (72 00 65 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 40 00 63 00 72 00 65 00 73 00 74 00 70 00 61 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account519 = {((72 65 63 69 65 76 65 40 72 65 73 75 6c 74 68 6f 6d 65 2e 78 79 7a) | (72 00 65 00 63 00 69 00 65 00 76 00 65 00 40 00 72 00 65 00 73 00 75 00 6c 00 74 00 68 00 6f 00 6d 00 65 00 2e 00 78 00 79 00 7a 00))}
		$account520 = {((72 65 63 6c 75 74 61 6d 69 65 6e 74 6f 31 40 63 6f 73 65 61 2e 6d 78) | (72 00 65 00 63 00 6c 00 75 00 74 00 61 00 6d 00 69 00 65 00 6e 00 74 00 6f 00 31 00 40 00 63 00 6f 00 73 00 65 00 61 00 2e 00 6d 00 78 00))}
		$account521 = {((72 65 67 61 6e 31 30 35 38 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (72 00 65 00 67 00 61 00 6e 00 31 00 30 00 35 00 38 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account522 = {((72 65 6e 65 2e 75 72 64 61 6e 65 74 61 40 64 65 65 70 62 6c 75 65 61 6d 65 72 69 63 61 2e 63 6f 6d) | (72 00 65 00 6e 00 65 00 2e 00 75 00 72 00 64 00 61 00 6e 00 65 00 74 00 61 00 40 00 64 00 65 00 65 00 70 00 62 00 6c 00 75 00 65 00 61 00 6d 00 65 00 72 00 69 00 63 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account523 = {((72 65 73 65 72 76 61 73 40 70 6f 6f 6c 64 65 65 78 63 75 72 73 69 6f 6e 65 73 2e 65 73) | (72 00 65 00 73 00 65 00 72 00 76 00 61 00 73 00 40 00 70 00 6f 00 6f 00 6c 00 64 00 65 00 65 00 78 00 63 00 75 00 72 00 73 00 69 00 6f 00 6e 00 65 00 73 00 2e 00 65 00 73 00))}
		$account524 = {((72 65 73 65 72 76 61 74 69 6f 6e 40 66 6c 79 65 67 79 70 74 61 76 69 61 74 69 6f 6e 2e 63 6f 6d) | (72 00 65 00 73 00 65 00 72 00 76 00 61 00 74 00 69 00 6f 00 6e 00 40 00 66 00 6c 00 79 00 65 00 67 00 79 00 70 00 74 00 61 00 76 00 69 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account525 = {((72 65 73 75 6c 74 62 6f 78 30 34 32 40 79 61 6e 64 65 78 2e 63 6f 6d) | (72 00 65 00 73 00 75 00 6c 00 74 00 62 00 6f 00 78 00 30 00 34 00 32 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account526 = {((72 65 73 75 6c 74 2e 70 61 63 6b 61 67 65 40 79 61 6e 64 65 78 2e 72 75) | (72 00 65 00 73 00 75 00 6c 00 74 00 2e 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account527 = {((72 65 73 75 6c 74 40 73 63 72 75 74 69 66 69 66 79 2e 78 79 7a) | (72 00 65 00 73 00 75 00 6c 00 74 00 40 00 73 00 63 00 72 00 75 00 74 00 69 00 66 00 69 00 66 00 79 00 2e 00 78 00 79 00 7a 00))}
		$account528 = {((72 65 79 40 66 72 6f 68 6e 6e 2e 63 6f 6d) | (72 00 65 00 79 00 40 00 66 00 72 00 6f 00 68 00 6e 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account529 = {((72 65 7a 75 6c 74 2e 6f 72 69 67 69 6e 40 6c 6a 76 65 73 2e 63 6f 6d) | (72 00 65 00 7a 00 75 00 6c 00 74 00 2e 00 6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 6c 00 6a 00 76 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account530 = {((72 66 79 5f 73 61 6c 65 73 38 30 36 40 64 67 72 72 66 79 2e 63 6f 6d) | (72 00 66 00 79 00 5f 00 73 00 61 00 6c 00 65 00 73 00 38 00 30 00 36 00 40 00 64 00 67 00 72 00 72 00 66 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account531 = {((72 69 63 61 72 64 6f 2e 6f 73 70 69 6e 61 40 62 6e 62 2d 73 70 61 2e 63 6f 6d) | (72 00 69 00 63 00 61 00 72 00 64 00 6f 00 2e 00 6f 00 73 00 70 00 69 00 6e 00 61 00 40 00 62 00 6e 00 62 00 2d 00 73 00 70 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account532 = {((72 69 7a 6b 79 40 72 61 6a 61 70 69 6e 64 61 68 2e 63 6f 6d) | (72 00 69 00 7a 00 6b 00 79 00 40 00 72 00 61 00 6a 00 61 00 70 00 69 00 6e 00 64 00 61 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account533 = {((72 6f 6e 61 6c 64 6f 31 40 65 63 6f 6f 72 67 61 6e 69 63 2e 63 6f) | (72 00 6f 00 6e 00 61 00 6c 00 64 00 6f 00 31 00 40 00 65 00 63 00 6f 00 6f 00 72 00 67 00 61 00 6e 00 69 00 63 00 2e 00 63 00 6f 00))}
		$account534 = {((72 6f 6f 74 40 6a 69 72 61 74 61 6e 65 2e 63 6f 6d) | (72 00 6f 00 6f 00 74 00 40 00 6a 00 69 00 72 00 61 00 74 00 61 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account535 = {((72 6f 73 65 2e 6e 75 6e 65 7a 40 79 61 6e 64 65 78 2e 72 75) | (72 00 6f 00 73 00 65 00 2e 00 6e 00 75 00 6e 00 65 00 7a 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account536 = {((72 6f 75 74 65 72 31 31 34 37 37 40 74 61 73 68 69 70 74 61 2e 63 6f 6d) | (72 00 6f 00 75 00 74 00 65 00 72 00 31 00 31 00 34 00 37 00 37 00 40 00 74 00 61 00 73 00 68 00 69 00 70 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account537 = {((72 6f 79 61 6c 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (72 00 6f 00 79 00 61 00 6c 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account538 = {((72 70 61 6c 6d 61 40 61 6d 65 74 72 6f 70 6f 6c 69 73 2e 63 6f 6d) | (72 00 70 00 61 00 6c 00 6d 00 61 00 40 00 61 00 6d 00 65 00 74 00 72 00 6f 00 70 00 6f 00 6c 00 69 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account539 = {((72 71 61 34 40 73 68 69 76 61 6e 69 6c 6f 63 6b 73 2e 63 6f 6d) | (72 00 71 00 61 00 34 00 40 00 73 00 68 00 69 00 76 00 61 00 6e 00 69 00 6c 00 6f 00 63 00 6b 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account540 = {((72 2e 74 6f 6d 65 40 79 61 6e 64 65 78 2e 63 6f 6d) | (72 00 2e 00 74 00 6f 00 6d 00 65 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account541 = {((72 75 6e 40 6b 61 67 61 62 6f 2e 6e 65 74) | (72 00 75 00 6e 00 40 00 6b 00 61 00 67 00 61 00 62 00 6f 00 2e 00 6e 00 65 00 74 00))}
		$account542 = {((73 61 62 65 72 61 2e 73 75 6c 74 61 6e 61 40 70 72 6f 74 69 73 74 68 61 2e 63 6f 6d) | (73 00 61 00 62 00 65 00 72 00 61 00 2e 00 73 00 75 00 6c 00 74 00 61 00 6e 00 61 00 40 00 70 00 72 00 6f 00 74 00 69 00 73 00 74 00 68 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account543 = {((73 61 63 6f 40 6b 65 6e 6e 79 63 6f 72 70 69 6e 67 2e 63 6f 6d) | (73 00 61 00 63 00 6f 00 40 00 6b 00 65 00 6e 00 6e 00 79 00 63 00 6f 00 72 00 70 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account544 = {((73 61 66 61 61 2e 62 69 73 68 61 72 61 40 73 61 6e 74 65 6d 6f 72 61 65 67 79 70 74 2e 63 6f 6d) | (73 00 61 00 66 00 61 00 61 00 2e 00 62 00 69 00 73 00 68 00 61 00 72 00 61 00 40 00 73 00 61 00 6e 00 74 00 65 00 6d 00 6f 00 72 00 61 00 65 00 67 00 79 00 70 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account545 = {((73 61 66 65 74 79 40 72 61 79 61 6e 65 74 65 63 68 2e 63 6f 6d) | (73 00 61 00 66 00 65 00 74 00 79 00 40 00 72 00 61 00 79 00 61 00 6e 00 65 00 74 00 65 00 63 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account546 = {((73 61 67 75 69 64 40 6a 70 61 68 2e 6f 72 67) | (73 00 61 00 67 00 75 00 69 00 64 00 40 00 6a 00 70 00 61 00 68 00 2e 00 6f 00 72 00 67 00))}
		$account547 = {((73 61 6c 65 65 6d 40 65 6a 61 7a 6f 6e 74 68 65 77 65 62 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 65 00 6d 00 40 00 65 00 6a 00 61 00 7a 00 6f 00 6e 00 74 00 68 00 65 00 77 00 65 00 62 00 2e 00 63 00 6f 00 6d 00))}
		$account548 = {((73 61 6c 65 73 30 30 31 40 63 61 69 72 6f 77 61 79 73 2e 6d 65) | (73 00 61 00 6c 00 65 00 73 00 30 00 30 00 31 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 6d 00 65 00))}
		$account549 = {((73 61 6c 65 73 31 40 72 61 7a 6f 72 77 69 72 65 66 65 63 6e 69 6e 67 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 31 00 40 00 72 00 61 00 7a 00 6f 00 72 00 77 00 69 00 72 00 65 00 66 00 65 00 63 00 6e 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account550 = {((73 61 6c 65 73 40 61 62 75 6f 64 65 68 62 72 6f 73 2e 63 6f) | (73 00 61 00 6c 00 65 00 73 00 40 00 61 00 62 00 75 00 6f 00 64 00 65 00 68 00 62 00 72 00 6f 00 73 00 2e 00 63 00 6f 00))}
		$account551 = {((73 61 6c 65 73 40 61 6d 65 72 69 63 61 6e 74 72 65 76 61 6c 65 72 69 6e 63 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 61 00 6d 00 65 00 72 00 69 00 63 00 61 00 6e 00 74 00 72 00 65 00 76 00 61 00 6c 00 65 00 72 00 69 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account552 = {((73 61 6c 65 73 40 61 73 70 6c 70 61 72 74 73 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 61 00 73 00 70 00 6c 00 70 00 61 00 72 00 74 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account553 = {((73 61 6c 65 73 40 62 65 73 74 69 6e 6a 65 63 74 69 6f 6e 6d 61 63 68 69 6e 65 73 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 62 00 65 00 73 00 74 00 69 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account554 = {((73 61 6c 65 73 40 62 68 61 76 6e 61 74 75 74 6f 72 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 62 00 68 00 61 00 76 00 6e 00 61 00 74 00 75 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account555 = {((73 61 6c 65 73 40 65 6d 70 72 6f 6d 61 65 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 65 00 6d 00 70 00 72 00 6f 00 6d 00 61 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account556 = {((73 61 6c 65 73 40 65 78 63 65 6c 61 72 69 66 72 65 69 67 68 74 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 65 00 78 00 63 00 65 00 6c 00 61 00 72 00 69 00 66 00 72 00 65 00 69 00 67 00 68 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account557 = {((73 61 6c 65 73 40 69 65 66 6c 6f 77 6d 65 74 65 72 73 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 69 00 65 00 66 00 6c 00 6f 00 77 00 6d 00 65 00 74 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account558 = {((73 61 6c 65 73 40 6a 69 71 64 79 69 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 6a 00 69 00 71 00 64 00 79 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account559 = {((73 61 6c 65 73 40 6d 61 69 7a 69 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 6d 00 61 00 69 00 7a 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account560 = {((73 61 6c 65 73 40 6d 6f 6e 74 61 6e 61 2e 63 6f 2e 6b 65) | (73 00 61 00 6c 00 65 00 73 00 40 00 6d 00 6f 00 6e 00 74 00 61 00 6e 00 61 00 2e 00 63 00 6f 00 2e 00 6b 00 65 00))}
		$account561 = {((73 61 6c 65 40 73 6f 6d 61 6b 69 6e 79 61 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 40 00 73 00 6f 00 6d 00 61 00 6b 00 69 00 6e 00 79 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account562 = {((73 61 6c 65 73 40 70 69 70 69 6e 67 7a 6f 6e 65 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 40 00 70 00 69 00 70 00 69 00 6e 00 67 00 7a 00 6f 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account563 = {((73 61 6c 65 73 74 65 61 6d 40 70 72 6f 74 65 63 74 6f 72 66 69 72 65 73 61 66 65 74 79 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 74 00 65 00 61 00 6d 00 40 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 66 00 69 00 72 00 65 00 73 00 61 00 66 00 65 00 74 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account564 = {((73 61 6d 63 6f 40 66 61 72 6d 2d 63 6f 6d 2e 6d 65) | (73 00 61 00 6d 00 63 00 6f 00 40 00 66 00 61 00 72 00 6d 00 2d 00 63 00 6f 00 6d 00 2e 00 6d 00 65 00))}
		$account565 = {((73 61 6e 62 72 69 74 68 31 31 32 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 61 00 6e 00 62 00 72 00 69 00 74 00 68 00 31 00 31 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account566 = {((73 61 6e 64 79 40 63 69 74 6f 74 65 73 74 2e 63 6f) | (73 00 61 00 6e 00 64 00 79 00 40 00 63 00 69 00 74 00 6f 00 74 00 65 00 73 00 74 00 2e 00 63 00 6f 00))}
		$account567 = {((73 61 6e 6a 61 6e 61 40 6c 65 67 61 6c 63 6f 75 6e 73 65 6c 62 64 2e 63 6f 6d) | (73 00 61 00 6e 00 6a 00 61 00 6e 00 61 00 40 00 6c 00 65 00 67 00 61 00 6c 00 63 00 6f 00 75 00 6e 00 73 00 65 00 6c 00 62 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account568 = {((73 61 72 61 40 68 69 76 65 2d 64 65 63 6f 72 2e 63 6f 6d) | (73 00 61 00 72 00 61 00 40 00 68 00 69 00 76 00 65 00 2d 00 64 00 65 00 63 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account569 = {((73 61 72 74 69 6b 61 68 40 63 72 6f 77 6e 63 6f 72 6b 65 2e 63 6f 6d) | (73 00 61 00 72 00 74 00 69 00 6b 00 61 00 68 00 40 00 63 00 72 00 6f 00 77 00 6e 00 63 00 6f 00 72 00 6b 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account570 = {((73 61 74 69 6e 64 65 72 40 62 6f 64 79 63 61 72 65 63 72 65 61 74 69 6f 6e 73 2e 63 6f 6d) | (73 00 61 00 74 00 69 00 6e 00 64 00 65 00 72 00 40 00 62 00 6f 00 64 00 79 00 63 00 61 00 72 00 65 00 63 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account571 = {((73 61 74 69 73 40 33 65 6e 61 6c 75 6d 69 6e 79 75 6d 2e 63 6f 6d 2e 74 72) | (73 00 61 00 74 00 69 00 73 00 40 00 33 00 65 00 6e 00 61 00 6c 00 75 00 6d 00 69 00 6e 00 79 00 75 00 6d 00 2e 00 63 00 6f 00 6d 00 2e 00 74 00 72 00))}
		$account572 = {((73 61 74 69 76 61 40 68 61 6e 77 69 68 61 2e 63 6f 6d) | (73 00 61 00 74 00 69 00 76 00 61 00 40 00 68 00 61 00 6e 00 77 00 69 00 68 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account573 = {((73 61 76 40 65 6d 65 63 6f 2e 69 63 75) | (73 00 61 00 76 00 40 00 65 00 6d 00 65 00 63 00 6f 00 2e 00 69 00 63 00 75 00))}
		$account574 = {((73 61 7a 7a 61 64 40 70 61 63 69 66 69 63 61 6c 62 64 2e 63 6f 6d) | (73 00 61 00 7a 00 7a 00 61 00 64 00 40 00 70 00 61 00 63 00 69 00 66 00 69 00 63 00 61 00 6c 00 62 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account575 = {((73 62 6f 75 72 64 61 69 73 40 73 69 65 6c 75 70 7a 2e 63 6f 6d) | (73 00 62 00 6f 00 75 00 72 00 64 00 61 00 69 00 73 00 40 00 73 00 69 00 65 00 6c 00 75 00 70 00 7a 00 2e 00 63 00 6f 00 6d 00))}
		$account576 = {((73 63 64 63 79 74 63 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 63 00 64 00 63 00 79 00 74 00 63 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account577 = {((73 65 6c 65 63 74 74 6f 6f 6c 73 40 79 61 6e 64 65 78 2e 63 6f 6d) | (73 00 65 00 6c 00 65 00 63 00 74 00 74 00 6f 00 6f 00 6c 00 73 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account578 = {((73 65 6c 76 61 40 72 65 67 6f 72 6e 73 2e 63 6f 6d) | (73 00 65 00 6c 00 76 00 61 00 40 00 72 00 65 00 67 00 6f 00 72 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account579 = {((73 65 6e 64 65 72 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (73 00 65 00 6e 00 64 00 65 00 72 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account580 = {((73 65 6e 64 40 6d 65 64 69 63 70 72 6f 64 75 63 74 69 6f 6e 2e 67 71) | (73 00 65 00 6e 00 64 00 40 00 6d 00 65 00 64 00 69 00 63 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 67 00 71 00))}
		$account581 = {((73 65 70 70 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (73 00 65 00 70 00 70 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account582 = {((73 65 72 76 65 72 31 40 74 61 73 68 69 70 74 61 2e 63 6f 6d) | (73 00 65 00 72 00 76 00 65 00 72 00 31 00 40 00 74 00 61 00 73 00 68 00 69 00 70 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account583 = {((73 65 72 76 65 72 40 74 61 73 68 69 70 74 61 2e 63 6f 6d) | (73 00 65 00 72 00 76 00 65 00 72 00 40 00 74 00 61 00 73 00 68 00 69 00 70 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account584 = {((73 65 72 76 69 63 65 40 70 74 6f 63 73 2e 78 79 7a) | (73 00 65 00 72 00 76 00 69 00 63 00 65 00 40 00 70 00 74 00 6f 00 63 00 73 00 2e 00 78 00 79 00 7a 00))}
		$account585 = {((73 2e 65 77 61 6c 64 74 40 6f 74 76 2d 69 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 2e 6d 65) | (73 00 2e 00 65 00 77 00 61 00 6c 00 64 00 74 00 40 00 6f 00 74 00 76 00 2d 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 2e 00 6d 00 65 00))}
		$account586 = {((73 68 61 68 69 64 40 6f 6e 79 78 66 72 65 69 67 68 74 2e 63 6f 6d) | (73 00 68 00 61 00 68 00 69 00 64 00 40 00 6f 00 6e 00 79 00 78 00 66 00 72 00 65 00 69 00 67 00 68 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account587 = {((73 68 61 6b 65 65 6c 75 64 64 69 6e 40 74 77 70 6c 2e 70 6b) | (73 00 68 00 61 00 6b 00 65 00 65 00 6c 00 75 00 64 00 64 00 69 00 6e 00 40 00 74 00 77 00 70 00 6c 00 2e 00 70 00 6b 00))}
		$account588 = {((73 68 6f 70 73 40 77 65 70 6d 69 6c 6c 2e 77 65 62 73 69 74 65) | (73 00 68 00 6f 00 70 00 73 00 40 00 77 00 65 00 70 00 6d 00 69 00 6c 00 6c 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account589 = {((73 68 72 75 74 69 6b 61 2e 63 68 61 75 64 68 61 72 79 40 6f 70 70 6f 6d 6f 62 69 6c 65 6d 70 2e 69 6e) | (73 00 68 00 72 00 75 00 74 00 69 00 6b 00 61 00 2e 00 63 00 68 00 61 00 75 00 64 00 68 00 61 00 72 00 79 00 40 00 6f 00 70 00 70 00 6f 00 6d 00 6f 00 62 00 69 00 6c 00 65 00 6d 00 70 00 2e 00 69 00 6e 00))}
		$account590 = {((73 69 6d 6f 6e 40 65 78 6f 74 69 63 70 6f 6f 6c 73 2e 63 6f 6d 2e 61 75) | (73 00 69 00 6d 00 6f 00 6e 00 40 00 65 00 78 00 6f 00 74 00 69 00 63 00 70 00 6f 00 6f 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 75 00))}
		$account591 = {((73 69 6d 6f 6e 2e 6e 65 77 74 6f 6e 40 63 6f 6e 74 65 63 73 2d 65 2e 63 6f 6d) | (73 00 69 00 6d 00 6f 00 6e 00 2e 00 6e 00 65 00 77 00 74 00 6f 00 6e 00 40 00 63 00 6f 00 6e 00 74 00 65 00 63 00 73 00 2d 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account592 = {((73 69 72 6f 68 6d 73 40 73 69 72 6f 68 6d 73 2e 63 6f 6d) | (73 00 69 00 72 00 6f 00 68 00 6d 00 73 00 40 00 73 00 69 00 72 00 6f 00 68 00 6d 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account593 = {((73 6b 74 40 73 74 61 72 74 72 61 6e 73 6c 6f 67 69 73 74 69 63 73 2e 63 6f 6d) | (73 00 6b 00 74 00 40 00 73 00 74 00 61 00 72 00 74 00 72 00 61 00 6e 00 73 00 6c 00 6f 00 67 00 69 00 73 00 74 00 69 00 63 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account594 = {((73 6c 65 65 76 65 73 31 30 30 40 79 61 6e 64 65 78 2e 63 6f 6d) | (73 00 6c 00 65 00 65 00 76 00 65 00 73 00 31 00 30 00 30 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account595 = {((73 6c 69 6d 31 40 67 65 2d 6c 6e 64 75 73 74 72 79 2e 63 6f 6d) | (73 00 6c 00 69 00 6d 00 31 00 40 00 67 00 65 00 2d 00 6c 00 6e 00 64 00 75 00 73 00 74 00 72 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account596 = {((73 6c 69 6d 32 40 74 65 69 74 65 63 2e 61 73 69 61) | (73 00 6c 00 69 00 6d 00 32 00 40 00 74 00 65 00 69 00 74 00 65 00 63 00 2e 00 61 00 73 00 69 00 61 00))}
		$account597 = {((73 6c 69 6d 73 68 61 64 65 73 31 40 64 65 65 70 73 61 65 65 6d 69 72 61 74 65 73 2e 63 6f 6d) | (73 00 6c 00 69 00 6d 00 73 00 68 00 61 00 64 00 65 00 73 00 31 00 40 00 64 00 65 00 65 00 70 00 73 00 61 00 65 00 65 00 6d 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account598 = {((73 6c 69 6d 73 68 61 64 65 73 40 64 65 65 70 73 61 65 65 6d 69 72 61 74 65 73 2e 63 6f 6d) | (73 00 6c 00 69 00 6d 00 73 00 68 00 61 00 64 00 65 00 73 00 40 00 64 00 65 00 65 00 70 00 73 00 61 00 65 00 65 00 6d 00 69 00 72 00 61 00 74 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account599 = {((73 6c 69 6d 40 77 6f 72 6b 70 6c 75 73 77 6f 72 6b 2e 63 6f 6d) | (73 00 6c 00 69 00 6d 00 40 00 77 00 6f 00 72 00 6b 00 70 00 6c 00 75 00 73 00 77 00 6f 00 72 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account600 = {((73 6c 79 2d 6f 72 69 67 69 6e 6c 6f 67 73 40 79 61 6e 64 65 78 2e 72 75) | (73 00 6c 00 79 00 2d 00 6f 00 72 00 69 00 67 00 69 00 6e 00 6c 00 6f 00 67 00 73 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00))}
		$account601 = {((73 6d 61 72 74 2d 6d 6f 6e 65 79 66 69 6c 65 40 73 74 72 79 6b 65 69 72 2e 63 6f 6d) | (73 00 6d 00 61 00 72 00 74 00 2d 00 6d 00 6f 00 6e 00 65 00 79 00 66 00 69 00 6c 00 65 00 40 00 73 00 74 00 72 00 79 00 6b 00 65 00 69 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account602 = {((73 6d 69 74 61 2e 70 61 67 61 64 65 40 61 31 66 65 6e 63 65 73 70 72 6f 64 75 63 74 73 2e 63 6f 6d) | (73 00 6d 00 69 00 74 00 61 00 2e 00 70 00 61 00 67 00 61 00 64 00 65 00 40 00 61 00 31 00 66 00 65 00 6e 00 63 00 65 00 73 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account603 = {((73 6d 69 74 68 79 6a 61 7a 7a 40 6a 61 6b 61 72 74 74 61 2e 78 79 7a) | (73 00 6d 00 69 00 74 00 68 00 79 00 6a 00 61 00 7a 00 7a 00 40 00 6a 00 61 00 6b 00 61 00 72 00 74 00 74 00 61 00 2e 00 78 00 79 00 7a 00))}
		$account604 = {((73 6e 40 69 6e 70 61 72 6b 2e 72 73) | (73 00 6e 00 40 00 69 00 6e 00 70 00 61 00 72 00 6b 00 2e 00 72 00 73 00))}
		$account605 = {((73 6e 70 40 31 73 74 2d 73 68 69 70 2e 63 6f 6d) | (73 00 6e 00 70 00 40 00 31 00 73 00 74 00 2d 00 73 00 68 00 69 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account606 = {((73 6f 66 74 40 72 6e 65 64 69 73 69 6c 6b 2e 6f 72 67) | (73 00 6f 00 66 00 74 00 40 00 72 00 6e 00 65 00 64 00 69 00 73 00 69 00 6c 00 6b 00 2e 00 6f 00 72 00 67 00))}
		$account607 = {((73 6f 6d 63 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (73 00 6f 00 6d 00 63 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account608 = {((73 6f 6e 73 40 72 65 62 75 2e 63 6f 2e 72 77) | (73 00 6f 00 6e 00 73 00 40 00 72 00 65 00 62 00 75 00 2e 00 63 00 6f 00 2e 00 72 00 77 00))}
		$account609 = {((73 6f 6e 75 2e 68 6f 6e 67 40 66 61 6b 6c 79 2d 63 61 6d 62 6f 64 69 61 2e 63 6f 6d) | (73 00 6f 00 6e 00 75 00 2e 00 68 00 6f 00 6e 00 67 00 40 00 66 00 61 00 6b 00 6c 00 79 00 2d 00 63 00 61 00 6d 00 62 00 6f 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account610 = {((73 70 61 72 6b 40 73 70 61 72 6b 69 6e 74 65 6d 61 74 69 6f 6e 61 6c 2e 63 6f 6d) | (73 00 70 00 61 00 72 00 6b 00 40 00 73 00 70 00 61 00 72 00 6b 00 69 00 6e 00 74 00 65 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account611 = {((73 74 61 6e 62 61 73 65 40 62 69 67 6d 61 6e 73 74 61 6e 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 62 00 61 00 73 00 65 00 40 00 62 00 69 00 67 00 6d 00 61 00 6e 00 73 00 74 00 61 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account612 = {((73 74 61 6e 40 66 6c 79 78 70 6f 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 40 00 66 00 6c 00 79 00 78 00 70 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account613 = {((73 74 61 6e 40 69 73 6b 72 65 61 6d 65 63 6f 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 40 00 69 00 73 00 6b 00 72 00 65 00 61 00 6d 00 65 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account614 = {((73 74 61 6e 6c 65 79 62 6f 78 40 79 61 6e 64 65 78 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 6c 00 65 00 79 00 62 00 6f 00 78 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account615 = {((73 74 61 6e 40 6f 72 61 6e 67 65 6f 6e 65 2e 69 6e) | (73 00 74 00 61 00 6e 00 40 00 6f 00 72 00 61 00 6e 00 67 00 65 00 6f 00 6e 00 65 00 2e 00 69 00 6e 00))}
		$account616 = {((73 74 61 6e 40 73 6f 6c 61 72 74 6f 72 62 69 6e 65 73 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 40 00 73 00 6f 00 6c 00 61 00 72 00 74 00 6f 00 72 00 62 00 69 00 6e 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account617 = {((73 74 61 6e 40 7a 69 2d 67 65 6d 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 40 00 7a 00 69 00 2d 00 67 00 65 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account618 = {((73 74 61 6e 7a 6f 37 37 40 73 75 7a 75 6b 69 72 6d 6b 6a 61 6b 61 72 74 61 2e 63 6f 6d) | (73 00 74 00 61 00 6e 00 7a 00 6f 00 37 00 37 00 40 00 73 00 75 00 7a 00 75 00 6b 00 69 00 72 00 6d 00 6b 00 6a 00 61 00 6b 00 61 00 72 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account619 = {((73 74 61 72 6f 6e 75 65 67 62 75 40 79 61 6e 64 65 78 2e 63 6f 6d) | (73 00 74 00 61 00 72 00 6f 00 6e 00 75 00 65 00 67 00 62 00 75 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account620 = {((73 74 61 72 2d 6f 72 69 67 69 6e 40 73 74 72 79 6b 65 69 72 2e 63 6f 6d) | (73 00 74 00 61 00 72 00 2d 00 6f 00 72 00 69 00 67 00 69 00 6e 00 40 00 73 00 74 00 72 00 79 00 6b 00 65 00 69 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account621 = {((73 74 65 70 68 61 6e 69 65 2e 67 69 65 74 40 74 65 63 68 6e 73 69 65 6d 2e 63 6f 6d) | (73 00 74 00 65 00 70 00 68 00 61 00 6e 00 69 00 65 00 2e 00 67 00 69 00 65 00 74 00 40 00 74 00 65 00 63 00 68 00 6e 00 73 00 69 00 65 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account622 = {((73 74 65 70 40 6b 63 63 61 6d 62 6f 64 69 61 2e 63 6f 6d) | (73 00 74 00 65 00 70 00 40 00 6b 00 63 00 63 00 61 00 6d 00 62 00 6f 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account623 = {((73 2e 74 65 72 61 73 61 40 73 68 69 62 61 74 61 2d 66 65 6e 64 65 72 74 65 61 6d 2e 74 65 61 6d) | (73 00 2e 00 74 00 65 00 72 00 61 00 73 00 61 00 40 00 73 00 68 00 69 00 62 00 61 00 74 00 61 00 2d 00 66 00 65 00 6e 00 64 00 65 00 72 00 74 00 65 00 61 00 6d 00 2e 00 74 00 65 00 61 00 6d 00))}
		$account624 = {((73 74 6f 72 65 73 40 69 6e 76 65 6e 74 77 65 6c 64 2e 63 6f 6d) | (73 00 74 00 6f 00 72 00 65 00 73 00 40 00 69 00 6e 00 76 00 65 00 6e 00 74 00 77 00 65 00 6c 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account625 = {((73 74 75 40 66 72 65 73 63 6e 6f 79 2e 63 6f 6d) | (73 00 74 00 75 00 40 00 66 00 72 00 65 00 73 00 63 00 6e 00 6f 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account626 = {((73 75 62 72 61 6e 2e 73 75 62 72 61 6e 40 78 65 72 69 6e 64 6f 2e 63 6f 6d) | (73 00 75 00 62 00 72 00 61 00 6e 00 2e 00 73 00 75 00 62 00 72 00 61 00 6e 00 40 00 78 00 65 00 72 00 69 00 6e 00 64 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account627 = {((73 75 63 63 65 73 73 40 70 6f 79 6c 6f 6e 65 2e 63 6f 6d) | (73 00 75 00 63 00 63 00 65 00 73 00 73 00 40 00 70 00 6f 00 79 00 6c 00 6f 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account628 = {((73 75 6a 69 74 40 61 6d 65 78 77 6f 72 6c 64 77 69 64 65 2e 63 6f 6d) | (73 00 75 00 6a 00 69 00 74 00 40 00 61 00 6d 00 65 00 78 00 77 00 6f 00 72 00 6c 00 64 00 77 00 69 00 64 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account629 = {((73 75 6d 61 79 79 61 68 2e 64 69 69 6a 6c 61 66 6f 6f 64 40 67 6d 61 69 6c 2e 63 6f 6d) | (73 00 75 00 6d 00 61 00 79 00 79 00 61 00 68 00 2e 00 64 00 69 00 69 00 6a 00 6c 00 61 00 66 00 6f 00 6f 00 64 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account630 = {((73 75 6e 69 6c 2e 6a 61 64 68 61 76 40 62 69 69 6c 74 2e 6d 65) | (73 00 75 00 6e 00 69 00 6c 00 2e 00 6a 00 61 00 64 00 68 00 61 00 76 00 40 00 62 00 69 00 69 00 6c 00 74 00 2e 00 6d 00 65 00))}
		$account631 = {((73 75 70 69 6e 40 64 61 69 70 68 61 74 66 6f 6f 64 2e 63 6f 6d 2e 76 6e) | (73 00 75 00 70 00 69 00 6e 00 40 00 64 00 61 00 69 00 70 00 68 00 61 00 74 00 66 00 6f 00 6f 00 64 00 2e 00 63 00 6f 00 6d 00 2e 00 76 00 6e 00))}
		$account632 = {((73 75 70 70 6c 69 65 72 40 61 6d 65 72 69 63 61 6e 74 72 65 76 61 6c 65 72 69 6e 63 2e 63 6f 6d) | (73 00 75 00 70 00 70 00 6c 00 69 00 65 00 72 00 40 00 61 00 6d 00 65 00 72 00 69 00 63 00 61 00 6e 00 74 00 72 00 65 00 76 00 61 00 6c 00 65 00 72 00 69 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account633 = {((73 75 70 70 6f 72 74 40 67 65 6e 65 72 63 65 2e 63 6f 6d) | (73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 67 00 65 00 6e 00 65 00 72 00 63 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account634 = {((74 61 6b 65 72 73 40 62 6c 61 63 6b 73 65 61 2e 72 65 64) | (74 00 61 00 6b 00 65 00 72 00 73 00 40 00 62 00 6c 00 61 00 63 00 6b 00 73 00 65 00 61 00 2e 00 72 00 65 00 64 00))}
		$account635 = {((74 65 61 6d 40 70 6f 73 6b 63 6f 71 2e 77 65 62 73 69 74 65) | (74 00 65 00 61 00 6d 00 40 00 70 00 6f 00 73 00 6b 00 63 00 6f 00 71 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account636 = {((74 65 63 68 6e 69 63 61 6c 40 6c 69 6f 6e 73 61 72 2e 6c 76) | (74 00 65 00 63 00 68 00 6e 00 69 00 63 00 61 00 6c 00 40 00 6c 00 69 00 6f 00 6e 00 73 00 61 00 72 00 2e 00 6c 00 76 00))}
		$account637 = {((74 65 67 61 77 6f 72 6b 73 40 6d 61 73 74 65 72 69 6e 64 6f 2e 6e 65 74) | (74 00 65 00 67 00 61 00 77 00 6f 00 72 00 6b 00 73 00 40 00 6d 00 61 00 73 00 74 00 65 00 72 00 69 00 6e 00 64 00 6f 00 2e 00 6e 00 65 00 74 00))}
		$account638 = {((74 65 6c 6c 65 79 5f 6d 69 6e 40 76 65 63 74 72 6f 6d 74 65 63 68 2e 63 6f 6d) | (74 00 65 00 6c 00 6c 00 65 00 79 00 5f 00 6d 00 69 00 6e 00 40 00 76 00 65 00 63 00 74 00 72 00 6f 00 6d 00 74 00 65 00 63 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account639 = {((74 65 72 72 79 2e 6d 69 6c 6c 65 72 40 72 6d 2d 65 6c 61 63 74 72 69 63 61 6c 2e 63 6f 6d) | (74 00 65 00 72 00 72 00 79 00 2e 00 6d 00 69 00 6c 00 6c 00 65 00 72 00 40 00 72 00 6d 00 2d 00 65 00 6c 00 61 00 63 00 74 00 72 00 69 00 63 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account640 = {((74 65 73 74 40 68 72 61 73 70 69 72 61 74 69 6f 6e 73 2e 63 6f 6d) | (74 00 65 00 73 00 74 00 40 00 68 00 72 00 61 00 73 00 70 00 69 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account641 = {((74 65 73 74 69 6e 67 40 62 68 61 76 6e 61 74 75 74 6f 72 2e 63 6f 6d) | (74 00 65 00 73 00 74 00 69 00 6e 00 67 00 40 00 62 00 68 00 61 00 76 00 6e 00 61 00 74 00 75 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account642 = {((74 65 73 74 40 70 75 73 68 70 61 67 65 73 65 6f 2e 63 6f 6d) | (74 00 65 00 73 00 74 00 40 00 70 00 75 00 73 00 68 00 70 00 61 00 67 00 65 00 73 00 65 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account643 = {((74 68 62 40 74 62 68 2d 74 77 2e 63 6f 6d) | (74 00 68 00 62 00 40 00 74 00 62 00 68 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account644 = {((74 68 65 64 72 6f 70 62 6f 78 78 38 38 40 79 61 6e 64 65 78 2e 63 6f 6d) | (74 00 68 00 65 00 64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 78 00 38 00 38 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account645 = {((74 69 6d 33 2e 34 34 40 79 61 6e 64 65 78 2e 63 6f 6d) | (74 00 69 00 6d 00 33 00 2e 00 34 00 34 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account646 = {((74 69 6e 61 2e 6d 65 6e 67 40 77 69 6e 67 73 75 6e 2d 63 68 69 6e 65 2e 63 6f 6d) | (74 00 69 00 6e 00 61 00 2e 00 6d 00 65 00 6e 00 67 00 40 00 77 00 69 00 6e 00 67 00 73 00 75 00 6e 00 2d 00 63 00 68 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account647 = {((74 6f 75 30 31 33 40 65 66 78 2e 6e 65 74 2e 6e 7a) | (74 00 6f 00 75 00 30 00 31 00 33 00 40 00 65 00 66 00 78 00 2e 00 6e 00 65 00 74 00 2e 00 6e 00 7a 00))}
		$account648 = {((74 72 69 72 65 6b 40 74 72 69 72 65 6b 61 70 65 72 6b 61 73 61 2e 63 6f 6d) | (74 00 72 00 69 00 72 00 65 00 6b 00 40 00 74 00 72 00 69 00 72 00 65 00 6b 00 61 00 70 00 65 00 72 00 6b 00 61 00 73 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account649 = {((74 73 2d 77 69 72 65 40 62 69 67 6d 61 6e 73 74 61 6e 2e 63 6f 6d) | (74 00 73 00 2d 00 77 00 69 00 72 00 65 00 40 00 62 00 69 00 67 00 6d 00 61 00 6e 00 73 00 74 00 61 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account650 = {((74 74 6b 67 61 6c 65 6e 40 74 74 6b 70 6c 63 2e 63 6f 6d) | (74 00 74 00 6b 00 67 00 61 00 6c 00 65 00 6e 00 40 00 74 00 74 00 6b 00 70 00 6c 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account651 = {((74 74 2e 73 77 69 66 74 40 79 61 6e 64 65 78 2e 63 6f 6d) | (74 00 74 00 2e 00 73 00 77 00 69 00 66 00 74 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account652 = {((74 75 72 6b 65 79 40 67 66 61 71 72 6f 63 68 65 6d 2e 63 6f 6d) | (74 00 75 00 72 00 6b 00 65 00 79 00 40 00 67 00 66 00 61 00 71 00 72 00 6f 00 63 00 68 00 65 00 6d 00 2e 00 63 00 6f 00 6d 00))}
		$account653 = {((75 61 61 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (75 00 61 00 61 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account654 = {((75 64 75 67 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (75 00 64 00 75 00 67 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account655 = {((75 67 6f 62 61 72 62 61 72 40 73 63 75 6b 73 75 6d 69 74 6f 6d 6f 2d 63 68 65 6d 2e 63 6f 2e 75 6b) | (75 00 67 00 6f 00 62 00 61 00 72 00 62 00 61 00 72 00 40 00 73 00 63 00 75 00 6b 00 73 00 75 00 6d 00 69 00 74 00 6f 00 6d 00 6f 00 2d 00 63 00 68 00 65 00 6d 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00))}
		$account656 = {((75 72 63 31 40 65 6d 6d 61 6e 6e 61 72 2e 63 6f 6d) | (75 00 72 00 63 00 31 00 40 00 65 00 6d 00 6d 00 61 00 6e 00 6e 00 61 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account657 = {((75 72 63 40 65 6d 6d 61 6e 6e 61 72 2e 63 6f 6d) | (75 00 72 00 63 00 40 00 65 00 6d 00 6d 00 61 00 6e 00 6e 00 61 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account658 = {((75 72 63 68 40 64 61 6d 69 65 6e 7a 79 2e 78 79 7a) | (75 00 72 00 63 00 68 00 40 00 64 00 61 00 6d 00 69 00 65 00 6e 00 7a 00 79 00 2e 00 78 00 79 00 7a 00))}
		$account659 = {((75 7a 40 63 61 69 72 6f 77 61 79 73 2e 6d 65) | (75 00 7a 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 6d 00 65 00))}
		$account660 = {((75 7a 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (75 00 7a 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account661 = {((76 61 65 6c 2e 68 61 62 62 61 6c 40 6d 6f 6d 72 6f 6c 2e 63 6f 6d) | (76 00 61 00 65 00 6c 00 2e 00 68 00 61 00 62 00 62 00 61 00 6c 00 40 00 6d 00 6f 00 6d 00 72 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account662 = {((76 61 6c 63 65 65 6a 61 79 40 6d 61 72 65 6a 67 72 6f 75 70 2e 63 6f 6d) | (76 00 61 00 6c 00 63 00 65 00 65 00 6a 00 61 00 79 00 40 00 6d 00 61 00 72 00 65 00 6a 00 67 00 72 00 6f 00 75 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account663 = {((76 61 6c 65 6e 74 69 6e 61 2e 6d 61 72 61 6e 67 6f 6e 40 67 72 75 70 70 6f 64 69 67 69 74 6f 75 63 68 2e 6d 65) | (76 00 61 00 6c 00 65 00 6e 00 74 00 69 00 6e 00 61 00 2e 00 6d 00 61 00 72 00 61 00 6e 00 67 00 6f 00 6e 00 40 00 67 00 72 00 75 00 70 00 70 00 6f 00 64 00 69 00 67 00 69 00 74 00 6f 00 75 00 63 00 68 00 2e 00 6d 00 65 00))}
		$account664 = {((76 61 6c 40 73 69 72 61 66 69 6d 61 72 69 6e 65 2e 63 6f 6d) | (76 00 61 00 6c 00 40 00 73 00 69 00 72 00 61 00 66 00 69 00 6d 00 61 00 72 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account665 = {((76 61 72 61 68 69 40 76 61 72 61 68 69 2e 69 6e) | (76 00 61 00 72 00 61 00 68 00 69 00 40 00 76 00 61 00 72 00 61 00 68 00 69 00 2e 00 69 00 6e 00))}
		$account666 = {((76 2e 63 6c 65 6d 65 6e 73 40 73 6c 65 65 2d 64 65 2e 6d 65) | (76 00 2e 00 63 00 6c 00 65 00 6d 00 65 00 6e 00 73 00 40 00 73 00 6c 00 65 00 65 00 2d 00 64 00 65 00 2e 00 6d 00 65 00))}
		$account667 = {((76 69 63 6b 79 2e 62 72 30 77 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (76 00 69 00 63 00 6b 00 79 00 2e 00 62 00 72 00 30 00 77 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account668 = {((76 69 63 74 6f 72 6d 75 6c 6c 65 72 31 30 40 79 61 6e 64 65 78 2e 63 6f 6d) | (76 00 69 00 63 00 74 00 6f 00 72 00 6d 00 75 00 6c 00 6c 00 65 00 72 00 31 00 30 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account669 = {((76 69 70 61 2e 61 67 72 61 69 6e 64 75 73 74 72 79 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (76 00 69 00 70 00 61 00 2e 00 61 00 67 00 72 00 61 00 69 00 6e 00 64 00 75 00 73 00 74 00 72 00 79 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account670 = {((76 69 70 40 71 61 74 61 72 70 68 61 72 6d 61 73 2e 6f 72 67) | (76 00 69 00 70 00 40 00 71 00 61 00 74 00 61 00 72 00 70 00 68 00 61 00 72 00 6d 00 61 00 73 00 2e 00 6f 00 72 00 67 00))}
		$account671 = {((77 61 6c 65 40 66 6c 6f 6f 64 2d 70 72 6f 74 65 63 74 69 6f 6e 2e 6f 72 67) | (77 00 61 00 6c 00 65 00 40 00 66 00 6c 00 6f 00 6f 00 64 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00))}
		$account672 = {((77 61 6e 74 6f 5f 74 69 6f 6e 6f 40 63 62 6e 2e 6e 65 74 2e 69 64) | (77 00 61 00 6e 00 74 00 6f 00 5f 00 74 00 69 00 6f 00 6e 00 6f 00 40 00 63 00 62 00 6e 00 2e 00 6e 00 65 00 74 00 2e 00 69 00 64 00))}
		$account673 = {((77 61 72 65 68 6f 75 73 65 65 40 63 6c 69 6d 61 73 65 6e 6d 6f 6e 74 65 72 72 65 79 2e 63 6f 6d 2e 6d 78) | (77 00 61 00 72 00 65 00 68 00 6f 00 75 00 73 00 65 00 65 00 40 00 63 00 6c 00 69 00 6d 00 61 00 73 00 65 00 6e 00 6d 00 6f 00 6e 00 74 00 65 00 72 00 72 00 65 00 79 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 78 00))}
		$account674 = {((77 65 62 6d 61 73 74 65 72 40 6d 65 72 63 61 6e 61 6e 61 6f 6b 75 6c 75 2e 63 6f 6d) | (77 00 65 00 62 00 6d 00 61 00 73 00 74 00 65 00 72 00 40 00 6d 00 65 00 72 00 63 00 61 00 6e 00 61 00 6e 00 61 00 6f 00 6b 00 75 00 6c 00 75 00 2e 00 63 00 6f 00 6d 00))}
		$account675 = {((77 65 6c 6c 73 40 65 73 74 69 6d 78 2e 63 6c 75 62) | (77 00 65 00 6c 00 6c 00 73 00 40 00 65 00 73 00 74 00 69 00 6d 00 78 00 2e 00 63 00 6c 00 75 00 62 00))}
		$account676 = {((77 65 74 67 72 6f 75 6e 64 40 70 6f 79 6c 6f 6e 65 2e 63 6f 6d) | (77 00 65 00 74 00 67 00 72 00 6f 00 75 00 6e 00 64 00 40 00 70 00 6f 00 79 00 6c 00 6f 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account677 = {((77 68 62 72 2e 73 76 63 40 6f 70 70 6f 62 69 68 61 72 2e 69 6e) | (77 00 68 00 62 00 72 00 2e 00 73 00 76 00 63 00 40 00 6f 00 70 00 70 00 6f 00 62 00 69 00 68 00 61 00 72 00 2e 00 69 00 6e 00))}
		$account678 = {((77 69 6e 74 6f 6d 40 77 6c 73 2d 63 6f 6d 2e 6d 65) | (77 00 69 00 6e 00 74 00 6f 00 6d 00 40 00 77 00 6c 00 73 00 2d 00 63 00 6f 00 6d 00 2e 00 6d 00 65 00))}
		$account679 = {((77 69 7a 40 6d 65 74 61 6c 66 61 62 6d 65 2e 69 63 75) | (77 00 69 00 7a 00 40 00 6d 00 65 00 74 00 61 00 6c 00 66 00 61 00 62 00 6d 00 65 00 2e 00 69 00 63 00 75 00))}
		$account680 = {((77 6f 72 6b 73 40 61 6d 65 72 69 63 61 6e 74 72 65 76 61 6c 65 72 69 6e 63 2e 63 6f 6d) | (77 00 6f 00 72 00 6b 00 73 00 40 00 61 00 6d 00 65 00 72 00 69 00 63 00 61 00 6e 00 74 00 72 00 65 00 76 00 61 00 6c 00 65 00 72 00 69 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00))}
		$account681 = {((77 70 6f 6c 6c 63 7a 79 6b 40 79 61 6e 64 65 78 2e 63 6f 6d) | (77 00 70 00 6f 00 6c 00 6c 00 63 00 7a 00 79 00 6b 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account682 = {((78 69 61 6f 2e 77 65 69 40 6c 75 63 6b 79 73 68 69 70 70 69 6e 71 2e 63 6f 6d) | (78 00 69 00 61 00 6f 00 2e 00 77 00 65 00 69 00 40 00 6c 00 75 00 63 00 6b 00 79 00 73 00 68 00 69 00 70 00 70 00 69 00 6e 00 71 00 2e 00 63 00 6f 00 6d 00))}
		$account683 = {((78 6d 6f 6e 69 40 74 61 73 68 69 70 74 61 2e 63 6f 6d) | (78 00 6d 00 6f 00 6e 00 69 00 40 00 74 00 61 00 73 00 68 00 69 00 70 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account684 = {((78 6d 6f 6e 69 2d 77 40 74 61 73 68 69 70 74 61 2e 63 6f 6d) | (78 00 6d 00 6f 00 6e 00 69 00 2d 00 77 00 40 00 74 00 61 00 73 00 68 00 69 00 70 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account685 = {((78 6d 77 65 62 40 66 6c 79 78 70 6f 2e 63 6f 6d) | (78 00 6d 00 77 00 65 00 62 00 40 00 66 00 6c 00 79 00 78 00 70 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account686 = {((78 75 6c 79 2e 64 6f 6e 68 61 6e 67 40 62 6e 66 75 72 6e 69 74 75 72 65 2e 6e 65 74) | (78 00 75 00 6c 00 79 00 2e 00 64 00 6f 00 6e 00 68 00 61 00 6e 00 67 00 40 00 62 00 6e 00 66 00 75 00 72 00 6e 00 69 00 74 00 75 00 72 00 65 00 2e 00 6e 00 65 00 74 00))}
		$account687 = {((78 75 40 77 65 69 66 65 6e 67 2d 66 75 6c 74 6f 6e 2e 63 6f 6d) | (78 00 75 00 40 00 77 00 65 00 69 00 66 00 65 00 6e 00 67 00 2d 00 66 00 75 00 6c 00 74 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account688 = {((79 67 40 63 61 69 72 6f 77 61 79 73 2e 69 63 75) | (79 00 67 00 40 00 63 00 61 00 69 00 72 00 6f 00 77 00 61 00 79 00 73 00 2e 00 69 00 63 00 75 00))}
		$account689 = {((79 6f 73 72 61 2e 67 61 6d 61 6c 40 63 73 61 74 6f 6c 69 6e 2e 63 6f 6d) | (79 00 6f 00 73 00 72 00 61 00 2e 00 67 00 61 00 6d 00 61 00 6c 00 40 00 63 00 73 00 61 00 74 00 6f 00 6c 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account690 = {((79 73 61 6c 67 61 64 6f 40 6d 6f 6e 74 61 63 61 72 67 61 73 70 65 72 75 2e 63 6f 6d) | (79 00 73 00 61 00 6c 00 67 00 61 00 64 00 6f 00 40 00 6d 00 6f 00 6e 00 74 00 61 00 63 00 61 00 72 00 67 00 61 00 73 00 70 00 65 00 72 00 75 00 2e 00 63 00 6f 00 6d 00))}
		$account691 = {((79 79 61 71 6f 62 40 74 72 65 76 69 73 71 61 2e 63 6f 6d) | (79 00 79 00 61 00 71 00 6f 00 62 00 40 00 74 00 72 00 65 00 76 00 69 00 73 00 71 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account692 = {((79 79 73 2e 6e 61 6d 40 68 61 6e 77 69 68 61 2e 63 6f 6d) | (79 00 79 00 73 00 2e 00 6e 00 61 00 6d 00 40 00 68 00 61 00 6e 00 77 00 69 00 68 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account693 = {((7a 61 66 61 72 40 67 75 64 64 75 70 61 6b 2e 63 6f 6d) | (7a 00 61 00 66 00 61 00 72 00 40 00 67 00 75 00 64 00 64 00 75 00 70 00 61 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account694 = {((7a 61 69 64 2e 61 6c 79 75 73 75 66 40 67 70 67 6f 6c 62 61 6c 2e 63 6f 6d) | (7a 00 61 00 69 00 64 00 2e 00 61 00 6c 00 79 00 75 00 73 00 75 00 66 00 40 00 67 00 70 00 67 00 6f 00 6c 00 62 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account695 = {((7a 61 69 6e 61 62 40 61 6c 6d 75 73 68 72 65 66 63 6f 6f 70 2e 63 6f 6d) | (7a 00 61 00 69 00 6e 00 61 00 62 00 40 00 61 00 6c 00 6d 00 75 00 73 00 68 00 72 00 65 00 66 00 63 00 6f 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account696 = {((7a 65 63 6f 40 6f 62 61 7a 6f 6c 75 2d 6f 76 69 6d 2e 70 77) | (7a 00 65 00 63 00 6f 00 40 00 6f 00 62 00 61 00 7a 00 6f 00 6c 00 75 00 2d 00 6f 00 76 00 69 00 6d 00 2e 00 70 00 77 00))}
		$account697 = {((7a 65 63 6f 73 70 69 72 69 74 75 61 6c 31 30 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (7a 00 65 00 63 00 6f 00 73 00 70 00 69 00 72 00 69 00 74 00 75 00 61 00 6c 00 31 00 30 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account698 = {((7a 68 75 2e 63 68 69 6e 61 40 79 61 6e 64 65 78 2e 63 6f 6d) | (7a 00 68 00 75 00 2e 00 63 00 68 00 69 00 6e 00 61 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account699 = {((7a 6c 6f 67 73 40 7a 6f 6c 76 74 65 6b 2e 63 6f 6d) | (7a 00 6c 00 6f 00 67 00 73 00 40 00 7a 00 6f 00 6c 00 76 00 74 00 65 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account700 = {((66 69 6c 65 6c 6f 67 67 65 72 40 79 61 6e 64 65 78 2e 63 6f 6d) | (66 00 69 00 6c 00 65 00 6c 00 6f 00 67 00 67 00 65 00 72 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account701 = {((77 65 6e 67 2e 7a 68 65 6e 67 40 79 61 6e 64 65 78 2e 63 6f 6d) | (77 00 65 00 6e 00 67 00 2e 00 7a 00 68 00 65 00 6e 00 67 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account702 = {((68 61 72 73 61 68 61 64 2e 61 6c 6b 61 61 62 69 39 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (68 00 61 00 72 00 73 00 61 00 68 00 61 00 64 00 2e 00 61 00 6c 00 6b 00 61 00 61 00 62 00 69 00 39 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account703 = {((73 61 6c 65 73 40 66 6c 65 78 69 2e 63 6f 2e 69 6e) | (73 00 61 00 6c 00 65 00 73 00 40 00 66 00 6c 00 65 00 78 00 69 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00))}
		$account704 = {((73 74 6f 72 65 67 6c 69 73 40 6c 6f 72 64 73 68 6f 74 65 6c 73 2e 63 6f 6d) | (73 00 74 00 6f 00 72 00 65 00 67 00 6c 00 69 00 73 00 40 00 6c 00 6f 00 72 00 64 00 73 00 68 00 6f 00 74 00 65 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account705 = {((73 6f 6c 6f 40 65 6e 70 61 72 2d 64 65 2e 63 6f 6d) | (73 00 6f 00 6c 00 6f 00 40 00 65 00 6e 00 70 00 61 00 72 00 2d 00 64 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account706 = {((66 69 67 75 72 65 40 61 6c 61 6d 69 74 65 63 2d 6d 61 2e 63 6f 6d) | (66 00 69 00 67 00 75 00 72 00 65 00 40 00 61 00 6c 00 61 00 6d 00 69 00 74 00 65 00 63 00 2d 00 6d 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account707 = {((61 69 73 68 61 68 40 6e 69 6e 61 6d 61 6a 75 2e 63 6f 6d 2e 6d 79) | (61 00 69 00 73 00 68 00 61 00 68 00 40 00 6e 00 69 00 6e 00 61 00 6d 00 61 00 6a 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 79 00))}
		$account708 = {((70 72 69 79 7a 61 68 61 72 61 63 6f 72 40 67 6d 61 69 6c 2e 63 6f 6d) | (70 00 72 00 69 00 79 00 7a 00 61 00 68 00 61 00 72 00 61 00 63 00 6f 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account709 = {((6f 6e 79 65 6b 61 63 68 69 40 61 6c 6e 61 2d 68 64 61 7a 2e 63 6f 6d) | (6f 00 6e 00 79 00 65 00 6b 00 61 00 63 00 68 00 69 00 40 00 61 00 6c 00 6e 00 61 00 2d 00 68 00 64 00 61 00 7a 00 2e 00 63 00 6f 00 6d 00))}
		$account710 = {((6d 6f 72 67 61 6e 40 73 61 6e 72 65 78 2d 73 67 2e 63 6f 6d) | (6d 00 6f 00 72 00 67 00 61 00 6e 00 40 00 73 00 61 00 6e 00 72 00 65 00 78 00 2d 00 73 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account711 = {((75 64 6f 62 69 40 73 61 6e 72 65 78 2d 73 67 2e 63 6f 6d) | (75 00 64 00 6f 00 62 00 69 00 40 00 73 00 61 00 6e 00 72 00 65 00 78 00 2d 00 73 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account712 = {((73 63 68 77 40 74 6f 74 61 6c 6c 79 61 6e 6f 6e 79 6d 6f 75 73 2e 63 6f 6d) | (73 00 63 00 68 00 77 00 40 00 74 00 6f 00 74 00 61 00 6c 00 6c 00 79 00 61 00 6e 00 6f 00 6e 00 79 00 6d 00 6f 00 75 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account713 = {((6f 6c 75 40 6f 6e 77 61 6d 61 72 63 68 2e 78 79 7a) | (6f 00 6c 00 75 00 40 00 6f 00 6e 00 77 00 61 00 6d 00 61 00 72 00 63 00 68 00 2e 00 78 00 79 00 7a 00))}
		$account714 = {((70 32 40 79 6f 6d 6e 69 6e 67 2d 66 6f 6f 64 2e 63 6f 6d) | (70 00 32 00 40 00 79 00 6f 00 6d 00 6e 00 69 00 6e 00 67 00 2d 00 66 00 6f 00 6f 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account715 = {((6e 61 69 72 6f 6a 6f 62 40 6a 62 72 6f 73 66 6f 72 64 2e 63 6f 6d) | (6e 00 61 00 69 00 72 00 6f 00 6a 00 6f 00 62 00 40 00 6a 00 62 00 72 00 6f 00 73 00 66 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00))}
		$account716 = {((79 61 73 6b 69 40 6f 6e 77 61 6d 61 72 63 68 2e 78 79 7a) | (79 00 61 00 73 00 6b 00 69 00 40 00 6f 00 6e 00 77 00 61 00 6d 00 61 00 72 00 63 00 68 00 2e 00 78 00 79 00 7a 00))}
		$account717 = {((6b 6f 6d 61 6e 67 2e 61 6e 40 6b 74 6d 69 6e 64 6f 6e 65 73 69 61 2e 63 6f 6d) | (6b 00 6f 00 6d 00 61 00 6e 00 67 00 2e 00 61 00 6e 00 40 00 6b 00 74 00 6d 00 69 00 6e 00 64 00 6f 00 6e 00 65 00 73 00 69 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account718 = {((74 61 72 73 75 61 76 6d 40 64 65 72 79 61 65 6c 65 6b 74 72 6f 6e 69 6b 2e 63 6f 6d) | (74 00 61 00 72 00 73 00 75 00 61 00 76 00 6d 00 40 00 64 00 65 00 72 00 79 00 61 00 65 00 6c 00 65 00 6b 00 74 00 72 00 6f 00 6e 00 69 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account719 = {((73 75 73 61 6e 6e 61 2d 6c 61 78 40 70 65 67 61 73 75 73 77 77 75 73 61 2e 63 6f 6d) | (73 00 75 00 73 00 61 00 6e 00 6e 00 61 00 2d 00 6c 00 61 00 78 00 40 00 70 00 65 00 67 00 61 00 73 00 75 00 73 00 77 00 77 00 75 00 73 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account720 = {((6e 6f 6f 72 40 63 6f 62 72 61 75 65 61 2e 63 6f 6d) | (6e 00 6f 00 6f 00 72 00 40 00 63 00 6f 00 62 00 72 00 61 00 75 00 65 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account721 = {((74 72 61 64 65 32 40 66 6f 72 65 73 74 63 6f 2d 74 77 2e 63 6f 6d) | (74 00 72 00 61 00 64 00 65 00 32 00 40 00 66 00 6f 00 72 00 65 00 73 00 74 00 63 00 6f 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account722 = {((67 75 79 64 75 62 65 6d 73 6c 6f 67 73 40 74 70 63 7a 6a 2e 62 69 7a) | (67 00 75 00 79 00 64 00 75 00 62 00 65 00 6d 00 73 00 6c 00 6f 00 67 00 73 00 40 00 74 00 70 00 63 00 7a 00 6a 00 2e 00 62 00 69 00 7a 00))}
		$account723 = {((6f 62 69 40 67 70 62 6f 63 73 68 2e 63 6f 6d) | (6f 00 62 00 69 00 40 00 67 00 70 00 62 00 6f 00 63 00 73 00 68 00 2e 00 63 00 6f 00 6d 00))}
		$account724 = {((6d 61 6b 65 73 61 6c 65 6c 6f 67 33 40 6d 61 72 6b 65 74 32 73 61 6c 65 73 2e 63 6f 6d) | (6d 00 61 00 6b 00 65 00 73 00 61 00 6c 00 65 00 6c 00 6f 00 67 00 33 00 40 00 6d 00 61 00 72 00 6b 00 65 00 74 00 32 00 73 00 61 00 6c 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account725 = {((70 61 6b 69 40 74 70 63 7a 6a 2e 62 69 7a) | (70 00 61 00 6b 00 69 00 40 00 74 00 70 00 63 00 7a 00 6a 00 2e 00 62 00 69 00 7a 00))}
		$account726 = {((6c 61 77 40 67 61 6c 61 78 79 72 61 63 6b 73 2e 63 6f 6d) | (6c 00 61 00 77 00 40 00 67 00 61 00 6c 00 61 00 78 00 79 00 72 00 61 00 63 00 6b 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account727 = {((63 6f 6d 65 72 63 69 61 6c 40 72 61 70 6f 73 6f 6c 64 61 2e 70 74) | (63 00 6f 00 6d 00 65 00 72 00 63 00 69 00 61 00 6c 00 40 00 72 00 61 00 70 00 6f 00 73 00 6f 00 6c 00 64 00 61 00 2e 00 70 00 74 00))}
		$account728 = {((64 6f 67 67 79 40 6d 6f 72 65 2d 6d 6f 6e 65 79 2e 73 69 74 65) | (64 00 6f 00 67 00 67 00 79 00 40 00 6d 00 6f 00 72 00 65 00 2d 00 6d 00 6f 00 6e 00 65 00 79 00 2e 00 73 00 69 00 74 00 65 00))}
		$account729 = {((77 68 69 74 65 6d 61 6e 70 6f 6f 6c 40 79 61 6e 64 65 78 2e 63 6f 6d) | (77 00 68 00 69 00 74 00 65 00 6d 00 61 00 6e 00 70 00 6f 00 6f 00 6c 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account730 = {((6c 75 63 6b 79 40 73 6f 6e 6f 66 67 72 61 63 65 6f 66 66 69 63 65 2e 77 65 62 73 69 74 65) | (6c 00 75 00 63 00 6b 00 79 00 40 00 73 00 6f 00 6e 00 6f 00 66 00 67 00 72 00 61 00 63 00 65 00 6f 00 66 00 66 00 69 00 63 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00))}
		$account731 = {((61 73 68 77 61 6e 69 73 68 61 72 6d 61 40 69 6e 64 69 63 61 69 6e 64 75 73 74 72 69 65 73 2e 63 6f 6d) | (61 00 73 00 68 00 77 00 61 00 6e 00 69 00 73 00 68 00 61 00 72 00 6d 00 61 00 40 00 69 00 6e 00 64 00 69 00 63 00 61 00 69 00 6e 00 64 00 75 00 73 00 74 00 72 00 69 00 65 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account732 = {((72 75 73 73 69 61 40 6b 70 74 69 2d 74 77 2e 63 6f 6d) | (72 00 75 00 73 00 73 00 69 00 61 00 40 00 6b 00 70 00 74 00 69 00 2d 00 74 00 77 00 2e 00 63 00 6f 00 6d 00))}
		$account733 = {((75 64 40 77 69 72 65 6c 6f 72 64 31 39 39 30 2e 70 77) | (75 00 64 00 40 00 77 00 69 00 72 00 65 00 6c 00 6f 00 72 00 64 00 31 00 39 00 39 00 30 00 2e 00 70 00 77 00))}
		$account734 = {((6f 6d 6f 62 61 40 63 6f 6e 69 6b 65 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (6f 00 6d 00 6f 00 62 00 61 00 40 00 63 00 6f 00 6e 00 69 00 6b 00 65 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account735 = {((70 72 69 6e 63 65 40 63 6f 6e 69 6b 65 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (70 00 72 00 69 00 6e 00 63 00 65 00 40 00 63 00 6f 00 6e 00 69 00 6b 00 65 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account736 = {((78 6d 6f 6e 69 40 6e 78 67 65 6e 62 69 7a 2e 75 73) | (78 00 6d 00 6f 00 6e 00 69 00 40 00 6e 00 78 00 67 00 65 00 6e 00 62 00 69 00 7a 00 2e 00 75 00 73 00))}
		$account737 = {((66 61 72 6d 65 72 62 72 6f 40 70 61 63 68 65 74 65 6c 2e 63 6f 6d) | (66 00 61 00 72 00 6d 00 65 00 72 00 62 00 72 00 6f 00 40 00 70 00 61 00 63 00 68 00 65 00 74 00 65 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account738 = {((69 6b 65 6e 6e 61 31 40 74 65 69 6a 69 6d 2d 66 72 6f 6e 74 69 65 72 2e 63 6f 6d) | (69 00 6b 00 65 00 6e 00 6e 00 61 00 31 00 40 00 74 00 65 00 69 00 6a 00 69 00 6d 00 2d 00 66 00 72 00 6f 00 6e 00 74 00 69 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account739 = {((6d 61 78 77 65 6c 6c 40 74 69 67 61 73 69 6e 61 72 6d 61 6e 64 69 72 69 2e 63 6f 2e 69 64) | (6d 00 61 00 78 00 77 00 65 00 6c 00 6c 00 40 00 74 00 69 00 67 00 61 00 73 00 69 00 6e 00 61 00 72 00 6d 00 61 00 6e 00 64 00 69 00 72 00 69 00 2e 00 63 00 6f 00 2e 00 69 00 64 00))}
		$account740 = {((6d 61 6a 6f 72 40 63 6e 76 65 73 74 65 72 2e 63 6f 6d) | (6d 00 61 00 6a 00 6f 00 72 00 40 00 63 00 6e 00 76 00 65 00 73 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account741 = {((73 61 6c 65 73 2e 64 65 6c 40 6d 61 63 77 69 6e 6c 6f 67 69 73 74 69 63 73 2e 69 6e) | (73 00 61 00 6c 00 65 00 73 00 2e 00 64 00 65 00 6c 00 40 00 6d 00 61 00 63 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 69 00 73 00 74 00 69 00 63 00 73 00 2e 00 69 00 6e 00))}
		$account742 = {((72 65 6a 75 76 6f 66 66 69 63 65 40 72 65 6a 75 76 69 6c 61 62 2e 63 6f 6d) | (72 00 65 00 6a 00 75 00 76 00 6f 00 66 00 66 00 69 00 63 00 65 00 40 00 72 00 65 00 6a 00 75 00 76 00 69 00 6c 00 61 00 62 00 2e 00 63 00 6f 00 6d 00))}
		$account743 = {((63 73 40 68 7a 71 69 79 6f 61 2e 63 6f 6d) | (63 00 73 00 40 00 68 00 7a 00 71 00 69 00 79 00 6f 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account744 = {((69 6e 66 6f 2e 63 65 6e 74 65 72 32 34 37 40 6c 69 62 65 72 74 79 6e 61 74 69 6f 6e 61 6c 6c 62 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 2e 00 63 00 65 00 6e 00 74 00 65 00 72 00 32 00 34 00 37 00 40 00 6c 00 69 00 62 00 65 00 72 00 74 00 79 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 6c 00 62 00 2e 00 63 00 6f 00 6d 00))}
		$account745 = {((6c 75 67 61 40 63 6d 69 73 2d 73 61 2e 63 6f 6d) | (6c 00 75 00 67 00 61 00 40 00 63 00 6d 00 69 00 73 00 2d 00 73 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account746 = {((6c 6f 67 73 40 74 73 68 75 6b 77 61 73 6f 6c 61 72 2e 63 6f 6d) | (6c 00 6f 00 67 00 73 00 40 00 74 00 73 00 68 00 75 00 6b 00 77 00 61 00 73 00 6f 00 6c 00 61 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account747 = {((62 62 6c 40 67 61 6c 61 78 79 72 61 63 6b 73 2e 63 6f 6d) | (62 00 62 00 6c 00 40 00 67 00 61 00 6c 00 61 00 78 00 79 00 72 00 61 00 63 00 6b 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account748 = {((6f 6b 40 61 63 68 69 65 76 65 6d 6f 72 6d 6f 6e 65 79 2e 63 6f 6d) | (6f 00 6b 00 40 00 61 00 63 00 68 00 69 00 65 00 76 00 65 00 6d 00 6f 00 72 00 6d 00 6f 00 6e 00 65 00 79 00 2e 00 63 00 6f 00 6d 00))}
		$account749 = {((73 75 70 70 6f 72 74 2d 45 55 40 64 61 74 61 63 69 74 79 2e 72 6f) | (73 00 75 00 70 00 70 00 6f 00 72 00 74 00 2d 00 45 00 55 00 40 00 64 00 61 00 74 00 61 00 63 00 69 00 74 00 79 00 2e 00 72 00 6f 00))}
		$account750 = {((6c 61 72 67 65 72 72 65 70 6f 72 74 40 73 74 61 72 6c 69 6e 6b 7a 2e 6f 72 67 2e 6e 67) | (6c 00 61 00 72 00 67 00 65 00 72 00 72 00 65 00 70 00 6f 00 72 00 74 00 40 00 73 00 74 00 61 00 72 00 6c 00 69 00 6e 00 6b 00 7a 00 2e 00 6f 00 72 00 67 00 2e 00 6e 00 67 00))}
		$account751 = {((67 65 6f 72 67 65 72 65 70 6f 72 74 40 73 74 61 72 6c 69 6e 6b 7a 2e 6f 72 67 2e 6e 67) | (67 00 65 00 6f 00 72 00 67 00 65 00 72 00 65 00 70 00 6f 00 72 00 74 00 40 00 73 00 74 00 61 00 72 00 6c 00 69 00 6e 00 6b 00 7a 00 2e 00 6f 00 72 00 67 00 2e 00 6e 00 67 00))}
		$account752 = {((6a 61 63 6b 40 73 74 61 67 61 6c 65 61 74 68 65 72 2e 63 6f 6d) | (6a 00 61 00 63 00 6b 00 40 00 73 00 74 00 61 00 67 00 61 00 6c 00 65 00 61 00 74 00 68 00 65 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account753 = {((70 69 6e 61 6b 69 40 67 6f 6f 64 65 61 72 74 68 69 6d 70 65 78 2e 63 6f 6d) | (70 00 69 00 6e 00 61 00 6b 00 69 00 40 00 67 00 6f 00 6f 00 64 00 65 00 61 00 72 00 74 00 68 00 69 00 6d 00 70 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account754 = {((73 63 61 6c 61 40 76 69 63 74 6f 72 61 6c 69 66 74 73 2e 63 6f 6d) | (73 00 63 00 61 00 6c 00 61 00 40 00 76 00 69 00 63 00 74 00 6f 00 72 00 61 00 6c 00 69 00 66 00 74 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account755 = {((63 6f 6e 74 61 74 6f 65 78 70 6f 72 74 61 63 61 6f 40 67 65 72 6d 69 70 61 73 74 6f 2d 62 72 2e 63 6f 6d) | (63 00 6f 00 6e 00 74 00 61 00 74 00 6f 00 65 00 78 00 70 00 6f 00 72 00 74 00 61 00 63 00 61 00 6f 00 40 00 67 00 65 00 72 00 6d 00 69 00 70 00 61 00 73 00 74 00 6f 00 2d 00 62 00 72 00 2e 00 63 00 6f 00 6d 00))}
		$account756 = {((61 64 6d 69 6e 40 6a 6f 6d 61 63 2d 6b 73 61 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 6a 00 6f 00 6d 00 61 00 63 00 2d 00 6b 00 73 00 61 00 2e 00 63 00 6f 00 6d 00))}
		$account757 = {((6f 6b 6f 6b 40 77 68 69 74 65 6d 6f 6e 65 79 31 2e 63 6f 6d) | (6f 00 6b 00 6f 00 6b 00 40 00 77 00 68 00 69 00 74 00 65 00 6d 00 6f 00 6e 00 65 00 79 00 31 00 2e 00 63 00 6f 00 6d 00))}
		$account758 = {((78 6d 63 68 69 6e 61 6d 61 64 65 40 74 65 73 74 70 72 6f 65 67 2e 63 6f 6d) | (78 00 6d 00 63 00 68 00 69 00 6e 00 61 00 6d 00 61 00 64 00 65 00 40 00 74 00 65 00 73 00 74 00 70 00 72 00 6f 00 65 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account759 = {((68 6b 40 66 6c 6f 72 69 64 65 69 65 2e 72 6f) | (68 00 6b 00 40 00 66 00 6c 00 6f 00 72 00 69 00 64 00 65 00 69 00 65 00 2e 00 72 00 6f 00))}
		$account760 = {((63 61 72 6f 6c 2e 66 69 6e 61 6e 63 65 40 63 6f 61 73 74 61 6c 70 65 74 72 6f 6c 2e 63 6f 6d) | (63 00 61 00 72 00 6f 00 6c 00 2e 00 66 00 69 00 6e 00 61 00 6e 00 63 00 65 00 40 00 63 00 6f 00 61 00 73 00 74 00 61 00 6c 00 70 00 65 00 74 00 72 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account761 = {((6d 65 40 63 6f 6e 69 6b 65 74 72 61 6e 73 70 6f 72 74 2e 63 6f 6d) | (6d 00 65 00 40 00 63 00 6f 00 6e 00 69 00 6b 00 65 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$account762 = {((64 69 67 69 64 6f 63 74 6f 72 61 75 40 67 6d 61 69 6c 2e 63 6f 6d) | (64 00 69 00 67 00 69 00 64 00 6f 00 63 00 74 00 6f 00 72 00 61 00 75 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account763 = {((68 72 73 69 6d 6f 6e 35 39 40 67 6d 61 69 6c 2e 63 6f 6d) | (68 00 72 00 73 00 69 00 6d 00 6f 00 6e 00 35 00 39 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account764 = {((6d 65 6e 65 40 74 65 73 74 70 72 6f 65 67 2e 63 6f 6d) | (6d 00 65 00 6e 00 65 00 40 00 74 00 65 00 73 00 74 00 70 00 72 00 6f 00 65 00 67 00 2e 00 63 00 6f 00 6d 00))}
		$account765 = {((77 69 6e 6e 40 61 63 63 61 75 74 6f 2e 63 6f) | (77 00 69 00 6e 00 6e 00 40 00 61 00 63 00 63 00 61 00 75 00 74 00 6f 00 2e 00 63 00 6f 00))}
		$account766 = {((6a 6f 73 68 40 61 63 63 61 75 74 6f 2e 63 6f) | (6a 00 6f 00 73 00 68 00 40 00 61 00 63 00 63 00 61 00 75 00 74 00 6f 00 2e 00 63 00 6f 00))}
		$account767 = {((64 69 76 69 40 61 63 63 61 75 74 6f 2e 63 6f) | (64 00 69 00 76 00 69 00 40 00 61 00 63 00 63 00 61 00 75 00 74 00 6f 00 2e 00 63 00 6f 00))}
		$account768 = {((61 63 68 40 61 63 63 61 75 74 6f 2e 63 6f) | (61 00 63 00 68 00 40 00 61 00 63 00 63 00 61 00 75 00 74 00 6f 00 2e 00 63 00 6f 00))}
		$account769 = {((6d 61 69 6c 64 75 70 6c 69 63 61 74 65 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6d 00 61 00 69 00 6c 00 64 00 75 00 70 00 6c 00 69 00 63 00 61 00 74 00 65 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account770 = {((79 75 6d 69 40 6a 6c 6a 6a 6d 65 74 61 6c 73 2e 63 6f 6d) | (79 00 75 00 6d 00 69 00 40 00 6a 00 6c 00 6a 00 6a 00 6d 00 65 00 74 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account771 = {((61 64 6d 69 6e 40 61 64 69 70 69 63 6f 2e 63 6f 6d) | (61 00 64 00 6d 00 69 00 6e 00 40 00 61 00 64 00 69 00 70 00 69 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account772 = {((6a 61 73 6f 6e 2e 73 61 6d 74 61 6e 69 40 72 78 63 6c 65 63 6f 2e 63 6f 6d) | (6a 00 61 00 73 00 6f 00 6e 00 2e 00 73 00 61 00 6d 00 74 00 61 00 6e 00 69 00 40 00 72 00 78 00 63 00 6c 00 65 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00))}
		$account773 = {((6d 69 62 72 61 68 69 6d 40 68 66 66 69 69 6c 74 72 61 74 69 6f 6e 2e 63 6f 6d) | (6d 00 69 00 62 00 72 00 61 00 68 00 69 00 6d 00 40 00 68 00 66 00 66 00 69 00 69 00 6c 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account774 = {((6d 72 73 74 40 6d 72 73 74 2d 6b 72 2e 69 63 75) | (6d 00 72 00 73 00 74 00 40 00 6d 00 72 00 73 00 74 00 2d 00 6b 00 72 00 2e 00 69 00 63 00 75 00))}
		$account775 = {((6e 6f 6f 72 2e 61 6b 62 61 72 69 40 70 65 74 72 6f 6c 6e 61 73 2e 69 63 75) | (6e 00 6f 00 6f 00 72 00 2e 00 61 00 6b 00 62 00 61 00 72 00 69 00 40 00 70 00 65 00 74 00 72 00 6f 00 6c 00 6e 00 61 00 73 00 2e 00 69 00 63 00 75 00))}
		$account776 = {((63 6f 6e 74 61 62 69 6c 69 64 61 64 40 69 64 6f 6c 7a 2e 70 77) | (63 00 6f 00 6e 00 74 00 61 00 62 00 69 00 6c 00 69 00 64 00 61 00 64 00 40 00 69 00 64 00 6f 00 6c 00 7a 00 2e 00 70 00 77 00))}
		$account777 = {((61 73 68 66 61 71 2e 61 6c 69 40 6e 61 74 69 6f 6e 61 6c 66 75 65 6c 73 2e 70 77) | (61 00 73 00 68 00 66 00 61 00 71 00 2e 00 61 00 6c 00 69 00 40 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 66 00 75 00 65 00 6c 00 73 00 2e 00 70 00 77 00))}
		$account778 = {((62 69 6c 6c 62 61 74 65 6d 61 6e 30 34 32 40 67 6d 61 69 6c 2e 63 6f 6d) | (62 00 69 00 6c 00 6c 00 62 00 61 00 74 00 65 00 6d 00 61 00 6e 00 30 00 34 00 32 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account779 = {((6c 6f 6e 67 6d 6f 6e 65 79 40 61 6b 2d 74 6f 70 72 65 6b 2e 63 6f 6d) | (6c 00 6f 00 6e 00 67 00 6d 00 6f 00 6e 00 65 00 79 00 40 00 61 00 6b 00 2d 00 74 00 6f 00 70 00 72 00 65 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account780 = {((6e 65 6a 6c 61 40 70 61 6d 69 6e 61 6b 69 64 73 2e 63 6f 6d) | (6e 00 65 00 6a 00 6c 00 61 00 40 00 70 00 61 00 6d 00 69 00 6e 00 61 00 6b 00 69 00 64 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account781 = {((77 69 6c 6c 79 63 6f 6b 65 72 30 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (77 00 69 00 6c 00 6c 00 79 00 63 00 6f 00 6b 00 65 00 72 00 30 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account782 = {((64 69 73 70 61 74 63 68 6f 66 66 69 63 65 40 75 70 73 64 65 6c 69 76 65 72 79 2e 63 66) | (64 00 69 00 73 00 70 00 61 00 74 00 63 00 68 00 6f 00 66 00 66 00 69 00 63 00 65 00 40 00 75 00 70 00 73 00 64 00 65 00 6c 00 69 00 76 00 65 00 72 00 79 00 2e 00 63 00 66 00))}
		$account783 = {((65 2d 73 61 69 6c 40 62 6f 6a 74 61 69 2e 78 79 7a) | (65 00 2d 00 73 00 61 00 69 00 6c 00 40 00 62 00 6f 00 6a 00 74 00 61 00 69 00 2e 00 78 00 79 00 7a 00))}
		$account784 = {((75 6d 61 69 72 61 40 64 75 74 61 72 69 6e 69 2e 63 6f 6d) | (75 00 6d 00 61 00 69 00 72 00 61 00 40 00 64 00 75 00 74 00 61 00 72 00 69 00 6e 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account785 = {((73 68 61 6e 40 66 61 72 6d 2d 66 69 6e 6e 2e 63 6f 6d) | (73 00 68 00 61 00 6e 00 40 00 66 00 61 00 72 00 6d 00 2d 00 66 00 69 00 6e 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account786 = {((73 61 6c 65 73 65 75 72 6f 70 6f 77 65 72 40 79 61 6e 64 65 78 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 65 00 75 00 72 00 6f 00 70 00 6f 00 77 00 65 00 72 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account787 = {((66 61 69 72 6f 6f 7a 40 72 65 6a 6f 69 63 65 74 72 61 64 65 2e 63 6f 6d) | (66 00 61 00 69 00 72 00 6f 00 6f 00 7a 00 40 00 72 00 65 00 6a 00 6f 00 69 00 63 00 65 00 74 00 72 00 61 00 64 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account788 = {((69 6d 69 73 73 79 6f 75 40 62 74 61 6d 61 69 6c 2e 6e 65 74 2e 63 6e) | (69 00 6d 00 69 00 73 00 73 00 79 00 6f 00 75 00 40 00 62 00 74 00 61 00 6d 00 61 00 69 00 6c 00 2e 00 6e 00 65 00 74 00 2e 00 63 00 6e 00))}
		$account789 = {((65 63 68 65 7a 6f 6e 61 40 62 6f 6e 66 69 67 6c 69 6f 6c 6c 69 2e 63 6f 6d) | (65 00 63 00 68 00 65 00 7a 00 6f 00 6e 00 61 00 40 00 62 00 6f 00 6e 00 66 00 69 00 67 00 6c 00 69 00 6f 00 6c 00 6c 00 69 00 2e 00 63 00 6f 00 6d 00))}
		$account790 = {((67 6d 6f 6f 72 65 40 73 74 75 64 79 67 72 75 6f 70 2e 63 6f 6d) | (67 00 6d 00 6f 00 6f 00 72 00 65 00 40 00 73 00 74 00 75 00 64 00 79 00 67 00 72 00 75 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00))}
		$account791 = {((65 79 75 70 40 70 72 65 73 74 69 67 65 73 67 6f 6c 64 73 2e 63 6f 6d) | (65 00 79 00 75 00 70 00 40 00 70 00 72 00 65 00 73 00 74 00 69 00 67 00 65 00 73 00 67 00 6f 00 6c 00 64 00 73 00 2e 00 63 00 6f 00 6d 00))}
		$account792 = {((6d 65 72 63 68 61 6e 64 69 73 65 40 65 6e 63 68 65 2e 63 6f 6d) | (6d 00 65 00 72 00 63 00 68 00 61 00 6e 00 64 00 69 00 73 00 65 00 40 00 65 00 6e 00 63 00 68 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account793 = {((73 70 61 6d 2d 68 40 68 67 6e 65 74 2e 6e 65 74 2e 62 72) | (73 00 70 00 61 00 6d 00 2d 00 68 00 40 00 68 00 67 00 6e 00 65 00 74 00 2e 00 6e 00 65 00 74 00 2e 00 62 00 72 00))}
		$account794 = {((77 65 61 6c 74 68 6d 79 73 6f 6e 40 79 61 6e 64 65 78 2e 63 6f 6d) | (77 00 65 00 61 00 6c 00 74 00 68 00 6d 00 79 00 73 00 6f 00 6e 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account795 = {((61 6e 64 72 65 73 2e 67 61 6c 61 72 72 61 67 61 40 73 69 73 6d 6f 64 65 2e 63 6f 6d) | (61 00 6e 00 64 00 72 00 65 00 73 00 2e 00 67 00 61 00 6c 00 61 00 72 00 72 00 61 00 67 00 61 00 40 00 73 00 69 00 73 00 6d 00 6f 00 64 00 65 00 2e 00 63 00 6f 00 6d 00))}
		$account796 = {((73 61 6c 65 73 65 75 72 6f 70 6f 77 65 72 40 79 61 6e 64 65 78 2e 63 6f 6d) | (73 00 61 00 6c 00 65 00 73 00 65 00 75 00 72 00 6f 00 70 00 6f 00 77 00 65 00 72 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account797 = {((69 6e 66 6f 40 73 74 61 72 6b 67 75 6c 66 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 73 00 74 00 61 00 72 00 6b 00 67 00 75 00 6c 00 66 00 2e 00 63 00 6f 00 6d 00))}
		$account798 = {((65 74 6f 70 69 63 61 6c 40 62 6f 6a 74 61 69 2e 63 6c 75 62) | (65 00 74 00 6f 00 70 00 69 00 63 00 61 00 6c 00 40 00 62 00 6f 00 6a 00 74 00 61 00 69 00 2e 00 63 00 6c 00 75 00 62 00))}
		$account799 = {((66 65 72 6e 61 6e 64 6f 40 64 69 67 69 74 61 6c 64 69 72 65 63 74 6f 2e 65 73) | (66 00 65 00 72 00 6e 00 61 00 6e 00 64 00 6f 00 40 00 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 2e 00 65 00 73 00))}
		$account800 = {((62 61 65 72 62 65 6c 73 63 68 65 69 62 6c 6c 31 38 30 39 40 67 6d 61 69 6c 2e 63 6f 6d) | (62 00 61 00 65 00 72 00 62 00 65 00 6c 00 73 00 63 00 68 00 65 00 69 00 62 00 6c 00 6c 00 31 00 38 00 30 00 39 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account801 = {((64 61 73 68 62 6f 61 72 64 40 67 72 61 6e 64 61 6d 69 73 68 61 62 6f 74 2e 72 75) | (64 00 61 00 73 00 68 00 62 00 6f 00 61 00 72 00 64 00 40 00 67 00 72 00 61 00 6e 00 64 00 61 00 6d 00 69 00 73 00 68 00 61 00 62 00 6f 00 74 00 2e 00 72 00 75 00))}
		$account802 = {((6c 6f 67 73 40 67 72 61 6e 64 61 6d 69 73 68 61 62 6f 74 2e 72 75) | (6c 00 6f 00 67 00 73 00 40 00 67 00 72 00 61 00 6e 00 64 00 61 00 6d 00 69 00 73 00 68 00 61 00 62 00 6f 00 74 00 2e 00 72 00 75 00))}
		$account803 = {((73 68 61 6e 40 66 61 72 6d 2d 66 69 6e 6e 2e 63 6f 6d) | (73 00 68 00 61 00 6e 00 40 00 66 00 61 00 72 00 6d 00 2d 00 66 00 69 00 6e 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account804 = {((69 6e 66 6f 40 73 74 61 72 6b 67 75 6c 66 2e 63 6f 6d) | (69 00 6e 00 66 00 6f 00 40 00 73 00 74 00 61 00 72 00 6b 00 67 00 75 00 6c 00 66 00 2e 00 63 00 6f 00 6d 00))}
		$account805 = {((6e 65 74 6c 69 6e 65 40 6e 65 74 6a 75 6c 2e 73 68 6f 70) | (6e 00 65 00 74 00 6c 00 69 00 6e 00 65 00 40 00 6e 00 65 00 74 00 6a 00 75 00 6c 00 2e 00 73 00 68 00 6f 00 70 00))}
		$account806 = {((6b 65 6e 64 61 6b 65 6e 64 61 40 6b 61 72 61 6e 65 78 2e 63 6f 6d) | (6b 00 65 00 6e 00 64 00 61 00 6b 00 65 00 6e 00 64 00 61 00 40 00 6b 00 61 00 72 00 61 00 6e 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account807 = {((66 6f 72 72 65 73 74 40 70 72 69 6e 75 74 72 69 74 69 6f 6e 2e 63 6f 6d) | (66 00 6f 00 72 00 72 00 65 00 73 00 74 00 40 00 70 00 72 00 69 00 6e 00 75 00 74 00 72 00 69 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00))}
		$account808 = {((74 65 63 68 6f 72 69 67 69 6e 34 35 36 30 40 67 6d 61 69 6c 2e 63 6f 6d) | (74 00 65 00 63 00 68 00 6f 00 72 00 69 00 67 00 69 00 6e 00 34 00 35 00 36 00 30 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account889 = {((69 66 65 65 40 72 69 63 68 65 74 63 68 2e 6c 74 64) | (69 00 66 00 65 00 65 00 40 00 72 00 69 00 63 00 68 00 65 00 74 00 63 00 68 00 2e 00 6c 00 74 00 64 00))}
		$account890 = {((64 61 76 69 64 63 68 75 7a 79 40 79 61 6e 64 65 78 2e 63 6f 6d) | (64 00 61 00 76 00 69 00 64 00 63 00 68 00 75 00 7a 00 79 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account891 = {((65 6e 64 72 69 74 2e 6e 65 6f 6e 40 6d 61 69 6c 2e 63 6f 6d) | (65 00 6e 00 64 00 72 00 69 00 74 00 2e 00 6e 00 65 00 6f 00 6e 00 40 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$account892 = {((6d 75 68 61 73 65 62 65 40 79 65 6b 61 6d 75 68 65 6e 64 69 73 6c 69 6b 2e 63 6f 6d) | (6d 00 75 00 68 00 61 00 73 00 65 00 62 00 65 00 40 00 79 00 65 00 6b 00 61 00 6d 00 75 00 68 00 65 00 6e 00 64 00 69 00 73 00 6c 00 69 00 6b 00 2e 00 63 00 6f 00 6d 00))}
		$account893 = {((6b 70 6c 61 73 74 69 6b 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6b 00 70 00 6c 00 61 00 73 00 74 00 69 00 6b 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account894 = {((61 64 6d 69 6e 40 61 6e 69 6e 64 69 74 61 65 6e 67 2e 6e 65 74) | (61 00 64 00 6d 00 69 00 6e 00 40 00 61 00 6e 00 69 00 6e 00 64 00 69 00 74 00 61 00 65 00 6e 00 67 00 2e 00 6e 00 65 00 74 00))}
		$account895 = {((70 6d 6f 6c 65 6d 61 6e 73 40 74 72 61 6e 65 64 69 63 6f 2e 6e 6c) | (70 00 6d 00 6f 00 6c 00 65 00 6d 00 61 00 6e 00 73 00 40 00 74 00 72 00 61 00 6e 00 65 00 64 00 69 00 63 00 6f 00 2e 00 6e 00 6c 00))}
		$account896 = {((6a 61 63 6b 6a 6f 68 6e 73 6f 6e 36 34 31 36 31 40 79 61 6e 64 65 78 2e 63 6f 6d) | (6a 00 61 00 63 00 6b 00 6a 00 6f 00 68 00 6e 00 73 00 6f 00 6e 00 36 00 34 00 31 00 36 00 31 00 40 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 63 00 6f 00 6d 00))}
		$account897 = {((6e 2e 6d 61 63 6b 65 79 40 69 74 65 6c 63 6f 6d 2e 6e 65 74 2e 61 75) | (6e 00 2e 00 6d 00 61 00 63 00 6b 00 65 00 79 00 40 00 69 00 74 00 65 00 6c 00 63 00 6f 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 61 00 75 00))}

	condition:
		any of them
}

rule INDICATOR_KB_GoBuildID_Zebrocy : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 6c 36 52 41 4b 58 68 33 57 67 31 79 7a 6e 36 33 6e 69 74 61 2f 62 32 5f 59 30 44 47 59 30 35 4e 46 57 75 5a 5f 34 67 55 54 2f 48 39 31 73 43 52 6b 74 6e 79 79 59 56 7a 45 43 66 76 76 41 2f 6c 38 66 2d 79 49 49 30 4c 5f 6d 69 53 6a 49 65 2d 56 51 75 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 66 69 47 47 76 4c 56 46 63 76 49 68 75 4a 73 53 61 61 69 6c 2f 6a 4c 74 39 54 45 50 51 69 75 73 67 37 49 70 52 6b 70 34 48 2f 68 6c 63 6f 58 5a 49 66 73 6c 31 44 34 35 32 31 4c 71 45 4c 2f 79 4c 38 64 4e 38 36 6d 43 4e 63 33 39 57 71 51 54 67 47 6e 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_GoStealer : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 78 51 56 2d 62 31 46 72 37 64 35 37 36 54 54 54 70 62 58 69 2f 67 71 34 46 67 56 51 71 4d 63 67 2d 2d 39 74 6d 59 31 33 79 2f 37 36 72 4b 4e 45 55 42 45 4e 6c 44 46 44 63 65 63 6d 6d 5f 2f 6d 62 77 31 37 41 5f 36 57 72 52 4f 61 4e 43 59 44 45 51 46 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 78 34 56 71 72 53 53 73 78 38 69 79 73 78 56 64 66 42 2d 7a 2f 67 49 46 33 70 37 53 55 78 69 5a 73 56 67 54 75 71 37 62 4e 2f 39 33 58 48 75 49 4c 47 6e 47 59 71 32 4c 38 33 66 52 70 6a 2f 65 6f 59 36 6e 54 71 77 6b 31 73 64 4d 48 54 61 58 7a 6c 77 22}
		$s3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 42 50 52 54 68 49 59 57 62 48 63 5a 51 51 34 4b 31 79 32 74 2f 32 6d 4f 30 2d 46 6a 4c 43 35 30 50 30 51 5a 75 4d 54 67 43 2f 39 69 36 54 59 77 5f 61 6b 69 45 46 39 5a 50 4e 30 73 33 70 2f 73 31 58 6f 71 58 72 37 45 79 58 4d 44 56 77 35 54 54 50 33 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_GoldenAxe : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 42 72 4a 75 79 4d 52 64 69 5a 37 70 43 39 43 61 68 30 69 73 2f 72 62 44 42 5f 5f 68 58 57 69 6d 69 76 62 53 47 69 43 4c 69 2f 42 33 35 53 50 4c 51 77 48 61 6c 33 63 63 52 32 67 58 4e 78 2f 68 45 6d 56 7a 68 4a 57 57 61 74 73 72 4b 77 6e 45 4e 68 5f 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 35 62 67 69 65 61 42 65 39 50 63 5a 43 5a 66 32 33 57 46 70 2f 62 43 5a 30 41 55 48 59 6c 71 51 6d 58 38 47 4a 41 53 56 36 2f 66 47 78 52 4c 4d 44 44 59 72 54 6d 31 6a 63 4c 4d 74 38 6a 2f 57 6f 66 33 6e 35 36 33 34 62 77 69 77 4c 48 46 4b 48 54 6e 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_Nemty : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 52 36 64 76 61 55 6b 74 67 76 32 53 6a 56 58 44 6f 4d 64 6f 2f 6b 4b 67 77 61 67 77 6f 4c 52 43 38 38 44 70 49 58 41 6d 78 2f 65 69 70 4e 71 37 5f 50 51 43 54 43 4f 68 5a 36 51 37 34 71 2f 52 48 4a 6b 43 61 4e 64 54 62 64 36 71 67 59 69 41 2d 45 43 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 76 73 64 6e 64 54 77 6c 6a 30 33 67 62 45 6f 44 75 30 36 53 2f 61 6e 4a 6b 58 47 68 37 4e 30 38 35 33 37 4d 30 52 4d 6d 73 2f 56 47 35 38 64 39 39 61 78 63 64 65 44 5f 7a 31 4a 49 6b 6f 2f 74 66 44 56 62 43 64 57 55 49 64 2d 56 58 39 30 6b 75 54 37 22}
		$s3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 46 47 39 4a 45 65 73 58 42 51 30 34 6f 4e 43 76 32 62 49 53 2f 4d 6d 6a 43 64 47 61 33 6f 67 55 5f 36 44 49 7a 36 62 5a 52 2f 41 6a 72 71 4b 42 53 65 7a 44 66 59 31 74 37 55 39 78 72 2d 2f 2d 30 36 64 49 70 5a 73 75 6b 69 56 63 4e 30 50 74 4f 43 62 22}
		$s4 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 4d 4a 38 62 53 31 65 6d 57 72 72 6c 58 69 45 5f 43 36 31 45 2f 41 36 47 61 5a 7a 68 4c 6c 73 5f 70 46 4b 4d 47 66 55 31 48 2f 5a 67 73 77 47 51 79 5f 6c 7a 4b 2d 49 34 63 5a 79 6b 77 6d 2f 38 4a 7a 6a 68 56 30 36 6a 5a 6f 73 53 61 35 51 69 68 35 4f 22}
		$s5 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 5f 76 51 61 6c 56 51 4b 6e 32 4f 38 6b 78 78 41 34 76 56 4d 2f 73 6c 58 6c 6b 6c 68 6e 6a 45 46 35 74 61 77 6a 6c 50 7a 57 2f 74 32 36 72 44 52 55 52 4b 36 69 69 30 4d 71 55 37 67 49 78 2f 4d 4e 71 36 76 6a 5f 75 4d 31 35 52 68 6a 56 43 32 51 75 58 22}
		$s6 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 4b 57 73 73 46 44 54 70 36 6d 71 31 36 78 6c 49 35 63 30 74 2f 6d 51 4c 67 6f 66 30 6f 79 70 2d 65 59 4b 71 4e 59 55 46 4c 2f 4e 70 38 53 37 31 7a 45 35 57 35 5f 42 73 4a 43 70 6a 73 6a 2f 68 58 70 46 44 61 56 43 74 61 79 32 35 30 39 52 30 35 66 64 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_QnapCrypt : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 58 63 42 71 62 51 6f 68 6d 37 55 65 76 64 59 4e 41 42 76 73 2f 32 52 63 4a 7a 31 36 31 36 6e 61 58 53 52 75 32 78 76 54 58 2f 62 36 46 33 4a 74 31 2d 35 57 41 49 65 78 53 79 7a 65 75 6e 2f 4d 70 48 71 73 35 66 4a 41 35 47 32 44 39 67 56 75 55 43 65 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_Snatch : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 38 43 32 56 76 44 54 48 2d 4d 75 55 50 78 38 74 4c 34 32 45 2f 50 57 46 39 69 75 45 32 6a 5f 5a 74 30 41 4e 73 54 6c 74 79 2f 63 36 34 73 77 5a 35 54 74 75 61 49 70 48 75 45 46 6d 67 61 2f 36 73 53 30 4b 57 4e 72 79 63 2d 59 41 64 75 44 6e 57 57 4f 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 55 42 72 66 4a 5f 77 7a 74 44 66 43 48 57 61 6b 71 76 6c 56 2f 4c 68 7a 66 6b 4a 77 76 4b 46 72 4e 68 4b 43 48 74 55 39 5f 2f 73 76 65 43 75 70 74 38 47 56 62 76 75 36 57 5a 69 79 41 2d 2f 47 63 69 6d 66 4c 5f 54 50 6c 36 46 54 50 50 72 69 42 44 72 22}
		$s3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 35 7a 43 79 39 6a 74 37 55 5a 61 49 73 35 59 50 6b 34 74 74 2f 31 59 74 36 76 37 67 43 70 44 47 2d 2d 2d 70 52 46 79 57 2d 2f 37 37 32 39 6e 4c 53 65 4b 4a 69 6b 33 31 66 74 7a 5f 56 65 2f 5a 35 45 56 47 33 6c 57 61 6b 33 79 6e 78 4e 72 4a 34 69 68 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_GoDownloader : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 31 4f 7a 4a 71 57 61 48 34 68 31 56 74 72 4c 50 2d 7a 6b 38 2f 47 39 77 33 32 68 61 37 5f 7a 69 57 31 46 61 2d 30 42 79 6a 2f 67 4c 74 66 68 62 58 5a 36 69 5f 57 30 65 35 65 5f 74 46 46 2f 65 6b 47 30 6e 39 68 4f 63 5a 6a 6d 77 7a 52 51 6e 52 71 43 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 6b 4b 78 79 6a 31 34 6c 34 4e 68 47 62 75 68 4f 67 7a 65 66 2f 61 62 5f 79 72 5f 70 55 6e 36 71 32 69 64 59 64 6f 42 68 6e 2f 68 46 41 6a 4f 5f 59 78 63 5f 72 4e 36 6d 48 46 75 48 4d 39 2f 53 6d 53 33 71 6d 4f 79 4a 42 63 5f 34 78 56 5f 71 67 33 42 22}
		$s3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 4d 69 57 37 58 4a 6e 51 73 42 58 78 6c 42 48 72 6f 38 47 57 2f 48 4d 71 51 6b 6e 52 67 4a 67 2d 6d 43 58 6f 6d 67 46 52 74 2f 38 38 63 63 4b 4d 72 66 41 5f 73 36 41 63 4f 4a 73 33 61 4d 2f 6a 53 55 41 55 5f 6c 33 52 72 4d 7a 6c 56 36 41 4e 45 59 45 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_RanumBot : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 68 4f 68 75 4f 41 34 57 36 30 61 42 42 52 6f 46 51 54 44 41 2f 64 6c 39 44 75 4c 41 67 45 63 61 62 59 47 4b 36 5a 54 32 74 2f 45 43 73 73 65 33 36 33 30 6a 56 5f 39 35 37 4f 71 71 4b 33 2f 5a 52 41 5f 4a 52 50 46 7a 78 75 74 4b 31 36 7a 6c 45 63 4d 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 4e 69 76 44 72 41 75 64 57 45 2d 45 36 78 74 42 58 65 77 77 2f 33 70 76 36 66 44 7a 44 71 74 34 76 30 59 78 6f 54 6b 50 74 2f 38 76 64 37 39 54 4e 45 2d 39 42 74 33 38 66 74 78 66 5f 56 2f 5f 47 4e 71 6e 71 45 55 73 52 66 2d 57 54 53 6d 6e 38 64 4d 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_Banload : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 61 33 36 32 39 65 65 36 61 62 36 31 30 61 35 37 66 32 34 32 66 35 39 61 33 64 64 35 65 35 66 36 64 65 37 33 64 61 34 30 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_Hive : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in Hive ransomware"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 58 44 75 62 37 44 47 6d 57 56 51 32 43 4f 43 36 57 34 49 66 2f 58 48 4d 71 52 50 66 32 6c 6e 4a 55 69 56 6b 47 31 43 52 36 2f 75 5f 4d 61 55 55 30 67 6f 32 55 55 6d 4c 62 5f 49 4e 75 76 2f 57 72 5a 53 79 7a 2d 57 4d 57 31 73 74 5f 4e 61 4d 39 33 35 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_Nodachi : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in Nodachi"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 33 41 41 79 68 4b 4b 30 77 46 66 43 59 4c 64 7a 35 6f 52 56 2f 7a 4b 79 69 42 48 43 73 41 45 79 44 49 57 68 61 57 35 41 57 2f 52 62 38 4e 4c 54 33 71 38 41 32 4f 4c 6d 36 69 7a 44 47 50 2f 38 47 39 6b 5f 67 6a 4f 54 58 5f 50 58 4b 6e 61 5f 49 4d 6a 22}
		$s2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 2d 65 79 46 64 38 6b 62 70 77 78 55 73 75 74 70 71 5a 6e 5f 2f 76 71 7a 51 58 58 35 52 61 34 71 6b 31 58 48 6f 71 6f 63 57 2f 77 64 2d 36 67 4c 7a 51 4b 5a 79 45 79 68 56 70 37 71 4f 6a 2f 4a 72 31 34 68 79 63 37 70 4c 4c 67 65 49 5a 4e 62 66 4c 44 22}
		$s3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 78 44 53 71 70 34 4b 47 6d 64 30 53 41 66 35 69 72 4d 47 68 2f 2d 6b 41 37 50 47 6a 4b 6f 4a 63 76 43 67 73 5a 44 53 74 6e 2f 6c 48 65 51 31 4c 51 4f 56 79 51 42 32 4e 6e 77 49 77 46 50 2f 2d 44 35 6f 45 42 63 32 33 4e 44 37 49 47 4c 54 45 53 64 4d 22}
		$s4 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 36 37 52 63 77 4e 73 70 4c 48 5f 5f 51 4a 72 45 6c 4d 63 42 2f 7a 4d 4a 66 37 47 6f 31 73 30 5a 6f 58 71 64 33 30 4c 62 5f 2f 4e 61 4a 6c 34 72 66 63 75 4c 45 47 35 4c 65 5a 2d 59 34 6b 2f 4d 7a 46 4e 76 57 37 39 65 6e 52 52 64 78 33 4c 6d 41 34 37 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_GoBrut : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in GoBrut"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 73 66 5f 32 5f 79 6c 63 6a 71 75 47 42 65 34 6d 51 39 39 4c 2f 61 50 76 64 4c 62 4d 32 7a 39 48 66 6f 44 4e 33 52 61 7a 47 2f 38 62 68 59 65 56 41 36 37 4e 2d 69 66 62 44 59 43 44 4a 65 2f 55 5a 7a 43 75 5f 45 46 4c 39 66 31 30 67 53 66 4f 34 4c 30 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_GoBuildID_BioPassDropper : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in BioPass dropper"

	strings:
		$s1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 4f 53 30 56 6c 6b 64 45 49 6c 63 6c 33 57 44 44 72 39 5a 61 2f 5f 6f 56 77 45 69 70 61 61 58 36 56 34 6d 45 45 59 67 32 56 2f 50 79 74 6c 79 65 49 59 67 56 36 35 6d 61 7a 34 77 54 32 59 2f 49 51 76 67 62 48 76 33 62 62 4c 56 34 32 69 31 30 71 71 32 22}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_KB_ID_Ransomware_Rhysida : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Rhysida ransomware"

	strings:
		$s1 = {((53 65 74 68 5a 65 6d 6c 61 6b 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (53 00 65 00 74 00 68 00 5a 00 65 00 6d 00 6c 00 61 00 6b 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s2 = {((4a 61 63 71 75 69 65 4b 75 6e 7a 65 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (4a 00 61 00 63 00 71 00 75 00 69 00 65 00 4b 00 75 00 6e 00 7a 00 65 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Payola : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Payola ransomware"

	strings:
		$s1 = {((70 63 73 75 70 70 6f 72 74 40 73 6b 69 66 66 2e 63 6f 6d) | (70 00 63 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 73 00 6b 00 69 00 66 00 66 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((70 63 74 61 6c 6b 30 31 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d) | (70 00 63 00 74 00 61 00 6c 00 6b 00 30 00 31 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_Xorist : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with Xorist ransomware"

	strings:
		$s1 = {((40 72 6f 6f 74 5f 62 61 63 6b 64 6f 6f 72 5f 73 79 6e 61 70 74 69 63 73 5f 56) | (40 00 72 00 6f 00 6f 00 74 00 5f 00 62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00 5f 00 73 00 79 00 6e 00 61 00 70 00 74 00 69 00 63 00 73 00 5f 00 56 00))}
		$s2 = {((40 44 6f 73 58 5f 50 6c 75 73) | (40 00 44 00 6f 00 73 00 58 00 5f 00 50 00 6c 00 75 00 73 00))}
		$s3 = {((40 43 69 6e 6f 73 68 69 5f 41 64 6d) | (40 00 43 00 69 00 6e 00 6f 00 73 00 68 00 69 00 5f 00 41 00 64 00 6d 00))}
		$s4 = {((40 61 63 33 73 73 30 72) | (40 00 61 00 63 00 33 00 73 00 73 00 30 00 72 00))}
		$s5 = {((4d 43 77 52 4b 31 5a 37 4b 34 47 59 48 74 39 5a 72 62 54 52 32 53 4d 43 45 71 7a 71 51 61 54 62 52 46) | (4d 00 43 00 77 00 52 00 4b 00 31 00 5a 00 37 00 4b 00 34 00 47 00 59 00 48 00 74 00 39 00 5a 00 72 00 62 00 54 00 52 00 32 00 53 00 4d 00 43 00 45 00 71 00 7a 00 71 00 51 00 61 00 54 00 62 00 52 00 46 00))}
		$s6 = {((30 78 33 33 34 46 30 39 33 63 39 44 65 36 35 35 32 41 46 34 63 43 30 42 32 35 32 64 41 38 32 61 43 37 37 46 65 42 34 36 37 44) | (30 00 78 00 33 00 33 00 34 00 46 00 30 00 39 00 33 00 63 00 39 00 44 00 65 00 36 00 35 00 35 00 32 00 41 00 46 00 34 00 63 00 43 00 30 00 42 00 32 00 35 00 32 00 64 00 41 00 38 00 32 00 61 00 43 00 37 00 37 00 46 00 65 00 42 00 34 00 36 00 37 00 44 00))}

	condition:
		any of them
}

rule INDICATOR_KB_ID_Ransomware_BlackHunt : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects files referencing identities associated with BlackHunt ransomware"

	strings:
		$s1 = {((6f 6e 69 6f 6e 37 34 36 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 63 6f 6d) | (6f 00 6e 00 69 00 6f 00 6e 00 37 00 34 00 36 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s2 = {((61 6d 69 6b 65 31 30 39 36 40 67 6d 61 69 6c 2e 63 6f 6d) | (61 00 6d 00 69 00 6b 00 65 00 31 00 30 00 39 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s3 = {((64 65 63 72 79 70 74 79 6f 75 72 64 61 74 61 40 6d 73 67 73 61 66 65 2e 69 6f) | (64 00 65 00 63 00 72 00 79 00 70 00 74 00 79 00 6f 00 75 00 72 00 64 00 61 00 74 00 61 00 40 00 6d 00 73 00 67 00 73 00 61 00 66 00 65 00 2e 00 69 00 6f 00))}
		$s4 = {((64 65 63 72 79 70 74 79 6f 75 72 64 61 74 61 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67) | (64 00 65 00 63 00 72 00 79 00 70 00 74 00 79 00 6f 00 75 00 72 00 64 00 61 00 74 00 61 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00))}
		$s5 = {((54 65 69 6b 6f 62 65 73 74 40 67 6d 61 69 6c 2e 63 6f 6d) | (54 00 65 00 69 00 6b 00 6f 00 62 00 65 00 73 00 74 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s6 = {((4c 6f 78 6f 63 6c 61 73 68 40 67 6d 61 69 6c 2e 63 6f 6d) | (4c 00 6f 00 78 00 6f 00 63 00 6c 00 61 00 73 00 68 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00))}
		$s7 = {((3a 2f 2f 73 64 6a 66 39 38 32 6c 6b 6a 73 64 76 63 6a 6c 6b 73 61 66 32 6b 6a 68 6c 6b 73 76 76 6e 6b 74 79 6f 69 61 73 75 63 39 32 6c 66 2e 6f 6e 69 6f 6e) | (3a 00 2f 00 2f 00 73 00 64 00 6a 00 66 00 39 00 38 00 32 00 6c 00 6b 00 6a 00 73 00 64 00 76 00 63 00 6a 00 6c 00 6b 00 73 00 61 00 66 00 32 00 6b 00 6a 00 68 00 6c 00 6b 00 73 00 76 00 76 00 6e 00 6b 00 74 00 79 00 6f 00 69 00 61 00 73 00 75 00 63 00 39 00 32 00 6c 00 66 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00))}

	condition:
		any of them
}

