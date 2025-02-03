rule Careto : hardened
{
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto generic malware signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

	strings:
		$name1 = {((43 61 72 65 74 6f) | (43 00 61 00 72 00 65 00 74 00 6f 00))}
		$s_1 = {((47 65 74 53 79 73 74 65 6d 52 65 70 6f 72 74) | (47 00 65 00 74 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 65 00 70 00 6f 00 72 00 74 00))}
		$s_2 = {((53 79 73 74 65 6d 52 65 70 6f 72 74 2e 74 78 74) | (53 00 79 00 73 00 74 00 65 00 6d 00 52 00 65 00 70 00 6f 00 72 00 74 00 2e 00 74 00 78 00 74 00))}
		$s_3 = /URL_AUX\w*=/ ascii wide
		$s_4 = /CaretoPruebas.+release/
		$sign_0 = {53 6f 66 69 61}
		$sign_1 = {54 65 63 53 79 73 74 65 6d 20 4c 74 64}
		$sign_2 = {3c 00 3c 00 3c 00 4f 00 62 00 73 00 6f 00 6c 00 65 00 74 00 65 00 3e 00 3e 00 3e 00}
		$rc4_1 = {((21 24 37 62 65 26 2e 4b 61 77 2d 31 32 5b 7d) | (21 00 24 00 37 00 62 00 65 00 26 00 2e 00 4b 00 61 00 77 00 2d 00 31 00 32 00 5b 00 7d 00))}
		$rc4_2 = {((43 61 67 75 65 6e 31 61 4d 61 72) | (43 00 61 00 67 00 75 00 65 00 6e 00 31 00 61 00 4d 00 61 00 72 00))}
		$rc4_3 = {8d 85 86 8a 8f 80 88 83 8d 82 88 85 86 8f 8f 87 8d 82 83 82 8c 8e 83 8d 89 82 86 87 82 83 83 81}
		$dec_1 = {8b 4d 08 0f be 04 59 0f be 4c 59 01 2b c7 c1 e0 04 2b cf 0b c1 50 8d 85 f0 fe ff ff}
		$dec_2 = {8b 4d f8 8b 16 88 04 11 8b 06 41 89 4d f8 c6 04 01 00 43 3b 5d fc}

	condition:
		$name1 and ( any of ( $s_* ) ) or all of ( $sign_* ) or any of ( $rc4_* ) or all of ( $dec_* )
}

rule Careto_SGH : hardened
{
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto SGH component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

	strings:
		$m1 = {((50 47 50 73 64 6b 44 72 69 76 65 72) | (50 00 47 00 50 00 73 00 64 00 6b 00 44 00 72 00 69 00 76 00 65 00 72 00))}
		$m2 = {((6a 70 65 67 31 78 33 32) | (6a 00 70 00 65 00 67 00 31 00 78 00 33 00 32 00))}
		$m3 = {((53 6b 79 70 65 49 45 36 50 6c 75 67 69 6e) | (53 00 6b 00 79 00 70 00 65 00 49 00 45 00 36 00 50 00 6c 00 75 00 67 00 69 00 6e 00))}
		$m4 = {((43 44 6c 6c 55 6e 69 6e 73 74 61 6c 6c) | (43 00 44 00 6c 00 6c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00))}

	condition:
		2 of them
}

rule Careto_OSX_SBD : hardened
{
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto OSX component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

	strings:
		$1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}

	condition:
		all of them
}

rule Careto_CnC : hardened
{
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto CnC communication signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

	strings:
		$1 = {((63 67 69 2d 62 69 6e 2f 63 6f 6d 6d 63 67 69 2e 63 67 69) | (63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 2f 00 63 00 6f 00 6d 00 6d 00 63 00 67 00 69 00 2e 00 63 00 67 00 69 00))}
		$2 = {((47 72 6f 75 70) | (47 00 72 00 6f 00 75 00 70 00))}
		$3 = {((49 6e 73 74 61 6c 6c) | (49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00))}
		$4 = {((42 6e) | (42 00 6e 00))}

	condition:
		all of them
}

rule Careto_CnC_domains : hardened limited
{
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto known command and control domains"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

	strings:
		$1 = {((6c 69 6e 6b 63 6f 6e 66 2e 6e 65 74) | (6c 00 69 00 6e 00 6b 00 63 00 6f 00 6e 00 66 00 2e 00 6e 00 65 00 74 00))}
		$2 = {((72 65 64 69 72 73 65 72 76 65 72 2e 6e 65 74) | (72 00 65 00 64 00 69 00 72 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 6e 00 65 00 74 00))}
		$3 = {((73 77 75 70 64 74 2e 63 6f 6d) | (73 00 77 00 75 00 70 00 64 00 74 00 2e 00 63 00 6f 00 6d 00))}

	condition:
		any of them
}

