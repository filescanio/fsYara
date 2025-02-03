rule SUSP_NET_Msil_Suspicious_Use_StrReverse : hardened
{
	meta:
		description = "Detects mixed use of Microsoft.CSharp and VisualBasic to use StrReverse"
		author = "dr4k0nia, modified by Florian Roth"
		reference = "https://github.com/dr4k0nia/yara-rules"
		version = "1.1"
		date = "01/31/2023"
		modified = "02/22/2023"
		score = 70
		hash = "02ce0980427dea835fc9d9eed025dd26672bf2c15f0b10486ff8107ce3950701"
		id = "830dec40-4412-59c1-8b4d-a237f14acd30"

	strings:
		$a1 = {2c 20 50 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d}
		$a2 = {2e 4e 45 54 46 72 61 6d 65 77 6f 72 6b 2c 56 65 72 73 69 6f 6e 3d}
		$csharp = {4d 69 63 72 6f 73 6f 66 74 2e 43 53 68 61 72 70}
		$vbnet = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63}
		$strreverse = {53 74 72 52 65 76 65 72 73 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50MB and all of ( $a* ) and $csharp and $vbnet and $strreverse
}

