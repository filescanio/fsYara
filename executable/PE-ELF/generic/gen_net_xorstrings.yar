rule MSIL_SUSP_OBFUSC_XorStringsNet : hardened
{
	meta:
		description = "Detects XorStringsNET string encryption, and other obfuscators derived from it"
		author = "dr4k0nia"
		version = "1.0"
		reference = "https://github.com/dr4k0nia/yara-rules"
		score = 75
		date = "26/03/2023"
		id = "f0724ca6-4bfe-5b88-9396-a58aa7461fd6"

	strings:
		$pattern = { 06 1E 58 07 8E 69 FE 17 }
		$a1 = {5f 43 6f 72 44 6c 6c 4d 61 69 6e}
		$a2 = {5f 43 6f 72 45 78 65 4d 61 69 6e}
		$a3 = {6d 73 63 6f 72 6c 69 62}
		$a4 = {2e 63 63 74 6f 72}
		$a5 = {53 79 73 74 65 6d 2e 50 72 69 76 61 74 65 2e 43 6f 72 6c 69 62}
		$a6 = {3c 4d 6f 64 75 6c 65 3e}
		$a7 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 73 44 65 74 61 69 6c 73 7b}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25MB and $pattern and 2 of ( $a* )
}

