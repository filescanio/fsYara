rule SUSP_PS1_JAB_Pattern_Jun22_1 : hardened
{
	meta:
		description = "Detects suspicious UTF16 and Base64 encoded PowerShell code that starts with a $ sign and a single char variable"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2022-06-10"
		score = 50
		id = "9ecca7d9-3b63-5615-a223-5efa1c53510e"

	strings:
		$xc1 = { 4a 41 42 ?? 41 43 41 41 50 51 41 67 41 }
		$xc2 = { 4a 00 41 00 42 00 ?? 00 41 00 43 00 41 00 41 00 50 00 51 00 41 00 67 00 41 }
		$xc3 = { 4a 41 42 ?? 41 44 30 41 }
		$xc4 = { 4a 00 41 00 42 00 ?? 00 41 00 44 00 30 00 41 }

	condition:
		filesize < 30MB and 1 of them
}

