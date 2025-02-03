rule PowerShell_ISESteroids_Obfuscation : hardened
{
	meta:
		description = "Detects PowerShell ISESteroids obfuscation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
		date = "2017-06-23"
		id = "d686c4de-28fd-5d77-91d4-dde5661b75cd"

	strings:
		$x1 = {2f 5c 2f 3d 3d 3d 5c 5f 5f}
		$x2 = {24 7b 5f 5f 2f 5c 2f 3d 3d}
		$x3 = {43 61 74 63 68 20 7b 20 7d}
		$x4 = {5c 5f 2f 3d 7d 20 24 7b 5f}

	condition:
		2 of them
}

rule SUSP_Obfuscted_PowerShell_Code : hardened
{
	meta:
		description = "Detects obfuscated PowerShell Code"
		date = "2018-12-13"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/silv0123/status/1073072691584880640"
		id = "e2d8fc9e-ce2b-5118-8305-0d5839561d4f"

	strings:
		$s1 = {27 29 2e 49 6e 76 6f 6b 65 28}
		$s2 = {28 22 7b 31 7d 7b 30 7d 22}
		$s3 = {7b 30 7d 22 20 2d 66}

	condition:
		#s1> 11 and #s2 > 10 and #s3 > 10
}

rule SUSP_PowerShell_Caret_Obfuscation_2 : refined hardened
{
	meta:
		description = "Detects powershell keyword obfuscated with carets"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-07-20"
		score = 50
		id = "976e261a-029c-5703-835f-a235c5657471"
		modified = "2024-04-04"

	strings:
		$r1 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r2 = /p[\^]?o\^w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r3 = /p[\^]?o[\^]?w\^e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r4 = /p[\^]?o[\^]?w[\^]?e\^r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r5 = /p[\^]?o[\^]?w[\^]?e[\^]?r\^s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r6 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s\^h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r7 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h\^e[\^]?l[\^]?l/ ascii wide nocase fullword
		$r8 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e\^l[\^]?l/ ascii wide nocase fullword
		$r9 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii wide nocase fullword

	condition:
		1 of them
}

rule SUSP_OBFUSC_PowerShell_True_Jun20_1 : hardened limited
{
	meta:
		description = "Detects indicators often found in obfuscated PowerShell scripts"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/corneacristian/mimikatz-bypass/"
		date = "2020-06-27"
		score = 60
		id = "e9bb870b-ad72-57d3-beff-2f84a81490eb"

	strings:
		$ = {24 7b 74 60 72 75 65 7d}
		$ = {24 7b 74 72 60 75 65 7d}
		$ = {24 7b 74 72 75 60 65 7d}
		$ = {24 7b 74 60 72 75 60 65 7d}
		$ = {24 7b 74 72 60 75 60 65 7d}
		$ = {24 7b 74 60 72 60 75 65 7d}
		$ = {24 7b 74 60 72 60 75 60 65 7d}

	condition:
		filesize < 6000KB and 1 of them
}

