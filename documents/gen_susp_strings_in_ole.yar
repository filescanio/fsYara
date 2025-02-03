rule MAL_RTF_Embedded_OLE_PE : hardened
{
	meta:
		description = "Detects a suspicious string often used in PE files in a hex encoded object stream"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.nextron-systems.com/2018/01/22/creating-yara-rules-detect-embedded-exe-files-ole-objects/"
		date = "2018-01-22"
		modified = "2023-11-25"
		score = 65
		id = "20044f08-9574-5baf-b91e-47613e490d62"

	strings:
		$a1 = {35 34 36 38 36 39 37 33 32 30 37 30 37 32 36 66 36 37 37 32 36 31 36 64 32 30 36 33 36 31 36 65 36 65 36 66 37 34 32 30 36 32 36 35 32 30 37 32 37 35 36 65 32 30 36 39 36 65 32 30 34 34 34 66 35 33 32 30 36 64 36 66 36 34 36 35}
		$a2 = {34 62 34 35 35 32 34 65 34 35 34 63 33 33 33 32 32 65 36 34 36 63 36 63}
		$a3 = {34 33 33 61 35 63 36 36 36 31 36 62 36 35 37 30 36 31 37 34 36 38 35 63}
		$m3 = {34 64 35 61 34 30 30 30 30 31 30 30 30 30 30 30 30 36 30 30 30 30 30 30 66 66 66 66}
		$m2 = {34 64 35 61 35 30 30 30 30 32 30 30 30 30 30 30 30 34 30 30 30 66 30 30 66 66 66 66}
		$m1 = {34 64 35 61 39 30 30 30 30 33 30 30 30 30 30 30 30 34 30 30 30 30 30 30 66 66 66 66}

	condition:
		uint32be( 0 ) == 0x7B5C7274 and 1 of them
}

