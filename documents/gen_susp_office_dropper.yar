rule SUSP_EnableContent_String_Gen : hardened
{
	meta:
		description = "Detects suspicious string that asks to enable active content in Office Doc"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-02-12"
		hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
		id = "d763bc21-2925-55df-85e0-1ee857e921ca"

	strings:
		$e1 = {45 6e 61 62 6c 65 20 45 64 69 74 69 6e 67}
		$e2 = {45 6e 61 62 6c 65 20 43 6f 6e 74 65 6e 74}
		$e3 = {45 6e 61 62 6c 65 20 65 64 69 74 69 6e 67}
		$e4 = {45 6e 61 62 6c 65 20 63 6f 6e 74 65 6e 74}

	condition:
		uint16( 0 ) == 0xcfd0 and ( $e1 in ( 0 .. 3000 ) or $e2 in ( 0 .. 3000 ) or $e3 in ( 0 .. 3000 ) or $e4 in ( 0 .. 3000 ) or 2 of them )
}

rule SUSP_WordDoc_VBA_Macro_Strings : hardened
{
	meta:
		description = "Detects suspicious strings in Word Doc that indcate malicious use of VBA macros"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-02-12"
		score = 60
		hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
		id = "210baf6e-ec67-5bc4-ba27-6a6de0c11a73"

	strings:
		$a1 = {5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c}
		$a2 = {5c 56 42 41 5c}
		$a3 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 20 57 6f 72 64}
		$a4 = {50 00 52 00 4f 00 4a 00 45 00 43 00 54 00 77 00 6d 00}
		$s1 = {41 70 70 44 61 74 61}
		$s2 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e}
		$s3 = {50 72 6f 6a 65 63 74 31}
		$s4 = {43 72 65 61 74 65 4f 62 6a 65 63 74}

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 800KB and all of them
}

rule SUSP_OfficeDoc_VBA_Base64Decode : hardened
{
	meta:
		description = "Detects suspicious VBA code with Base64 decode functions"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
		date = "2019-06-21"
		score = 70
		hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
		id = "99690116-fc89-53d7-8f29-575d75d53fc9"

	strings:
		$s1 = {42 36 34 5f 43 48 41 52 5f 44 49 43 54}
		$s2 = {42 61 73 65 36 34 44 65 63 6f 64 65}
		$s3 = {42 61 73 65 36 34 45 6e 63 6f 64 65}

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 60KB and 2 of them
}

rule SUSP_VBA_FileSystem_Access : hardened
{
	meta:
		description = "Detects suspicious VBA that writes to disk and is activated on document open"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-06-21"
		score = 60
		hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
		id = "91241b91-ca3f-5817-bf78-550fe015b467"

	strings:
		$s1 = {5c 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 68 00 61 00 72 00 65 00 64 00 5c 00}
		$s2 = {53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74}
		$a1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e}
		$a2 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c}
		$a3 = {41 75 74 6f 4f 70 65 6e}

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 100KB and all of ( $s* ) and 1 of ( $a* )
}

rule SUSP_Excel_IQY_RemoteURI_Syntax : hardened
{
	meta:
		description = "Detects files with Excel IQY RemoteURI syntax"
		author = "Nick Carr"
		reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
		date = "2018-08-17"
		modified = "2023-11-25"
		score = 55
		id = "ea3427da-9cce-5ad9-9c78-e3cee802ba80"

	strings:
		$URL = {68 74 74 70}
		$fp1 = {68 74 74 70 73 3a 2f 2f 67 6f 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d}

	condition:
		uint32( 0 ) == 0x0d424557 and uint32( 4 ) == 0x0a0d310a and filesize < 1MB and $URL and not 1 of ( $fp* )
}

rule SUSP_Macro_Sheet_Obfuscated_Char : hardened
{
	meta:
		description = "Finding hidden/very-hidden macros with many CHAR functions"
		author = "DissectMalware"
		date = "2020-04-07"
		score = 65
		hash1 = "0e9ec7a974b87f4c16c842e648dd212f80349eecb4e636087770bc1748206c3b"
		reference = "https://twitter.com/DissectMalware/status/1247595433305800706"
		id = "791e9bba-3e4e-5efd-a800-a612c6f92cfb"

	strings:
		$ole_marker = {D0 CF 11 E0 A1 B1 1A E1}
		$s1 = {45 78 63 65 6c}
		$macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
		$macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
		$char_func = {06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1E 3D  00 41 6F 00}

	condition:
		$ole_marker at 0 and 1 of ( $macro_sheet_h* ) and #char_func > 10 and $s1
}

