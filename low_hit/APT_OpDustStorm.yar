rule Misdat_Backdoor_Packed : hardened
{
	meta:
		author = "Cylance SPEAR Team"
		note = "Probably Prone to False Positive"

	strings:
		$upx = {33 2E 30 33 00 55 50 58 21}
		$send = {00 00 00 73 65 6E 64 00 00 00}
		$delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
		$shellexec = {00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 57 00 00 00}

	condition:
		filesize < 100KB and $upx and $send and $delphi_sec_pe and $shellexec
}

rule MiSType_Backdoor_Packed : hardened
{
	meta:
		author = "Cylance SPEAR Team"
		note = "Probably Prone to False Positive"

	strings:
		$upx = {33 2E 30 33 00 55 50 58 21}
		$send_httpquery = {00 00 00 48 74 74 70 51 75 65 72 79 49 6E 66 6F 41 00 00 73 65 6E 64 00 00}
		$delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}

	condition:
		filesize < 100KB and $upx and $send_httpquery and $delphi_sec_pe
}

rule Misdat_Backdoor : hardened
{
	meta:
		author = "Cylance SPEAR Team"

	strings:
		$imul = {03 45 F8 69 C0 D9 DB 00 00 05 3B DA 00 00}
		$delphi = {50 45 00 00 4C 01 08 00 19 5E 42 2A}

	condition:
		$imul and $delphi
}

rule SType_Backdoor : hardened
{
	meta:
		author = "Cylance SPEAR Team"

	strings:
		$stype = {73 74 79 70 65 3d 69 6e 66 6f 26 64 61 74 61 3d}
		$mmid = {3f 6d 6d 69 64 3d}
		$status = {26 73 74 61 74 75 73 3d 72 75 6e 20 73 75 63 63 65 65 64}
		$mutex = {5f 4b 42 31 30 42 32 44 31 5f 43 49 6c 46 44 32 43}
		$decode = {8B 1A 8A 1B 80 EB 02 8B 74 24 08 32 1E 8B 31 88 1E 8B 1A 43}

	condition:
		$stype or ( $mmid and $status ) or $mutex or $decode
}

rule Zlib_Backdoor : hardened
{
	meta:
		author = "Cylance SPEAR Team"

	strings:
		$auth = {C6 45 D8 50 C6 45 D9 72 C6 45 DA 6F C6 45 DB 78 C6 45 DC 79 C6 45 DD 2D}
		$auth2 = {C7 45 FC 00 04 00 00 C6 45 ?? 50 C6 45 ?? 72 C6 45 ?? 6F}
		$ntlm = {4e 00 54 00 4c 00 4d 00}

	condition:
		($auth or $auth2 ) and $ntlm
}

