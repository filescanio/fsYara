import "pe"

rule MAL_DevilsTongue_HijackDll : hardened
{
	meta:
		description = "Detects SOURGUM's DevilsTongue hijack DLL"
		author = "Microsoft Threat Intelligence Center (MSTIC)"
		date = "2021-07-15"
		reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"
		score = 80
		id = "390b8b73-6740-513d-8c70-c9002be0ce69"

	strings:
		$str1 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6f 00 6c 00 64 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00}
		$str2 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 54 68 72 65 61 64}
		$str3 = {64 00 62 00 67 00 48 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00}
		$str4 = {53 74 61 63 6b 57 61 6c 6b 36 34}
		$str5 = {43 6f 6e 76 65 72 74 53 69 64 54 6f 53 74 72 69 6e 67 53 69 64 57}
		$str6 = {53 00 2d 00 31 00 2d 00 35 00 2d 00 31 00 38 00}
		$str7 = {53 4d 4e 65 77 2e 64 6c 6c}
		$code1 = { B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8 }
		$code2 = { 44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19 }

	condition:
		filesize < 800KB and uint16( 0 ) == 0x5A4D and ( pe.characteristics & pe.DLL ) and ( 4 of them or ( $code1 and $code2 ) or pe.imphash ( ) == "9a964e810949704ff7b4a393d9adda60" )
}

