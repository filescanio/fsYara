rule SUSP_EXPL_Msg_CVE_2023_23397_Mar23 : hardened
{
	meta:
		description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
		author = "delivr.to, modified by Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
		date = "2023-03-15"
		modified = "2023-03-17"
		score = 60
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
		hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
		hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
		hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
		id = "0a4d7bbe-1e17-5240-ad0f-29511752b267"

	strings:
		$psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }
		$u1 = { 00 00 5C 00 5C 00 }
		$fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and uint32be( 4 ) == 0xA1B11AE1 and 1 of ( $psetid* ) and $rfp and $u1 and not 1 of ( $fp* )
}

rule EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 : hardened
{
	meta:
		description = "Detects suspicious .msg file with a PidLidReminderFileParameter property exploiting CVE-2023-23397 (modified delivr.to rule - more specific = less FPs but limited to exfil using IP addresses, not FQDNs)"
		author = "delivr.to, Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
		date = "2023-03-15"
		modified = "2023-03-18"
		score = 75
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
		hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
		hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
		hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
		hash = "e7a1391dd53f349094c1235760ed0642519fd87baf740839817d47488b9aef02"
		id = "d85bf1d9-aebe-5f8c-9dd4-c509f64e221a"

	strings:
		$psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }
		$u1 = { 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 3? 00 3? 00|3? 00 3? 00|3? 00) }
		$u2 = { 00 5C 5C (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 3? 3?|3? 3?|3?) }
		$fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}

	condition:
		( uint16( 0 ) == 0xCFD0 and 1 of ( $psetid* ) or uint32be( 0 ) == 0x789F3E22 ) and any of ( $u* ) and $rfp and not 1 of ( $fp* )
}

rule EXPL_SUSP_Outlook_CVE_2023_23397_SMTP_Mail_Mar23 : hardened limited
{
	meta:
		author = "Nils Kuhnert"
		date = "2023-03-17"
		modified = "2023-03-24"
		description = "Detects suspicious *.eml files that include TNEF content that possibly exploits CVE-2023-23397. Lower score than EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 as we're only looking for UNC prefix."
		score = 60
		reference = "https://twitter.com/wdormann/status/1636491612686622723"
		id = "922fae73-520d-5659-8331-f242c7c55810"

	strings:
		$mail1 = { 0A 46 72 6F 6D 3A 20 }
		$mail2 = { 0A 54 6F 3A }
		$mail3 = { 0A 52 65 63 65 69 76 65 64 3A }
		$tnef1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6d 73 2d 74 6e 65 66}
		$tnef2 = {78 9f 3e 22}
		$ipm1 = {49 50 4d 2e 54 61 73 6b}
		$ipm2 = {49 50 4d 2e 41 70 70 6f 69 6e 74 6d 65 6e 74}
		$unc = {00 00 00 5c}

	condition:
		all of ( $mail* ) and all of ( $tnef* ) and 1 of ( $ipm* ) and $unc
}

