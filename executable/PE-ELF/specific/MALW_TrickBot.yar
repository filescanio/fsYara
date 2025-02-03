rule MALW_trickbot_bankBot : Trojan hardened
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "Detects Trickbot Banking Trojan"
		score = 60

	strings:
		$str_trick_01 = {6d 6f 64 75 6c 65 63 6f 6e 66 69 67}
		$str_trick_02 = {53 74 61 72 74}
		$str_trick_03 = {43 6f 6e 74 72 6f 6c}
		$str_trick_04 = {46 72 65 65 42 75 66 66 65 72}
		$str_trick_05 = {52 65 6c 65 61 73 65}

	condition:
		all of ( $str_trick_* )
}

rule MALW_systeminfo_trickbot_module : Trojan hardened
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "Detects systeminfo module from Trickbot Trojan"

	strings:
		$str_systeminf_01 = {3c 70 72 6f 67 72 61 6d 3e}
		$str_systeminf_02 = {3c 73 65 72 76 69 63 65 3e}
		$str_systeminf_03 = {3c 2f 73 79 73 74 65 6d 69 6e 66 6f 3e}
		$str_systeminf_04 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f 2e 70 64 62}
		$str_systeminf_05 = {3c 2f 61 75 74 6f 73 74 61 72 74 3e}
		$str_systeminf_06 = {3c 2f 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e}

	condition:
		all of ( $str_systeminf_* )
}

rule MALW_dllinject_trickbot_module : Trojan hardened
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = " Detects dllinject module from Trickbot Trojan"

	strings:
		$str_dllinj_01 = {75 73 65 72 5f 70 72 65 66 28}
		$str_dllinj_02 = {3c 69 67 6e 6f 72 65 5f 6d 61 73 6b 3e}
		$str_dllinj_03 = {3c 72 65 71 75 69 72 65 5f 68 65 61 64 65 72 3e}
		$str_dllinj_04 = {3c 2f 64 69 6e 6a 3e}

	condition:
		all of ( $str_dllinj_* )
}

rule MALW_mailsercher_trickbot_module : Trojan hardened
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = " Detects mailsearcher module from Trickbot Trojan"
		score = 75

	strings:
		$str_mails_01 = {6d 61 69 6c 73 65 61 72 63 68 65 72}
		$str_mails_02 = {68 61 6e 64 6c 65 72}
		$str_mails_03 = {63 6f 6e 66}
		$str_mails_04 = {63 74 6c}
		$str_mails_05 = {53 65 74 43 6f 6e 66}
		$str_mails_06 = {66 69 6c 65}
		$str_mails_07 = {6e 65 65 64 69 6e 66 6f}
		$str_mails_08 = {6d 61 69 6c 63 6f 6e 66}

	condition:
		all of ( $str_mails_* )
}

