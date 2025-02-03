rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_1 : hardened
{
	meta:
		description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers - file encrypt.sh"
		author = "Florian Roth"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
		date = "2023-02-04"
		score = 85
		hash1 = "10c3b6b03a9bf105d264a8e7f30dcab0a6c59a414529b0af0a6bd9f1d2984459"
		id = "7178dbe4-f573-5279-a23e-9bab8ae8b743"

	strings:
		$x1 = {2f 62 69 6e 2f 66 69 6e 64 20 2f 20 2d 6e 61 6d 65 20 2a 2e 6c 6f 67 20 2d 65 78 65 63 20 2f 62 69 6e 2f 72 6d 20 2d 72 66 20 7b 7d 20 5c 3b}
		$x2 = {2f 62 69 6e 2f 74 6f 75 63 68 20 2d 72 20 2f 65 74 63 2f 76 6d 77 61 72 65 2f 72 68 74 74 70 70 72 6f 78 79 2f 63 6f 6e 66 69 67 2e 78 6d 6c 20 2f 62 69 6e 2f 68 6f 73 74 64 2d 70 72 6f 62 65 2e 73 68}
		$x3 = {67 72 65 70 20 65 6e 63 72 79 70 74 20 7c 20 2f 62 69 6e 2f 67 72 65 70 20 2d 76 20 67 72 65 70 20 7c 20 2f 62 69 6e 2f 77 63 20 2d 6c 29}
		$s1 = {23 23 20 45 4e 43 52 59 50 54}
		$s2 = {2f 62 69 6e 2f 66 69 6e 64 20 2f 20 2d 6e 61 6d 65 20 2a 2e 6c 6f 67 20 2d 65 78 65 63 20 2f 62 69 6e}

	condition:
		uint16( 0 ) == 0x2123 and filesize < 10KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

rule MAL_RANSOM_ELF_ESXi_Attacks_Feb23_1 : hardened
{
	meta:
		description = "Detects ransomware exploiting and encrypting ESXi servers"
		author = "Florian Roth"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
		date = "2023-02-04"
		score = 85
		hash1 = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
		id = "d0a813aa-41f8-57df-b708-18ccb0d7a3e5"

	strings:
		$x1 = {75 73 61 67 65 3a 20 65 6e 63 72 79 70 74 20 3c 70 75 62 6c 69 63 5f 6b 65 79 3e 20 3c 66 69 6c 65 5f 74 6f 5f 65 6e 63 72 79 70 74 3e 20 5b 3c 65 6e 63 5f 73 74 65 70 3e 5d 20 5b 3c 65 6e 63 5f 73 69 7a 65 3e 5d 20 5b 3c 66 69 6c 65 5f 73 69 7a 65 3e 5d}
		$x2 = {5b 20 25 73 20 5d 20 2d 20 46 41 49 4c 20 7b 20 45 72 72 6e 6f 3a 20 25 64 20 7d}
		$s1 = {6c 50 45 4d 5f 72 65 61 64 5f 62 69 6f 5f 52 53 41 50 72 69 76 61 74 65 4b 65 79}
		$s2 = {6c 45 52 52 5f 67 65 74 5f 65 72 72 6f 72}
		$s3 = {67 65 74 5f 70 6b 5f 64 61 74 61 3a 20 6b 65 79 20 66 69 6c 65 20 69 73 20 65 6d 70 74 79 21}
		$op1 = { 8b 45 a8 03 45 d0 89 45 d4 8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 }
		$op2 = { 48 89 95 40 fd ff ff 48 83 bd 40 fd ff ff 00 0f 85 2e 01 00 00 48 8b 9d 50 ff ff ff 48 89 9d 30 fd ff ff 48 83 bd 30 fd ff ff 00 78 13 f2 48 0f 2a 85 30 fd ff ff }
		$op3 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d }

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

rule APT_PY_ESXi_Backdoor_Dec22 : hardened
{
	meta:
		description = "Detects Python backdoor found on ESXi servers"
		author = "Florian Roth"
		reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
		date = "2022-12-14"
		score = 85
		id = "f0a3b9b9-0031-5d9f-97f8-70f83863ee63"

	strings:
		$x1 = {63 6d 64 20 3d 20 73 74 72 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 65 6e 63 6f 64 65 64 5f 63 6d 64 29 2c 20}
		$x2 = {73 68 20 2d 69 20 32 3e 26 31 20 7c 20 6e 63 20 25 73 20 25 73 20 3e 20 2f 74 6d 70 2f}

	condition:
		filesize < 10KB and 1 of them or all of them
}

rule APT_SH_ESXi_Backdoor_Dec22 : hardened
{
	meta:
		description = "Detects malicious script found on ESXi servers"
		author = "Florian Roth"
		reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
		date = "2022-12-14"
		score = 75
		id = "983ac20c-2e61-5365-8849-b3aeb999f909"

	strings:
		$x1 = {6d 76 20 2f 62 69 6e 2f 68 6f 73 74 64 2d 70 72 6f 62 65 2e 73 68 20 2f 62 69 6e 2f 68 6f 73 74 64 2d 70 72 6f 62 65 2e 73 68 2e 31}
		$x2 = {2f 62 69 6e 2f 6e 6f 68 75 70 20 2f 62 69 6e 2f 70 79 74 68 6f 6e 20 2d 75 20 2f 73 74 6f 72 65 2f 70 61 63 6b 61 67 65 73 2f 76 6d 74 6f 6f 6c 73 2e 70 79}
		$x3 = {2f 62 69 6e 2f 72 6d 20 2f 62 69 6e 2f 68 6f 73 74 64 2d 70 72 6f 62 65 2e 73 68 2e 31}

	condition:
		filesize < 10KB and 1 of them
}

rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_2 : hardened
{
	meta:
		description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers"
		author = "Florian Roth"
		reference = "https://dev.to/xakrume/esxiargs-encryption-malware-launches-massive-attacks-against-vmware-esxi-servers-pfe"
		date = "2023-02-06"
		score = 85
		id = "d1282dee-0496-52f1-a2b7-27657ab4df8c"

	strings:
		$x1 = {65 63 68 6f 20 22 53 54 41 52 54 20 45 4e 43 52 59 50 54 3a 20 24 66 69 6c 65 5f 65 20 53 49 5a 45 3a 20 24 73 69 7a 65 5f 6b 62 20 53 54 45 50 20 53 49 5a 45 3a 20}

	condition:
		filesize < 10KB and 1 of them
}

rule SUSP_ESXiArgs_Endpoint_Conf_Aug23 : hardened
{
	meta:
		description = "Detects indicators found in endpoint.conf files as modified by actors in the ESXiArgs campaign"
		author = "Florian Roth"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-47"
		date = "2023-08-04"
		score = 75
		id = "3e0b5dbf-7c5b-5599-823a-ce35fbdbe64b"

	strings:
		$a1 = {2f 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 73 2e 78 6d 6c}
		$a2 = {2f 76 61 72 2f 72 75 6e 2f 76 6d 77 61 72 65 2f 70 72 6f 78 79 2d 73 64 6b 2d 74 75 6e 6e 65 6c}
		$a3 = {72 65 64 69 72 65 63 74}
		$a4 = {61 6c 6c 6f 77}
		$s1 = {20 6c 6f 63 61 6c 20 38 30 30 38 20 61 6c 6c 6f 77 20 61 6c 6c 6f 77}

	condition:
		filesize < 2KB and all of them
}

