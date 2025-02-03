rule APT_KE3CHANG_TMPFILE : APT KE3CHANG TMPFILE hardened
{
	meta:
		description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
		author = "Markus Neis, Swisscom"
		reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
		date = "2020-06-18"
		hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"
		id = "84d411af-ea3d-5862-8c2f-7caca60c1b66"

	strings:
		$pps1 = {50 53 50 61 72 65 6e 74 50 61 74 68 20 20 20 20 20 20 20 20 20 20 20 20 20 3a 20 4d 69 63 72 6f 73 6f 66 74 2e 50 6f 77 65 72 53 68 65 6c 6c 2e 43 6f 72 65 5c 52 65 67 69 73 74 72 79 3a 3a 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45}
		$pps2 = {50 53 50 61 74 68 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 3a 20 4d 69 63 72 6f 73 6f 66 74 2e 50 6f 77 65 72 53 68 65 6c 6c 2e 43 6f 72 65 5c 52 65 67 69 73 74 72 79 3a 3a 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45}
		$psp1 = {3a 20 4d 69 63 72 6f 73 6f 66 74 2e 50 6f 77 65 72 53 68 65 6c 6c 2e 43 6f 72 65 5c 52 65 67 69 73 74 72 79}
		$s4 = {50 53 43 68 69 6c 64 4e 61 6d 65 20 20 3a 20 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72}
		$s1 = {44 69 73 61 62 6c 65 46 69 72 73 74 52 75 6e 43 75 73 74 6f 6d 69 7a 65 20 3a 20 32}
		$s7 = {50 53 43 68 69 6c 64 4e 61 6d 65 20 20 3a 20 33}
		$s8 = {32 35 30 30 20 20 20 20 20 20 20 20 20 3a 20 33}

	condition:
		uint16( 0 ) == 0x5350 and filesize < 1KB and $psp1 and 1 of ( $pps* ) and 1 of ( $s* )
}

rule APT_MAL_Ke3chang_Ketrican_Jun20_1 : hardened
{
	meta:
		description = "Detects Ketrican malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "BfV Cyber-Brief Nr. 01/2020"
		date = "2020-06-18"
		hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
		hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"
		id = "ccd8322e-c822-512a-9ac5-eabc9d09640b"

	strings:
		$xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45
               FC 68 E0 58 40 00 8F 45 FC E9 }
		$op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 }
		$op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 1 of ( $x* ) or 2 of them
}

