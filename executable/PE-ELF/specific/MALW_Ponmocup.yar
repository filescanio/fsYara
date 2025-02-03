rule Trj_Ponmocup : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Ponmocup Installer"

	strings:
		$mz = { 4d 5a }
		$pac = { 48 8F BB 54 5F 3E 4F 4E }
		$unp = { 8B B8 7C 1F 46 00 33 C8 }

	condition:
		($mz at 0 ) and ( $pac at 0x61F7C ) and ( $unp at 0x29F0 )
}

rule Trj_Ponmocup_Downloader : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Ponmocup Downloader"

	strings:
		$mz = { 4d 5a }
		$vb5 = {56 42 35}
		$tpb = {77 00 77 00 77 00 2e 00 74 00 68 00 65 00 70 00 69 00 72 00 61 00 74 00 65 00 62 00 61 00 79 00 2e 00 6f 00 72 00 67 00}
		$ua = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 37 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 35 00 2e 00 32 00 3b 00 20 00 53 00 56 00 31 00 29 00}

	condition:
		($mz at 0 ) and ( $vb5 ) and ( $tpb ) and ( $ua )
}

rule Trj_Ponmocup_dll : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Ponmocup Bot DLL"

	strings:
		$mz = { 4d 5a }
		$pck = { 00 81 23 00 33 3E 00 00 3B F4 56 00 00 00 7D 00 }
		$upk = { 68 F4 14 00 10 A1 6C C0 02 10 FF D0 59 59 E9 7A }

	condition:
		($mz at 0 ) and ( $pck at 0x8a50 ) and ( $upk at 0x61f )
}

