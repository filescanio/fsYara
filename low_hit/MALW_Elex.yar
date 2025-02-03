rule Trj_Elex_Installer_NSIS : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex Installer NSIS"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"

	strings:
		$mz = { 4d 5a }
		$str1 = {4e 75 6c 6c 73 6f 66 74 }
		$str2 = {b7 a2 d5 dc 0c d6 a6 3a}

	condition:
		($mz at 0 ) and ( $str1 at 0xA008 ) and ( $str2 at 0x1c8700 )
}

rule Trj_Elex_Installer : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex Installer"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"

	strings:
		$mz = { 4d 5a }
		$str1 = {65 00 76 00 65 00 72 00 79 00 74 00 68 00 69 00 6e 00 67 00}
		$str2 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73}
		$str3 = {53 53 46 4b}

	condition:
		($mz at 0 ) and ( $str1 ) and ( $str2 ) and ( $str3 )
}

import "pe"

rule Trj_Elex_Service32 : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex Service 32 bits"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"

	strings:
		$mz = { 4d 5a }
		$str1 = {68 74 74 70 3a 2f 2f 78 61 2e 78 69 6e 67 63 6c 6f 75 64 2e 63 6f 6d 2f 76 34 2f 73 6f 66 2d 65 76 65 72 79 74 68 69 6e 67 2f}
		$str2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 73 65 61 72 63 68 31 32 33 2e 63 6f 6d}
		$str3 = {32 31 65 32 32 33 62 33 66 30 63 39 37 64 62 33 63 32 38 31 64 61 31 67 37 7a 63 63 61 65 66 6f 7a 7a 6a 63 6b 74 6d 6c 6d 61}

	condition:
		(pe.machine == pe.MACHINE_I386 ) and ( $mz at 0 ) and ( $str1 ) and ( $str2 ) and ( $str3 )
}

import "pe"

rule Trj_Elex_Service64 : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex Service 64 bits"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"

	strings:
		$mz = { 4d 5a }
		$str1 = {68 74 74 70 3a 2f 2f 78 61 2e 78 69 6e 67 63 6c 6f 75 64 2e 63 6f 6d 2f 76 34 2f 73 6f 66 2d 65 76 65 72 79 74 68 69 6e 67 2f}
		$str2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 73 65 61 72 63 68 31 32 33 2e 63 6f 6d}
		$str3 = {32 31 65 32 32 33 62 33 66 30 63 39 37 64 62 33 63 32 38 31 64 61 31 67 37 7a 63 63 61 65 66 6f 7a 7a 6a 63 6b 74 6d 6c 6d 61}

	condition:
		(pe.machine == pe.MACHINE_AMD64 ) and ( $mz at 0 ) and ( $str1 ) and ( $str2 ) and ( $str3 )
}

import "pe"

rule Trj_Elex_Dll32 : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex DLL 32 bits"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"

	strings:
		$mz = { 4d 5a }
		$str1 = {59 00 72 00 72 00 65 00 68 00 73 00}
		$str2 = {52 6f 6f 6b 49 45 2f 31 2e 30}

	condition:
		(pe.machine == pe.MACHINE_I386 ) and ( pe.characteristics & pe.DLL ) and ( $mz at 0 ) and ( $str1 ) and ( $str2 )
}

import "pe"

rule Trj_Elex_Dll64 : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex DLL 64 bits"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"

	strings:
		$mz = { 4d 5a }
		$str1 = {59 00 72 00 72 00 65 00 68 00 73 00}
		$str2 = {52 6f 6f 6b 49 45 2f 31 2e 30}

	condition:
		(pe.machine == pe.MACHINE_AMD64 ) and ( pe.characteristics & pe.DLL ) and ( $mz at 0 ) and ( $str1 ) and ( $str2 )
}

