private rule PotaoDecoy : hardened
{
	strings:
		$mz = { 4d 5a }
		$str1 = {65 72 6f 71 77 31 31}
		$str2 = {32 73 66 73 64 66}
		$str3 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72}
		$wiki_str = {73 00 70 00 61 00 6e 00 6e 00 65 00 64 00 20 00 6d 00 6f 00 72 00 65 00 20 00 74 00 68 00 61 00 6e 00 20 00 31 00 30 00 30 00 20 00 79 00 65 00 61 00 72 00 73 00 20 00 61 00 6e 00 64 00 20 00 72 00 75 00 69 00 6e 00 65 00 64 00 20 00 74 00 68 00 72 00 65 00 65 00 20 00 63 00 6f 00 6e 00 73 00 65 00 63 00 75 00 74 00 69 00 76 00 65 00}
		$old_ver1 = {53 68 65 6C 6C 33 32 2E 64 6C 6C 00 64 61 66 73 72 00 00 00 64 61 66 73 72 00 00 00 64 6F 63 (00 | 78)}
		$old_ver2 = {6F 70 65 6E 00 00 00 00 64 6F 63 00 64 61 66 73 72 00 00 00 53 68 65 6C 6C 33 32 2E 64 6C 6C 00}

	condition:
		($mz at 0 ) and ( ( all of ( $str* ) ) or any of ( $old_ver* ) or $wiki_str )
}

private rule PotaoDll : hardened
{
	strings:
		$mz = { 4d 5a }
		$dllstr1 = {3f 41 56 43 6e 63 42 75 66 66 65 72 40 40}
		$dllstr2 = {3f 41 56 43 6e 63 52 65 71 75 65 73 74 40 40}
		$dllstr3 = {50 65 74 72 6f 7a 61 76 6f 64 73 6b 61 79 61 2c 20 31 31 2c 20 39}
		$dllstr4 = {5f 53 63 61 6e 40 30}
		$dllstr5 = {00 2f 73 79 6e 63 2f 64 6f 63 75 6d 65 6e 74 2f}
		$dllstr6 = {5c 74 65 6d 70 2e 74 65 6d 70}
		$dllname1 = {6e 6f 64 65 36 39 4d 61 69 6e 4d 6f 64 75 6c 65 2e 64 6c 6c}
		$dllname2 = {6e 6f 64 65 36 39 2d 6d 61 69 6e 2e 64 6c 6c}
		$dllname3 = {6e 6f 64 65 36 39 4d 61 69 6e 4d 6f 64 75 6c 65 44 2e 64 6c 6c}
		$dllname4 = {74 61 73 6b 2d 64 69 73 6b 73 63 61 6e 6e 65 72 2e 64 6c 6c}
		$dllname5 = {00 53 63 72 65 65 6e 2e 64 6c 6c}
		$dllname6 = {50 6f 6b 65 72 32 2e 64 6c 6c}
		$dllname7 = {50 61 73 73 77 6f 72 64 53 74 65 61 6c 65 72 2e 64 6c 6c}
		$dllname8 = {4b 65 79 4c 6f 67 32 52 75 6e 6e 65 72 2e 64 6c 6c}
		$dllname9 = {47 65 74 41 6c 6c 53 79 73 74 65 6d 49 6e 66 6f 2e 64 6c 6c}
		$dllname10 = {46 69 6c 65 50 61 74 68 53 74 65 61 6c 65 72 2e 64 6c 6c}

	condition:
		($mz at 0 ) and ( any of ( $dllstr* ) and any of ( $dllname* ) )
}

private rule PotaoUSB : hardened
{
	strings:
		$mz = { 4d 5a }
		$binary1 = { 33 C0 8B C8 83 E1 03 BA ?? ?? ?? 00 2B D1 8A 0A 32 88 ?? ?? ?? 00 2A C8 FE C9 88 88 ?? ?? ?? 00 40 3D ?? ?? 00 00 7C DA C3 }
		$binary2 = { 55 8B EC 51 56 C7 45 FC 00 00 00 00 EB 09 8B 45 FC 83 C0 01 89 45 FC 81 7D FC ?? ?? 00 00 7D 3D 8B 4D FC 0F BE 89 ?? ?? ?? 00 8B 45 FC 33 D2 BE 04 00 00 00 F7 F6 B8 03 00 00 00 2B C2 0F BE 90 ?? ?? ?? 00 33 CA 2B 4D FC 83 E9 01 81 E1 FF 00 00 00 8B 45 FC 88 88 ?? ?? ?? 00 EB B1 5E 8B E5 5D C3}

	condition:
		($mz at 0 ) and any of ( $binary* )
}

private rule PotaoSecondStage : hardened
{
	strings:
		$mz = { 4d 5a }
		$binary1 = {51 7A BB 85 [10-180] E8 47 D2 A8}
		$binary2 = {5F 21 63 DD [10-30] EC FD 33 02}
		$binary3 = {CA 77 67 57 [10-30] BA 08 20 7A}
		$str1 = {3f 41 56 43 72 79 70 74 33 32 49 6d 70 6f 72 74 40 40}
		$str2 = {25 2e 35 6c 6c 78}

	condition:
		($mz at 0 ) and any of ( $binary* ) and any of ( $str* )
}

rule Potao : hardened
{
	meta:
		Author = "Anton Cherepanov"
		Date = "2015/07/29"
		Description = "Operation Potao"
		Reference = "http://www.welivesecurity.com/wp-content/uploads/2015/07/Operation-Potao-Express_final_v2.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "threatintel@eset.com"
		License = "BSD 2-Clause"

	condition:
		PotaoDecoy or PotaoDll or PotaoUSB or PotaoSecondStage
}

