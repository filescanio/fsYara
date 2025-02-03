rule Powerstager : hardened
{
	meta:
		author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
		date = "02JAN2018"
		hash1 = "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa"
		hash2 = "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5"
		description = "Detects PowerStager Windows executable, both x86 and x64"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/"
		reference2 = "https://github.com/z0noxz/powerstager"

	strings:
		$filename = /%s\\[a-zA-Z0-9]{12}/
		$pathname = {((54 45 4d 50) | (54 00 45 00 4d 00 50 00))}
		$filedesc = {((4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f 72 20 73 69 74 20 61 6d 65 74 2c 20 63 6f 6e 73 65 63 74 65 74 65 75 72 20 61 64 69 70 69 73 63 69 6e 67 20 65 6c 69 74) | (4c 00 6f 00 72 00 65 00 6d 00 20 00 69 00 70 00 73 00 75 00 6d 00 20 00 64 00 6f 00 6c 00 6f 00 72 00 20 00 73 00 69 00 74 00 20 00 61 00 6d 00 65 00 74 00 2c 00 20 00 63 00 6f 00 6e 00 73 00 65 00 63 00 74 00 65 00 74 00 65 00 75 00 72 00 20 00 61 00 64 00 69 00 70 00 69 00 73 00 63 00 69 00 6e 00 67 00 20 00 65 00 6c 00 69 00 74 00))}
		$apicall_01 = {6d 65 6d 73 65 74}
		$apicall_02 = {67 65 74 65 6e 76}
		$apicall_03 = {66 6f 70 65 6e}
		$apicall_04 = {6d 65 6d 63 70 79}
		$apicall_05 = {66 77 72 69 74 65}
		$apicall_06 = {66 63 6c 6f 73 65}
		$apicall_07 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41}
		$decoder_x86_01 = { 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }
		$decoder_x86_02 = { 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }
		$decoder_x64_01 = { 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }
		$decoder_x64_02 = { 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }

	condition:
		uint16be( 0 ) == 0x4D5A and all of ( $apicall_* ) and $filename and $pathname and $filedesc and ( 2 of ( $decoder_x86* ) or 2 of ( $decoder_x64* ) )
}

