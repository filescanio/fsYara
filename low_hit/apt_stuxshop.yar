rule STUXSHOP_config : hardened
{
	meta:
		desc = "Stuxshop standalone sample configuration"
		author = "JAG-S (turla@chronicle.security)"
		hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
		reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
		id = "67367db5-51b3-5177-960a-5b06161154e2"

	strings:
		$cnc1 = {((68 74 74 70 3a 2f 2f 32 31 31 2e 32 34 2e 32 33 37 2e 32 32 36 2f 69 6e 64 65 78 2e 70 68 70 3f 64 61 74 61 3d) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 31 00 31 00 2e 00 32 00 34 00 2e 00 32 00 33 00 37 00 2e 00 32 00 32 00 36 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 64 00 61 00 74 00 61 00 3d 00))}
		$cnc2 = {((68 74 74 70 3a 2f 2f 74 6f 64 61 79 73 66 75 74 62 6f 6c 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 3f 64 61 74 61 3d) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 6f 00 64 00 61 00 79 00 73 00 66 00 75 00 74 00 62 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 64 00 61 00 74 00 61 00 3d 00))}
		$cnc3 = {((68 74 74 70 3a 2f 2f 37 38 2e 31 31 31 2e 31 36 39 2e 31 34 36 2f 69 6e 64 65 78 2e 70 68 70 3f 64 61 74 61 3d) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 37 00 38 00 2e 00 31 00 31 00 31 00 2e 00 31 00 36 00 39 00 2e 00 31 00 34 00 36 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 64 00 61 00 74 00 61 00 3d 00))}
		$cnc4 = {((68 74 74 70 3a 2f 2f 6d 79 70 72 65 6d 69 65 72 66 75 74 62 6f 6c 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 3f 64 61 74 61 3d) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 79 00 70 00 72 00 65 00 6d 00 69 00 65 00 72 00 66 00 75 00 74 00 62 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 64 00 61 00 74 00 61 00 3d 00))}
		$regkey1 = {((53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 4d 53 2d 44 4f 53 20 45 6d 75 6c 61 74 69 6f 6e) | (53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 4d 00 53 00 2d 00 44 00 4f 00 53 00 20 00 45 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00))}
		$regkey2 = {((4e 54 56 44 4d 50 61 72 61 6d 73) | (4e 00 54 00 56 00 44 00 4d 00 50 00 61 00 72 00 61 00 6d 00 73 00))}
		$flowerOverlap1 = { 85 C0 75 3B 57 FF 75 1C FF 75 18 FF 75 14 50 FF 75 10 FF 75 FC FF 15 }
		$flowerOverlap2 = { 85 C0 75 4C 8B 45 1C 89 45 0C 8D 45 0C 50 8D 45 08 FF 75 18 50 6A 00 FF 75 10 FF 75 20 FF 15 }
		$flowerOverlap3 = { 55 8B EC 53 56 8B 75 20 85 F6 74 03 83 26 00 8D 45 20 50 68 19 00 02 00 6A 00 FF 75 0C FF 75 08 }
		$flowerOverlap4 = { 55 8B EC 51 8D 4D FC 33 C0 51 50 6A 26 50 89 45 FC FF 15 }
		$flowerOverlap5 = { 85 DB 74 04 8B C3 EB 1A 8B 45 08 3B 45 14 74 07 B8 5D 06 00 00 EB 0B 85 F6 74 05 8B 45 0C 89 06 }
		$flowerOverlap6 = { 85 FF 74 12 83 7D F8 01 75 0C FF 75 0C FF 75 08 FF 15 }

	condition:
		all of ( $flowerOverlap* ) or 2 of ( $cnc* ) or all of ( $regkey* )
}

rule STUXSHOP_OSCheck : hardened
{
	meta:
		author = "Silas Cutler (havex@Chronicle.Security)"
		desc = "Identifies the OS Check function in STUXSHOP and CheshireCat"
		hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
		id = "24fb5c6f-d5ab-5f17-942c-b712e2c017d4"

	strings:
		$ = {10 F7 D8 1B C0 83 C0 ?? E9 ?? 01 00 00 39 85 7C FF FF FF 0F 85 ?? 01 00
      00 83 BD 70 FF FF FF 04 8B 8D 74 FF FF FF 75 0B 85 C9 0F 85 ?? 01 00 00 6A 05
      5E }
		$ = {01 00 00 3B FA 0F 84 ?? 01 00 00 80 7D 80 00 B1 62 74 1D 6A 0D 8D 45 80
      68 ?? ?? ?? 10 50 FF 15 ?? ?? ?? 10 83 C4 0C B1 6F 85 C0 75 03 8A 4D 8D 8B C6
      }

	condition:
		any of them
}

