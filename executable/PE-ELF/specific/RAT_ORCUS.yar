rule RAT_Orcus : hardened
{
	meta:
		author = " J from THL <j@techhelplist.com> with thx to MalwareHunterTeam"
		date = "2017/01"
		reference = "https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/"
		version = 1
		maltype = "RAT"
		filetype = "memory"
		vetted_family = "OrcusRAT"

	strings:
		$text01 = {4f 72 63 75 73 2e 43 6f 6d 6d 61 6e 64 4d 61 6e 61 67 65 6d 65 6e 74}
		$text02 = {4f 72 63 75 73 2e 43 6f 6d 6d 61 6e 64 73 2e}
		$text03 = {4f 72 63 75 73 2e 43 6f 6e 66 69 67 2e}
		$text04 = {4f 72 63 75 73 2e 43 6f 6e 6e 65 63 74 69 6f 6e 2e}
		$text05 = {4f 72 63 75 73 2e 43 6f 72 65 2e}
		$text06 = {4f 72 63 75 73 2e 65 78 65}
		$text07 = {4f 72 63 75 73 2e 45 78 74 65 6e 73 69 6f 6e 73 2e}
		$text08 = {4f 72 63 75 73 2e 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 50 72 6f 6d 70 74 46 6f 72 6d}
		$text09 = {4f 72 63 75 73 2e 4d 61 69 6e 46 6f 72 6d 2e}
		$text10 = {4f 72 63 75 73 2e 4e 61 74 69 76 65 2e}
		$text11 = {4f 72 63 75 73 2e 50 6c 75 67 69 6e 73 2e}
		$text12 = {6f 72 63 75 73 2e 70 6c 75 67 69 6e 73 2e 64 6c 6c}
		$text13 = {4f 72 63 75 73 2e 50 72 6f 70 65 72 74 69 65 73 2e}
		$text14 = {4f 72 63 75 73 2e 50 72 6f 74 65 63 74 69 6f 6e 2e}
		$text15 = {4f 72 63 75 73 2e 53 68 61 72 65 2e}
		$text16 = {4f 72 63 75 73 2e 53 68 61 72 65 64}
		$text17 = {4f 72 63 75 73 2e 53 74 61 74 69 63 43 6f 6d 6d 61 6e 64 73}
		$text18 = {4f 72 63 75 73 2e 55 74 69 6c 69 74 69 65 73 2e}
		$text19 = {5c 50 72 6f 6a 65 63 74 73 5c 4f 72 63 75 73 5c 53 6f 75 72 63 65 5c 4f 72 63 75 73 2e}
		$text20 = {2e 6f 72 63 75 73 2e 70 6c 75 67 69 6e 73 2e 64 6c 6c 2e 7a 69 70}
		$text21 = {2e 6f 72 63 75 73 2e 73 68 61 72 65 64 2e 64 6c 6c 2e 7a 69 70}
		$text22 = {2e 6f 72 63 75 73 2e 73 68 61 72 65 64 2e 75 74 69 6c 69 74 69 65 73 2e 64 6c 6c 2e 7a 69 70}
		$text23 = {2e 6f 72 63 75 73 2e 73 74 61 74 69 63 63 6f 6d 6d 61 6e 64 73 2e 64 6c 6c 2e 7a 69 70}
		$text24 = {48 76 6e 63 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e}
		$text25 = {48 76 6e 63 41 63 74 69 6f 6e}
		$text26 = {68 76 6e 63 44 65 73 6b 74 6f 70}
		$text27 = {2e 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 50 72 6f 6d 70 74 46 6f 72 6d}
		$text28 = {52 65 71 75 65 73 74 4b 65 79 4c 6f 67 43 6f 6d 6d 61 6e 64}
		$text29 = {67 65 74 5f 4b 65 79 4c 6f 67 46 69 6c 65}
		$text30 = {4c 69 76 65 4b 65 79 6c 6f 67 67 65 72 43 6f 6d 6d 61 6e 64}
		$text31 = {4f 52 43 55 53 2e 53 54 41 54 49 43 43 4f 4d 4d 41 4e 44 53 2c 20 56 45 52 53 49 4f 4e 3d}
		$text32 = {50 72 65 70 61 72 65 4f 72 63 75 73 46 69 6c 65 54 6f 52 65 6d 6f 76 65}
		$text33 = {43 6f 6e 76 65 72 74 46 72 6f 6d 4f 72 63 75 73 56 61 6c 75 65 4b 69 6e 64}

	condition:
		13 of them
}

