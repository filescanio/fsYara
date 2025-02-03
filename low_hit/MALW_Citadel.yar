rule citadel13xy : hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Citadel 1.5.x.y trojan banker"
		date = "2013-01-12"
		version = "1.0"
		filetype = "memory"

	strings:
		$a = {43 6f 64 65 64 20 62 79 20 42 52 49 41 4e 20 4b 52 45 42 53 20 66 6f 72 20 70 65 72 73 6f 6e 6e 61 6c 20 75 73 65 20 6f 6e 6c 79 2e 20 49 20 6c 6f 76 65 20 6d 79 20 6a 6f 62 20 26 20 77 69 66 65 2e}
		$b = {68 74 74 70 3a 2f 2f 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 2e 63 6f 6d 2f 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 2f 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 2e 70 68 70}
		$c = {25 42 4f 54 49 44 25}
		$d = {25 42 4f 54 4e 45 54 25}
		$e = {63 69 74 5f 76 69 64 65 6f 2e 6d 6f 64 75 6c 65}
		$f = {62 63 5f 72 65 6d 6f 76 65}
		$g = {62 63 5f 61 64 64}
		$ggurl = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 77 65 62 68 70}

	condition:
		3 of them
}

rule Citadel_Malware : hardened
{
	meta:
		author = "xylitol@temari.fr"
		date = "2015-10-08"
		description = "Search for nss3.dll pattern indicating an hexed copy of Citadel malware to work on firefox > v23.0"

	strings:
		$s1 = {((43 6f 64 65 64 20 62 79 20 42 52 49 41 4e 20 4b 52 45 42 53 20 66 6f 72 20 70 65 72 73 6f 6e 61 6c 20 75 73 65 20 6f 6e 6c 79 2e 20 49 20 6c 6f 76 65 20 6d 79 20 6a 6f 62 20 26 20 77 69 66 65) | (43 00 6f 00 64 00 65 00 64 00 20 00 62 00 79 00 20 00 42 00 52 00 49 00 41 00 4e 00 20 00 4b 00 52 00 45 00 42 00 53 00 20 00 66 00 6f 00 72 00 20 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 20 00 75 00 73 00 65 00 20 00 6f 00 6e 00 6c 00 79 00 2e 00 20 00 49 00 20 00 6c 00 6f 00 76 00 65 00 20 00 6d 00 79 00 20 00 6a 00 6f 00 62 00 20 00 26 00 20 00 77 00 69 00 66 00 65 00))}
		$s2 = {((6e 73 73 33 2e 64 6c 6c) | (6e 00 73 00 73 00 33 00 2e 00 64 00 6c 00 6c 00))}
		$h1 = {8B C7 EB F5 55 8B EC}
		$h2 = {55 8B EC 83 EC 0C 8A 82 00 01 00 00}
		$h3 = {3D D0 FF 1F 03 77 ?? 83 7D}
		$h4 = {83 F9 66 74 ?? 83 F9 6E 74 ?? 83 F9 76 74 ?? 83 F9 7A}

	condition:
		all of ( $s* ) and 2 of ( $h* )
}

