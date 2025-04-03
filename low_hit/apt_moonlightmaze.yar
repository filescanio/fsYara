rule apt_RU_MoonlightMaze_customlokitools : hardened limited
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-15"
		version = "1.1"
		last_modified = "2017-03-22"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
		hash = "14cce7e641d308c3a177a8abb5457019"
		hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
		hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
		hash = "1980958afffb6a9d5a6c73fc1e2795c2"
		hash = "e59f92aadb6505f29a9f368ab803082e"
		id = "d5795d3b-bbb1-59e9-b86d-666b5c911f3b"

	strings:
		$a1 = {((57 72 69 74 65 20 66 69 6c 65 20 4f 6b 2e 2e 2e) | (57 00 72 00 69 00 74 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 4f 00 6b 00 2e 00 2e 00 2e 00))}
		$a2 = {((45 52 52 4f 52 3a 20 43 61 6e 20 6e 6f 74 20 6f 70 65 6e 20 73 6f 63 6b 65 74 2e 2e 2e 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 2e 00 2e 00 2e 00))}
		$a3 = {((45 72 72 6f 72 20 69 6e 20 70 61 72 61 6d 65 74 72 73 3a) | (45 00 72 00 72 00 6f 00 72 00 20 00 69 00 6e 00 20 00 70 00 61 00 72 00 61 00 6d 00 65 00 74 00 72 00 73 00 3a 00))}
		$a4 = {((55 73 61 67 65 3a 20 40 3c 67 65 74 2f 70 75 74 3e 20 3c 49 50 3e 20 3c 50 4f 52 54 3e 20 3c 66 69 6c 65 3e) | (55 00 73 00 61 00 67 00 65 00 3a 00 20 00 40 00 3c 00 67 00 65 00 74 00 2f 00 70 00 75 00 74 00 3e 00 20 00 3c 00 49 00 50 00 3e 00 20 00 3c 00 50 00 4f 00 52 00 54 00 3e 00 20 00 3c 00 66 00 69 00 6c 00 65 00 3e 00))}
		$a5 = {((45 52 52 4f 52 3a 20 4e 6f 74 20 63 6f 6e 6e 65 63 74 2e 2e 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 4e 00 6f 00 74 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 2e 00 2e 00 2e 00))}
		$a6 = {((43 6f 6e 6e 65 63 74 20 73 75 63 63 65 73 73 66 75 6c 2e 2e 2e 2e) | (43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 2e 00 2e 00 2e 00 2e 00))}
		$a7 = {((63 6c 6e 74 20 3c 25 64 3e 20 72 71 73 74 64 20 6e 20 6c 6c 20 6b 6c 6c) | (63 00 6c 00 6e 00 74 00 20 00 3c 00 25 00 64 00 3e 00 20 00 72 00 71 00 73 00 74 00 64 00 20 00 6e 00 20 00 6c 00 6c 00 20 00 6b 00 6c 00 6c 00))}
		$a8 = {((63 6c 6e 74 20 3c 25 64 3e 20 72 71 73 74 64 20 73 77 61 70) | (63 00 6c 00 6e 00 74 00 20 00 3c 00 25 00 64 00 3e 00 20 00 72 00 71 00 73 00 74 00 64 00 20 00 73 00 77 00 61 00 70 00))}
		$a9 = {((63 6c 64 20 6e 74 20 73 67 6e 6c 20 70 72 63 73 20 67 72 70) | (63 00 6c 00 64 00 20 00 6e 00 74 00 20 00 73 00 67 00 6e 00 6c 00 20 00 70 00 72 00 63 00 73 00 20 00 67 00 72 00 70 00))}
		$a10 = {((63 6c 64 20 6e 74 20 73 67 6e 6c 20 70 72 6e 74) | (63 00 6c 00 64 00 20 00 6e 00 74 00 20 00 73 00 67 00 6e 00 6c 00 20 00 70 00 72 00 6e 00 74 00))}
		$a11 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6f 72 6b 20 65 72 72 6f 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 5000KB and 3 of ( $a* )
}

rule apt_RU_MoonlightMaze_customsniffer : hardened limited
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-15"
		version = "1.1"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze sniffer tools"
		hash = "7b86f40e861705d59f5206c482e1f2a5"
		hash = "927426b558888ad680829bd34b0ad0e7"
		original_filename = "ora;tdn"
		id = "8cc76e4d-a956-543c-81e0-827dfdb5da1c"

	strings:
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 76 61 72 2f 74 6d 70 2f 67 6f 67 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 79 66 69 6c 65 6e 61 6d 65 3d 20 7c 25 73 7c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 79 70 69 64 2c 6d 79 67 69 64 3d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 79 70 69 64 3d 7c 25 64 7c 20 6d 79 67 69 64 3d 7c 25 64 7c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 79 64 65 76 6e 61 6d 65 3d 20 7c 25 73 7c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		2 of ( $a* )
}

rule loki2crypto : hardened
{
	meta:
		author = "Costin Raiu, Kaspersky Lab"
		date = "2017-03-21"
		version = "1.0"
		description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		hash = "19fbd8cbfb12482e8020a887d6427315"
		hash = "ea06b213d5924de65407e8931b1e4326"
		hash = "14ecd5e6fc8e501037b54ca263896a11"
		hash = "e079ec947d3d4dacb21e993b760a65dc"
		hash = "edf900cebb70c6d1fcab0234062bfc28"
		id = "d67288f8-5205-5882-8dff-041d092eea4f"

	strings:
		$modulus = {DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

	condition:
		( any of them )
}

rule apt_RU_MoonlightMaze_de_tool : hardened limited
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
		hash = "4bc7ed168fb78f0dc688ee2be20c9703"
		hash = "8b56e8552a74133da4bc5939b5f74243"
		id = "09bfebca-7cec-5514-9f48-c0c2c57efcf9"

	strings:
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 56 6e 75 6b 3a 20 25 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 79 6e 3a 20 25 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a3 = {25 73 0A 25 73 0A 25 73 0A 25 73 0A}

	condition:
		(( 2 of ( $a* ) ) )
}

rule apt_RU_MoonlightMaze_cle_tool : hardened
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
		hash = "647d7b711f7b4434145ea30d0ef207b0"
		id = "99ae07b9-eb42-53dc-bd8b-75ab6a0b8cab"

	strings:
		$a1 = {((2e 2f 61 20 66 69 6c 65 6e 61 6d 65 20 74 65 6d 70 6c 61 74 65 5f 66 69 6c 65) | (2e 00 2f 00 61 00 20 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 20 00 74 00 65 00 6d 00 70 00 6c 00 61 00 74 00 65 00 5f 00 66 00 69 00 6c 00 65 00))}
		$a2 = {((4d 61 79 20 62 65 20 25 73 20 69 73 20 65 6d 70 74 79 3f) | (4d 00 61 00 79 00 20 00 62 00 65 00 20 00 25 00 73 00 20 00 69 00 73 00 20 00 65 00 6d 00 70 00 74 00 79 00 3f 00))}
		$a3 = {((74 65 6d 70 6c 61 74 65 20 73 74 72 69 6e 67 20 3d 20 7c 25 73 7c) | (74 00 65 00 6d 00 70 00 6c 00 61 00 74 00 65 00 20 00 73 00 74 00 72 00 69 00 6e 00 67 00 20 00 3d 00 20 00 7c 00 25 00 73 00 7c 00))}
		$a4 = {4e 6f 20 62 6c 6f 63 6b 73 20 21 21 21}
		$a5 = {((4e 6f 20 64 61 74 61 20 69 6e 20 74 68 69 73 20 62 6c 6f 63 6b 20 21 21 21 21 21 21) | (4e 00 6f 00 20 00 64 00 61 00 74 00 61 00 20 00 69 00 6e 00 20 00 74 00 68 00 69 00 73 00 20 00 62 00 6c 00 6f 00 63 00 6b 00 20 00 21 00 21 00 21 00 21 00 21 00 21 00))}
		$a6 = {4e 6f 20 67 6f 6f 64 20 6c 69 6e 65}

	condition:
		(( 3 of ( $a* ) ) )
}

rule apt_RU_MoonlightMaze_xk_keylogger : hardened limited
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze 'xk' keylogger"
		id = "cf585cd0-afdd-5782-a6e5-bb9509cbf01d"

	strings:
		$a1 = {4c 6f 67 20 65 6e 64 65 64 20 61 74 20 3d 3e 20 25 73}
		$a2 = {4c 6f 67 20 73 74 61 72 74 65 64 20 61 74 20 3d 3e 20 25 73 20 5b 70 69 64 20 25 64 5d}
		$a3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 68 6f 73 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a5 = {6d 79 20 68 6f 73 74 6e 61 6d 65 3a 20 25 73}
		$a6 = {2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 6c 6f 67}
		$a7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 76 61 72 2f 74 6d 70 2f 2e 58 74 6d 70 30 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a8 = {6d 79 66 69 6c 65 6e 61 6d 65 3d 2d 25 73 2d}
		$a9 = {2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 70 69 64}
		$a10 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 79 70 69 64 3d 2d 25 64 2d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a11 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 76 61 72 2f 74 6d 70 2f 74 61 73 6b 67 69 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a12 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 79 67 69 64 3d 2d 25 64 2d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		(( 3 of ( $a* ) ) )
}

rule apt_RU_MoonlightMaze_encrypted_keylog : hardened
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze encrypted keylogger logs"
		id = "f0d464f0-3955-5f41-a57f-8aa225e1171d"

	strings:
		$a1 = {47 01 22 2A 6D 3E 39 2C}

	condition:
		uint32( 0 ) == 0x2a220147 and ( $a1 at 0 )
}

rule apt_RU_MoonlightMaze_IRIX_exploit_GEN : hardened
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Irix exploits from David Hedley used by Moonlight Maze hackers"
		reference2 = "https://www.exploit-db.com/exploits/19274/"
		hash = "008ea82f31f585622353bd47fa1d84be"
		hash = "a26bad2b79075f454c83203fa00ed50c"
		hash = "f67fc6e90f05ba13f207c7fdaa8c2cab"
		hash = "5937db3896cdd8b0beb3df44e509e136"
		hash = "f4ed5170dcea7e5ba62537d84392b280"
		id = "4f9ab7b0-4fb9-5311-ae23-01d0a9e2e104"

	strings:
		$a1 = {73 74 61 63 6b 20 3d 20 30 78 25 78 2c 20 74 61 72 67 5f 61 64 64 72 20 3d 20 30 78 25 78}
		$a2 = {65 78 65 63 6c 20 66 61 69 6c 65 64}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( all of them )
}

rule apt_RU_MoonlightMaze_u_logcleaner : hardened
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect log cleaners based on utclean.c"
		reference2 = "http://cd.textfiles.com/cuteskunk/Unix-Hacking-Exploits/utclean.c"
		hash = "d98796dcda1443a37b124dbdc041fe3b"
		hash = "73a518f0a73ab77033121d4191172820"
		id = "2dc1b796-c8fe-5a87-9d6b-3a322f4a43ab"

	strings:
		$a1 = {48 69 64 69 6e 67 20 63 6f 6d 70 6c 69 74 2e 2e 2e 6e}
		$a2 = {75 73 61 67 65 3a 20 25 73 20 3c 75 73 65 72 6e 61 6d 65 3e 20 3c 66 69 78 74 68 69 6e 67 73 3e 20 5b 68 6f 73 74 6e 61 6d 65 5d}
		$a3 = {6c 73 20 2d 6c 61 20 25 73 2a 20 3b 20 2f 62 69 6e 2f 63 70 20 20 2e 2f 77 74 6d 70 2e 74 6d 70 20 25 73 3b 20 72 6d 20 20 2e 2f 77 74 6d 70 2e 74 6d 70}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( any of them )
}

rule apt_RU_MoonlightMaze_wipe : hardened
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect log cleaner based on wipe.c"
		reference2 = "http://www.afn.org/~afn28925/wipe.c"
		hash = "e69efc504934551c6a77b525d5343241"
		id = "35060c3d-b805-54a6-a241-eb6e99168fa8"

	strings:
		$a1 = {45 52 52 4f 52 3a 20 55 6e 6c 69 6e 6b 69 6e 67 20 74 6d 70 20 57 54 4d 50 20 66 69 6c 65 2e}
		$a2 = {55 53 41 47 45 3a 20 77 69 70 65 20 5b 20 75 7c 77 7c 6c 7c 61 20 5d 20 2e 2e 2e 6f 70 74 69 6f 6e 73 2e 2e 2e}
		$a3 = {45 72 61 73 65 20 61 63 63 74 20 65 6e 74 72 69 65 73 20 6f 6e 20 74 74 79 20 3a 20 20 20 77 69 70 65 20 61 20 5b 75 73 65 72 6e 61 6d 65 5d 20 5b 74 74 79 5d}
		$a4 = {41 6c 74 65 72 20 6c 61 73 74 6c 6f 67 20 65 6e 74 72 79 20 20 20 20 20 20 20 3a 20 20 20 77 69 70 65 20 6c 20 5b 75 73 65 72 6e 61 6d 65 5d 20 5b 74 74 79 5d 20 5b 74 69 6d 65 5d 20 5b 68 6f 73 74 5d}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( 2 of them )
}

