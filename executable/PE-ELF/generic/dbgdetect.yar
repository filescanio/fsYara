rule dbgdetect_funcs : dbgdetect hardened
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$func1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74}
		$func2 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67}
		$func3 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e}
		$func4 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$func5 = {49 73 44 65 62 75 67 67 65 64}
		$func6 = {4e 74 47 6c 6f 62 61 6c 46 6c 61 67 73}
		$func7 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74}
		$func8 = {53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 54 68 72 65 61 64}
		$func9 = {44 65 62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73}

	condition:
		2 of them
}

rule dbgdetect_procs : dbgdetect hardened limited
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$proc1 = {((77 69 72 65 73 68 61 72 6b) | (77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00))}
		$proc2 = {((66 69 6c 65 6d 6f 6e) | (66 00 69 00 6c 00 65 00 6d 00 6f 00 6e 00))}
		$proc3 = {((70 72 6f 63 65 78 70) | (70 00 72 00 6f 00 63 00 65 00 78 00 70 00))}
		$proc4 = {((70 72 6f 63 6d 6f 6e) | (70 00 72 00 6f 00 63 00 6d 00 6f 00 6e 00))}
		$proc5 = {((72 65 67 6d 6f 6e) | (72 00 65 00 67 00 6d 00 6f 00 6e 00))}
		$proc6 = {((69 64 61 67) | (69 00 64 00 61 00 67 00))}
		$proc7 = {((69 6d 6d 75 6e 69 74 79 64 65 62 75 67 67 65 72) | (69 00 6d 00 6d 00 75 00 6e 00 69 00 74 00 79 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00))}
		$proc8 = {((6f 6c 6c 79 64 62 67) | (6f 00 6c 00 6c 00 79 00 64 00 62 00 67 00))}
		$proc9 = {((70 65 74 6f 6f 6c 73) | (70 00 65 00 74 00 6f 00 6f 00 6c 00 73 00))}

	condition:
		2 of them
}

rule dbgdetect_files : dbgdetect hardened limited
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$file1 = {((73 79 73 65 72 64 62 67 6d 73 67) | (73 00 79 00 73 00 65 00 72 00 64 00 62 00 67 00 6d 00 73 00 67 00))}
		$file2 = {((73 79 73 65 72 62 6f 6f 74) | (73 00 79 00 73 00 65 00 72 00 62 00 6f 00 6f 00 74 00))}
		$file3 = {((53 49 43 45) | (53 00 49 00 43 00 45 00))}
		$file4 = {((4e 54 49 43 45) | (4e 00 54 00 49 00 43 00 45 00))}

	condition:
		2 of them
}

