rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork hardened
{
	meta:
		description = "Detection of Linux variant of Winnti"
		author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
		version = "1.0"
		date = "2019-05-15"
		TLP = "White"
		sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
		id = "d641de9a-e563-5067-b7e4-0aa83a087ed4"

	strings:
		$config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
		$export1 = {6f 75 72 5f 73 6f 63 6b 65 74 73}
		$export2 = {67 65 74 5f 6f 75 72 5f 70 69 64 73}

	condition:
		uint16( 0 ) == 0x457f and all of them
}

rule APT_MAL_WinntiLinux_Main_AzazelFork_May19 : hardened
{
	meta:
		description = "Detection of Linux variant of Winnti"
		author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
		version = "1.0"
		date = "2019-05-15"
		TLP = "White"
		sha256 = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
		id = "a1693e2d-4d89-5cc7-ab14-c8feb000638a"

	strings:
		$uuid_lookup = {2f 75 73 72 2f 73 62 69 6e 2f 64 6d 69 64 65 63 6f 64 65 20 20 7c 20 67 72 65 70 20 2d 69 20 27 55 55 49 44 27 20 7c 63 75 74 20 2d 64 27 20 27 20 2d 66 32 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c}
		$dbg_msg = {5b 61 64 76 4e 65 74 53 72 76 5d 20 63 61 6e 20 6e 6f 74 20 63 72 65 61 74 65 20 61 20 50 46 5f 49 4e 45 54 20 73 6f 63 6b 65 74}
		$rtti_name1 = {43 4e 65 74 42 61 73 65}
		$rtti_name2 = {43 4d 79 45 6e 67 69 6e 65 4e 65 74 45 76 65 6e 74}
		$rtti_name3 = {43 42 75 66 66 65 72 43 61 63 68 65}
		$rtti_name4 = {43 53 6f 63 6b 73 35 42 61 73 65}
		$rtti_name5 = {43 44 61 74 61 45 6e 67 69 6e 65}
		$rtti_name6 = {43 53 6f 63 6b 73 35 4d 67 72}
		$rtti_name7 = {43 52 65 6d 6f 74 65 4d 73 67}

	condition:
		uint16( 0 ) == 0x457f and ( ( $dbg_msg and 1 of ( $rtti* ) ) or ( 5 of ( $rtti* ) ) or ( $uuid_lookup and 2 of ( $rtti* ) ) )
}

