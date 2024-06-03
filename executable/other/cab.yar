rule cab_file_bat_cmd {
	meta:
		author = "OPSWAT"
		description = "The file is a cab file maskerading as a bat file to autoextract and execute its packed content"
		mitre_attack = "T1036.008"
		score = 100
		//f6a4eacc001f50411cd36094d7dc9f35762ad93c561b667fd885285b2772b2fd
	strings:
		$st0 = "extrac32 /y \"%~f0\"" ascii wide nocase
		$st1 = "extrac32 /y '%~f0'" ascii wide nocase
	condition:
		uint32(0) == 0x4643534D
			and ($st0 in (0..128) or $st1 in (0..128))
}
