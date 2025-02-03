rule SUSP_ELF_SPARC_Hunting_SBZ_Obfuscation : hardened
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth to avoid elf module import"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		date = "2023-04-02"
		modified = "2023-05-08"
		score = 60
		id = "15ee9a66-d823-508c-a14c-2c6ff45f47e5"

	strings:
		$xor_block = { 9A 18 E0 47 9A 1B 40 01 9A 18 80 0D }
		$a1 = {53 55 4e 57 5f}

	condition:
		uint32be( 0 ) == 0x7f454c46 and $a1 and $xor_block
}

rule SUSP_ELF_SPARC_Hunting_SBZ_UniqueStrings : hardened
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth for performance reasons"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		date = "2023-04-02"
		modified = "2023-05-08"
		score = 60
		id = "d2f70d10-412e-5e83-ba4f-eac251012dc1"

	strings:
		$s1 = {3c 25 75 3e 5b 25 73 5d 20 45 76 65 6e 74 20 23 25 75 3a 20}
		$s2 = {6c 70 72 63 3a 25 30 38 58}
		$s3 = {64 69 75 58 78 6f 62 42}
		$s4 = {43 48 4d 5f 46 57}

	condition:
		2 of ( $* )
}

rule SUSP_ELF_SPARC_Hunting_SBZ_ModuleStruct : hardened
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth for FP reduction reasons"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		date = "2023-04-02"
		modified = "2023-05-08"
		score = 60
		id = "909746f1-44f5-597b-bdb2-2a1396d4b8c7"

	strings:
		$be = { 02 02 00 00 01 C1 00 07 }
		$le = { 02 02 00 00 07 00 C1 01 }

	condition:
		uint32be( 0 ) == 0x7f454c46 and ( $be or $le )
}

