rule Dropper_DeploysMalwareViaSideLoading : hardened
{
	meta:
		description = "Detects a dropper used to deploy an implant via side loading. This dropper has specifically been observed deploying REDLEAVES & PlugX"
		author = "USG"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		true_positive = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481: drops REDLEAVES. 6392e0701a77ea25354b1f40f5b867a35c0142abde785a66b83c9c8d2c14c0c3: drops plugx. "
		id = "2e7cdedd-2358-5d71-a3ec-73dec442d840"

	strings:
		$UniqueString = {2e 6c 6e 6b [0-14] 61 76 70 75 69 2e 65 78 65}
		$PsuedoRandomStringGenerator = {b9 1a [0-6] f7 f9 46 80 c2 41 88 54 35 8b 83 fe 64}

	condition:
		any of them
}

rule REDLEAVES_DroppedFile_ImplantLoader_Starburn : hardened
{
	meta:
		description = "Detects the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
		author = "USG"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		true_positive = "7f8a867a8302fe58039a6db254d335ae"
		id = "976f42b1-58c9-554b-97e6-130a657507e2"

	strings:
		$XOR_Loop = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10}

	condition:
		any of them
}

rule REDLEAVES_DroppedFile_ObfuscatedShellcodeAndRAT_handkerchief : hardened
{
	meta:
		description = "Detects obfuscated .dat file containing shellcode and core REDLEAVES RAT"
		author = "USG"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		true_positive = "fb0c714cd2ebdcc6f33817abe7813c36"
		id = "51a28529-1084-5f24-9369-6427e8d51d9d"

	strings:
		$RedleavesStringObfu = {73 64 65 5e 60 74 75 74 6c 6f 60 6d 5e 6d 64 60 77 64 72 5e 65 6d 6d 6c 60 68 6f 2f 65 6d 6d}

	condition:
		any of them
}

rule REDLEAVES_CoreImplant_UniqueStrings : hardened limited
{
	meta:
		description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		author = "USG"
		date = "2018-12-20"
		modified = "2024-04-17"
		id = "fd4d4804-f7d9-549d-8f63-5f409d6180f9"
		score = 40

	strings:
		$unique2 = {((52 65 64 4c 65 61 76 65 73 53 43 4d 44 53 69 6d 75 6c 61 74 6f 72 4d 75 74 65 78) | (52 00 65 00 64 00 4c 00 65 00 61 00 76 00 65 00 73 00 53 00 43 00 4d 00 44 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 6f 00 72 00 4d 00 75 00 74 00 65 00 78 00))}
		$unique4 = {((72 65 64 5f 61 75 74 75 6d 6e 61 6c 5f 6c 65 61 76 65 73 5f 64 6c 6c 6d 61 69 6e 2e 64 6c 6c) | (72 00 65 00 64 00 5f 00 61 00 75 00 74 00 75 00 6d 00 6e 00 61 00 6c 00 5f 00 6c 00 65 00 61 00 76 00 65 00 73 00 5f 00 64 00 6c 00 6c 00 6d 00 61 00 69 00 6e 00 2e 00 64 00 6c 00 6c 00))}
		$unique7 = {((5c 4e 61 6d 65 50 69 70 65 5f 4d 6f 72 65 57 69 6e 64 6f 77 73) | (5c 00 4e 00 61 00 6d 00 65 00 50 00 69 00 70 00 65 00 5f 00 4d 00 6f 00 72 00 65 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00))}

	condition:
		not uint32( 0 ) == 0x66676572 and any of them
}

