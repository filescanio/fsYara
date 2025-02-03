private rule WindowsPE : hardened
{
	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550
}

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {49 73 44 65 62 75 67 67 65 64}

	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {4e 74 47 6c 6f 62 61 6c 46 6c 61 67 73}

	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}

	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74}

	condition:
		any of them
}

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding hardened
{
	meta:
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		weight = 1

	strings:
		$ = {53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 54 68 72 65 61 64}

	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {44 65 62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73}

	condition:
		any of them
}

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {47 65 6e 65 72 61 74 65 43 6f 6e 73 6f 6c 65 43 74 72 6c 45 76 65 6e 74}

	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {53 65 74 43 6f 6e 73 6f 6c 65 43 74 72 6c 48 61 6e 64 6c 65 72}

	condition:
		any of them
}

rule ThreadControl__Context : AntiDebug ThreadControl hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74}

	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {5f 5f 69 6e 76 6f 6b 65 5f 5f 77 61 74 73 6f 6e}

	condition:
		any of them
}

rule SEH__v3 : AntiDebug SEH hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {5f 5f 5f 5f 65 78 63 65 70 74 5f 5f 68 61 6e 64 6c 65 72 33}
		$ = {5f 5f 5f 5f 6c 6f 63 61 6c 5f 5f 75 6e 77 69 6e 64 33}

	condition:
		any of them
}

rule SEH__v4 : AntiDebug SEH hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {5f 5f 5f 5f 65 78 63 65 70 74 5f 5f 68 61 6e 64 6c 65 72 34}
		$ = {5f 5f 5f 5f 6c 6f 63 61 6c 5f 5f 75 6e 77 69 6e 64 34}
		$ = {5f 5f 58 63 70 74 46 69 6c 74 65 72}

	condition:
		any of them
}

rule SEH__vba : AntiDebug SEH hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {76 62 61 45 78 63 65 70 74 48 61 6e 64 6c 65 72}

	condition:
		any of them
}

rule SEH__vectored : AntiDebug SEH hardened
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$ = {41 64 64 56 65 63 74 6f 72 65 64 45 78 63 65 70 74 69 6f 6e 48 61 6e 64 6c 65 72}
		$ = {52 65 6d 6f 76 65 56 65 63 74 6f 72 65 64 45 78 63 65 70 74 69 6f 6e 48 61 6e 64 6c 65 72}

	condition:
		any of them
}

rule SEH_Save : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH hardened
{
	meta:
		author = "Malware Utkonos"
		original_author = "naxonez"
		source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$a = { 64 ff 35 00 00 00 00 }

	condition:
		WindowsPE and $a
}

rule SEH_Init : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH hardened
{
	meta:
		author = "Malware Utkonos"
		original_author = "naxonez"
		source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:
		$a = { 64 A3 00 00 00 00 }
		$b = { 64 89 25 00 00 00 00 }

	condition:
		WindowsPE and ( $a or $b )
}

rule Check_Dlls : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for common sandbox dlls"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$dll1 = {((73 62 69 65 64 6c 6c 2e 64 6c 6c) | (73 00 62 00 69 00 65 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00))}
		$dll2 = {((64 62 67 68 65 6c 70 2e 64 6c 6c) | (64 00 62 00 67 00 68 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00))}
		$dll3 = {((61 70 69 5f 6c 6f 67 2e 64 6c 6c) | (61 00 70 00 69 00 5f 00 6c 00 6f 00 67 00 2e 00 64 00 6c 00 6c 00))}
		$dll4 = {((64 69 72 5f 77 61 74 63 68 2e 64 6c 6c) | (64 00 69 00 72 00 5f 00 77 00 61 00 74 00 63 00 68 00 2e 00 64 00 6c 00 6c 00))}
		$dll5 = {((70 73 74 6f 72 65 63 2e 64 6c 6c) | (70 00 73 00 74 00 6f 00 72 00 65 00 63 00 2e 00 64 00 6c 00 6c 00))}
		$dll6 = {((76 6d 63 68 65 63 6b 2e 64 6c 6c) | (76 00 6d 00 63 00 68 00 65 00 63 00 6b 00 2e 00 64 00 6c 00 6c 00))}
		$dll7 = {((77 70 65 73 70 79 2e 64 6c 6c) | (77 00 70 00 65 00 73 00 70 00 79 00 2e 00 64 00 6c 00 6c 00))}

	condition:
		2 of them
}

rule Check_Qemu_Description : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for QEMU systembiosversion key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((48 41 52 44 57 41 52 45 5c 44 65 73 63 72 69 70 74 69 6f 6e 5c 53 79 73 74 65 6d) | (48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00))}
		$value = {((53 79 73 74 65 6d 42 69 6f 73 56 65 72 73 69 6f 6e) | (53 00 79 00 73 00 74 00 65 00 6d 00 42 00 69 00 6f 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$data = {((51 45 4d 55) | (51 00 45 00 4d 00 55 00))}

	condition:
		all of them
}

rule Check_Qemu_DeviceMap : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for Qemu reg keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((48 41 52 44 57 41 52 45 5c 44 45 56 49 43 45 4d 41 50 5c 53 63 73 69 5c 53 63 73 69 20 50 6f 72 74 20 30 5c 53 63 73 69 20 42 75 73 20 30 5c 54 61 72 67 65 74 20 49 64 20 30 5c 4c 6f 67 69 63 61 6c 20 55 6e 69 74 20 49 64 20 30) | (48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 45 00 56 00 49 00 43 00 45 00 4d 00 41 00 50 00 5c 00 53 00 63 00 73 00 69 00 5c 00 53 00 63 00 73 00 69 00 20 00 50 00 6f 00 72 00 74 00 20 00 30 00 5c 00 53 00 63 00 73 00 69 00 20 00 42 00 75 00 73 00 20 00 30 00 5c 00 54 00 61 00 72 00 67 00 65 00 74 00 20 00 49 00 64 00 20 00 30 00 5c 00 4c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 20 00 55 00 6e 00 69 00 74 00 20 00 49 00 64 00 20 00 30 00))}
		$value = {((49 64 65 6e 74 69 66 69 65 72) | (49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00))}
		$data = {((51 45 4d 55) | (51 00 45 00 4d 00 55 00))}

	condition:
		all of them
}

rule Check_VBox_Description : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox description reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((48 41 52 44 57 41 52 45 5c 44 65 73 63 72 69 70 74 69 6f 6e 5c 53 79 73 74 65 6d) | (48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00))}
		$value = {((53 79 73 74 65 6d 42 69 6f 73 56 65 72 73 69 6f 6e) | (53 00 79 00 73 00 74 00 65 00 6d 00 42 00 69 00 6f 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$data = {((56 42 4f 58) | (56 00 42 00 4f 00 58 00))}

	condition:
		all of them
}

rule Check_VBox_DeviceMap : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox registry keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((48 41 52 44 57 41 52 45 5c 44 45 56 49 43 45 4d 41 50 5c 53 63 73 69 5c 53 63 73 69 20 50 6f 72 74 20 30 5c 53 63 73 69 20 42 75 73 20 30 5c 54 61 72 67 65 74 20 49 64 20 30 5c 4c 6f 67 69 63 61 6c 20 55 6e 69 74 20 49 64 20 30) | (48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 45 00 56 00 49 00 43 00 45 00 4d 00 41 00 50 00 5c 00 53 00 63 00 73 00 69 00 5c 00 53 00 63 00 73 00 69 00 20 00 50 00 6f 00 72 00 74 00 20 00 30 00 5c 00 53 00 63 00 73 00 69 00 20 00 42 00 75 00 73 00 20 00 30 00 5c 00 54 00 61 00 72 00 67 00 65 00 74 00 20 00 49 00 64 00 20 00 30 00 5c 00 4c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 20 00 55 00 6e 00 69 00 74 00 20 00 49 00 64 00 20 00 30 00))}
		$value = {((49 64 65 6e 74 69 66 69 65 72) | (49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00))}
		$data = {((56 42 4f 58) | (56 00 42 00 4f 00 58 00))}

	condition:
		all of them
}

rule Check_VBox_Guest_Additions : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of the guest additions registry key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((53 4f 46 54 57 41 52 45 5c 4f 72 61 63 6c 65 5c 56 69 72 74 75 61 6c 42 6f 78 20 47 75 65 73 74 20 41 64 64 69 74 69 6f 6e 73) | (53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4f 00 72 00 61 00 63 00 6c 00 65 00 5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 20 00 47 00 75 00 65 00 73 00 74 00 20 00 41 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 73 00))}

	condition:
		any of them
}

rule Check_VBox_VideoDrivers : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for reg keys of Vbox video drivers"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((48 41 52 44 57 41 52 45 5c 44 65 73 63 72 69 70 74 69 6f 6e 5c 53 79 73 74 65 6d) | (48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00))}
		$value = {((56 69 64 65 6f 42 69 6f 73 56 65 72 73 69 6f 6e) | (56 00 69 00 64 00 65 00 6f 00 42 00 69 00 6f 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$data = {((56 49 52 54 55 41 4c 42 4f 58) | (56 00 49 00 52 00 54 00 55 00 41 00 4c 00 42 00 4f 00 58 00))}

	condition:
		all of them
}

rule Check_VMWare_DeviceMap : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmWare Registry Keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$key = {((48 41 52 44 57 41 52 45 5c 44 45 56 49 43 45 4d 41 50 5c 53 63 73 69 5c 53 63 73 69 20 50 6f 72 74 20 30 5c 53 63 73 69 20 42 75 73 20 30 5c 54 61 72 67 65 74 20 49 64 20 30 5c 4c 6f 67 69 63 61 6c 20 55 6e 69 74 20 49 64 20 30) | (48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 45 00 56 00 49 00 43 00 45 00 4d 00 41 00 50 00 5c 00 53 00 63 00 73 00 69 00 5c 00 53 00 63 00 73 00 69 00 20 00 50 00 6f 00 72 00 74 00 20 00 30 00 5c 00 53 00 63 00 73 00 69 00 20 00 42 00 75 00 73 00 20 00 30 00 5c 00 54 00 61 00 72 00 67 00 65 00 74 00 20 00 49 00 64 00 20 00 30 00 5c 00 4c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 20 00 55 00 6e 00 69 00 74 00 20 00 49 00 64 00 20 00 30 00))}
		$value = {((49 64 65 6e 74 69 66 69 65 72) | (49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00))}
		$data = {((56 4d 77 61 72 65) | (56 00 4d 00 77 00 61 00 72 00 65 00))}

	condition:
		all of them
}

rule Check_VmTools : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmTools reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$ = {((53 4f 46 54 57 41 52 45 5c 56 4d 77 61 72 65 2c 20 49 6e 63 2e 5c 56 4d 77 61 72 65 20 54 6f 6f 6c 73) | (53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 56 00 4d 00 77 00 61 00 72 00 65 00 2c 00 20 00 49 00 6e 00 63 00 2e 00 5c 00 56 00 4d 00 77 00 61 00 72 00 65 00 20 00 54 00 6f 00 6f 00 6c 00 73 00))}

	condition:
		any of them
}

rule Check_Wine : hardened
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of Wine"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$ = {77 69 6e 65 5f 67 65 74 5f 75 6e 69 78 5f 66 69 6c 65 5f 6e 61 6d 65}

	condition:
		any of them
}

rule vmdetect : hardened limited
{
	meta:
		author = "nex"
		description = "Possibly employs anti-virtualization techniques"

	strings:
		$vmware = {56 4D 58 68}
		$virtualpc = {0F 3F 07 0B}
		$ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
		$vmcheckdll = {45 C7 00 01}
		$redpill = {0F 01 0D 00 00 00 00 C3}
		$vmware1 = {56 4d 58 68}
		$vmware2 = {56 65 6e 5f 56 4d 77 61 72 65 5f}
		$vmware3 = {50 72 6f 64 5f 56 4d 77 61 72 65 5f 56 69 72 74 75 61 6c 5f}
		$vmware4 = {68 67 66 73 2e 73 79 73}
		$vmware5 = {6d 68 67 66 73 2e 73 79 73}
		$vmware6 = {70 72 6c 65 74 68 2e 73 79 73}
		$vmware7 = {70 72 6c 66 73 2e 73 79 73}
		$vmware8 = {70 72 6c 6d 6f 75 73 65 2e 73 79 73}
		$vmware9 = {70 72 6c 76 69 64 65 6f 2e 73 79 73}
		$vmware10 = {70 72 6c 5f 70 76 33 32 2e 73 79 73}
		$vmware11 = {76 70 63 2d 73 33 2e 73 79 73}
		$vmware12 = {76 6d 73 72 76 63 2e 73 79 73}
		$vmware13 = {76 6d 78 38 36 2e 73 79 73}
		$vmware14 = {76 6d 6e 65 74 2e 73 79 73}
		$vmware15 = {76 6d 69 63 68 65 61 72 74 62 65 61 74}
		$vmware16 = {76 6d 69 63 76 73 73}
		$vmware17 = {76 6d 69 63 73 68 75 74 64 6f 77 6e}
		$vmware18 = {76 6d 69 63 65 78 63 68 61 6e 67 65}
		$vmware19 = {76 6d 64 65 62 75 67}
		$vmware20 = {76 6d 6d 6f 75 73 65}
		$vmware21 = {76 6d 74 6f 6f 6c 73}
		$vmware22 = {56 4d 4d 45 4d 43 54 4c}
		$vmware23 = {76 6d 78 38 36}
		$vmware24 = {76 6d 77 61 72 65}
		$virtualpc1 = {76 70 63 62 75 73}
		$virtualpc2 = {76 70 63 2d 73 33}
		$virtualpc3 = {76 70 63 75 68 75 62}
		$virtualpc4 = {6d 73 76 6d 6d 6f 75 66}
		$xen1 = {78 65 6e 65 76 74 63 68 6e}
		$xen2 = {78 65 6e 6e 65 74}
		$xen3 = {78 65 6e 6e 65 74 36}
		$xen4 = {78 65 6e 73 76 63}
		$xen5 = {78 65 6e 76 64 62}
		$xen6 = {58 65 6e 56 4d 4d}
		$virtualbox1 = {56 42 6f 78 48 6f 6f 6b 2e 64 6c 6c}
		$virtualbox2 = {56 42 6f 78 53 65 72 76 69 63 65}
		$virtualbox3 = {56 42 6f 78 54 72 61 79}
		$virtualbox4 = {56 42 6f 78 4d 6f 75 73 65}
		$virtualbox5 = {56 42 6f 78 47 75 65 73 74}
		$virtualbox6 = {56 42 6f 78 53 46}
		$virtualbox7 = {56 42 6f 78 47 75 65 73 74 41 64 64 69 74 69 6f 6e 73}
		$virtualbox8 = {56 42 4f 58 20 48 41 52 44 44 49 53 4b}
		$vmware_mac_1a = {30 30 2d 30 35 2d 36 39}
		$vmware_mac_1b = {30 30 3a 30 35 3a 36 39}
		$vmware_mac_1c = {30 30 30 35 36 39}
		$vmware_mac_2a = {30 30 2d 35 30 2d 35 36}
		$vmware_mac_2b = {30 30 3a 35 30 3a 35 36}
		$vmware_mac_2c = {30 30 35 30 35 36}
		$vmware_mac_3a = {30 30 2d 30 43 2d 32 39}
		$vmware_mac_3b = {30 30 3a 30 43 3a 32 39}
		$vmware_mac_3c = {30 30 30 43 32 39}
		$vmware_mac_4a = {30 30 2d 31 43 2d 31 34}
		$vmware_mac_4b = {30 30 3a 31 43 3a 31 34}
		$vmware_mac_4c = {30 30 31 43 31 34}
		$virtualbox_mac_1a = {30 38 2d 30 30 2d 32 37}
		$virtualbox_mac_1b = {30 38 3a 30 30 3a 32 37}
		$virtualbox_mac_1c = {30 38 30 30 32 37}

	condition:
		any of them
}

import "pe"

rule Check_Debugger : hardened
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	condition:
		pe.imports( "kernel32.dll" , "CheckRemoteDebuggerPresent" ) and pe.imports ( "kernel32.dll" , "IsDebuggerPresent" )
}

import "pe"

rule Check_DriveSize : hardened limited
{
	meta:
		Author = "Nick Hoffman"
		Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$physicaldrive = {((5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30) | (5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00))}
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15}

	condition:
		pe.imports( "kernel32.dll" , "CreateFileA" ) and pe.imports ( "kernel32.dll" , "DeviceIoControl" ) and $dwIoControlCode and $physicaldrive
}

import "pe"

rule Check_FilePaths : hardened
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for filepaths containing popular sandbox names"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$path1 = {((53 41 4e 44 42 4f 58) | (53 00 41 00 4e 00 44 00 42 00 4f 00 58 00))}
		$path2 = {((5c 53 41 4d 50 4c 45) | (5c 00 53 00 41 00 4d 00 50 00 4c 00 45 00))}
		$path3 = {((5c 56 49 52 55 53) | (5c 00 56 00 49 00 52 00 55 00 53 00))}

	condition:
		all of ( $path* ) and pe.imports ( "kernel32.dll" , "GetModuleFileNameA" )
}

import "pe"

rule Check_UserNames : hardened
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for malware checking for common sandbox usernames"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$user1 = {((4d 41 4c 54 45 53 54) | (4d 00 41 00 4c 00 54 00 45 00 53 00 54 00))}
		$user2 = {((54 45 51 55 49 4c 41 42 4f 4f 4d 42 4f 4f 4d) | (54 00 45 00 51 00 55 00 49 00 4c 00 41 00 42 00 4f 00 4f 00 4d 00 42 00 4f 00 4f 00 4d 00))}
		$user3 = {((53 41 4e 44 42 4f 58) | (53 00 41 00 4e 00 44 00 42 00 4f 00 58 00))}
		$user4 = {((56 49 52 55 53) | (56 00 49 00 52 00 55 00 53 00))}
		$user5 = {((4d 41 4c 57 41 52 45) | (4d 00 41 00 4c 00 57 00 41 00 52 00 45 00))}

	condition:
		all of ( $user* ) and pe.imports ( "advapi32.dll" , "GetUserNameA" )
}

import "pe"

rule Check_OutputDebugStringA_iat : hardened
{
	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"

	condition:
		pe.imports( "kernel32.dll" , "OutputDebugStringA" )
}

import "pe"

rule Check_FindWindowA_iat : hardened
{
	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if FindWindowA() is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

	strings:
		$ollydbg = {4f 4c 4c 59 44 42 47}
		$windbg = {57 69 6e 44 62 67 46 72 61 6d 65 43 6c 61 73 73}

	condition:
		pe.imports( "user32.dll" , "FindWindowA" ) and ( $ollydbg or $windbg )
}

import "pe"

rule DebuggerCheck__MemoryWorkingSet : AntiDebug DebuggerCheck hardened
{
	meta:
		author = "Fernando Mercês"
		date = "2015-06"
		description = "Anti-debug process memory working set size check"
		reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

	condition:
		pe.imports( "kernel32.dll" , "K32GetProcessMemoryInfo" ) and pe.imports ( "kernel32.dll" , "GetCurrentProcess" )
}

rule WMI_VM_Detect : WMI_VM_Detect hardened limited
{
	meta:
		version = 2
		threat = "Using WMI to detect virtual machines via querying video card information"
		behaviour_class = "Evasion"
		author = "Joe Giron"
		date = "2015-09-25"
		description = "Detection of Virtual Appliances through the use of WMI for use of evasion."

	strings:
		$selstr = {((53 45 4c 45 43 54 20 44 65 73 63 72 69 70 74 69 6f 6e 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72) | (53 00 45 00 4c 00 45 00 43 00 54 00 20 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 69 00 64 00 65 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00))}
		$selstr2 = {((53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72) | (53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 69 00 64 00 65 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00))}
		$vm1 = {((76 69 72 74 75 61 6c 62 6f 78 20 67 72 61 70 68 69 63 73 20 61 64 61 70 74 65 72) | (76 00 69 00 72 00 74 00 75 00 61 00 6c 00 62 00 6f 00 78 00 20 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 73 00 20 00 61 00 64 00 61 00 70 00 74 00 65 00 72 00))}
		$vm2 = {((76 6d 77 61 72 65 20 73 76 67 61 20 69 69) | (76 00 6d 00 77 00 61 00 72 00 65 00 20 00 73 00 76 00 67 00 61 00 20 00 69 00 69 00))}
		$vm3 = {((76 6d 20 61 64 64 69 74 69 6f 6e 73 20 73 33 20 74 72 69 6f 33 32 2f 36 34) | (76 00 6d 00 20 00 61 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 73 00 20 00 73 00 33 00 20 00 74 00 72 00 69 00 6f 00 33 00 32 00 2f 00 36 00 34 00))}
		$vm4 = {((70 61 72 61 6c 6c 65 6c) | (70 00 61 00 72 00 61 00 6c 00 6c 00 65 00 6c 00))}
		$vm5 = {((72 65 6d 6f 74 65 66 78) | (72 00 65 00 6d 00 6f 00 74 00 65 00 66 00 78 00))}
		$vm6 = {((63 69 72 72 75 73 20 6c 6f 67 69 63) | (63 00 69 00 72 00 72 00 75 00 73 00 20 00 6c 00 6f 00 67 00 69 00 63 00))}
		$vm7 = {((6d 61 74 72 6f 78) | (6d 00 61 00 74 00 72 00 6f 00 78 00))}

	condition:
		any of ( $selstr* ) and any of ( $vm* )
}

rule anti_dbg : hardened limited
{
	meta:
		author = "x0r"
		description = "Checks if being debugged"
		version = "0.2"

	strings:
		$d1 = {4b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$c1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74}
		$c2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74}
		$c3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67}
		$c4 = {43 6f 6e 74 69 6e 75 65 44 65 62 75 67 45 76 65 6e 74}
		$c5 = {44 65 62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73}

	condition:
		$d1 and 1 of ( $c* )
}

rule anti_dbgtools : hardened limited
{
	meta:
		author = "x0r"
		description = "Checks for the presence of known debug tools"
		version = "0.1"

	strings:
		$f1 = {70 72 6f 63 65 78 70 2e 65 78 65}
		$f2 = {70 72 6f 63 6d 6f 6e 2e 65 78 65}
		$f3 = {70 72 6f 63 65 73 73 6d 6f 6e 69 74 6f 72 2e 65 78 65}
		$f4 = {77 69 72 65 73 68 61 72 6b 2e 65 78 65}
		$f5 = {66 69 64 64 6c 65 72 2e 65 78 65}
		$f6 = {77 69 6e 64 62 67 2e 65 78 65}
		$f7 = {6f 6c 6c 79 64 62 67 2e 65 78 65}
		$f8 = {77 69 6e 68 65 78 2e 65 78 65}
		$f9 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 2e 65 78 65}
		$f10 = {68 69 65 77 33 32 2e 65 78 65}
		$c11 = {5c 5c 2e 5c 4e 54 49 43 45}
		$c12 = {5c 5c 2e 5c 53 49 43 45}
		$c13 = {5c 5c 2e 5c 53 79 73 65 72}
		$c14 = {5c 5c 2e 5c 53 79 73 65 72 42 6f 6f 74}
		$c15 = {5c 5c 2e 5c 53 79 73 65 72 44 62 67 4d 73 67}

	condition:
		any of them
}

rule antisb_joesanbox : hardened limited
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for Joe Sandbox"
		version = "0.1"

	strings:
		$p1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}
		$c1 = {52 65 67 51 75 65 72 79 56 61 6c 75 65}
		$s1 = {35 35 32 37 34 2d 36 34 30 2d 32 36 37 33 30 36 34 2d 32 33 39 35 30}

	condition:
		all of them
}

rule antisb_anubis : hardened limited
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for Anubis"
		version = "0.1"

	strings:
		$p1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}
		$c1 = {52 65 67 51 75 65 72 79 56 61 6c 75 65}
		$s1 = {37 36 34 38 37 2d 33 33 37 2d 38 34 32 39 39 35 35 2d 32 32 36 31 34}
		$s2 = {37 36 34 38 37 2d 36 34 30 2d 31 34 35 37 32 33 36 2d 32 33 38 33 37}

	condition:
		$p1 and $c1 and 1 of ( $s* )
}

rule antisb_threatExpert : hardened limited
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for ThreatExpert"
		version = "0.1"

	strings:
		$f1 = {64 62 67 68 65 6c 70 2e 64 6c 6c}

	condition:
		all of them
}

rule antisb_sandboxie : hardened limited
{
	meta:
		author = "x0r"
		description = "Anti-Sandbox checks for Sandboxie"
		version = "0.1"

	strings:
		$f1 = {53 62 69 65 44 4c 4c 2e 64 6c 6c}

	condition:
		all of them
}

rule antivm_virtualbox : hardened limited
{
	meta:
		author = "x0r"
		description = "AntiVM checks for VirtualBox"
		version = "0.1"

	strings:
		$s1 = {56 42 6f 78 53 65 72 76 69 63 65 2e 65 78 65}

	condition:
		any of them
}

rule antivm_vmware : hardened limited
{
	meta:
		author = "x0r"
		description = "AntiVM checks for VMWare"
		version = "0.1"

	strings:
		$s1 = {76 6d 77 61 72 65 2e 65 78 65}
		$s2 = {76 6d 77 61 72 65 2d 61 75 74 68 64 2e 65 78 65}
		$s3 = {76 6d 77 61 72 65 2d 68 6f 73 74 64 2e 65 78 65}
		$s4 = {76 6d 77 61 72 65 2d 74 72 61 79 2e 65 78 65}
		$s5 = {76 6d 77 61 72 65 2d 76 6d 78 2e 65 78 65}
		$s6 = {76 6d 6e 65 74 64 68 63 70 2e 65 78 65}
		$s7 = {76 70 78 63 6c 69 65 6e 74 2e 65 78 65}
		$s8 = { b868584d56bb00000000b90a000000ba58560000ed }

	condition:
		any of them
}

rule antivm_bios : hardened limited
{
	meta:
		author = "x0r"
		description = "AntiVM checks for Bios version"
		version = "0.2"

	strings:
		$p1 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d}
		$p2 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 42 49 4f 53}
		$c1 = {52 65 67 51 75 65 72 79 56 61 6c 75 65}
		$r1 = {53 79 73 74 65 6d 42 69 6f 73 56 65 72 73 69 6f 6e}
		$r2 = {56 69 64 65 6f 42 69 6f 73 56 65 72 73 69 6f 6e}
		$r3 = {53 79 73 74 65 6d 4d 61 6e 75 66 61 63 74 75 72 65 72}

	condition:
		1 of ( $p* ) and 1 of ( $c* ) and 1 of ( $r* )
}

rule disable_antivirus : hardened limited
{
	meta:
		author = "x0r"
		description = "Disable AntiVirus"
		version = "0.2"

	strings:
		$p1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 44 69 73 61 6c 6c 6f 77 52 75 6e}
		$p2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c}
		$p3 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72}
		$c1 = {52 65 67 53 65 74 56 61 6c 75 65}
		$r1 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79}
		$r2 = {44 6f 6e 74 52 65 70 6f 72 74 49 6e 66 65 63 74 69 6f 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e}
		$r3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65}
		$r4 = {52 75 6e 49 6e 76 61 6c 69 64 53 69 67 6e 61 74 75 72 65 73}
		$r5 = {41 6e 74 69 56 69 72 75 73 4f 76 65 72 72 69 64 65}
		$r6 = {43 68 65 63 6b 45 78 65 53 69 67 6e 61 74 75 72 65 73}
		$f1 = {62 6c 61 63 6b 64 2e 65 78 65}
		$f2 = {62 6c 61 63 6b 69 63 65 2e 65 78 65}
		$f3 = {6c 6f 63 6b 64 6f 77 6e 2e 65 78 65}
		$f4 = {6c 6f 63 6b 64 6f 77 6e 32 30 30 30 2e 65 78 65}
		$f5 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65}
		$f6 = {74 73 6b 69 6c 6c 2e 65 78 65}
		$f7 = {73 6d 63 2e 65 78 65}
		$f8 = {73 6e 69 66 66 65 6d 2e 65 78 65}
		$f9 = {7a 61 70 72 6f 2e 65 78 65}
		$f10 = {7a 6c 63 6c 69 65 6e 74 2e 65 78 65}
		$f11 = {7a 6f 6e 65 61 6c 61 72 6d 2e 65 78 65}

	condition:
		($c1 and $p1 and 1 of ( $f* ) ) or ( $c1 and $p2 ) or 1 of ( $r* ) or $p3
}

rule disable_uax : hardened limited
{
	meta:
		author = "x0r"
		description = "Disable User Access Control"
		version = "0.1"

	strings:
		$p1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72}
		$r1 = {55 41 43 44 69 73 61 62 6c 65 4e 6f 74 69 66 79}

	condition:
		all of them
}

rule disable_firewall : hardened limited
{
	meta:
		author = "x0r"
		description = "Disable Firewall"
		version = "0.1"

	strings:
		$p1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79}
		$c1 = {52 65 67 53 65 74 56 61 6c 75 65}
		$r1 = {46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79}
		$r2 = {45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c}
		$r3 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79}
		$s1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d}

	condition:
		(1 of ( $p* ) and $c1 and 1 of ( $r* ) ) or $s1
}

rule disable_registry : hardened limited
{
	meta:
		author = "x0r"
		description = "Disable Registry editor"
		version = "0.1"

	strings:
		$p1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d}
		$c1 = {52 65 67 53 65 74 56 61 6c 75 65}
		$r1 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73}
		$r2 = {44 69 73 61 62 6c 65 52 65 67 65 64 69 74}

	condition:
		1 of ( $p* ) and $c1 and 1 of ( $r* )
}

rule disable_dep : hardened
{
	meta:
		author = "x0r"
		description = "Bypass DEP"
		version = "0.1"

	strings:
		$c1 = {45 6e 61 62 6c 65 45 78 65 63 75 74 65 50 72 6f 74 65 63 74 69 6f 6e 53 75 70 70 6f 72 74}
		$c2 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$c3 = {56 69 72 74 75 61 6c 50 72 6f 63 74 65 63 74 45 78}
		$c4 = {53 65 74 50 72 6f 63 65 73 73 44 45 50 50 6f 6c 69 63 79}
		$c5 = {5a 77 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79}

	condition:
		any of them
}

rule disable_taskmanager : hardened limited
{
	meta:
		author = "x0r"
		description = "Disable Task Manager"
		version = "0.1"

	strings:
		$p1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d}
		$r1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72}

	condition:
		1 of ( $p* ) and 1 of ( $r* )
}

rule check_patchlevel : hardened limited
{
	meta:
		author = "x0r"
		description = "Check if hotfix are applied"
		version = "0.1"

	strings:
		$p1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 48 6f 74 66 69 78}

	condition:
		any of them
}

rule win_hook : hardened limited
{
	meta:
		author = "x0r"
		description = "Affect hook table"
		version = "0.1"

	strings:
		$f1 = {75 73 65 72 33 32 2e 64 6c 6c}
		$c1 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78}
		$c2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41}
		$c3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78}

	condition:
		$f1 and 1 of ( $c* )
}

rule vmdetect_misc : vmdetect hardened limited
{
	meta:
		author = "@abhinavbom"
		maltype = "NA"
		version = "0.1"
		date = "31/10/2015"
		description = "Following Rule is referenced from AlienVault's Yara rule repository.This rule contains additional processes and driver names."

	strings:
		$vbox1 = {((56 42 6f 78 53 65 72 76 69 63 65) | (56 00 42 00 6f 00 78 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00))}
		$vbox2 = {((56 42 6f 78 54 72 61 79) | (56 00 42 00 6f 00 78 00 54 00 72 00 61 00 79 00))}
		$vbox3 = {((53 4f 46 54 57 41 52 45 5c 4f 72 61 63 6c 65 5c 56 69 72 74 75 61 6c 42 6f 78 20 47 75 65 73 74 20 41 64 64 69 74 69 6f 6e 73) | (53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4f 00 72 00 61 00 63 00 6c 00 65 00 5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 20 00 47 00 75 00 65 00 73 00 74 00 20 00 41 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 73 00))}
		$vbox4 = {((53 4f 46 54 57 41 52 45 5c 5c 4f 72 61 63 6c 65 5c 5c 56 69 72 74 75 61 6c 42 6f 78 20 47 75 65 73 74 20 41 64 64 69 74 69 6f 6e 73) | (53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 5c 00 4f 00 72 00 61 00 63 00 6c 00 65 00 5c 00 5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 20 00 47 00 75 00 65 00 73 00 74 00 20 00 41 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 73 00))}
		$wine1 = {((77 69 6e 65 5f 67 65 74 5f 75 6e 69 78 5f 66 69 6c 65 5f 6e 61 6d 65) | (77 00 69 00 6e 00 65 00 5f 00 67 00 65 00 74 00 5f 00 75 00 6e 00 69 00 78 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 6e 00 61 00 6d 00 65 00))}
		$vmware1 = {((76 6d 6d 6f 75 73 65 2e 73 79 73) | (76 00 6d 00 6d 00 6f 00 75 00 73 00 65 00 2e 00 73 00 79 00 73 00))}
		$vmware2 = {((56 4d 77 61 72 65 20 56 69 72 74 75 61 6c 20 49 44 45 20 48 61 72 64 20 44 72 69 76 65) | (56 00 4d 00 77 00 61 00 72 00 65 00 20 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 20 00 49 00 44 00 45 00 20 00 48 00 61 00 72 00 64 00 20 00 44 00 72 00 69 00 76 00 65 00))}
		$miscvm1 = {((53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 44 69 73 6b 5c 45 6e 75 6d) | (53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 69 00 73 00 6b 00 5c 00 45 00 6e 00 75 00 6d 00))}
		$miscvm2 = {((53 59 53 54 45 4d 5c 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 5c 53 65 72 76 69 63 65 73 5c 5c 44 69 73 6b 5c 5c 45 6e 75 6d) | (53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 5c 00 44 00 69 00 73 00 6b 00 5c 00 5c 00 45 00 6e 00 75 00 6d 00))}
		$vmdrv1 = {((68 67 66 73 2e 73 79 73) | (68 00 67 00 66 00 73 00 2e 00 73 00 79 00 73 00))}
		$vmdrv2 = {((76 6d 68 67 66 73 2e 73 79 73) | (76 00 6d 00 68 00 67 00 66 00 73 00 2e 00 73 00 79 00 73 00))}
		$vmdrv3 = {((70 72 6c 65 74 68 2e 73 79 73) | (70 00 72 00 6c 00 65 00 74 00 68 00 2e 00 73 00 79 00 73 00))}
		$vmdrv4 = {((70 72 6c 66 73 2e 73 79 73) | (70 00 72 00 6c 00 66 00 73 00 2e 00 73 00 79 00 73 00))}
		$vmdrv5 = {((70 72 6c 6d 6f 75 73 65 2e 73 79 73) | (70 00 72 00 6c 00 6d 00 6f 00 75 00 73 00 65 00 2e 00 73 00 79 00 73 00))}
		$vmdrv6 = {((70 72 6c 76 69 64 65 6f 2e 73 79 73) | (70 00 72 00 6c 00 76 00 69 00 64 00 65 00 6f 00 2e 00 73 00 79 00 73 00))}
		$vmdrv7 = {((70 72 6c 5f 70 76 33 32 2e 73 79 73) | (70 00 72 00 6c 00 5f 00 70 00 76 00 33 00 32 00 2e 00 73 00 79 00 73 00))}
		$vmdrv8 = {((76 70 63 2d 73 33 2e 73 79 73) | (76 00 70 00 63 00 2d 00 73 00 33 00 2e 00 73 00 79 00 73 00))}
		$vmdrv9 = {((76 6d 73 72 76 63 2e 73 79 73) | (76 00 6d 00 73 00 72 00 76 00 63 00 2e 00 73 00 79 00 73 00))}
		$vmdrv10 = {((76 6d 78 38 36 2e 73 79 73) | (76 00 6d 00 78 00 38 00 36 00 2e 00 73 00 79 00 73 00))}
		$vmdrv11 = {((76 6d 6e 65 74 2e 73 79 73) | (76 00 6d 00 6e 00 65 00 74 00 2e 00 73 00 79 00 73 00))}
		$vmsrvc1 = {((76 6d 69 63 68 65 61 72 74 62 65 61 74) | (76 00 6d 00 69 00 63 00 68 00 65 00 61 00 72 00 74 00 62 00 65 00 61 00 74 00))}
		$vmsrvc2 = {((76 6d 69 63 76 73 73) | (76 00 6d 00 69 00 63 00 76 00 73 00 73 00))}
		$vmsrvc3 = {((76 6d 69 63 73 68 75 74 64 6f 77 6e) | (76 00 6d 00 69 00 63 00 73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00))}
		$vmsrvc4 = {((76 6d 69 63 65 78 63 68 61 6e 67 65) | (76 00 6d 00 69 00 63 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00))}
		$vmsrvc5 = {((76 6d 63 69) | (76 00 6d 00 63 00 69 00))}
		$vmsrvc6 = {((76 6d 64 65 62 75 67) | (76 00 6d 00 64 00 65 00 62 00 75 00 67 00))}
		$vmsrvc7 = {((76 6d 6d 6f 75 73 65) | (76 00 6d 00 6d 00 6f 00 75 00 73 00 65 00))}
		$vmsrvc8 = {((56 4d 54 6f 6f 6c 73) | (56 00 4d 00 54 00 6f 00 6f 00 6c 00 73 00))}
		$vmsrvc9 = {((56 4d 4d 45 4d 43 54 4c) | (56 00 4d 00 4d 00 45 00 4d 00 43 00 54 00 4c 00))}
		$vmsrvc10 = {((76 6d 77 61 72 65) | (76 00 6d 00 77 00 61 00 72 00 65 00))}
		$vmsrvc11 = {((76 6d 78 38 36) | (76 00 6d 00 78 00 38 00 36 00))}
		$vmsrvc12 = {((76 70 63 62 75 73) | (76 00 70 00 63 00 62 00 75 00 73 00))}
		$vmsrvc13 = {((76 70 63 2d 73 33) | (76 00 70 00 63 00 2d 00 73 00 33 00))}
		$vmsrvc14 = {((76 70 63 75 68 75 62) | (76 00 70 00 63 00 75 00 68 00 75 00 62 00))}
		$vmsrvc15 = {((6d 73 76 6d 6d 6f 75 66) | (6d 00 73 00 76 00 6d 00 6d 00 6f 00 75 00 66 00))}
		$vmsrvc16 = {((56 42 6f 78 4d 6f 75 73 65) | (56 00 42 00 6f 00 78 00 4d 00 6f 00 75 00 73 00 65 00))}
		$vmsrvc17 = {((56 42 6f 78 47 75 65 73 74) | (56 00 42 00 6f 00 78 00 47 00 75 00 65 00 73 00 74 00))}
		$vmsrvc18 = {((56 42 6f 78 53 46) | (56 00 42 00 6f 00 78 00 53 00 46 00))}
		$vmsrvc19 = {((78 65 6e 65 76 74 63 68 6e) | (78 00 65 00 6e 00 65 00 76 00 74 00 63 00 68 00 6e 00))}
		$vmsrvc20 = {((78 65 6e 6e 65 74) | (78 00 65 00 6e 00 6e 00 65 00 74 00))}
		$vmsrvc21 = {((78 65 6e 6e 65 74 36) | (78 00 65 00 6e 00 6e 00 65 00 74 00 36 00))}
		$vmsrvc22 = {((78 65 6e 73 76 63) | (78 00 65 00 6e 00 73 00 76 00 63 00))}
		$vmsrvc23 = {((78 65 6e 76 64 62) | (78 00 65 00 6e 00 76 00 64 00 62 00))}
		$miscproc1 = {((76 6d 77 61 72 65 32) | (76 00 6d 00 77 00 61 00 72 00 65 00 32 00))}
		$miscproc2 = {((76 6d 6f 75 6e 74 32) | (76 00 6d 00 6f 00 75 00 6e 00 74 00 32 00))}
		$miscproc3 = {((76 6d 75 73 72 76 63) | (76 00 6d 00 75 00 73 00 72 00 76 00 63 00))}
		$miscproc4 = {((76 6d 73 72 76 63) | (76 00 6d 00 73 00 72 00 76 00 63 00))}
		$miscproc5 = {((76 62 6f 78 73 65 72 76 69 63 65) | (76 00 62 00 6f 00 78 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00))}
		$miscproc6 = {((76 62 6f 78 74 72 61 79) | (76 00 62 00 6f 00 78 00 74 00 72 00 61 00 79 00))}
		$miscproc7 = {((78 65 6e 73 65 72 76 69 63 65) | (78 00 65 00 6e 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00))}
		$vmware_mac_1a = {30 30 2d 30 35 2d 36 39}
		$vmware_mac_1b = {30 30 3a 30 35 3a 36 39}
		$vmware_mac_2a = {30 30 2d 35 30 2d 35 36}
		$vmware_mac_2b = {30 30 3a 35 30 3a 35 36}
		$vmware_mac_3a = {30 30 2d 30 43 2d 32 39}
		$vmware_mac_3b = {30 30 3a 30 43 3a 32 39}
		$vmware_mac_4a = {30 30 2d 31 43 2d 31 34}
		$vmware_mac_4b = {30 30 3a 31 43 3a 31 34}
		$virtualbox_mac_1a = {30 38 2d 30 30 2d 32 37}
		$virtualbox_mac_1b = {30 38 3a 30 30 3a 32 37}

	condition:
		2 of them
}

