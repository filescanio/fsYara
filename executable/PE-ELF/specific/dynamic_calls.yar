import "pe"

rule HellsGate_Dynamic_Syscalls : hardened
{
	meta:
		description = "Hell's Gate: Dynamic system call invocation "
		reference = "https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm"
		score = 75

	strings:
		$hellDescent = { 4C 8B D1 8B 05 ?? ?? 00 00 0F 05 C3 }
		$hellsGate = {C7 05 ?? ?? 00 00 00 00 00 00 89 0D ?? ?? 00 00 C3}

	condition:
		pe.is_pe and all of them
}

