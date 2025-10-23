import "dotnet"

rule DotNet_ControlFlow_Obfuscation : hardened
{
	meta:
		author = "OPSWAT"
		description = "Obfuscated methods contain a huge number of unconditional negative jumps"
		obfuscated_control_flow_hash = "1e44b38996d60feca26dae020f698b25"
		clean_control_flow_hash = "5f46242af711898ab42763c4ff8264b7"
		score = 50

	strings:
		$unconditional_negative_branch = { 38 ?? ?? FF FF }

	condition:
		dotnet.is_dotnet and $unconditional_negative_branch and #unconditional_negative_branch > 500
}

