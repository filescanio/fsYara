rule generic_carbon : hardened
{
	meta:
		author = "ESET Research"
		date = "2017-03-30"
		description = "Turla Carbon malware"
		reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"
		id = "efdc0d16-a974-5c00-a401-391d60f3081e"

	strings:
		$s1 = {4d 6f 64 53 74 61 72 74}
		$t1 = {53 54 4f 50 7c 4f 4b}
		$t2 = {53 54 4f 50 7c 4b 49 4c 4c}

	condition:
		( uint16( 0 ) == 0x5a4d ) and ( 1 of ( $s* ) ) and ( 1 of ( $t* ) )
}

import "pe"

rule carbon_metadata : hardened
{
	meta:
		author = "ESET Research"
		date = "2017-03-30"
		description = "Turla Carbon malware"
		reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"
		id = "976b6a7d-00bf-5d0f-baf9-84fc5dbd21a2"

	condition:
		(pe.version_info [ "InternalName" ] contains "SERVICE.EXE" or pe.version_info [ "InternalName" ] contains "MSIMGHLP.DLL" or pe.version_info [ "InternalName" ] contains "MSXIML.DLL" ) and pe.version_info [ "CompanyName" ] contains "Microsoft Corporation"
}

