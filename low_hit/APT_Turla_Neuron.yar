rule MW_neuron2_decryption_routine : Turla APT hardened
{
	meta:
		description = "Rule for detection of Neuron2 based on the routine used to decrypt the payload"
		author = "NCSC"
		family = "Turla"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		date = "2018-01-18"
		hash1 = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"

	strings:
		$ = {81 FA FF 00 00 00 0F B6 C2 0F 46 C2 0F B6 0C 04 48 03 CF 0F B6 D1 8A 0C 14 8D 50 01 43 32 0C 13 41 88 0A 49 FF C2 49 83 E9 01}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

