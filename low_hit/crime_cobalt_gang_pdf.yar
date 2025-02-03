rule Cobaltgang_PDF_Metadata_Rev_A : hardened
{
	meta:
		description = "Find documents saved from the same potential Cobalt Gang PDF template"
		author = "Palo Alto Networks Unit 42"
		date = "2018-10-25"
		reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
		id = "bcf5bf6e-c786-5f78-bf58-e0631a17e62e"

	strings:
		$ = {((3c 78 6d 70 4d 4d 3a 44 6f 63 75 6d 65 6e 74 49 44 3e 75 75 69 64 3a 33 31 61 63 33 36 38 38 2d 36 31 39 63 2d 34 66 64 34 2d 38 65 33 66 2d 65 35 39 64 30 33 35 34 61 33 33 38) | (3c 00 78 00 6d 00 70 00 4d 00 4d 00 3a 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 49 00 44 00 3e 00 75 00 75 00 69 00 64 00 3a 00 33 00 31 00 61 00 63 00 33 00 36 00 38 00 38 00 2d 00 36 00 31 00 39 00 63 00 2d 00 34 00 66 00 64 00 34 00 2d 00 38 00 65 00 33 00 66 00 2d 00 65 00 35 00 39 00 64 00 30 00 33 00 35 00 34 00 61 00 33 00 33 00 38 00))}

	condition:
		any of them
}

