rule EXPL_CVE_2021_40444_Document_Rels_XML : hardened limited
{
	meta:
		description = "Detects indicators found in weaponized documents that exploit CVE-2021-40444"
		author = "Jeremy Brown / @alteredbytes"
		reference = "https://twitter.com/AlteredBytes/status/1435811407249952772"
		date = "2021-09-10"
		id = "812bb68e-71ea-5a9a-8d39-ab99fdaa6c58"

	strings:
		$b1 = {2f 72 65 6c 61 74 69 6f 6e 73 68 69 70 73 2f 6f 6c 65 4f 62 6a 65 63 74}
		$b2 = {2f 72 65 6c 61 74 69 6f 6e 73 68 69 70 73 2f 61 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65}
		$c1 = {54 61 72 67 65 74 3d 22 6d 68 74 6d 6c 3a 68 74 74 70}
		$c2 = {21 78 2d 75 73 63 3a 68 74 74 70}
		$c3 = {54 61 72 67 65 74 4d 6f 64 65 3d 22 45 78 74 65 72 6e 61 6c 22}

	condition:
		uint32( 0 ) == 0x6D783F3C and filesize < 10KB and 1 of ( $b* ) and all of ( $c* )
}

rule EXPL_MAL_MalDoc_OBFUSCT_MHTML_Sep21_1 : hardened
{
	meta:
		description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
		date = "2021-09-18"
		score = 90
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		id = "781cfd61-d5ac-58e5-868f-dbd2a2df3500"

	strings:
		$h1 = {((3c 3f 78 6d 6c 20) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00))}
		$s1 = {((31 30 39 3b 26 23 31 30 34 3b 26 23 31 31 36 3b 26 23 31 30 39 3b 26 23 31 30 38 3b 26 23 35 38 3b 26 23 31 30 34 3b 26 23 31 31 36 3b 26 23 31 30 39 3b 26 23 31 30 38) | (31 00 30 00 39 00 3b 00 26 00 23 00 31 00 30 00 34 00 3b 00 26 00 23 00 31 00 31 00 36 00 3b 00 26 00 23 00 31 00 30 00 39 00 3b 00 26 00 23 00 31 00 30 00 38 00 3b 00 26 00 23 00 35 00 38 00 3b 00 26 00 23 00 31 00 30 00 34 00 3b 00 26 00 23 00 31 00 31 00 36 00 3b 00 26 00 23 00 31 00 30 00 39 00 3b 00 26 00 23 00 31 00 30 00 38 00))}

	condition:
		filesize < 25KB and all of them
}

rule EXPL_XML_Encoded_CVE_2021_40444 : hardened
{
	meta:
		author = "James E.C, Proofpoint"
		description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		date = "2021-09-18"
		modified = "2021-09-19"
		score = 70
		hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E"
		hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69"
		id = "4bf9ec64-c662-5c8f-9e58-12a7412ef07d"

	strings:
		$h1 = {((3c 3f 78 6d 6c 20) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00))}
		$t_xml_r = /Target[\s]{0,20}=[\s]{0,20}\["']([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/
		$t_mode_r = /TargetMode[\s]{0,20}=[\s]{0,20}\["']([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/

	condition:
		filesize < 500KB and $h1 and all of ( $t_* )
}

rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_1 : Windows CVE hardened
{
	meta:
		author = "Florian Roth (Nextron Systems)"
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		date = "2021-09-18"
		score = 65
		hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E"
		hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69"
		id = "ffcaf270-f574-5692-90e5-6776c34eb71b"

	strings:
		$h1 = {((3c 3f 78 6d 6c 20) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00))}
		$xml_e = {((54 61 72 67 65 74 3d 22 26 23) | (54 00 61 00 72 00 67 00 65 00 74 00 3d 00 22 00 26 00 23 00))}
		$xml_mode_1 = {((54 61 72 67 65 74 4d 6f 64 65 3d 22 26 23) | (54 00 61 00 72 00 67 00 65 00 74 00 4d 00 6f 00 64 00 65 00 3d 00 22 00 26 00 23 00))}

	condition:
		filesize < 500KB and $h1 and 1 of ( $xml* )
}

rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_2 : Windows CVE hardened
{
	meta:
		author = "Florian Roth (Nextron Systems)"
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		date = "2021-09-18"
		score = 65
		id = "c3c5ec4f-5d2a-523c-bd4b-b75c04bac87d"

	strings:
		$h1 = {((3c 3f 78 6d 6c 20) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00))}
		$a1 = {((54 61 72 67 65 74) | (54 00 61 00 72 00 67 00 65 00 74 00))}
		$a2 = {((54 61 72 67 65 74 4d 6f 64 65) | (54 00 61 00 72 00 67 00 65 00 74 00 4d 00 6f 00 64 00 65 00))}
		$xml_e = {((26 23 78 30 30 30 30) | (26 00 23 00 78 00 30 00 30 00 30 00 30 00))}

	condition:
		filesize < 500KB and all of them
}

