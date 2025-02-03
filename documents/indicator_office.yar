rule INDICATOR_RTF_EXPLOIT_CVE_2017_0199_1 : hardened limited
{
	meta:
		description = "Detects RTF documents potentially exploiting CVE-2017-0199"
		author = "ditekSHen"

	strings:
		$urlmoniker3 = { 45 0a 30 0a 43 0a 39 0a 45 0a 41 0a 37 0a 39 0a 
                         46 0a 39 0a 42 0a 41 0a 43 0a 45 0a 31 0a 31 0a 
                         38 0a 43 0a 38 0a 32 0a 30 0a 30 0a 41 0a 41 0a 
                         30 0a 30 0a 34 0a 42 0a 41 0a 39 0a 30 0a 42 }
		$urlmoniker4 = { 45 0d 0a 30 0d 0a 43 0d 0a 39 0d 0a 45 0d 0a 41
                         0d 0a 37 0d 0a 39 0d 0a 46 0d 0a 39 0d 0a 42 0d 
                         0a 41 0d 0a 43 0d 0a 45 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 43 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 41 0d 0a 41 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 42 0d 0a 41 0d 0a 39 0d 0a 30 0d 0a 42 }
		$urlmoniker6 = { 65 0a 30 0a 63 0a 39 0a 65 0a 61 0a 37 0a 39 0a
                         66 0a 39 0a 62 0a 61 0a 63 0a 65 0a 31 0a 31 0a
                         38 0a 63 0a 38 0a 32 0a 30 0a 30 0a 61 0a 61 0a
                         30 0a 30 0a 34 0a 62 0a 61 0a 39 0a 30 0a 62 }
		$urlmoniker7 = { 65 0d 0a 30 0d 0a 63 0d 0a 39 0d 0a 65 0d 0a 61
                         0d 0a 37 0d 0a 39 0d 0a 66 0d 0a 39 0d 0a 62 0d
                         0a 61 0d 0a 63 0d 0a 65 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 63 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 61 0d 0a 61 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 62 0d 0a 61 0d 0a 39 0d 0a 30 0d 0a 62 }
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$ole3 = {36 34 33 30 36 33 36 36 33 31 33 31 36 35 33 30 36 31 33 31 36 32 33 31 33 31 36 31 36 35 33 31}
		$ole4 = {36 34 30 61 33 30 30 61 36 33 30 61 36 36 30 61 33 31 30 61 33 31 30 61 36 35 30 61 33 30 30 61 36 31 30 61 33 31 30 61 36 32 30 61 33 31 30 61 33 31 30 61 36 31 30 61 36 35 30 61 33 31}
		$ole5 = { 64 0a 30 0a 63 0a 66 0a 31 0a 31 0a 65 0a 30 }
		$ole6 = { 64 0d 0a 30 0d 0a 63 0d 0a 66 0d 0a 31 0d 0a 31 0d 0a 65 0d 0a 30 }
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $urlmoniker* ) and 1 of ( $ole* ) and 1 of ( $obj* )
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_1 : hardened limited
{
	meta:
		description = "Detects RTF documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"
		score = 70

	strings:
		$s1 = {30 32 63 65 30 32 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$s2 = {35 32 30 30 36 66 30 30 36 66 30 30 37 34 30 30 32 30 30 30 34 35 30 30 36 65 30 30 37 34 30 30 37 32 30 30 37 39 30 30}
		$ole1 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$olex = { (64|44)[0-1]30[0-1](63|43)[0-1](66|46)[0-1]31[0-1]31[0-1](65|45)[0-1]30[0-1](61|41)[0-1]31[0-1](62|42)[0-1]31[0-1]31[0-1](61|41) }
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}

	condition:
		uint32( 0 ) == 0x74725c7b and all of ( $s* ) and 1 of ( $ole* ) and 2 of ( $obj* )
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_2 : hardened limited
{
	meta:
		description = "detects an obfuscated RTF variant documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"

	strings:
		$eq1 = {30 32 63 65 30 32 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$eq2 = {65 71 75 61 74 69 6f 6e 2e}
		$eq3 = {36 35 35 31 37 35 34 31 37 34 34 39 36 66 34 65 32 65 33 33}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}
		$s1 = {34 63 36 66 36 31 36 34 34 63 36 39 36 32 37 32 36 31 37 32 37 39}
		$s2 = {34 37 36 35 37 34 35 30 37 32 36 66 36 33 34 31 36 34 36 34 37 32 36 35 37 33 37 33}
		$s3 = {35 35 35 32 34 63 34 34 36 66 37 37 36 65 36 63 36 66 36 31 36 34 35 34 36 66 34 36 36 39 36 63 36 35}
		$s4 = {35 33 36 38 36 35 36 63 36 63 34 35 37 38 36 35 36 33 37 35 37 34 36 35}
		$s5 = {34 35 37 38 36 39 37 34 35 30 37 32 36 66 36 33 36 35 37 33 37 33}

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $eq* ) and 1 of ( $obj* ) and 2 of ( $s* )
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_3 : hardened limited
{
	meta:
		description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
		author = "ditekSHen"

	strings:
		$ole1 = {34 66 30 30 36 63 30 30 36 35 30 30 33 31 30 30 33 30 30 30 34 65 30 30 34 31 30 30 35 34 30 30 34 39 30 30 37 36 30 30 36 35}
		$ole2 = { (3666|3466) (3663|3463) (3635|3435) 3331 3330 (3665|3465) (3631|3431) (3734|3534) (3639|3439) (3736|3536) (3635|3435) }
		$clsid1 = {32 63 65 30 32 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$clsid2 = { 32 (43|63) (45|65) 30 32 30 30 30 30 30 30 30 30 30 30 (43|63) 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36 }
		$re = {35 32 30 30 36 66 30 30 36 66 30 30 37 34 30 30 32 30 30 30 34 35 30 30 36 65 30 30 37 34 30 30 37 32 30 30 37 39 30 30}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}

	condition:
		uint32( 0 ) == 0x74725c7b and ( 1 of ( $ole* ) and 1 of ( $clsid* ) and $re and 1 of ( $obj* ) )
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_4 : hardened
{
	meta:
		description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
		author = "ditekSHen"
		score = 70

	strings:
		$s1 = { (36|34)[0-2]35[0-2](37|35)[0-2]31[0-2](37|35)[0-2]35[0-2](36|34)[0-2]31[0-2](37|35)[0-2]34[0-2](36|34)[0-2]39[0-2](36|34)[0-2]66[0-2](36|34)[0-2]65[0-2]32[0-2]65[0-2]33[0-2]33 }
		$s2 = { (7d|5c|2b|24)[0-2](37|35)[0-2]31[0-2](37|35)[0-2]35[0-2](36|34)[0-2]31[0-2](37|35)[0-2]34[0-2](36|34)[0-2]39[0-2](36|34)[0-2]66[0-2](36|34)[0-2]65[0-2]32[0-2]65[0-2]33[0-2]33 }
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}

	condition:
		uint32( 0 ) == 0x74725c7b and ( 1 of ( $s* ) and 1 of ( $obj* ) )
}

rule INDICATOR_OLE_EXPLOIT_CVE_2017_11882_1 : hardened limited
{
	meta:
		description = "detects OLE documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"

	strings:
		$s1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$s2 = { 02 ce 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$s3 = {6f 00 6c 00 65 00 31 00 30 00 6e 00 61 00 74 00 69 00 76 00 65 00}
		$s4 = {52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00}

	condition:
		uint16( 0 ) == 0xcfd0 and all of them
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_8759_1 : hardened limited
{
	meta:
		description = "detects CVE-2017-8759 weaponized RTF documents."
		author = "ditekSHen"

	strings:
		$clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$clsid2 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$clsid3 = {30 30 30 33 30 30 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$clsid4 = {34 66 34 63 34 35 33 32 34 63 36 39 36 65 36 62}
		$clsid5 = {4f 4c 45 32 4c 69 6e 6b}
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$ole3 = {36 34 33 30 36 33 36 36 33 31 33 31 36 35 33 30 36 31 33 31 36 32 33 31 33 31 36 31 36 35 33 31}
		$ole4 = {36 34 30 61 33 30 30 61 36 33 30 61 36 36 30 61 33 31 30 61 33 31 30 61 36 35 30 61 33 30 30 61 36 31 30 61 33 31 30 61 36 32 30 61 33 31 30 61 33 31 30 61 36 31 30 61 36 35 30 61 33 31}
		$s1 = {77 00 73 00 64 00 6c 00 3d 00 68 00 74 00 74 00 70 00}
		$s2 = {4d 45 54 41 46 49 4c 45 50 49 43 54}
		$s3 = {49 4e 43 4c 55 44 45 50 49 43 54 55 52 45 20 22 68 74 74 70}
		$s4 = {21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $clsid* ) and 1 of ( $ole* ) and 2 of ( $s* )
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_8759_2 : hardened limited
{
	meta:
		description = "detects CVE-2017-8759 weaponized RTF documents."
		author = "ditekSHen"
		score = 80

	strings:
		$clsid1 = { 88 d9 6a 0c f1 92 11 d4 a6 5f 00 40 96 32 51 e5 }
		$clsid2 = {38 38 64 39 36 61 30 63 66 31 39 32 31 31 64 34 61 36 35 66 30 30 34 30 39 36 33 32 35 31 65 35}
		$clsid3 = {34 64 37 33 37 38 36 64 36 63 33 32 32 65 35 33 34 31 35 38 35 38 34 64 34 63 35 32 36 35 36 31 36 34 36 35 37 32 32 65}
		$clsid4 = {4d 73 78 6d 6c 32 2e 53 41 58 58 4d 4c 52 65 61 64 65 72 2e}
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$ole3 = {36 34 33 30 36 33 36 36 33 31 33 31 36 35 33 30 36 31 33 31 36 32 33 31 33 31 36 31 36 35 33 31}
		$ole4 = {36 34 30 61 33 30 30 61 36 33 30 61 36 36 30 61 33 31 30 61 33 31 30 61 36 35 30 61 33 30 30 61 36 31 30 61 33 31 30 61 36 32 30 61 33 31 30 61 33 31 30 61 36 31 30 61 36 35 30 61 33 31}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6f 62 6a 63 6c 61 73 73 20 68 74 6d 6c 66 69 6c 65}
		$soap1 = {63 37 62 30 61 62 65 63 31 39 37 66 64 32 31 31 39 37 38 65 30 30 30 30 66 38 37 35 37 65}

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $clsid* ) and 1 of ( $ole* ) and ( 2 of ( $obj* ) or 1 of ( $soap* ) )
}

rule INDICATOR_RTF_Exploit_Scripting : hardened limited
{
	meta:
		description = "detects CVE-2017-8759 or CVE-2017-8570 weaponized RTF documents."
		author = "ditekSHen"

	strings:
		$clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$clsid2 = {30 30 30 33 30 30 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$clsid3 = {34 66 34 63 34 35 33 32 34 63 36 39 36 65 36 62}
		$clsid4 = {4f 4c 45 32 4c 69 6e 6b}
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$ole3 = {36 34 33 30 36 33 36 36 33 31 33 31 36 35 33 30 36 31 33 31 36 32 33 31 33 31 36 31 36 35 33 31}
		$ole4 = {36 34 30 61 33 30 30 61 36 33 30 61 36 36 30 61 33 31 30 61 33 31 30 61 36 35 30 61 33 30 30 61 36 31 30 61 33 31 30 61 36 32 30 61 33 31 30 61 33 31 30 61 36 31 30 61 36 35 30 61 33 31}
		$ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
		$ole6 = {44 30 63 66 31 31 45}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}
		$obj8 = {5c 6f 62 6a 63 6c 61 73 73 20 68 74 6d 6c 66 69 6c 65}
		$sct1 = { 33 (43|63) (3533|3733) (3433|3633) (3532|3732) (3439|3639)( 3530|3730) (3534|3734) (3443|3643) (3435|3635) (3534|3734) }
		$sct2 = { (3737|3537) (3733|3533) (3633|3433) (3732|3532) (3639|3439) (3730|3530) (3734|3534) (3245|3265) (3733|3533) (3638|3438) (3635|3435) (3643|3443) (3643|3443) }

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $clsid* ) and 1 of ( $ole* ) and 1 of ( $obj* ) and 1 of ( $sct* )
}

rule INDICATOR_RTF_Embedded_Excel_SheetMacroEnabled : hardened limited
{
	meta:
		description = "Detects RTF documents embedding an Excel sheet with macros enabled. Observed in exploit followed by dropper behavior"
		author = "ditekSHen"

	strings:
		$ex1 = {34 35 37 38 36 33 36 35 36 63 32 65 35 33 36 38 36 35 36 35 37 34 34 64 36 31 36 33 37 32 36 66 34 35 36 65 36 31 36 32 36 63 36 35 36 34 32 65}
		$ex2 = {30 30 30 32 30 38 33 32 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$ex3 = {45 78 63 65 6c 2e 53 68 65 65 74 4d 61 63 72 6f 45 6e 61 62 6c 65 64 2e}
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$ole3 = {36 34 33 30 36 33 36 36 33 31 33 31 36 35 33 30 36 31 33 31 36 32 33 31 33 31 36 31 36 35 33 31}
		$ole4 = {36 34 30 61 33 30 30 61 36 33 30 61 36 36 30 61 33 31 30 61 33 31 30 61 36 35 30 61 33 30 30 61 36 31 30 61 33 31 30 61 36 32 30 61 33 31 30 61 33 31 30 61 36 31 30 61 36 35 30 61 33 31}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}

	condition:
		uint32( 0 ) == 0x74725c7b and ( 1 of ( $ex* ) and 1 of ( $ole* ) and 2 of ( $obj* ) )
}

rule INDICATOR_OLE_MetadataCMD : hardened
{
	meta:
		description = "Detects OLE documents with Windows command-line utilities commands (certutil, powershell, etc.) stored in the metadata (author, last modified by, etc.)."
		author = "ditekSHen"

	strings:
		$cmd1 = { 00 1E 00 00 00 [1-4] 00 00 (63|43) (6D|4D) (64|44) (00|20) }
		$cmd2 = { 00 1E 00 00 00 [1-4] 00 00 (6D|4D) (73|53) (68|48) (74|54) (61|41) (00|20) }
		$cmd3 = { 00 1E 00 00 00 [1-4] 00 00 (77|57) (73|53) (63|43) (72|52) (69|49) (70|50) (74|54) (00|20) }
		$cmd4 = { 00 1E 00 00 00 [1-4] 00 00 (63|42) (65|45) (72|52) (74|54) (75|55) (74|54) (69|49) (6C|4C) (00|20) }
		$cmd5 = { 00 1E 00 00 00 [1-4] 00 00 (70|50) (6F|4F) (77|57) (65|45) (72|52) (73|43) (68|48) (65|45) (6C|4C) (6C|4C) (00|20) }
		$cmd6 = { 00 1E 00 00 00 [1-4] 00 00 (6E|4E) (65|45) (74|54) 2E (77|57) (65|45) (62|42) (63|43) (6C|4C) (69|49) (65|45) (6E|4E) (74|54) (00|20) }

	condition:
		uint16( 0 ) == 0xcfd0 and any of them
}

rule INDICATOR_RTF_MultiExploit_Embedded_Files : hardened limited
{
	meta:
		description = "Detects RTF documents potentially exploting multiple vulnerabilities and embeding next stage scripts and/or binaries"
		author = "ditekSHen"

	strings:
		$eq1 = {30 32 63 65 30 32 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$eq2 = { 02ce020000000000c000000000000046 }
		$ole2link1 = {30 33 30 30 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$ole2link2 = { (36|34) (66|46) (36|34) (63|43) (36|34) 35 33 32 (36|34) (63|43) (36|34) 39 (36|34) (65|45) (36|34) (62|42) }
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6d 6d 61 74 68}
		$pkg = { (70|50) (61|41) (63|43) (6b|4b) (61|41) (67|47) (65|45) }
		$emb_exe = { 3265 (3635|3435) (3738|3538) (3635|3435) 3030 }
		$emb_scr = { 3265 (3733|3533) (3633|3433) (3532|3732) 3030 }
		$emb_dll = { 3265 (3634|3434) (3663|3463) (3663|3463) 3030 }
		$emb_doc = { 3265 (3634|3434) (3666|3466) (3633|3433) 3030 }
		$emb_bat = { 3265 (3632|3432) (3631|3431) (3734|3534) 3030 }
		$emb_sct = { 3265 (3733|3533) (3633|3433) (3734|3534) 3030 }
		$emb_txt = { 3265 (3734|3534) (3738|3538) (3734|3534) 3030 }
		$emb_psw = { 3265 (3730|3530) (3733|3533) 313030 }

	condition:
		uint32( 0 ) == 0x74725c7b and ( 1 of ( $eq* ) or 1 of ( $ole2link* ) ) and $pkg and 2 of ( $obj* ) and 1 of ( $emb* )
}

rule INDICATOR_RTF_Equation_BITSAdmin_Downloader : hardened limited
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and BITSAdmin. Common exploit + dropper behavior."
		author = "ditekSHen"
		snort2_sid = "910002-910003"
		snort3_sid = "910001"
		clamav_sig = "INDICATOR.RTF.EquationBITSAdminDownloader"

	strings:
		$eq = {30 32 30 30 30 30 30 30 30 32 43 45 30 32 30 30 30 30 30 30 30 30 30 30 43 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$ba = {36 32 36 39 37 34 37 33 36 31 36 34 36 64 36 39 36 65}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}

	condition:
		uint32( 0 ) == 0x74725c7b and ( ( $eq and $ba ) and 1 of ( $obj* ) )
}

rule INDICATOR_RTF_Equation_CertUtil_Downloader : hardened limited
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and CertUtil. Common exploit + dropper behavior."
		author = "ditekSHen"
		snort2_sid = "910006-910007"
		snort3_sid = "910003"
		clamav_sig = "INDICATOR.RTF.EquationCertUtilDownloader"

	strings:
		$eq = {30 32 30 30 30 30 30 30 30 32 43 45 30 32 30 30 30 30 30 30 30 30 30 30 43 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$cu = {36 33 36 35 37 32 37 34 37 35 37 34 36 39 36 63}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}

	condition:
		uint32( 0 ) == 0x74725c7b and ( ( $eq and $cu ) and 1 of ( $obj* ) )
}

rule INDICATOR_RTF_Equation_PowerShell_Downloader : hardened limited
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and PowerShell. Common exploit + dropper behavior."
		author = "ditekSHen"
		snort2_sid = "910004-910005"
		snort3_sid = "910002"
		clamav_sig = "INDICATOR.RTF.EquationPowerShellDownloader"

	strings:
		$eq = {30 32 30 30 30 30 30 30 30 32 43 45 30 32 30 30 30 30 30 30 30 30 30 30 43 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$ps = {37 30 36 66 37 37 36 35 37 32 37 33 36 38 36 35 36 63 36 63}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}

	condition:
		uint32( 0 ) == 0x74725c7b and ( ( $ps and $eq ) and 1 of ( $obj* ) )
}

rule INDICATOR_RTF_LNK_Shell_Explorer_Execution : hardened limited
{
	meta:
		description = "detects RTF files with Shell.Explorer.1 OLE objects with embedded LNK files referencing an executable."
		author = "ditekSHen"

	strings:
		$clsid = {63 33 32 61 62 32 65 61 63 31 33 30 63 66 31 31 61 37 65 62 30 30 30 30 63 30 35 62 61 65 30 62}
		$lnk_header = {34 63 30 30 30 30 30 30 30 31 31 34 30 32 30 30}
		$http_url = {36 38 30 30 37 34 30 30 37 34 30 30 37 30 30 30}
		$file_url = {36 36 30 30 36 39 30 30 36 63 30 30 36 35 30 30 33 61}

	condition:
		uint32( 0 ) == 0x74725c7b and filesize < 1500KB and $clsid and $lnk_header and ( $http_url or $file_url )
}

rule INDICATOR_RTF_Forms_HTML_Execution : hardened limited
{
	meta:
		description = "detects RTF files with Forms.HTML:Image.1 or Forms.HTML:Submitbutton.1 OLE objects referencing file or HTTP URLs."
		author = "ditekSHen"

	strings:
		$img_clsid = {31 32 64 31 31 32 35 35 63 36 35 63 63 66 31 31 38 64 36 37 30 30 61 61 30 30 62 64 63 65 31 64}
		$sub_clsid = {31 30 64 31 31 32 35 35 63 36 35 63 63 66 31 31 38 64 36 37 30 30 61 61 30 30 62 64 63 65 31 64}
		$http_url = {36 38 30 30 37 34 30 30 37 34 30 30 37 30 30 30}
		$file_url = {36 36 30 30 36 39 30 30 36 63 30 30 36 35 30 30 33 61}

	condition:
		uint32( 0 ) == 0x74725c7b and filesize < 1500KB and ( $img_clsid or $sub_clsid ) and ( $http_url or $file_url )
}

rule INDICATOR_PUB_MSIEXEC_Remote : hardened
{
	meta:
		description = "detects VB-enable Microsoft Publisher files utilizing Microsoft Installer to retrieve remote files and execute them"
		author = "ditekSHen"

	strings:
		$s1 = {4d 69 63 72 6f 73 6f 66 74 20 50 75 62 6c 69 73 68 65 72}
		$s2 = {6d 73 69 65 78 65 63 2e 65 78 65}
		$s3 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e}
		$s4 = {2f 6e 6f 72 65 73 74 61 72 74}
		$s5 = {2f 69 20 68 74 74 70}
		$s6 = {57 73 63 72 69 70 74 2e 53 68 65 6c 6c}
		$s7 = {5c 00 56 00 42 00 45 00 36 00 2e 00 44 00 4c 00 4c 00 23 00}

	condition:
		uint16( 0 ) == 0xcfd0 and 6 of them
}

rule INDICATOR_RTF_Ancalog_Exploit_Builder_Document : hardened
{
	meta:
		description = "Detects documents generated by Phantom Crypter/Ancalog"
		author = "ditekSHen"
		snort2_sid = "910000-910001"
		snort3_sid = "910000"
		clamav_sig = "INDICATOR.RTF.AncalogExploitBuilderDocument"

	strings:
		$builder1 = {7b 5c 2a 5c 61 6e 63 61 6c 6f 67}
		$builder2 = {5c 61 6e 63 61 6c 6f 67}

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $builder* )
}

rule INDICATOR_RTF_ThreadKit_Exploit_Builder_Document : hardened
{
	meta:
		description = "Detects vaiations of RTF documents generated by ThreadKit builder."
		author = "ditekSHen"

	strings:
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$obj7 = {5c 6d 6d 61 74 68}
		$pat1 = /\\objupdate\\v[\\\s\n\r]/ ascii

	condition:
		uint32( 0 ) == 0x74725c7b and 2 of ( $obj* ) and 1 of ( $pat* )
}

rule INDICATOR_XML_LegacyDrawing_AutoLoad_Document : hardened
{
	meta:
		description = "detects AutoLoad documents using LegacyDrawing"
		author = "ditekSHen"

	strings:
		$s1 = {3c 6c 65 67 61 63 79 44 72 61 77 69 6e 67 20 72 3a 69 64 3d 22}
		$s2 = {3c 6f 6c 65 4f 62 6a 65 63 74 20 70 72 6f 67 49 64 3d 22}
		$s3 = {61 75 74 6f 4c 6f 61 64 3d 22 74 72 75 65 22}

	condition:
		uint32( 0 ) == 0x6d783f3c and all of ( $s* )
}

rule INDICATOR_XML_OLE_AutoLoad_Document : hardened
{
	meta:
		description = "detects AutoLoad documents using OLE Object"
		author = "ditekSHen"

	strings:
		$s1 = {61 75 74 6f 4c 6f 61 64 3d 22 74 72 75 65 22}
		$s2 = {2f 72 65 6c 61 74 69 6f 6e 73 68 69 70 73 2f 6f 6c 65 4f 62 6a 65 63 74 22}
		$s3 = {54 61 72 67 65 74 3d 22 2e 2e 2f 65 6d 62 65 64 64 69 6e 67 73 2f 6f 6c 65 4f 62 6a 65 63 74}

	condition:
		uint32( 0 ) == 0x6d783f3c and all of ( $s* )
}

rule INDICATOR_XML_Squiblydoo_1 : hardened limited
{
	meta:
		description = "detects Squiblydoo variants extracted from exploit RTF documents."
		author = "ditekSHen"

	strings:
		$slt = {3c 73 63 72 69 70 74 6c 65 74}
		$ws1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 22 20 26 20 22 2e 53 68 65 6c 6c 22 29}
		$ws2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$ws3 = {41 63 74 69 76 65 78 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$r1 = {5b 22 72 75 6e 22 5d}
		$r2 = {2e 72 75 6e 20 22 63 6d 64}
		$r3 = {2e 72 75 6e 20 63 68 72 28}

	condition:
		( uint32( 0 ) == 0x4d583f3c or uint32( 0 ) == 0x6d783f3c ) and $slt and 1 of ( $ws* ) and 1 of ( $r* )
}

rule INDICATOR_OLE_Suspicious_Reverse : hardened limited
{
	meta:
		description = "detects OLE documents containing VB scripts with reversed suspicious strings"
		author = "ditekSHen"

	strings:
		$vb = {5c 56 42 45 37 2e 44 4c 4c}
		$cmd1 = {43 4d 44 20 43 3a 5c}
		$cmd2 = {43 4d 44 20 2f 63 20}
		$kw1 = {5d 72 41 48 43 5b}
		$kw2 = {65 6b 4f 56 4e 49}
		$kw3 = {45 63 61 4c 50 45 72}
		$kw4 = {54 63 45 4a 42 4f 2d 57 45 6e}
		$kw5 = {65 4c 62 41 69 72 61 76 2d 54 65 67}
		$kw6 = {52 65 76 65 52 53 45 28}
		$kw7 = {2d 4a 4f 49 6e}

	condition:
		uint16( 0 ) == 0xcfd0 and $vb and ( ( 1 of ( $cmd* ) and 1 of ( $kw* ) ) or ( 2 of ( $kw* ) ) )
}

rule INDICATOR_OLE_Suspicious_ActiveX : hardened
{
	meta:
		description = "detects OLE documents with suspicious ActiveX content"
		author = "ditekSHen"

	strings:
		$vb = {5c 56 42 45 37 2e 44 4c 4c}
		$ax1 = {5f 4c 61 79 6f 75 74}
		$ax2 = {4d 75 6c 74 69 50 61 67 65 31 5f}
		$ax3 = {5f 4d 6f 75 73 65 4d 6f 76 65}
		$ax4 = {5f 4d 6f 75 73 65 48 6f 76 65 72}
		$ax5 = {5f 4d 6f 75 73 65 4c 65 61 76 65}
		$ax6 = {5f 4d 6f 75 73 65 45 6e 74 65 72}
		$ax7 = {49 6d 61 67 65 43 6f 6d 62 6f 32 31 5f 43 68 61 6e 67 65}
		$ax8 = {49 6e 6b 45 64 69 74 31 5f 47 6f 74 46 6f 63 75 73}
		$ax9 = {49 6e 6b 50 69 63 74 75 72 65 31 5f}
		$ax10 = {53 79 73 74 65 6d 4d 6f 6e 69 74 6f 72 31 5f}
		$ax11 = {57 65 62 42 72 6f 77 73 65 72 31 5f}
		$ax12 = {5f 43 6c 69 63 6b}
		$kw1 = {43 72 65 61 74 65 4f 62 6a 65 63 74}
		$kw2 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65}
		$kw3 = {2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f}
		$kw4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c}
		$kw5 = { 43 68 72 [0-2] 41 73 63 [0-2] 4d 69 64 }
		$kw6 = { 43 68 [0-2] 72 24 28 40 24 28 22 26 48 }
		$kw7 = { 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 }

	condition:
		uint16( 0 ) == 0xcfd0 and $vb and 1 of ( $ax* ) and 2 of ( $kw* )
}

rule INDICATOR_OLE_Suspicious_MITRE_T1117 : hardened limited
{
	meta:
		description = "Detects MITRE technique T1117 in OLE documents"
		author = "ditekSHen"

	strings:
		$s1 = {73 63 72 6f 62 6a 2e 64 6c 6c}
		$s2 = {72 65 67 73 76 72 33 32}
		$s3 = {4a 79 5a 57 64 7a 64 6e 49 7a 4d 69 35 6c 65 47 55}
		$s4 = {48 4e 6a 63 6d 39 69 61 69 35 6b 62 47 77}

	condition:
		uint16( 0 ) == 0xcfd0 and 2 of them
}

rule INDICATOR_OLE_RemoteTemplate : hardened
{
	meta:
		description = "Detects XML relations where an OLE object is refrencing an external target in dropper OOXML documents"
		author = "ditekSHen"

	strings:
		$olerel = {72 65 6c 61 74 69 6f 6e 73 68 69 70 73 2f 6f 6c 65 4f 62 6a 65 63 74}
		$target1 = {54 61 72 67 65 74 3d 22 68 74 74 70}
		$target2 = {54 61 72 67 65 74 3d 22 66 69 6c 65}
		$mode = {54 61 72 67 65 74 4d 6f 64 65 3d 22 45 78 74 65 72 6e 61 6c}

	condition:
		$olerel and $mode and 1 of ( $target* )
}

rule INDICATOR_RTF_MalVer_Objects : hardened
{
	meta:
		description = "Detects RTF documents with non-standard version and embeding one of the object mostly observed in exploit documents."
		author = "ditekSHen"

	strings:
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}

	condition:
		uint32( 0 ) == 0x74725c7b and ( ( not uint8( 4 ) == 0x66 or not uint8( 5 ) == 0x31 or not uint8( 6 ) == 0x5c ) and 1 of ( $obj* ) )
}

rule INDICATOR_PPT_MasterMana : hardened limited
{
	meta:
		description = "Detects known malicious pattern (MasterMana) in PowerPoint documents."
		author = "ditekSHen"

	strings:
		$a1 = {61 75 74 6f 5f 63 6c 6f 73 65}
		$a2 = {61 75 74 6f 63 6c 6f 73 65}
		$a3 = {61 75 74 6f 5f 6f 70 65 6e}
		$a4 = {61 75 74 6f 6f 70 65 6e}
		$vb1 = {5c 56 42 45 37 2e 44 4c 4c}
		$vb2 = { 41 74 74 72 69 62 75 74 ?? 65 20 56 42 5f 4e 61 6d ?? 65 }
		$clsid = {30 00 30 00 30 00 32 00 30 00 34 00 45 00 46 00 2d 00 30 00 30 00 30 00 30 00 2d 00 30 00 30 00 30 00 30 00 2d 00 43 00 30 00 30 00 30 00 2d 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 34 00 36 00}
		$i1 = {((40 6a 2e 6d 70 2f) | (40 00 6a 00 2e 00 6d 00 70 00 2f 00))}
		$i2 = {((6a 2e 6d 70 2f) | (6a 00 2e 00 6d 00 70 00 2f 00))}
		$i3 = {((5c 70 6d 2e 6a 5c 5c 3a) | (5c 00 70 00 6d 00 2e 00 6a 00 5c 00 5c 00 3a 00))}
		$i4 = {((2e 7a 7a 2e 68 74 2f) | (2e 00 7a 00 7a 00 2e 00 68 00 74 00 2f 00))}
		$i5 = {((2f 70 6d 2e 6a 40) | (2f 00 70 00 6d 00 2e 00 6a 00 40 00))}
		$i6 = {((5c 70 6d 2e 6a 40) | (5c 00 70 00 6d 00 2e 00 6a 00 40 00))}

	condition:
		uint16( 0 ) == 0xcfd0 and 1 of ( $i* ) and $clsid and 1 of ( $a* ) and 1 of ( $vb* )
}

rule INDICATOR_XML_WebRelFrame_RemoteTemplate : hardened limited
{
	meta:
		description = "Detects XML web frame relations refrencing an external target in dropper OOXML documents"
		author = "ditekSHen"

	strings:
		$target1 = {2f 66 72 61 6d 65 22 20 54 61 72 67 65 74 3d 22 68 74 74 70}
		$target2 = {2f 66 72 61 6d 65 22 20 54 61 72 67 65 74 3d 22 66 69 6c 65}
		$mode = {54 61 72 67 65 74 4d 6f 64 65 3d 22 45 78 74 65 72 6e 61 6c}

	condition:
		uint32( 0 ) == 0x6d783f3c and ( 1 of ( $target* ) and $mode )
}

rule INDICATOR_PDF_IPDropper : hardened
{
	meta:
		description = "Detects PDF documents with Action and URL pointing to direct IP address"
		author = "ditekSHen"

	strings:
		$s1 = { 54 79 70 65 20 2f 41 63 74 69 6f 6e 0d 0a 2f 53 20 2f 55 52 49 0d 0a }
		$s2 = /\/URI \(http(s)?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}\// ascii

	condition:
		uint32( 0 ) == 0x46445025 and all of them
}

rule INDICATOR_OLE_Excel4Macros_DL1 : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"

	strings:
		$s1 = {4d 61 63 72 6f 73 20 45 78 63 65 6c 20 34 2e 30}
		$s2 = { 00 4d 61 63 72 6f 31 85 00 }
		$s3 = {68 74 74 70}
		$s4 = {66 69 6c 65 3a}
		$fa_exe = {2e 65 78 65}
		$fa_scr = {2e 73 63 72}
		$fa_dll = {2e 64 6c 6c}
		$fa_bat = {2e 62 61 74}
		$fa_cmd = {2e 63 6d 64}
		$fa_sct = {2e 73 63 74}
		$fa_txt = {2e 74 78 74}
		$fa_psw = {2e 70 73 31}
		$fa_py = {2e 70 79}
		$fa_js = {2e 6a 73}

	condition:
		uint16( 0 ) == 0xcfd0 and ( 3 of ( $s* ) and 1 of ( $fa* ) )
}

rule INDICATOR_OLE_Excel4Macros_DL2 : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"

	strings:
		$e1 = {4d 61 63 72 6f 73 20 45 78 63 65 6c 20 34 2e 30}
		$e2 = { 00 4d 61 63 72 6f 31 85 00 }
		$a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }
		$a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a6 = {61 75 74 6f 5f 6f 70 65 6e}
		$a7 = {61 75 74 6f 5f 63 6c 6f 73 65}
		$x1 = {2a 20 23 2c 23 23 30}
		$x2 = {3d 45 58 45 43 28 43 48 41 52 28}
		$x3 = {2d 77 20 31 20 73 74 41 52 74 60 2d 73}
		$x4 = {29 26 43 48 41 52 28}
		$x5 = {52 65 76 65 72 73 65}

	condition:
		uint16( 0 ) == 0xcfd0 and ( 1 of ( $e* ) and 1 of ( $a* ) and ( #x1 > 3 or 2 of ( $x* ) ) )
}

rule INDICATOR_RTF_Embedded_Excel_URLDownloadToFile : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects RTF documents that embed Excel documents for detection evation."

	strings:
		$clsid1 = {32 30 30 38 30 32 30 30 30 30 30 30 30 30 30 30 63 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36}
		$obj1 = {5c 6f 62 6a 68 74 6d 6c}
		$obj2 = {5c 6f 62 6a 64 61 74 61}
		$obj3 = {5c 6f 62 6a 75 70 64 61 74 65}
		$obj4 = {5c 6f 62 6a 65 6d 62}
		$obj5 = {5c 6f 62 6a 61 75 74 6c 69 6e 6b}
		$obj6 = {5c 6f 62 6a 6c 69 6e 6b}
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$ole3 = {36 34 33 30 36 33 36 36 33 31 33 31 36 35 33 30 36 31 33 31 36 32 33 31 33 31 36 31 36 35 33 31}
		$ole4 = {36 34 30 61 33 30 30 61 36 33 30 61 36 36 30 61 33 31 30 61 33 31 30 61 36 35 30 61 33 30 30 61 36 31 30 61 33 31 30 61 36 32 30 61 33 31 30 61 33 31 30 61 36 31 30 61 36 35 30 61 33 31}
		$ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
		$ole6 = {44 30 63 66 31 31 45}
		$s1 = {35 35 35 32 34 63 34 34 36 66 37 37 36 65 36 63 36 66 36 31 36 34 35 34 36 66 34 36 36 39 36 63 36 35 34 31}
		$s2 = {35 35 35 32 34 63 34 64 34 66 34 65}

	condition:
		uint32( 0 ) == 0x74725c7b and ( 1 of ( $clsid* ) and 1 of ( $obj* ) and 1 of ( $ole* ) and 1 of ( $s* ) )
}

rule INDICATOR_OLE_Excel4Macros_DL3 : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"

	strings:
		$a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }
		$a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a6 = {61 75 74 6f 5f 6f 70 65 6e}
		$a7 = {61 75 74 6f 5f 63 6c 6f 73 65}
		$s1 = {2a 20 23 2c 23 23 30}
		$s2 = {55 52 4c 4d 6f 6e}
		$s3 = {44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}
		$s4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}

	condition:
		uint16( 0 ) == 0xcfd0 and 1 of ( $a* ) and all of ( $s* ) and #s1 > 3
}

rule INDICATOR_DOC_PhishingPatterns : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE, RTF, PDF and OOXML (decompressed) documents with common phishing strings"
		score = 40

	strings:
		$s1 = {50 45 52 46 4f 52 4d 20 54 48 45 20 46 4f 4c 4c 4f 57 49 4e 47 20 53 54 45 50 53 20 54 4f 20 50 45 52 46 4f 52 4d 20 44 45 43 52 59 50 54 49 4f 4e}
		$s2 = {45 6e 61 62 6c 65 20 45 64 69 74 69 6e 67}
		$s3 = {45 6e 61 62 6c 65 20 43 6f 6e 74 65 6e 74}
		$s4 = {57 48 59 20 49 20 43 41 4e 4e 4f 54 20 4f 50 45 4e 20 54 48 49 53 20 44 4f 43 55 4d 45 4e 54 3f}
		$s5 = {59 6f 75 20 61 72 65 20 75 73 69 6e 67 20 69 4f 53 20 6f 72 20 41 6e 64 72 6f 69 64 2c 20 70 6c 65 61 73 65 20 75 73 65 20 44 65 73 6b 74 6f 70 20 50 43}
		$s6 = {59 6f 75 20 61 72 65 20 74 72 79 69 6e 67 20 74 6f 20 76 69 65 77 20 74 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 75 73 69 6e 67 20 4f 6e 6c 69 6e 65 20 56 69 65 77 65 72}
		$s7 = {54 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 77 61 73 20 65 64 69 74 65 64 20 69 6e 20 61 20 64 69 66 66 65 72 65 6e 74 20 76 65 72 73 69 6f 6e 20 6f 66}
		$s8 = {64 6f 63 75 6d 65 6e 74 20 61 72 65 20 6c 6f 63 6b 65 64 20 61 6e 64 20 77 69 6c 6c 20 6e 6f 74}
		$s9 = {75 6e 74 69 6c 20 74 68 65 20 22 45 6e 61 62 6c 65 22 20 62 75 74 74 6f 6e 20 69 73 20 70 72 65 73 73 65 64}
		$s10 = {54 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 63 72 65 61 74 65 64 20 69 6e 20 6f 6e 6c 69 6e 65 20 76 65 72 73 69 6f 6e 20 6f 66 20 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65}
		$s11 = {54 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 63 72 65 61 74 65 64 20 69 6e 20 70 72 65 76 69 6f 75 73 20 76 65 72 73 69 6f 6e 20 6f 66 20 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65}
		$s12 = {54 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 70 72 6f 74 65 63 74 65 64 20 62 79 20 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65}
		$s13 = {54 68 69 73 20 64 6f 63 75 6d 65 6e 74 20 65 6e 63 72 79 70 74 65 64 20 62 79}
		$s14 = {64 6f 63 75 6d 65 6e 74 20 63 72 65 61 74 65 64 20 69 6e 20 65 61 72 6c 69 65 72 20 76 65 72 73 69 6f 6e 20 6f 66 20 6d 69 63 72 6f 73 6f 66 74 20 6f 66 66 69 63 65}

	condition:
		( uint16( 0 ) == 0xcfd0 or uint32( 0 ) == 0x74725c7b or uint32( 0 ) == 0x46445025 or uint32( 0 ) == 0x6d783f3c ) and 2 of them
}

rule INDICATOR_OOXML_Excel4Macros_EXEC : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"

	strings:
		$ms = {3c 78 6d 3a 6d 61 63 72 6f 73 68 65 65 74}
		$s1 = {3e 46 4f 52 4d 55 4c 41 2e 46 49 4c 4c 28}
		$s2 = {3e 52 45 47 49 53 54 45 52 28}
		$s3 = {3e 45 58 45 43 28}
		$s4 = {3e 52 55 4e 28}

	condition:
		uint32( 0 ) == 0x6d783f3c and $ms and ( 2 of ( $s* ) or ( $s3 ) )
}

rule INDICATOR_OOXML_Excel4Macros_AutoOpenHidden : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet auto_open and state hidden"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"

	strings:
		$s1 = {73 74 61 74 65 3d 22 76 65 72 79 68 69 64 64 65 6e 22}
		$s2 = {3c 64 65 66 69 6e 65 64 4e 61 6d 65 20 6e 61 6d 65 3d 22 5f 78 6c 6e 6d 2e 41 75 74 6f 5f 4f 70 65 6e}

	condition:
		uint32( 0 ) == 0x6d783f3c and all of them
}

rule INDICATOR_SUSPICOIUS_RTF_EncodedURL : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables calling ClearMyTracksByProcess"

	strings:
		$s1 = {((5c 75 2d 36 35 34 33 31 3f 5c 75 2d 36 35 34 31 39 3f 5c 75 2d 36 35 34 31 39 3f 5c 75 2d 36 35 34 32 33 3f 5c 75 2d) | (5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 31 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 31 00 39 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 31 00 39 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 32 00 33 00 3f 00 5c 00 75 00 2d 00))}
		$s2 = {((5c 75 2d 36 35 34 33 32 3f 5c 75 2d 36 35 34 32 30 3f 5c 75 2d 36 35 34 32 30 3f 5c 75 2d 36 35 34 32 34 3f 5c 75 2d) | (5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 32 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 32 00 30 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 32 00 30 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 32 00 34 00 3f 00 5c 00 75 00 2d 00))}
		$s3 = {((5c 75 2d 36 35 34 33 33 3f 5c 75 2d 36 35 34 33 30 3f 5c 75 2d 36 35 34 32 37 3f 5c 75 2d 36 35 34 33 34 3f 5c 75 2d) | (5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 33 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 30 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 32 00 37 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 34 00 3f 00 5c 00 75 00 2d 00))}
		$s4 = {((5c 75 2d 36 35 34 33 34 3f 5c 75 2d 36 35 34 33 31 3f 5c 75 2d 36 35 34 32 38 3f 5c 75 2d 36 35 34 33 35 3f 5c 75 2d) | (5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 34 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 31 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 32 00 38 00 3f 00 5c 00 75 00 2d 00 36 00 35 00 34 00 33 00 35 00 3f 00 5c 00 75 00 2d 00))}

	condition:
		uint32( 0 ) == 0x74725c7b and any of them
}

rule INDICATOR_RTF_RemoteTemplate : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects RTF documents potentially exploiting CVE-2017-11882"

	strings:
		$s1 = {7b 5c 2a 5c 74 65 6d 70 6c 61 74 65 20 68 74 74 70}
		$s2 = {7b 5c 2a 5c 74 65 6d 70 6c 61 74 65 20 66 69 6c 65}
		$s3 = {7b 5c 2a 5c 74 65 6d 70 6c 61 74 65 20 5c 75 2d}

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of them
}

