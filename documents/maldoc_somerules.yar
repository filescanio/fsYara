rule maldoc_API_hashing : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
		$a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}

	condition:
		any of them
}

rule maldoc_indirect_function_call_1 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a = {FF 75 ?? FF 55 ??}
		$pdf = {25 50 44 46}

	condition:
		not $pdf in ( 0 .. 100 ) and for any i in ( 1 .. #a ) : ( uint8( @a [ i ] + 2 ) == uint8( @a [ i ] + 5 ) )
}

rule maldoc_indirect_function_call_2 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
		$pdf = {25 50 44 46}

	condition:
		not $pdf in ( 0 .. 100 ) and for any i in ( 1 .. #a ) : ( ( uint8( @a [ i ] + 2 ) == uint8( @a [ i ] + 8 ) ) and ( uint8( @a [ i ] + 3 ) == uint8( @a [ i ] + 9 ) ) and ( uint8( @a [ i ] + 4 ) == uint8( @a [ i ] + 10 ) ) and ( uint8( @a [ i ] + 5 ) == uint8( @a [ i ] + 11 ) ) )
}

rule maldoc_indirect_function_call_3 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a = {FF B7 ?? ?? ?? ?? FF 57 ??}
		$pdf = {25 50 44 46}

	condition:
		not $pdf in ( 0 .. 100 ) and $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
		$a2 = {64 A1 30 00 00 00}

	condition:
		any of them
}

rule maldoc_find_kernel32_base_method_2 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a = {31 ?? ?? 30 64 8B ??}

	condition:
		for any i in ( 1 .. #a ) : ( ( uint8( @a [ i ] + 1 ) >= 0xC0 ) and ( ( ( uint8( @a [ i ] + 1 ) & 0x38 ) >> 3 ) == ( uint8( @a [ i ] + 1 ) & 0x07 ) ) and ( ( uint8( @a [ i ] + 2 ) & 0xF8 ) == 0xA0 ) and ( uint8( @a [ i ] + 6 ) <= 0x3F ) and ( ( ( uint8( @a [ i ] + 6 ) & 0x38 ) >> 3 ) != ( uint8( @a [ i ] + 6 ) & 0x07 ) ) )
}

rule maldoc_find_kernel32_base_method_3 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}

	condition:
		for any i in ( 1 .. #a ) : ( ( ( uint8( @a [ i ] + 5 ) & 0x07 ) == ( uint8( @a [ i ] + 8 ) & 0x07 ) ) and ( uint8( @a [ i ] + 8 ) <= 0x3F ) and ( ( ( uint8( @a [ i ] + 8 ) & 0x38 ) >> 3 ) != ( uint8( @a [ i ] + 8 ) & 0x07 ) ) )
}

rule maldoc_getEIP_method_1 : maldoc hardened
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"

	strings:
		$a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}

	condition:
		$a
}

rule mwi_document : exploitdoc maldoc hardened
{
	meta:
		description = "MWI generated document"
		author = "@Ydklijnsma"
		source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

	strings:
		$field_creation_tag = {7b 5c 66 69 65 6c 64 7b 5c 2a 5c 66 6c 64 69 6e 73 74 20 7b 20 49 4e 43 4c 55 44 45 50 49 43 54 55 52 45}
		$mwistat_url = {2e 70 68 70 3f 69 64 3d}
		$field_closing_tag = {5c 5c 2a 20 4d 45 52 47 45 46 4f 52 4d 41 54 20 5c 5c 64 7d 7d 7b 5c 66 6c 64 72 73 6c 74 7d 7d}

	condition:
		all of them
}

rule macrocheck : maldoc hardened
{
	meta:
		Author = "Fireeye Labs"
		Date = "2014/11/30"
		Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
		Reference = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

	strings:
		$PARAMpword = {((70 77 6f 72 64 3d) | (70 00 77 00 6f 00 72 00 64 00 3d 00))}
		$PARAMmsg = {((6d 73 67 3d) | (6d 00 73 00 67 00 3d 00))}
		$PARAMuname = {75 6e 61 6d 65 3d}
		$userform = {((55 73 65 72 46 6f 72 6d) | (55 00 73 00 65 00 72 00 46 00 6f 00 72 00 6d 00))}
		$userloginform = {((55 73 65 72 4c 6f 67 69 6e 46 6f 72 6d) | (55 00 73 00 65 00 72 00 4c 00 6f 00 67 00 69 00 6e 00 46 00 6f 00 72 00 6d 00))}
		$invalid = {((49 6e 76 61 6c 69 64 20 75 73 65 72 6e 61 6d 65 20 6f 72 20 70 61 73 73 77 6f 72 64) | (49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 20 00 6f 00 72 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$up1 = {((75 70 6c 6f 61 64 50 4f 53 54) | (75 00 70 00 6c 00 6f 00 61 00 64 00 50 00 4f 00 53 00 54 00))}
		$up2 = {((70 6f 73 74 55 70 6c 6f 61 64) | (70 00 6f 00 73 00 74 00 55 00 70 00 6c 00 6f 00 61 00 64 00))}

	condition:
		all of ( $PARAM* ) or ( ( $invalid or $userloginform or $userform ) and ( $up1 or $up2 ) )
}

rule office_document_vba : maldoc hardened
{
	meta:
		description = "Office document with embedded VBA"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-12-17"
		reference = "https://github.com/jipegit/"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = {50 4b}
		$97str1 = {5f 00 56 00 42 00 41 00 5f 00 50 00 52 00 4f 00 4a 00 45 00 43 00 54 00 5f 00 43 00 55 00 52 00}
		$97str2 = {56 42 41 50 72 6f 6a 65 63 74}
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
		$xmlstr1 = {76 62 61 50 72 6f 6a 65 63 74 2e 62 69 6e}
		$xmlstr2 = {76 62 61 44 61 74 61 2e 78 6d 6c}

	condition:
		($officemagic at 0 and any of ( $97str* ) ) or ( $zipmagic at 0 and any of ( $xmlstr* ) )
}

rule Office_AutoOpen_Macro : maldoc hardened limited
{
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 60
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 41 75 74 6f 4f 70 65 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 61 00 63 00 72 00 6f 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint32be( 0 ) == 0xd0cf11e0 and all of ( $s* ) and filesize < 300000
}

rule RTF_Shellcode : maldoc refined hardened
{
	meta:
		author = "RSA-IR – Jared Greenhill"
		date = "01/21/13"
		description = "identifies RTF's with potential shellcode"
		filetype = "RTF"

	strings:
		$rtfmagic = {7B 5C 72 74 66}
		$scregex = /(90){4,20}/

	condition:
		($rtfmagic at 0 ) and ( $scregex )
}

