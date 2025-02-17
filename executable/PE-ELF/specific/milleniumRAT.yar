import "pe"

rule milleniumRAT : refined hardened
{
	meta:
		author = "OPSWAT"
		description = "Detects Millenium RAT"
		date = "17-02-2025"
		vetted_family = "MilleniumRAT"
		score = 75

	strings:
		$st_eof = {5b 00 45 00 4f 00 46 00 5d 00}
		$st_av = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 20 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00}
		$st_tg = {54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 64 00 61 00 74 00 61 00}
		$st_buildmsg = {53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 61 00 20 00 62 00 75 00 69 00 6c 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 61 00 20 00 62 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 20 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 6b 00 65 00 79 00 21 00}
		$checklink_github = {72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00}
		$checklink_pasteCom = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00}
		$checklink_pasteOrg = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 6f 00 72 00 67 00}
		$netw_proc0 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 61 00 63 00 6b 00 65 00 72 00}
		$netw_proc1 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00}
		$netw_proc2 = {6e 00 65 00 74 00 6d 00 6f 00 6e 00}
		$netw_proc3 = {74 00 63 00 70 00 76 00 69 00 65 00 77 00}
		$netw_proc4 = {77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00}
		$netw_proc5 = {66 00 69 00 6c 00 65 00 6d 00 6f 00 6e 00}
		$enc_ftype0 = {2e 00 6c 00 6e 00 6b 00}
		$enc_ftype1 = {2e 00 70 00 6e 00 67 00}
		$enc_ftype2 = {2e 00 6a 00 70 00 67 00}
		$enc_ftype3 = {2e 00 62 00 6d 00 70 00}
		$enc_ftype4 = {2e 00 74 00 78 00 74 00}
		$enc_ftype5 = {2e 00 64 00 6f 00 63 00}
		$enc_ftype6 = {2e 00 74 00 78 00 74 00}
		$enc_ftype7 = {2e 00 64 00 6f 00 63 00 78 00}
		$enc_ftype8 = {2e 00 78 00 6c 00 73 00}
		$enc_ftype9 = {2e 00 78 00 6c 00 73 00 78 00}
		$enc_ftype10 = {2e 00 64 00 6f 00 63 00}
		$enc_ftype11 = {2e 00 70 00 70 00 74 00}
		$enc_ftype12 = {2e 00 70 00 70 00 74 00 78 00}
		$enc_ftype13 = {2e 00 63 00 73 00 76 00}
		$enc_ftype14 = {2e 00 73 00 71 00 6c 00}
		$enc_ftype15 = {2e 00 70 00 68 00 70 00}
		$enc_ftype16 = {2e 00 70 00 70 00 74 00}
		$enc_ftype17 = {2e 00 68 00 74 00 6d 00 6c 00}
		$enc_ftype18 = {2e 00 78 00 6d 00 6c 00}
		$enc_ftype19 = {2e 00 6a 00 61 00 72 00}
		$enc_ftype21 = {2e 00 70 00 79 00}
		$grab_ftype0 = {2e 00 70 00 64 00 66 00}
		$grab_ftype1 = {2e 00 72 00 64 00 70 00}
		$grab_ftype2 = {2e 00 74 00 78 00 74 00}
		$grab_ftype3 = {2e 00 72 00 74 00 66 00}
		$grab_ftype4 = {2e 00 64 00 6f 00 63 00}
		$grab_ftype5 = {2e 00 64 00 6f 00 63 00 78 00}
		$grab_ftype6 = {2e 00 78 00 6c 00 73 00}
		$grab_ftype7 = {2e 00 78 00 6c 00 73 00 78 00}
		$grab_ftype8 = {2e 00 6f 00 64 00 74 00}
		$grab_ftype9 = {2e 00 73 00 71 00 6c 00}
		$grab_ftype10 = {2e 00 70 00 68 00 70 00}
		$grab_ftype11 = {2e 00 70 00 79 00}
		$grab_ftype12 = {68 00 74 00 6d 00 6c 00}
		$grab_ftype13 = {2e 00 78 00 6d 00 6c 00}
		$grab_ftype14 = {2e 00 6a 00 73 00 6f 00 6e 00}
		$grab_ftype15 = {2e 00 63 00 73 00 76 00}
		$config_load = {
            (06 | 07 | 08 | 09 | 11 ??)     // IL: ldloc.2
            [1-2]                           // IL: ldc.i4.X or ldc.i4.s 
            9A                              // IL: ldelem.ref
            6F ?? ?? ?? 0A                  // IL: callvirt  instance string [mscorlib]System.Object::ToString()
            28 ?? ?? ?? 06                  // IL: call      string TelegramRAT.Program::Rot13(string)
            80 ?? ?? ?? 04                  // IL: stsfld    string TelegramRAT.config::___
        }

	condition:
		uint16( 0 ) == 0x5A4D and pe.imports ( "mscoree.dll" ) and 3 of ( $st* ) and 1 of ( $checklink* ) and 4 of ( $netw* ) and 15 of ( $enc* ) and 10 of ( $grab* ) and #config_load >= 8
}

