rule WEBSHELL_PHP_Generic : hardened limited
{
	meta:
		description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones inclusing suspicious strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/14"
		modified = "2023-09-18"
		hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
		hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
		hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
		hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
		hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
		hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
		hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
		hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
		hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
		hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
		hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
		hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
		hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
		hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
		hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
		hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
		hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
		hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
		hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
		hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
		hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
		hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
		hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
		hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
		hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
		hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
		hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
		id = "294ce5d5-55b2-5c79-b0f8-b66f949efbb2"

	strings:
		$wfp_tiny1 = {65 73 63 61 70 65 73 68 65 6c 6c 61 72 67}
		$wfp_tiny2 = {61 64 64 73 6c 61 73 68 65 73}
		$gfp_tiny3 = {69 6e 63 6c 75 64 65 20 22 2e 2f 63 6f 6d 6d 6f 6e 2e 70 68 70 22 3b}
		$gfp_tiny4 = {61 73 73 65 72 74 28 27 46 41 4c 53 45 27 29 3b}
		$gfp_tiny5 = {61 73 73 65 72 74 28 66 61 6c 73 65 29 3b}
		$gfp_tiny6 = {61 73 73 65 72 74 28 46 41 4c 53 45 29 3b}
		$gfp_tiny7 = {61 73 73 65 72 74 28 27 61 72 72 61 79 5f 6b 65 79 5f 65 78 69 73 74 73 28}
		$gfp_tiny8 = {65 63 68 6f 20 73 68 65 6c 6c 5f 65 78 65 63 28 24 61 73 70 65 6c 6c 63 6f 6d 6d 61 6e 64 20 2e 20 27 20 32 3e 26 31 27 29 3b}
		$gfp_tiny9 = {74 68 72 6f 77 20 6e 65 77 20 45 78 63 65 70 74 69 6f 6e 28 27 43 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 73 6f 75 72 63 65 20 77 69 74 68 20 69 64 20 27 20 2e 20 24 73 6f 75 72 63 65 49 64 29 3b}
		$gfp_tiny10 = {72 65 74 75 72 6e 20 69 73 73 65 74 28 20 24 5f 50 4f 53 54 5b 20 24 6b 65 79 20 5d 20 29 20 3f 20 24 5f 50 4f 53 54 5b 20 24 6b 65 79 20 5d 20 3a 20 28 20 69 73 73 65 74 28 20 24 5f 52 45 51 55 45 53 54 5b 20 24 6b 65 79 20 5d 20 29 20 3f 20 24 5f 52 45 51 55 45 53 54 5b 20 24 6b 65 79 20 5d 20 3a 20 24 64 65 66 61 75 6c 74 20 29 3b}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$inp1 = {((70 68 70 3a 2f 2f 69 6e 70 75 74) | (70 00 68 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 70 00 75 00 74 00))}
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
		$inp15 = {((5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 27 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp16 = {((5f 53 45 52 56 45 52 5b 22 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 22 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = {((61 72 72 61 79 5f 76 61 6c 75 65 73 28 24 5f 53 45 52 56 45 52 29) | (61 00 72 00 72 00 61 00 79 00 5f 00 76 00 61 00 6c 00 75 00 65 00 73 00 28 00 24 00 5f 00 53 00 45 00 52 00 56 00 45 00 52 00 29 00))}
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$inp20 = {((54 53 4f 50 5f) | (54 00 53 00 4f 00 50 00 5f 00))}
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}
		$gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6 = {73 65 6c 66 2e 64 65 6c 65 74 65}
		$gen_bit_sus9 = {22 63 6d 64 20 2f 63}
		$gen_bit_sus10 = {22 63 6d 64 22}
		$gen_bit_sus11 = {22 63 6d 64 2e 65 78 65}
		$gen_bit_sus12 = {((25 63 6f 6d 73 70 65 63 25) | (25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00))}
		$gen_bit_sus13 = {((25 43 4f 4d 53 50 45 43 25) | (25 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 25 00))}
		$gen_bit_sus18 = {48 6b 6c 6d 2e 47 65 74 56 61 6c 75 65 4e 61 6d 65 73 28 29 3b}
		$gen_bit_sus19 = {((68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 78 63 68 61 6e 67 65 2f) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 68 00 65 00 6d 00 61 00 73 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2f 00))}
		$gen_bit_sus21 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus22 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus23 = {((55 50 4c 4f 41 44) | (55 00 50 00 4c 00 4f 00 41 00 44 00))}
		$gen_bit_sus24 = {((66 69 6c 65 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus25 = {((66 69 6c 65 5f 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus29 = {((41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39) | (41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00))}
		$gen_bit_sus29b = {((61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 32 33 34 35 36 37) | (61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 32 00 33 00 34 00 35 00 36 00 37 00))}
		$gen_bit_sus30 = {((73 65 72 76 2d 75) | (73 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus31 = {((53 65 72 76 2d 75) | (53 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus32 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = {((43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 42 69 6e 61 72 79) | (43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 3a 00 20 00 42 00 69 00 6e 00 61 00 72 00 79 00))}
		$gen_bit_sus35 = {((63 72 61 63 6b) | (63 00 72 00 61 00 63 00 6b 00))}
		$gen_bit_sus44 = {((3c 70 72 65 3e) | (3c 00 70 00 72 00 65 00 3e 00))}
		$gen_bit_sus45 = {((3c 50 52 45 3e) | (3c 00 50 00 52 00 45 00 3e 00))}
		$gen_bit_sus46 = {((73 68 65 6c 6c 5f) | (73 00 68 00 65 00 6c 00 6c 00 5f 00))}
		$gen_bit_sus50 = {((62 79 70 61 73 73) | (62 00 79 00 70 00 61 00 73 00 73 00))}
		$gen_bit_sus52 = {((20 5e 20 24) | (20 00 5e 00 20 00 24 00))}
		$gen_bit_sus53 = {((2e 73 73 68 2f 61 75 74 68 6f 72 69 7a 65 64 5f 6b 65 79 73) | (2e 00 73 00 73 00 68 00 2f 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00))}
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = {((64 75 6d 70 65 72) | (64 00 75 00 6d 00 70 00 65 00 72 00))}
		$gen_bit_sus59 = {((27 63 6d 64 27) | (27 00 63 00 6d 00 64 00 27 00))}
		$gen_bit_sus60 = {((22 65 78 65 63 75 74 65 22) | (22 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 22 00))}
		$gen_bit_sus61 = {((2f 62 69 6e 2f 73 68) | (2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00))}
		$gen_bit_sus62 = {((43 79 62 65 72) | (43 00 79 00 62 00 65 00 72 00))}
		$gen_bit_sus63 = {((70 6f 72 74 73 63 61 6e) | (70 00 6f 00 72 00 74 00 73 00 63 00 61 00 6e 00))}
		$gen_bit_sus66 = {((77 68 6f 61 6d 69) | (77 00 68 00 6f 00 61 00 6d 00 69 00))}
		$gen_bit_sus67 = {((24 70 61 73 73 77 6f 72 64 3d 27) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 27 00))}
		$gen_bit_sus68 = {((24 70 61 73 73 77 6f 72 64 3d 22) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 22 00))}
		$gen_bit_sus69 = {((24 63 6d 64) | (24 00 63 00 6d 00 64 00))}
		$gen_bit_sus70 = {((22 3f 3e 22 2e) | (22 00 3f 00 3e 00 22 00 2e 00))}
		$gen_bit_sus71 = {((48 61 63 6b 69 6e 67) | (48 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus72 = {((68 61 63 6b 69 6e 67) | (68 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus73 = {((2e 68 74 70 61 73 73 77 64) | (2e 00 68 00 74 00 70 00 61 00 73 00 73 00 77 00 64 00))}
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_bit_sus75 = {((75 70 6c 6f 61 64 65 64) | (75 00 70 00 6c 00 6f 00 61 00 64 00 65 00 64 00))}
		$gen_much_sus7 = {57 65 62 20 53 68 65 6c 6c}
		$gen_much_sus8 = {57 65 62 53 68 65 6c 6c}
		$gen_much_sus3 = {68 69 64 64 65 64 20 73 68 65 6c 6c}
		$gen_much_sus4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c 2e 31}
		$gen_much_sus5 = {41 73 70 45 78 65 63}
		$gen_much_sus14 = {5c 70 63 41 6e 79 77 68 65 72 65 5c}
		$gen_much_sus15 = {61 6e 74 69 76 69 72 75 73}
		$gen_much_sus16 = {4d 63 41 66 65 65}
		$gen_much_sus17 = {6e 69 73 68 61 6e 67}
		$gen_much_sus18 = {((22 75 6e 73 61 66 65) | (22 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus19 = {((27 75 6e 73 61 66 65) | (27 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus24 = {((65 78 70 6c 6f 69 74) | (65 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus25 = {((45 78 70 6c 6f 69 74) | (45 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus26 = {((54 56 71 51 41 41 4d 41 41 41) | (54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00))}
		$gen_much_sus30 = {((48 61 63 6b 65 72) | (48 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus31 = {((48 41 43 4b 45 44) | (48 00 41 00 43 00 4b 00 45 00 44 00))}
		$gen_much_sus32 = {((68 61 63 6b 65 64) | (68 00 61 00 63 00 6b 00 65 00 64 00))}
		$gen_much_sus33 = {((68 61 63 6b 65 72) | (68 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus34 = {((67 72 61 79 68 61 74) | (67 00 72 00 61 00 79 00 68 00 61 00 74 00))}
		$gen_much_sus35 = {((4d 69 63 72 6f 73 6f 66 74 20 46 72 6f 6e 74 50 61 67 65) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 46 00 72 00 6f 00 6e 00 74 00 50 00 61 00 67 00 65 00))}
		$gen_much_sus36 = {((52 6f 6f 74 6b 69 74) | (52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus37 = {((72 6f 6f 74 6b 69 74) | (72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus38 = {((2f 2a 2d 2f 2a 2d 2a 2f) | (2f 00 2a 00 2d 00 2f 00 2a 00 2d 00 2a 00 2f 00))}
		$gen_much_sus39 = {((75 22 2b 22 6e 22 2b 22 73) | (75 00 22 00 2b 00 22 00 6e 00 22 00 2b 00 22 00 73 00))}
		$gen_much_sus40 = {((22 65 22 2b 22 76) | (22 00 65 00 22 00 2b 00 22 00 76 00))}
		$gen_much_sus41 = {((61 22 2b 22 6c 22) | (61 00 22 00 2b 00 22 00 6c 00 22 00))}
		$gen_much_sus42 = {((22 2b 22 28 22 2b 22) | (22 00 2b 00 22 00 28 00 22 00 2b 00 22 00))}
		$gen_much_sus43 = {((71 22 2b 22 75 22) | (71 00 22 00 2b 00 22 00 75 00 22 00))}
		$gen_much_sus44 = {((22 75 22 2b 22 65) | (22 00 75 00 22 00 2b 00 22 00 65 00))}
		$gen_much_sus45 = {((2f 2a 2f 2f 2a 2f) | (2f 00 2a 00 2f 00 2f 00 2a 00 2f 00))}
		$gen_much_sus46 = {((28 22 2f 2a 2f 22) | (28 00 22 00 2f 00 2a 00 2f 00 22 00))}
		$gen_much_sus47 = {((65 76 61 6c 28 65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00 65 00 76 00 61 00 6c 00 28 00))}
		$gen_much_sus48 = {((75 6e 6c 69 6e 6b 28 5f 5f 46 49 4c 45 5f 5f 29) | (75 00 6e 00 6c 00 69 00 6e 00 6b 00 28 00 5f 00 5f 00 46 00 49 00 4c 00 45 00 5f 00 5f 00 29 00))}
		$gen_much_sus49 = {((53 68 65 6c 6c 2e 55 73 65 72 73) | (53 00 68 00 65 00 6c 00 6c 00 2e 00 55 00 73 00 65 00 72 00 73 00))}
		$gen_much_sus50 = {((50 61 73 73 77 6f 72 64 54 79 70 65 3d 52 65 67 75 6c 61 72) | (50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 54 00 79 00 70 00 65 00 3d 00 52 00 65 00 67 00 75 00 6c 00 61 00 72 00))}
		$gen_much_sus51 = {((2d 45 78 70 69 72 65 3d 30) | (2d 00 45 00 78 00 70 00 69 00 72 00 65 00 3d 00 30 00))}
		$gen_much_sus60 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus61 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus62 = {((2b 2b 3b 24) | (2b 00 2b 00 3b 00 24 00))}
		$gen_much_sus63 = {((2b 2b 3b 20 24) | (2b 00 2b 00 3b 00 20 00 24 00))}
		$gen_much_sus64 = {((5f 2e 3d 24 5f) | (5f 00 2e 00 3d 00 24 00 5f 00))}
		$gen_much_sus70 = {((2d 70 65 72 6d 20 2d 30 34 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 34 00 30 00 30 00 30 00))}
		$gen_much_sus71 = {((2d 70 65 72 6d 20 2d 30 32 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 32 00 30 00 30 00 30 00))}
		$gen_much_sus72 = {((67 72 65 70 20 2d 6c 69 20 70 61 73 73 77 6f 72 64) | (67 00 72 00 65 00 70 00 20 00 2d 00 6c 00 69 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$gen_much_sus73 = {((2d 6e 61 6d 65 20 63 6f 6e 66 69 67 2e 69 6e 63 2e 70 68 70) | (2d 00 6e 00 61 00 6d 00 65 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 63 00 2e 00 70 00 68 00 70 00))}
		$gen_much_sus75 = {((70 61 73 73 77 6f 72 64 20 63 72 61 63 6b) | (70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 63 00 72 00 61 00 63 00 6b 00))}
		$gen_much_sus76 = {((6d 79 73 71 6c 44 6c 6c 2e 64 6c 6c) | (6d 00 79 00 73 00 71 00 6c 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00))}
		$gen_much_sus77 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$gen_much_sus80 = {((66 6f 70 65 6e 28 22 2e 68 74 61 63 63 65 73 73 22 2c 22 77) | (66 00 6f 00 70 00 65 00 6e 00 28 00 22 00 2e 00 68 00 74 00 61 00 63 00 63 00 65 00 73 00 73 00 22 00 2c 00 22 00 77 00))}
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = {((50 48 50 53 68 65 6c 6c) | (50 00 48 00 50 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus821 = {((50 48 50 20 53 68 65 6c 6c) | (50 00 48 00 50 00 20 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus83 = {((70 68 70 73 68 65 6c 6c) | (70 00 68 00 70 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus84 = {((50 48 50 73 68 65 6c 6c) | (50 00 48 00 50 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus87 = {((64 65 66 61 63 65) | (64 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus88 = {((44 65 66 61 63 65) | (44 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus89 = {((62 61 63 6b 64 6f 6f 72) | (62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00))}
		$gen_much_sus90 = {((72 30 30 74) | (72 00 30 00 30 00 74 00))}
		$gen_much_sus91 = {((78 70 5f 63 6d 64 73 68 65 6c 6c) | (78 00 70 00 5f 00 63 00 6d 00 64 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus92 = {((73 74 72 5f 72 6f 74 31 33) | (73 00 74 00 72 00 5f 00 72 00 6f 00 74 00 31 00 33 00))}
		$gif = { 47 49 46 38 }
		$cmpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cmpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
		$cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
		$cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$fp1 = {23 20 53 6f 6d 65 20 65 78 61 6d 70 6c 65 73 20 66 72 6f 6d 20 6f 62 66 75 73 63 61 74 65 64 20 6d 61 6c 77 61 72 65 3a}
		$fp2 = {7b 40 73 65 65 20 54 46 69 6c 65 55 70 6c 6f 61 64 7d 20 66 6f 72 20 66 75 72 74 68 65 72 20 64 65 74 61 69 6c 73 2e}

	condition:
		not ( any of ( $gfp_tiny* ) or 1 of ( $fp* ) ) and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $inp* ) ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or ( ( $gif at 0 or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 3 of ( $gen_bit_sus* ) ) ) or ( filesize < 50KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) or ( filesize < 100KB and ( 2 of ( $gen_much_sus* ) or 6 of ( $gen_bit_sus* ) ) ) or ( filesize < 150KB and ( 3 of ( $gen_much_sus* ) or 7 of ( $gen_bit_sus* ) ) ) or ( filesize < 500KB and ( 4 of ( $gen_much_sus* ) or 8 of ( $gen_bit_sus* ) ) ) ) and ( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or ( filesize < 500KB and ( 4 of ( $cmpayload* ) ) ) )
}

rule WEBSHELL_PHP_Generic_Callback : hardened limited
{
	meta:
		description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/01/14"
		modified = "2023-09-18"
		score = 60
		hash = "e98889690101b59260e871c49263314526f2093f"
		hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
		hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
		hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
		hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
		hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
		hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
		hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
		hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
		hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
		hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
		hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
		hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
		hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
		hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"
		id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"

	strings:
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$gfp_tiny3 = {69 6e 63 6c 75 64 65 20 22 2e 2f 63 6f 6d 6d 6f 6e 2e 70 68 70 22 3b}
		$gfp_tiny4 = {61 73 73 65 72 74 28 27 46 41 4c 53 45 27 29 3b}
		$gfp_tiny5 = {61 73 73 65 72 74 28 66 61 6c 73 65 29 3b}
		$gfp_tiny6 = {61 73 73 65 72 74 28 46 41 4c 53 45 29 3b}
		$gfp_tiny7 = {61 73 73 65 72 74 28 27 61 72 72 61 79 5f 6b 65 79 5f 65 78 69 73 74 73 28}
		$gfp_tiny8 = {65 63 68 6f 20 73 68 65 6c 6c 5f 65 78 65 63 28 24 61 73 70 65 6c 6c 63 6f 6d 6d 61 6e 64 20 2e 20 27 20 32 3e 26 31 27 29 3b}
		$gfp_tiny9 = {74 68 72 6f 77 20 6e 65 77 20 45 78 63 65 70 74 69 6f 6e 28 27 43 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 73 6f 75 72 63 65 20 77 69 74 68 20 69 64 20 27 20 2e 20 24 73 6f 75 72 63 65 49 64 29 3b}
		$gfp_tiny10 = {72 65 74 75 72 6e 20 69 73 73 65 74 28 20 24 5f 50 4f 53 54 5b 20 24 6b 65 79 20 5d 20 29 20 3f 20 24 5f 50 4f 53 54 5b 20 24 6b 65 79 20 5d 20 3a 20 28 20 69 73 73 65 74 28 20 24 5f 52 45 51 55 45 53 54 5b 20 24 6b 65 79 20 5d 20 29 20 3f 20 24 5f 52 45 51 55 45 53 54 5b 20 24 6b 65 79 20 5d 20 3a 20 24 64 65 66 61 75 6c 74 20 29 3b}
		$inp1 = {((70 68 70 3a 2f 2f 69 6e 70 75 74) | (70 00 68 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 70 00 75 00 74 00))}
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = {((5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 27 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp16 = {((5f 53 45 52 56 45 52 5b 22 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 22 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = {((61 72 72 61 79 5f 76 61 6c 75 65 73 28 24 5f 53 45 52 56 45 52 29) | (61 00 72 00 72 00 61 00 79 00 5f 00 76 00 61 00 6c 00 75 00 65 00 73 00 28 00 24 00 5f 00 53 00 45 00 52 00 56 00 45 00 52 00 29 00))}
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_callback2 = {((46 49 4c 54 45 52 5f 43 41 4c 4c 42 41 43 4b) | (46 00 49 00 4c 00 54 00 45 00 52 00 5f 00 43 00 41 00 4c 00 4c 00 42 00 41 00 43 00 4b 00))}
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = {((49 57 50 4d 4c 5f 42 61 63 6b 65 6e 64 5f 41 63 74 69 6f 6e 5f 4c 6f 61 64 65 72) | (49 00 57 00 50 00 4d 00 4c 00 5f 00 42 00 61 00 63 00 6b 00 65 00 6e 00 64 00 5f 00 41 00 63 00 74 00 69 00 6f 00 6e 00 5f 00 4c 00 6f 00 61 00 64 00 65 00 72 00))}
		$cfp3 = {3c 3f 70 68 70 63 6c 61 73 73 20 57 50 4d 4c}
		$gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6 = {73 65 6c 66 2e 64 65 6c 65 74 65}
		$gen_bit_sus9 = {22 63 6d 64 20 2f 63}
		$gen_bit_sus10 = {22 63 6d 64 22}
		$gen_bit_sus11 = {22 63 6d 64 2e 65 78 65}
		$gen_bit_sus12 = {((25 63 6f 6d 73 70 65 63 25) | (25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00))}
		$gen_bit_sus13 = {((25 43 4f 4d 53 50 45 43 25) | (25 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 25 00))}
		$gen_bit_sus18 = {48 6b 6c 6d 2e 47 65 74 56 61 6c 75 65 4e 61 6d 65 73 28 29 3b}
		$gen_bit_sus19 = {((68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 78 63 68 61 6e 67 65 2f) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 68 00 65 00 6d 00 61 00 73 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2f 00))}
		$gen_bit_sus21 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus22 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus23 = {((55 50 4c 4f 41 44) | (55 00 50 00 4c 00 4f 00 41 00 44 00))}
		$gen_bit_sus24 = {((66 69 6c 65 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus25 = {((66 69 6c 65 5f 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus29 = {((41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39) | (41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00))}
		$gen_bit_sus29b = {((61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 32 33 34 35 36 37) | (61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 32 00 33 00 34 00 35 00 36 00 37 00))}
		$gen_bit_sus30 = {((73 65 72 76 2d 75) | (73 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus31 = {((53 65 72 76 2d 75) | (53 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus32 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = {((43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 42 69 6e 61 72 79) | (43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 3a 00 20 00 42 00 69 00 6e 00 61 00 72 00 79 00))}
		$gen_bit_sus35 = {((63 72 61 63 6b) | (63 00 72 00 61 00 63 00 6b 00))}
		$gen_bit_sus44 = {((3c 70 72 65 3e) | (3c 00 70 00 72 00 65 00 3e 00))}
		$gen_bit_sus45 = {((3c 50 52 45 3e) | (3c 00 50 00 52 00 45 00 3e 00))}
		$gen_bit_sus46 = {((73 68 65 6c 6c 5f) | (73 00 68 00 65 00 6c 00 6c 00 5f 00))}
		$gen_bit_sus50 = {((62 79 70 61 73 73) | (62 00 79 00 70 00 61 00 73 00 73 00))}
		$gen_bit_sus52 = {((20 5e 20 24) | (20 00 5e 00 20 00 24 00))}
		$gen_bit_sus53 = {((2e 73 73 68 2f 61 75 74 68 6f 72 69 7a 65 64 5f 6b 65 79 73) | (2e 00 73 00 73 00 68 00 2f 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00))}
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = {((64 75 6d 70 65 72) | (64 00 75 00 6d 00 70 00 65 00 72 00))}
		$gen_bit_sus59 = {((27 63 6d 64 27) | (27 00 63 00 6d 00 64 00 27 00))}
		$gen_bit_sus60 = {((22 65 78 65 63 75 74 65 22) | (22 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 22 00))}
		$gen_bit_sus61 = {((2f 62 69 6e 2f 73 68) | (2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00))}
		$gen_bit_sus62 = {((43 79 62 65 72) | (43 00 79 00 62 00 65 00 72 00))}
		$gen_bit_sus63 = {((70 6f 72 74 73 63 61 6e) | (70 00 6f 00 72 00 74 00 73 00 63 00 61 00 6e 00))}
		$gen_bit_sus66 = {((77 68 6f 61 6d 69) | (77 00 68 00 6f 00 61 00 6d 00 69 00))}
		$gen_bit_sus67 = {((24 70 61 73 73 77 6f 72 64 3d 27) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 27 00))}
		$gen_bit_sus68 = {((24 70 61 73 73 77 6f 72 64 3d 22) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 22 00))}
		$gen_bit_sus69 = {((24 63 6d 64) | (24 00 63 00 6d 00 64 00))}
		$gen_bit_sus70 = {((22 3f 3e 22 2e) | (22 00 3f 00 3e 00 22 00 2e 00))}
		$gen_bit_sus71 = {((48 61 63 6b 69 6e 67) | (48 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus72 = {((68 61 63 6b 69 6e 67) | (68 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus73 = {((2e 68 74 70 61 73 73 77 64) | (2e 00 68 00 74 00 70 00 61 00 73 00 73 00 77 00 64 00))}
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7 = {57 65 62 20 53 68 65 6c 6c}
		$gen_much_sus8 = {57 65 62 53 68 65 6c 6c}
		$gen_much_sus3 = {68 69 64 64 65 64 20 73 68 65 6c 6c}
		$gen_much_sus4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c 2e 31}
		$gen_much_sus5 = {41 73 70 45 78 65 63}
		$gen_much_sus14 = {5c 70 63 41 6e 79 77 68 65 72 65 5c}
		$gen_much_sus15 = {61 6e 74 69 76 69 72 75 73}
		$gen_much_sus16 = {4d 63 41 66 65 65}
		$gen_much_sus17 = {6e 69 73 68 61 6e 67}
		$gen_much_sus18 = {((22 75 6e 73 61 66 65) | (22 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus19 = {((27 75 6e 73 61 66 65) | (27 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus24 = {((65 78 70 6c 6f 69 74) | (65 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus25 = {((45 78 70 6c 6f 69 74) | (45 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus26 = {((54 56 71 51 41 41 4d 41 41 41) | (54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00))}
		$gen_much_sus30 = {((48 61 63 6b 65 72) | (48 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus31 = {((48 41 43 4b 45 44) | (48 00 41 00 43 00 4b 00 45 00 44 00))}
		$gen_much_sus32 = {((68 61 63 6b 65 64) | (68 00 61 00 63 00 6b 00 65 00 64 00))}
		$gen_much_sus33 = {((68 61 63 6b 65 72) | (68 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus34 = {((67 72 61 79 68 61 74) | (67 00 72 00 61 00 79 00 68 00 61 00 74 00))}
		$gen_much_sus35 = {((4d 69 63 72 6f 73 6f 66 74 20 46 72 6f 6e 74 50 61 67 65) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 46 00 72 00 6f 00 6e 00 74 00 50 00 61 00 67 00 65 00))}
		$gen_much_sus36 = {((52 6f 6f 74 6b 69 74) | (52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus37 = {((72 6f 6f 74 6b 69 74) | (72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus38 = {((2f 2a 2d 2f 2a 2d 2a 2f) | (2f 00 2a 00 2d 00 2f 00 2a 00 2d 00 2a 00 2f 00))}
		$gen_much_sus39 = {((75 22 2b 22 6e 22 2b 22 73) | (75 00 22 00 2b 00 22 00 6e 00 22 00 2b 00 22 00 73 00))}
		$gen_much_sus40 = {((22 65 22 2b 22 76) | (22 00 65 00 22 00 2b 00 22 00 76 00))}
		$gen_much_sus41 = {((61 22 2b 22 6c 22) | (61 00 22 00 2b 00 22 00 6c 00 22 00))}
		$gen_much_sus42 = {((22 2b 22 28 22 2b 22) | (22 00 2b 00 22 00 28 00 22 00 2b 00 22 00))}
		$gen_much_sus43 = {((71 22 2b 22 75 22) | (71 00 22 00 2b 00 22 00 75 00 22 00))}
		$gen_much_sus44 = {((22 75 22 2b 22 65) | (22 00 75 00 22 00 2b 00 22 00 65 00))}
		$gen_much_sus45 = {((2f 2a 2f 2f 2a 2f) | (2f 00 2a 00 2f 00 2f 00 2a 00 2f 00))}
		$gen_much_sus46 = {((28 22 2f 2a 2f 22) | (28 00 22 00 2f 00 2a 00 2f 00 22 00))}
		$gen_much_sus47 = {((65 76 61 6c 28 65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00 65 00 76 00 61 00 6c 00 28 00))}
		$gen_much_sus48 = {((75 6e 6c 69 6e 6b 28 5f 5f 46 49 4c 45 5f 5f 29) | (75 00 6e 00 6c 00 69 00 6e 00 6b 00 28 00 5f 00 5f 00 46 00 49 00 4c 00 45 00 5f 00 5f 00 29 00))}
		$gen_much_sus49 = {((53 68 65 6c 6c 2e 55 73 65 72 73) | (53 00 68 00 65 00 6c 00 6c 00 2e 00 55 00 73 00 65 00 72 00 73 00))}
		$gen_much_sus50 = {((50 61 73 73 77 6f 72 64 54 79 70 65 3d 52 65 67 75 6c 61 72) | (50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 54 00 79 00 70 00 65 00 3d 00 52 00 65 00 67 00 75 00 6c 00 61 00 72 00))}
		$gen_much_sus51 = {((2d 45 78 70 69 72 65 3d 30) | (2d 00 45 00 78 00 70 00 69 00 72 00 65 00 3d 00 30 00))}
		$gen_much_sus60 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus61 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus62 = {((2b 2b 3b 24) | (2b 00 2b 00 3b 00 24 00))}
		$gen_much_sus63 = {((2b 2b 3b 20 24) | (2b 00 2b 00 3b 00 20 00 24 00))}
		$gen_much_sus64 = {((5f 2e 3d 24 5f) | (5f 00 2e 00 3d 00 24 00 5f 00))}
		$gen_much_sus70 = {((2d 70 65 72 6d 20 2d 30 34 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 34 00 30 00 30 00 30 00))}
		$gen_much_sus71 = {((2d 70 65 72 6d 20 2d 30 32 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 32 00 30 00 30 00 30 00))}
		$gen_much_sus72 = {((67 72 65 70 20 2d 6c 69 20 70 61 73 73 77 6f 72 64) | (67 00 72 00 65 00 70 00 20 00 2d 00 6c 00 69 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$gen_much_sus73 = {((2d 6e 61 6d 65 20 63 6f 6e 66 69 67 2e 69 6e 63 2e 70 68 70) | (2d 00 6e 00 61 00 6d 00 65 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 63 00 2e 00 70 00 68 00 70 00))}
		$gen_much_sus75 = {((70 61 73 73 77 6f 72 64 20 63 72 61 63 6b) | (70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 63 00 72 00 61 00 63 00 6b 00))}
		$gen_much_sus76 = {((6d 79 73 71 6c 44 6c 6c 2e 64 6c 6c) | (6d 00 79 00 73 00 71 00 6c 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00))}
		$gen_much_sus77 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$gen_much_sus80 = {((66 6f 70 65 6e 28 22 2e 68 74 61 63 63 65 73 73 22 2c 22 77) | (66 00 6f 00 70 00 65 00 6e 00 28 00 22 00 2e 00 68 00 74 00 61 00 63 00 63 00 65 00 73 00 73 00 22 00 2c 00 22 00 77 00))}
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = {((50 48 50 53 68 65 6c 6c) | (50 00 48 00 50 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus821 = {((50 48 50 20 53 68 65 6c 6c) | (50 00 48 00 50 00 20 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus83 = {((70 68 70 73 68 65 6c 6c) | (70 00 68 00 70 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus84 = {((50 48 50 73 68 65 6c 6c) | (50 00 48 00 50 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus87 = {((64 65 66 61 63 65) | (64 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus88 = {((44 65 66 61 63 65) | (44 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus89 = {((62 61 63 6b 64 6f 6f 72) | (62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00))}
		$gen_much_sus90 = {((72 30 30 74) | (72 00 30 00 30 00 74 00))}
		$gen_much_sus91 = {((78 70 5f 63 6d 64 73 68 65 6c 6c) | (78 00 70 00 5f 00 63 00 6d 00 64 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus92 = {((62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28) | (62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00))}
		$gen_much_sus93 = {((65 76 61 6c 28 22 2f 2a) | (65 00 76 00 61 00 6c 00 28 00 22 00 2f 00 2a 00))}
		$gen_much_sus94 = {((68 74 74 70 5f 72 65 73 70 6f 6e 73 65 5f 63 6f 64 65 28 34 30 34 29) | (68 00 74 00 74 00 70 00 5f 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 5f 00 63 00 6f 00 64 00 65 00 28 00 34 00 30 00 34 00 29 00))}
		$gif = { 47 49 46 38 }

	condition:
		not ( any of ( $gfp* ) ) and not ( any of ( $gfp_tiny* ) ) and ( any of ( $inp* ) ) and ( not any of ( $cfp* ) and ( any of ( $callback* ) or all of ( $m_callback* ) ) ) and ( filesize < 1000 or ( $gif at 0 or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 3 of ( $gen_bit_sus* ) ) ) or ( filesize < 50KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) or ( filesize < 100KB and ( 2 of ( $gen_much_sus* ) or 6 of ( $gen_bit_sus* ) ) ) or ( filesize < 150KB and ( 3 of ( $gen_much_sus* ) or 7 of ( $gen_bit_sus* ) ) ) or ( filesize < 500KB and ( 4 of ( $gen_much_sus* ) or 8 of ( $gen_bit_sus* ) ) ) ) )
}

rule WEBSHELL_PHP_Base64_Encoded_Payloads : FILE hardened limited
{
	meta:
		description = "php webshell containing base64 encoded payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
		hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
		hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
		hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
		hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
		hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
		hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
		hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
		hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
		hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
		hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
		hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
		hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
		hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
		hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"
		id = "4e42b47d-725b-5e1f-9408-6c6329f60506"

	strings:
		$decode1 = {((62 61 73 65 36 34 5f 64 65 63 6f 64 65) | (62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00))}
		$decode2 = {((6f 70 65 6e 73 73 6c 5f 64 65 63 72 79 70 74) | (6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 5f 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00))}
		$one1 = {6c 65 47 56 6a}
		$one2 = {56 34 5a 57}
		$one3 = {5a 58 68 6c 59}
		$one4 = {55 41 65 41 42 6c 41 47 4d 41}
		$one5 = {6c 41 48 67 41 5a 51 42 6a 41}
		$one6 = {5a 51 42 34 41 47 55 41 59 77}
		$two1 = {7a 61 47 56 73 62 46 39 6c 65 47 56 6a}
		$two2 = {4e 6f 5a 57 78 73 58 32 56 34 5a 57}
		$two3 = {63 32 68 6c 62 47 78 66 5a 58 68 6c 59}
		$two4 = {4d 41 61 41 42 6c 41 47 77 41 62 41 42 66 41 47 55 41 65 41 42 6c 41 47 4d 41}
		$two5 = {7a 41 47 67 41 5a 51 42 73 41 47 77 41 58 77 42 6c 41 48 67 41 5a 51 42 6a 41}
		$two6 = {63 77 42 6f 41 47 55 41 62 41 42 73 41 46 38 41 5a 51 42 34 41 47 55 41 59 77}
		$three1 = {77 59 58 4e 7a 64 47 68 79 64}
		$three2 = {42 68 63 33 4e 30 61 48 4a 31}
		$three3 = {63 47 46 7a 63 33 52 6f 63 6e}
		$three4 = {41 41 59 51 42 7a 41 48 4d 41 64 41 42 6f 41 48 49 41 64 51}
		$three5 = {77 41 47 45 41 63 77 42 7a 41 48 51 41 61 41 42 79 41 48 55 41}
		$three6 = {63 41 42 68 41 48 4d 41 63 77 42 30 41 47 67 41 63 67 42 31 41}
		$four1 = {7a 65 58 4e 30 5a 57}
		$four2 = {4e 35 63 33 52 6c 62}
		$four3 = {63 33 6c 7a 64 47 56 74}
		$four4 = {4d 41 65 51 42 7a 41 48 51 41 5a 51 42 74 41}
		$four5 = {7a 41 48 6b 41 63 77 42 30 41 47 55 41 62 51}
		$four6 = {63 77 42 35 41 48 4d 41 64 41 42 6c 41 47 30 41}
		$five1 = {77 62 33 42 6c 62}
		$five2 = {42 76 63 47 56 75}
		$five3 = {63 47 39 77 5a 57}
		$five4 = {41 41 62 77 42 77 41 47 55 41 62 67}
		$five5 = {77 41 47 38 41 63 41 42 6c 41 47 34 41}
		$five6 = {63 41 42 76 41 48 41 41 5a 51 42 75 41}
		$six1 = {77 63 6d 39 6a 58 32 39 77 5a 57}
		$six2 = {42 79 62 32 4e 66 62 33 42 6c 62}
		$six3 = {63 48 4a 76 59 31 39 76 63 47 56 75}
		$six4 = {41 41 63 67 42 76 41 47 4d 41 58 77 42 76 41 48 41 41 5a 51 42 75 41}
		$six5 = {77 41 48 49 41 62 77 42 6a 41 46 38 41 62 77 42 77 41 47 55 41 62 67}
		$six6 = {63 41 42 79 41 47 38 41 59 77 42 66 41 47 38 41 63 41 42 6c 41 47 34 41}
		$seven1 = {77 59 32 35 30 62 46 39 6c 65 47 56 6a}
		$seven2 = {42 6a 62 6e 52 73 58 32 56 34 5a 57}
		$seven3 = {63 47 4e 75 64 47 78 66 5a 58 68 6c 59}
		$seven4 = {41 41 59 77 42 75 41 48 51 41 62 41 42 66 41 47 55 41 65 41 42 6c 41 47 4d 41}
		$seven5 = {77 41 47 4d 41 62 67 42 30 41 47 77 41 58 77 42 6c 41 48 67 41 5a 51 42 6a 41}
		$seven6 = {63 41 42 6a 41 47 34 41 64 41 42 73 41 46 38 41 5a 51 42 34 41 47 55 41 59 77}
		$eight1 = {6c 64 6d 46 73}
		$eight2 = {56 32 59 57}
		$eight3 = {5a 58 5a 68 62}
		$eight4 = {55 41 64 67 42 68 41 47 77 41}
		$eight5 = {6c 41 48 59 41 59 51 42 73 41}
		$eight6 = {5a 51 42 32 41 47 45 41 62 41}
		$nine1 = {68 63 33 4e 6c 63 6e}
		$nine2 = {46 7a 63 32 56 79 64}
		$nine3 = {59 58 4e 7a 5a 58 4a 30}
		$nine4 = {45 41 63 77 42 7a 41 47 55 41 63 67 42 30 41}
		$nine5 = {68 41 48 4d 41 63 77 42 6c 41 48 49 41 64 41}
		$nine6 = {59 51 42 7a 41 48 4d 41 5a 51 42 79 41 48 51 41}
		$execu1 = {6c 65 47 56 6a 64}
		$execu2 = {56 34 5a 57 4e 31}
		$execu3 = {5a 58 68 6c 59 33}
		$esystem1 = {6c 63 33 6c 7a 64 47 56 74}
		$esystem2 = {56 7a 65 58 4e 30 5a 57}
		$esystem3 = {5a 58 4e 35 63 33 52 6c 62}
		$opening1 = {76 63 47 56 75 61 57 35 6e}
		$opening2 = {39 77 5a 57 35 70 62 6d}
		$opening3 = {62 33 42 6c 62 6d 6c 75 5a}
		$fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
		$fp2 = {59 58 42 70 4c 6e 52 6c 62 47 56 6e 63 6d 46 74 4c 6d 39}
		$fp3 = {20 47 45 54 20 2f}
		$fp4 = {20 50 4f 53 54 20 2f}
		$fpa1 = {2f 63 6e 3d 52 65 63 69 70 69 65 6e 74 73}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 300KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and not any of ( $fp* ) and any of ( $decode* ) and ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or ( any of ( $four* ) and not any of ( $esystem* ) ) or ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule WEBSHELL_PHP_Unknown_1 : hardened
{
	meta:
		description = "obfuscated php webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
		hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
		date = "2021/01/07"
		modified = "2023-04-05"
		id = "93d01a4c-4c18-55d2-b682-68a1f6460889"

	strings:
		$sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
		$sp1 = {((3d 65 78 70 6c 6f 64 65 28 63 68 72 28) | (3d 00 65 00 78 00 70 00 6c 00 6f 00 64 00 65 00 28 00 63 00 68 00 72 00 28 00))}
		$sp2 = {((3b 20 69 66 20 28 21 66 75 6e 63 74 69 6f 6e 5f 65 78 69 73 74 73 28 27) | (3b 00 20 00 69 00 66 00 20 00 28 00 21 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 5f 00 65 00 78 00 69 00 73 00 74 00 73 00 28 00 27 00))}
		$sp3 = {((20 3d 20 4e 55 4c 4c 3b 20 66 6f 72 28) | (20 00 3d 00 20 00 4e 00 55 00 4c 00 4c 00 3b 00 20 00 66 00 6f 00 72 00 28 00))}

	condition:
		filesize < 300KB and all of ( $sp* )
}

rule WEBSHELL_PHP_Generic_Eval : hardened
{
	meta:
		description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
		hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
		hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
		hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
		hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
		hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
		hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
		hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
		hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
		hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
		hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
		hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
		hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
		hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
		hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
		hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
		hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
		hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
		hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
		id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"

	strings:
		$geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(\(base64_decode)?(\(stripslashes)?[\t ]*(\(trim)?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$gfp_3 = {20 47 45 54 20 2f}
		$gfp_4 = {20 50 4f 53 54 20 2f}

	condition:
		filesize < 300KB and not ( any of ( $gfp* ) ) and $geval
}

rule WEBSHELL_PHP_Double_Eval_Tiny : hardened limited
{
	meta:
		description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021-01-11"
		modified = "2023-07-05"
		hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
		hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
		hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
		hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
		hash = "006620d2a701de73d995fc950691665c0692af11"
		id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"

	strings:
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
		$fp1 = {((63 6c 6f 6e 65) | (63 00 6c 00 6f 00 6e 00 65 00))}
		$fp2 = {2a 20 40 61 73 73 65 72 74}
		$fp3 = {2a 40 61 73 73 65 72 74}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize > 70 and filesize < 300 and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and #payload >= 2 and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC : hardened limited
{
	meta:
		description = "PHP webshell obfuscated"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/12"
		modified = "2023-04-05"
		hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
		hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
		hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
		hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
		id = "f66e337b-8478-5cd3-b01a-81133edaa8e5"

	strings:
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$o1 = {((63 68 72 28) | (63 00 68 00 72 00 28 00))}
		$o2 = {((63 68 72 20 28) | (63 00 68 00 72 00 20 00 28 00))}
		$o3 = {((67 6f 74 6f) | (67 00 6f 00 74 00 6f 00))}
		$o4 = {((5c 78 39) | (5c 00 78 00 39 00))}
		$o5 = {((5c 78 33) | (5c 00 78 00 33 00))}
		$o6 = {((5c 36 31) | (5c 00 36 00 31 00))}
		$o7 = {((5c 34 34) | (5c 00 34 00 34 00))}
		$o8 = {((5c 31 31 32) | (5c 00 31 00 31 00 32 00))}
		$o9 = {((5c 31 32 30) | (5c 00 31 00 32 00 30 00))}
		$fp1 = {((24 67 6f 74 6f) | (24 00 67 00 6f 00 74 00 6f 00))}
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}

	condition:
		not ( any of ( $gfp* ) ) and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( not $fp1 and ( ( filesize < 20KB and ( ( #o1 + #o2 ) > 50 or #o3 > 10 or ( #o4 + #o5 + #o6 + #o7 + #o8 + #o9 ) > 20 ) ) or ( filesize < 200KB and ( ( #o1 + #o2 ) > 200 or #o3 > 30 or ( #o4 + #o5 + #o6 + #o7 + #o8 + #o9 ) > 30 ) ) ) ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) )
}

rule WEBSHELL_PHP_OBFUSC_Encoded : hardened limited
{
	meta:
		description = "PHP webshell obfuscated by encoding"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/04/18"
		modified = "2023-04-05"
		score = 70
		hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
		hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
		hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"
		id = "134c1189-1b41-58d5-af66-beaa4795a704"

	strings:
		$enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 700KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $enc* )
}

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex : hardened limited
{
	meta:
		description = "PHP webshell obfuscated by encoding of mixed hex and dec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/04/18"
		modified = "2023-04-05"
		hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
		hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
		hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
		hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
		hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
		hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
		hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
		hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
		hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
		hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
		hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
		hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"
		id = "9ae920e2-17c8-58fd-8566-90d461a54943"

	strings:
		$mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 700KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $mix* )
}

rule WEBSHELL_PHP_OBFUSC_Tiny : hardened limited
{
	meta:
		description = "PHP webshell obfuscated"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/12"
		modified = "2023-07-05"
		hash = "b7b7aabd518a2f8578d4b1bc9a3af60d155972f1"
		hash = "694ec6e1c4f34632a9bd7065f73be473"
		hash = "5c871183444dbb5c8766df6b126bd80c624a63a16cc39e20a0f7b002216b2ba5"
		id = "d78e495f-54d2-5f5f-920f-fb6612afbca3"

	strings:
		$obf1 = /\w'\.'\w/ wide ascii
		$obf2 = /\w\"\.\"\w/ wide ascii
		$obf3 = {((5d 2e 24) | (5d 00 2e 00 24 00))}
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}

	condition:
		filesize < 500 and not ( any of ( $gfp* ) ) and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Str_Replace : hardened limited
{
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/12"
		modified = "2023-04-05"
		hash = "691305753e26884d0f930cda0fe5231c6437de94"
		hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
		hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
		hash = "d1863aeca1a479462648d975773f795bb33a7af2"
		hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
		hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"
		id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"

	strings:
		$payload1 = {((73 74 72 5f 72 65 70 6c 61 63 65) | (73 00 74 00 72 00 5f 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00))}
		$payload2 = {((66 75 6e 63 74 69 6f 6e) | (66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00))}
		$goto = {((67 6f 74 6f) | (67 00 6f 00 74 00 6f 00))}
		$chr1 = {((5c 36 31) | (5c 00 36 00 31 00))}
		$chr2 = {((5c 31 31 32) | (5c 00 31 00 31 00 32 00))}
		$chr3 = {((5c 31 32 30) | (5c 00 31 00 32 00 30 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 300KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $payload* ) and #goto > 1 and ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Fopo : hardened limited
{
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
		hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
		hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
		date = "2021/01/12"
		modified = "2023-04-05"
		id = "a298e99d-1ba8-58c8-afb9-fc988ea91e9a"

	strings:
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
		$one1 = {((37 51 47 56 32 59 57 77 6f) | (37 00 51 00 47 00 56 00 32 00 59 00 57 00 77 00 6f 00))}
		$one2 = {((74 41 5a 58 5a 68 62 43) | (74 00 41 00 5a 00 58 00 5a 00 68 00 62 00 43 00))}
		$one3 = {((4f 30 42 6c 64 6d 46 73 4b) | (4f 00 30 00 42 00 6c 00 64 00 6d 00 46 00 73 00 4b 00))}
		$one4 = {((73 41 51 41 42 6c 41 48 59 41 59 51 42 73 41 43 67 41) | (73 00 41 00 51 00 41 00 42 00 6c 00 41 00 48 00 59 00 41 00 59 00 51 00 42 00 73 00 41 00 43 00 67 00 41 00))}
		$one5 = {((37 41 45 41 41 5a 51 42 32 41 47 45 41 62 41 41 6f 41) | (37 00 41 00 45 00 41 00 41 00 5a 00 51 00 42 00 32 00 41 00 47 00 45 00 41 00 62 00 41 00 41 00 6f 00 41 00))}
		$one6 = {((4f 77 42 41 41 47 55 41 64 67 42 68 41 47 77 41 4b 41) | (4f 00 77 00 42 00 41 00 41 00 47 00 55 00 41 00 64 00 67 00 42 00 68 00 41 00 47 00 77 00 41 00 4b 00 41 00))}
		$two1 = {((37 51 47 46 7a 63 32 56 79 64 43) | (37 00 51 00 47 00 46 00 7a 00 63 00 32 00 56 00 79 00 64 00 43 00))}
		$two2 = {((74 41 59 58 4e 7a 5a 58 4a 30 4b) | (74 00 41 00 59 00 58 00 4e 00 7a 00 5a 00 58 00 4a 00 30 00 4b 00))}
		$two3 = {((4f 30 42 68 63 33 4e 6c 63 6e 51 6f) | (4f 00 30 00 42 00 68 00 63 00 33 00 4e 00 6c 00 63 00 6e 00 51 00 6f 00))}
		$two4 = {((73 41 51 41 42 68 41 48 4d 41 63 77 42 6c 41 48 49 41 64 41 41 6f 41) | (73 00 41 00 51 00 41 00 42 00 68 00 41 00 48 00 4d 00 41 00 63 00 77 00 42 00 6c 00 41 00 48 00 49 00 41 00 64 00 41 00 41 00 6f 00 41 00))}
		$two5 = {((37 41 45 41 41 59 51 42 7a 41 48 4d 41 5a 51 42 79 41 48 51 41 4b 41) | (37 00 41 00 45 00 41 00 41 00 59 00 51 00 42 00 7a 00 41 00 48 00 4d 00 41 00 5a 00 51 00 42 00 79 00 41 00 48 00 51 00 41 00 4b 00 41 00))}
		$two6 = {((4f 77 42 41 41 47 45 41 63 77 42 7a 41 47 55 41 63 67 42 30 41 43 67 41) | (4f 00 77 00 42 00 41 00 41 00 47 00 45 00 41 00 63 00 77 00 42 00 7a 00 41 00 47 00 55 00 41 00 63 00 67 00 42 00 30 00 41 00 43 00 67 00 41 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 3000KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and $payload and ( any of ( $one* ) or any of ( $two* ) )
}

rule WEBSHELL_PHP_Gzinflated : hardened limited
{
	meta:
		description = "PHP webshell which directly eval()s obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/12"
		modified = "2023-07-05"
		hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"
		hash = "6f36d201cd32296bad9d5864c7357e8634f365cc"
		hash = "ab10a1e69f3dfe7c2ad12b2e6c0e66db819c2301"
		hash = "a6cf337fe11fe646d7eee3d3f09c7cb9643d921d"
		hash = "07eb6634f28549ebf26583e8b154c6a579b8a733"
		id = "9cf99ae4-9f7c-502f-9294-b531002953d6"

	strings:
		$payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
		$payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
		$payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
		$payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
		$payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase
		$fp1 = {59 58 42 70 4c 6e 52 6c 62 47 56 6e 63 6d 46 74 4c 6d 39}
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 700KB and not ( any of ( $gfp* ) ) and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and 1 of ( $payload* ) and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC_3 : hardened limited
{
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/04/17"
		modified = "2023-07-05"
		hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
		hash = "d6b851cae249ea6744078393f622ace15f9880bc"
		hash = "14e02b61905cf373ba9234a13958310652a91ece"
		hash = "6f97f607a3db798128288e32de851c6f56e91c1d"
		id = "f2017e6f-0623-53ff-aa26-a479f3a02024"

	strings:
		$obf1 = {((63 68 72 28) | (63 00 68 00 72 00 28 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_callback2 = {((46 49 4c 54 45 52 5f 43 41 4c 4c 42 41 43 4b) | (46 00 49 00 4c 00 54 00 45 00 52 00 5f 00 43 00 41 00 4c 00 4c 00 42 00 41 00 43 00 4b 00))}
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = {((49 57 50 4d 4c 5f 42 61 63 6b 65 6e 64 5f 41 63 74 69 6f 6e 5f 4c 6f 61 64 65 72) | (49 00 57 00 50 00 4d 00 4c 00 5f 00 42 00 61 00 63 00 6b 00 65 00 6e 00 64 00 5f 00 41 00 63 00 74 00 69 00 6f 00 6e 00 5f 00 4c 00 6f 00 61 00 64 00 65 00 72 00))}
		$cfp3 = {3c 3f 70 68 70 63 6c 61 73 73 20 57 50 4d 4c}
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}
		$cobfs1 = {((67 7a 69 6e 66 6c 61 74 65) | (67 00 7a 00 69 00 6e 00 66 00 6c 00 61 00 74 00 65 00))}
		$cobfs2 = {((67 7a 75 6e 63 6f 6d 70 72 65 73 73) | (67 00 7a 00 75 00 6e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00))}
		$cobfs3 = {((67 7a 64 65 63 6f 64 65) | (67 00 7a 00 64 00 65 00 63 00 6f 00 64 00 65 00))}
		$cobfs4 = {((62 61 73 65 36 34 5f 64 65 63 6f 64 65) | (62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00))}
		$cobfs5 = {((70 61 63 6b) | (70 00 61 00 63 00 6b 00))}
		$cobfs6 = {((75 6e 64 65 63 6f 64 65) | (75 00 6e 00 64 00 65 00 63 00 6f 00 64 00 65 00))}
		$gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6 = {73 65 6c 66 2e 64 65 6c 65 74 65}
		$gen_bit_sus9 = {22 63 6d 64 20 2f 63}
		$gen_bit_sus10 = {22 63 6d 64 22}
		$gen_bit_sus11 = {22 63 6d 64 2e 65 78 65}
		$gen_bit_sus12 = {((25 63 6f 6d 73 70 65 63 25) | (25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00))}
		$gen_bit_sus13 = {((25 43 4f 4d 53 50 45 43 25) | (25 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 25 00))}
		$gen_bit_sus18 = {48 6b 6c 6d 2e 47 65 74 56 61 6c 75 65 4e 61 6d 65 73 28 29 3b}
		$gen_bit_sus19 = {((68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 78 63 68 61 6e 67 65 2f) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 68 00 65 00 6d 00 61 00 73 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2f 00))}
		$gen_bit_sus21 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus22 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus23 = {((55 50 4c 4f 41 44) | (55 00 50 00 4c 00 4f 00 41 00 44 00))}
		$gen_bit_sus24 = {((66 69 6c 65 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus25 = {((66 69 6c 65 5f 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus29 = {((41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39) | (41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00))}
		$gen_bit_sus29b = {((61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 32 33 34 35 36 37) | (61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 32 00 33 00 34 00 35 00 36 00 37 00))}
		$gen_bit_sus30 = {((73 65 72 76 2d 75) | (73 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus31 = {((53 65 72 76 2d 75) | (53 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus32 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = {((43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 42 69 6e 61 72 79) | (43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 3a 00 20 00 42 00 69 00 6e 00 61 00 72 00 79 00))}
		$gen_bit_sus35 = {((63 72 61 63 6b) | (63 00 72 00 61 00 63 00 6b 00))}
		$gen_bit_sus44 = {((3c 70 72 65 3e) | (3c 00 70 00 72 00 65 00 3e 00))}
		$gen_bit_sus45 = {((3c 50 52 45 3e) | (3c 00 50 00 52 00 45 00 3e 00))}
		$gen_bit_sus46 = {((73 68 65 6c 6c 5f) | (73 00 68 00 65 00 6c 00 6c 00 5f 00))}
		$gen_bit_sus50 = {((62 79 70 61 73 73) | (62 00 79 00 70 00 61 00 73 00 73 00))}
		$gen_bit_sus52 = {((20 5e 20 24) | (20 00 5e 00 20 00 24 00))}
		$gen_bit_sus53 = {((2e 73 73 68 2f 61 75 74 68 6f 72 69 7a 65 64 5f 6b 65 79 73) | (2e 00 73 00 73 00 68 00 2f 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00))}
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = {((64 75 6d 70 65 72) | (64 00 75 00 6d 00 70 00 65 00 72 00))}
		$gen_bit_sus59 = {((27 63 6d 64 27) | (27 00 63 00 6d 00 64 00 27 00))}
		$gen_bit_sus60 = {((22 65 78 65 63 75 74 65 22) | (22 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 22 00))}
		$gen_bit_sus61 = {((2f 62 69 6e 2f 73 68) | (2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00))}
		$gen_bit_sus62 = {((43 79 62 65 72) | (43 00 79 00 62 00 65 00 72 00))}
		$gen_bit_sus63 = {((70 6f 72 74 73 63 61 6e) | (70 00 6f 00 72 00 74 00 73 00 63 00 61 00 6e 00))}
		$gen_bit_sus66 = {((77 68 6f 61 6d 69) | (77 00 68 00 6f 00 61 00 6d 00 69 00))}
		$gen_bit_sus67 = {((24 70 61 73 73 77 6f 72 64 3d 27) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 27 00))}
		$gen_bit_sus68 = {((24 70 61 73 73 77 6f 72 64 3d 22) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 22 00))}
		$gen_bit_sus69 = {((24 63 6d 64) | (24 00 63 00 6d 00 64 00))}
		$gen_bit_sus70 = {((22 3f 3e 22 2e) | (22 00 3f 00 3e 00 22 00 2e 00))}
		$gen_bit_sus71 = {((48 61 63 6b 69 6e 67) | (48 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus72 = {((68 61 63 6b 69 6e 67) | (68 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus73 = {((2e 68 74 70 61 73 73 77 64) | (2e 00 68 00 74 00 70 00 61 00 73 00 73 00 77 00 64 00))}
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7 = {57 65 62 20 53 68 65 6c 6c}
		$gen_much_sus8 = {57 65 62 53 68 65 6c 6c}
		$gen_much_sus3 = {68 69 64 64 65 64 20 73 68 65 6c 6c}
		$gen_much_sus4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c 2e 31}
		$gen_much_sus5 = {41 73 70 45 78 65 63}
		$gen_much_sus14 = {5c 70 63 41 6e 79 77 68 65 72 65 5c}
		$gen_much_sus15 = {61 6e 74 69 76 69 72 75 73}
		$gen_much_sus16 = {4d 63 41 66 65 65}
		$gen_much_sus17 = {6e 69 73 68 61 6e 67}
		$gen_much_sus18 = {((22 75 6e 73 61 66 65) | (22 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus19 = {((27 75 6e 73 61 66 65) | (27 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus24 = {((65 78 70 6c 6f 69 74) | (65 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus25 = {((45 78 70 6c 6f 69 74) | (45 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus26 = {((54 56 71 51 41 41 4d 41 41 41) | (54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00))}
		$gen_much_sus30 = {((48 61 63 6b 65 72) | (48 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus31 = {((48 41 43 4b 45 44) | (48 00 41 00 43 00 4b 00 45 00 44 00))}
		$gen_much_sus32 = {((68 61 63 6b 65 64) | (68 00 61 00 63 00 6b 00 65 00 64 00))}
		$gen_much_sus33 = {((68 61 63 6b 65 72) | (68 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus34 = {((67 72 61 79 68 61 74) | (67 00 72 00 61 00 79 00 68 00 61 00 74 00))}
		$gen_much_sus35 = {((4d 69 63 72 6f 73 6f 66 74 20 46 72 6f 6e 74 50 61 67 65) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 46 00 72 00 6f 00 6e 00 74 00 50 00 61 00 67 00 65 00))}
		$gen_much_sus36 = {((52 6f 6f 74 6b 69 74) | (52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus37 = {((72 6f 6f 74 6b 69 74) | (72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus38 = {((2f 2a 2d 2f 2a 2d 2a 2f) | (2f 00 2a 00 2d 00 2f 00 2a 00 2d 00 2a 00 2f 00))}
		$gen_much_sus39 = {((75 22 2b 22 6e 22 2b 22 73) | (75 00 22 00 2b 00 22 00 6e 00 22 00 2b 00 22 00 73 00))}
		$gen_much_sus40 = {((22 65 22 2b 22 76) | (22 00 65 00 22 00 2b 00 22 00 76 00))}
		$gen_much_sus41 = {((61 22 2b 22 6c 22) | (61 00 22 00 2b 00 22 00 6c 00 22 00))}
		$gen_much_sus42 = {((22 2b 22 28 22 2b 22) | (22 00 2b 00 22 00 28 00 22 00 2b 00 22 00))}
		$gen_much_sus43 = {((71 22 2b 22 75 22) | (71 00 22 00 2b 00 22 00 75 00 22 00))}
		$gen_much_sus44 = {((22 75 22 2b 22 65) | (22 00 75 00 22 00 2b 00 22 00 65 00))}
		$gen_much_sus45 = {((2f 2a 2f 2f 2a 2f) | (2f 00 2a 00 2f 00 2f 00 2a 00 2f 00))}
		$gen_much_sus46 = {((28 22 2f 2a 2f 22) | (28 00 22 00 2f 00 2a 00 2f 00 22 00))}
		$gen_much_sus47 = {((65 76 61 6c 28 65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00 65 00 76 00 61 00 6c 00 28 00))}
		$gen_much_sus48 = {((75 6e 6c 69 6e 6b 28 5f 5f 46 49 4c 45 5f 5f 29) | (75 00 6e 00 6c 00 69 00 6e 00 6b 00 28 00 5f 00 5f 00 46 00 49 00 4c 00 45 00 5f 00 5f 00 29 00))}
		$gen_much_sus49 = {((53 68 65 6c 6c 2e 55 73 65 72 73) | (53 00 68 00 65 00 6c 00 6c 00 2e 00 55 00 73 00 65 00 72 00 73 00))}
		$gen_much_sus50 = {((50 61 73 73 77 6f 72 64 54 79 70 65 3d 52 65 67 75 6c 61 72) | (50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 54 00 79 00 70 00 65 00 3d 00 52 00 65 00 67 00 75 00 6c 00 61 00 72 00))}
		$gen_much_sus51 = {((2d 45 78 70 69 72 65 3d 30) | (2d 00 45 00 78 00 70 00 69 00 72 00 65 00 3d 00 30 00))}
		$gen_much_sus60 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus61 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus62 = {((2b 2b 3b 24) | (2b 00 2b 00 3b 00 24 00))}
		$gen_much_sus63 = {((2b 2b 3b 20 24) | (2b 00 2b 00 3b 00 20 00 24 00))}
		$gen_much_sus64 = {((5f 2e 3d 24 5f) | (5f 00 2e 00 3d 00 24 00 5f 00))}
		$gen_much_sus70 = {((2d 70 65 72 6d 20 2d 30 34 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 34 00 30 00 30 00 30 00))}
		$gen_much_sus71 = {((2d 70 65 72 6d 20 2d 30 32 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 32 00 30 00 30 00 30 00))}
		$gen_much_sus72 = {((67 72 65 70 20 2d 6c 69 20 70 61 73 73 77 6f 72 64) | (67 00 72 00 65 00 70 00 20 00 2d 00 6c 00 69 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$gen_much_sus73 = {((2d 6e 61 6d 65 20 63 6f 6e 66 69 67 2e 69 6e 63 2e 70 68 70) | (2d 00 6e 00 61 00 6d 00 65 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 63 00 2e 00 70 00 68 00 70 00))}
		$gen_much_sus75 = {((70 61 73 73 77 6f 72 64 20 63 72 61 63 6b) | (70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 63 00 72 00 61 00 63 00 6b 00))}
		$gen_much_sus76 = {((6d 79 73 71 6c 44 6c 6c 2e 64 6c 6c) | (6d 00 79 00 73 00 71 00 6c 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00))}
		$gen_much_sus77 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$gen_much_sus80 = {((66 6f 70 65 6e 28 22 2e 68 74 61 63 63 65 73 73 22 2c 22 77) | (66 00 6f 00 70 00 65 00 6e 00 28 00 22 00 2e 00 68 00 74 00 61 00 63 00 63 00 65 00 73 00 73 00 22 00 2c 00 22 00 77 00))}
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = {((50 48 50 53 68 65 6c 6c) | (50 00 48 00 50 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus821 = {((50 48 50 20 53 68 65 6c 6c) | (50 00 48 00 50 00 20 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus83 = {((70 68 70 73 68 65 6c 6c) | (70 00 68 00 70 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus84 = {((50 48 50 73 68 65 6c 6c) | (50 00 48 00 50 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus87 = {((64 65 66 61 63 65) | (64 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus88 = {((44 65 66 61 63 65) | (44 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus89 = {((62 61 63 6b 64 6f 6f 72) | (62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00))}
		$gen_much_sus90 = {((72 30 30 74) | (72 00 30 00 30 00 74 00))}
		$gen_much_sus91 = {((78 70 5f 63 6d 64 73 68 65 6c 6c) | (78 00 70 00 5f 00 63 00 6d 00 64 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus92 = {((62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28) | (62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00))}
		$gen_much_sus93 = {((65 76 61 6c 28 22 2f 2a) | (65 00 76 00 61 00 6c 00 28 00 22 00 2f 00 2a 00))}
		$gen_much_sus94 = {((3d 24 5f 43 4f 4f 4b 49 45 3b) | (3d 00 24 00 5f 00 43 00 4f 00 4f 00 4b 00 49 00 45 00 3b 00))}
		$gif = { 47 49 46 38 }

	condition:
		(( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( ( not any of ( $cfp* ) and ( any of ( $callback* ) or all of ( $m_callback* ) ) ) or ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) ) and ( any of ( $cobfs* ) ) and ( filesize < 1KB or ( filesize < 3KB and ( ( $gif at 0 or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 3 of ( $gen_bit_sus* ) ) ) or ( filesize < 50KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) or ( filesize < 100KB and ( 2 of ( $gen_much_sus* ) or 6 of ( $gen_bit_sus* ) ) ) or ( filesize < 150KB and ( 3 of ( $gen_much_sus* ) or 7 of ( $gen_bit_sus* ) ) ) or ( filesize < 500KB and ( 4 of ( $gen_much_sus* ) or 8 of ( $gen_bit_sus* ) ) ) ) or #obf1 > 10 ) ) )
}

rule WEBSHELL_PHP_Includer_Eval : hardened limited
{
	meta:
		description = "PHP webshell which eval()s another included file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/13"
		modified = "2023-04-05"
		hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
		hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
		hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
		hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"
		id = "995fcc34-f91e-5c9c-97b1-84eed1714d40"

	strings:
		$payload1 = {((65 76 61 6c) | (65 00 76 00 61 00 6c 00))}
		$payload2 = {((61 73 73 65 72 74) | (61 00 73 00 73 00 65 00 72 00 74 00))}
		$include1 = {((24 5f 46 49 4c 45) | (24 00 5f 00 46 00 49 00 4c 00 45 00))}
		$include2 = {((69 6e 63 6c 75 64 65) | (69 00 6e 00 63 00 6c 00 75 00 64 00 65 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 200 and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and 1 of ( $payload* ) and 1 of ( $include* )
}

rule WEBSHELL_PHP_Includer_Tiny : hardened limited
{
	meta:
		description = "Suspicious: Might be PHP webshell includer, check the included file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/04/17"
		modified = "2023-07-05"
		hash = "0687585025f99596508783b891e26d6989eec2ba"
		hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
		hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"
		id = "9bf96ddc-d984-57eb-9803-0b01890711b5"

	strings:
		$php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 100 and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $php_include* )
}

rule WEBSHELL_PHP_Dynamic : hardened limited
{
	meta:
		description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/01/13"
		modified = "2023-10-06"
		score = 60
		hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
		hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
		hash = "c4765e81550b476976604d01c20e3dbd415366df"
		hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"
		id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"

	strings:
		$pd_fp1 = {((77 68 6f 6f 70 73 5f 61 64 64 5f 73 74 61 63 6b 5f 66 72 61 6d 65) | (77 00 68 00 6f 00 6f 00 70 00 73 00 5f 00 61 00 64 00 64 00 5f 00 73 00 74 00 61 00 63 00 6b 00 5f 00 66 00 72 00 61 00 6d 00 65 00))}
		$pd_fp2 = {((6e 65 77 20 24 65 63 28 24 63 6f 64 65 2c 20 24 6d 6f 64 65 2c 20 24 6f 70 74 69 6f 6e 73 2c 20 24 75 73 65 72 69 6e 66 6f 29 3b) | (6e 00 65 00 77 00 20 00 24 00 65 00 63 00 28 00 24 00 63 00 6f 00 64 00 65 00 2c 00 20 00 24 00 6d 00 6f 00 64 00 65 00 2c 00 20 00 24 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 2c 00 20 00 24 00 75 00 73 00 65 00 72 00 69 00 6e 00 66 00 6f 00 29 00 3b 00))}
		$pd_fp3 = {28 24 69 29 5d 20 3d 20 36 30 30 3b}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
		$dynamic8 = /\${[^}]{1,20}}(\[[^\]]{1,20}\])?\(\${/ wide ascii
		$fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B }
		$fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B }
		$fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B}
		$fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B }
		$fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B }
		$fp6 = {2f 2f 20 54 4f 44 4f 20 65 72 72 6f 72 20 61 62 6f 75 74 20 6d 69 73 73 69 6e 67 20 65 78 70 72 65 73 73 69 6f 6e}
		$fp7 = {2f 2f 20 54 68 69 73 20 69 73 20 61 6e 20 69 6e 76 61 6c 69 64 20 6c 6f 63 61 74 69 6f 6e 20 66 6f 72 20 61 6e 20 61 74 74 72 69 62 75 74 65 2c 20}
		$fp8 = {2f 2a 20 41 75 74 6f 2d 67 65 6e 65 72 61 74 65 64 20 66 72 6f 6d 20 70 68 70 2f 70 68 70 2d 6c 61 6e 67 73 70 65 63 20 74 65 73 74 73 20 2a 2f}

	condition:
		filesize > 20 and filesize < 200 and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $dynamic* ) ) and not any of ( $pd_fp* ) and not 1 of ( $fp* )
}

import "math"

rule WEBSHELL_PHP_Dynamic_Big : hardened limited
{
	meta:
		description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/02/07"
		modified = "2023-09-18"
		score = 50
		hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
		hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
		hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
		hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
		hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
		hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
		hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
		hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
		hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"
		id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"

	strings:
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
		$new_php2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$new_php3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$php_short = {3c 3f}
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
		$dynamic8 = {((65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00))}
		$gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6 = {73 65 6c 66 2e 64 65 6c 65 74 65}
		$gen_bit_sus9 = {22 63 6d 64 20 2f 63}
		$gen_bit_sus10 = {22 63 6d 64 22}
		$gen_bit_sus11 = {22 63 6d 64 2e 65 78 65}
		$gen_bit_sus12 = {((25 63 6f 6d 73 70 65 63 25) | (25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00))}
		$gen_bit_sus13 = {((25 43 4f 4d 53 50 45 43 25) | (25 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 25 00))}
		$gen_bit_sus18 = {48 6b 6c 6d 2e 47 65 74 56 61 6c 75 65 4e 61 6d 65 73 28 29 3b}
		$gen_bit_sus19 = {((68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 78 63 68 61 6e 67 65 2f) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 68 00 65 00 6d 00 61 00 73 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2f 00))}
		$gen_bit_sus21 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus22 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$gen_bit_sus23 = {((55 50 4c 4f 41 44) | (55 00 50 00 4c 00 4f 00 41 00 44 00))}
		$gen_bit_sus24 = {((66 69 6c 65 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus25 = {((66 69 6c 65 5f 75 70 6c 6f 61 64) | (66 00 69 00 6c 00 65 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$gen_bit_sus27 = {((7a 75 6e 63 6f 6d 70) | (7a 00 75 00 6e 00 63 00 6f 00 6d 00 70 00))}
		$gen_bit_sus28 = {((61 73 65 36) | (61 00 73 00 65 00 36 00))}
		$gen_bit_sus29 = {((41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39) | (41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00))}
		$gen_bit_sus29b = {((61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 32 33 34 35 36 37) | (61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 32 00 33 00 34 00 35 00 36 00 37 00))}
		$gen_bit_sus30 = {((73 65 72 76 2d 75) | (73 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus31 = {((53 65 72 76 2d 75) | (53 00 65 00 72 00 76 00 2d 00 75 00))}
		$gen_bit_sus32 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = {((43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 42 69 6e 61 72 79) | (43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 3a 00 20 00 42 00 69 00 6e 00 61 00 72 00 79 00))}
		$gen_bit_sus35 = {((63 72 61 63 6b) | (63 00 72 00 61 00 63 00 6b 00))}
		$gen_bit_sus44 = {((3c 70 72 65 3e) | (3c 00 70 00 72 00 65 00 3e 00))}
		$gen_bit_sus45 = {((3c 50 52 45 3e) | (3c 00 50 00 52 00 45 00 3e 00))}
		$gen_bit_sus46 = {((73 68 65 6c 6c 5f) | (73 00 68 00 65 00 6c 00 6c 00 5f 00))}
		$gen_bit_sus50 = {((62 79 70 61 73 73) | (62 00 79 00 70 00 61 00 73 00 73 00))}
		$gen_bit_sus52 = {((20 5e 20 24) | (20 00 5e 00 20 00 24 00))}
		$gen_bit_sus53 = {((2e 73 73 68 2f 61 75 74 68 6f 72 69 7a 65 64 5f 6b 65 79 73) | (2e 00 73 00 73 00 68 00 2f 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00))}
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = {((64 75 6d 70 65 72) | (64 00 75 00 6d 00 70 00 65 00 72 00))}
		$gen_bit_sus59 = {((27 63 6d 64 27) | (27 00 63 00 6d 00 64 00 27 00))}
		$gen_bit_sus60 = {((22 65 78 65 63 75 74 65 22) | (22 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 22 00))}
		$gen_bit_sus61 = {((2f 62 69 6e 2f 73 68) | (2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00))}
		$gen_bit_sus62 = {((43 79 62 65 72) | (43 00 79 00 62 00 65 00 72 00))}
		$gen_bit_sus63 = {((70 6f 72 74 73 63 61 6e) | (70 00 6f 00 72 00 74 00 73 00 63 00 61 00 6e 00))}
		$gen_bit_sus65 = {((77 68 6f 61 6d 69) | (77 00 68 00 6f 00 61 00 6d 00 69 00))}
		$gen_bit_sus67 = {((24 70 61 73 73 77 6f 72 64 3d 27) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 27 00))}
		$gen_bit_sus68 = {((24 70 61 73 73 77 6f 72 64 3d 22) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 22 00))}
		$gen_bit_sus69 = {((24 63 6d 64) | (24 00 63 00 6d 00 64 00))}
		$gen_bit_sus70 = {((22 3f 3e 22 2e) | (22 00 3f 00 3e 00 22 00 2e 00))}
		$gen_bit_sus71 = {((48 61 63 6b 69 6e 67) | (48 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus72 = {((68 61 63 6b 69 6e 67) | (68 00 61 00 63 00 6b 00 69 00 6e 00 67 00))}
		$gen_bit_sus73 = {((2e 68 74 70 61 73 73 77 64) | (2e 00 68 00 74 00 70 00 61 00 73 00 73 00 77 00 64 00))}
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_bit_sus99 = {((24 70 61 73 73 77 6f 72 64 20 3d 20) | (24 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 3d 00 20 00))}
		$gen_bit_sus100 = {((28 29 3b 24) | (28 00 29 00 3b 00 24 00))}
		$gen_much_sus7 = {57 65 62 20 53 68 65 6c 6c}
		$gen_much_sus8 = {57 65 62 53 68 65 6c 6c}
		$gen_much_sus3 = {68 69 64 64 65 64 20 73 68 65 6c 6c}
		$gen_much_sus4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c 2e 31}
		$gen_much_sus5 = {41 73 70 45 78 65 63}
		$gen_much_sus14 = {5c 70 63 41 6e 79 77 68 65 72 65 5c}
		$gen_much_sus15 = {61 6e 74 69 76 69 72 75 73}
		$gen_much_sus16 = {4d 63 41 66 65 65}
		$gen_much_sus17 = {6e 69 73 68 61 6e 67}
		$gen_much_sus18 = {((22 75 6e 73 61 66 65) | (22 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus19 = {((27 75 6e 73 61 66 65) | (27 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$gen_much_sus24 = {((65 78 70 6c 6f 69 74) | (65 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus25 = {((45 78 70 6c 6f 69 74) | (45 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$gen_much_sus26 = {((54 56 71 51 41 41 4d 41 41 41) | (54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00))}
		$gen_much_sus30 = {((48 61 63 6b 65 72) | (48 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus31 = {((48 41 43 4b 45 44) | (48 00 41 00 43 00 4b 00 45 00 44 00))}
		$gen_much_sus32 = {((68 61 63 6b 65 64) | (68 00 61 00 63 00 6b 00 65 00 64 00))}
		$gen_much_sus33 = {((68 61 63 6b 65 72) | (68 00 61 00 63 00 6b 00 65 00 72 00))}
		$gen_much_sus34 = {((67 72 61 79 68 61 74) | (67 00 72 00 61 00 79 00 68 00 61 00 74 00))}
		$gen_much_sus35 = {((4d 69 63 72 6f 73 6f 66 74 20 46 72 6f 6e 74 50 61 67 65) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 46 00 72 00 6f 00 6e 00 74 00 50 00 61 00 67 00 65 00))}
		$gen_much_sus36 = {((52 6f 6f 74 6b 69 74) | (52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus37 = {((72 6f 6f 74 6b 69 74) | (72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$gen_much_sus38 = {((2f 2a 2d 2f 2a 2d 2a 2f) | (2f 00 2a 00 2d 00 2f 00 2a 00 2d 00 2a 00 2f 00))}
		$gen_much_sus39 = {((75 22 2b 22 6e 22 2b 22 73) | (75 00 22 00 2b 00 22 00 6e 00 22 00 2b 00 22 00 73 00))}
		$gen_much_sus40 = {((22 65 22 2b 22 76) | (22 00 65 00 22 00 2b 00 22 00 76 00))}
		$gen_much_sus41 = {((61 22 2b 22 6c 22) | (61 00 22 00 2b 00 22 00 6c 00 22 00))}
		$gen_much_sus42 = {((22 2b 22 28 22 2b 22) | (22 00 2b 00 22 00 28 00 22 00 2b 00 22 00))}
		$gen_much_sus43 = {((71 22 2b 22 75 22) | (71 00 22 00 2b 00 22 00 75 00 22 00))}
		$gen_much_sus44 = {((22 75 22 2b 22 65) | (22 00 75 00 22 00 2b 00 22 00 65 00))}
		$gen_much_sus45 = {((2f 2a 2f 2f 2a 2f) | (2f 00 2a 00 2f 00 2f 00 2a 00 2f 00))}
		$gen_much_sus46 = {((28 22 2f 2a 2f 22) | (28 00 22 00 2f 00 2a 00 2f 00 22 00))}
		$gen_much_sus47 = {((65 76 61 6c 28 65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00 65 00 76 00 61 00 6c 00 28 00))}
		$gen_much_sus48 = {((75 6e 6c 69 6e 6b 28 5f 5f 46 49 4c 45 5f 5f 29) | (75 00 6e 00 6c 00 69 00 6e 00 6b 00 28 00 5f 00 5f 00 46 00 49 00 4c 00 45 00 5f 00 5f 00 29 00))}
		$gen_much_sus49 = {((53 68 65 6c 6c 2e 55 73 65 72 73) | (53 00 68 00 65 00 6c 00 6c 00 2e 00 55 00 73 00 65 00 72 00 73 00))}
		$gen_much_sus50 = {((50 61 73 73 77 6f 72 64 54 79 70 65 3d 52 65 67 75 6c 61 72) | (50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 54 00 79 00 70 00 65 00 3d 00 52 00 65 00 67 00 75 00 6c 00 61 00 72 00))}
		$gen_much_sus51 = {((2d 45 78 70 69 72 65 3d 30) | (2d 00 45 00 78 00 70 00 69 00 72 00 65 00 3d 00 30 00))}
		$gen_much_sus60 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus61 = {((5f 3d 24 24 5f) | (5f 00 3d 00 24 00 24 00 5f 00))}
		$gen_much_sus62 = {((2b 2b 3b 24) | (2b 00 2b 00 3b 00 24 00))}
		$gen_much_sus63 = {((2b 2b 3b 20 24) | (2b 00 2b 00 3b 00 20 00 24 00))}
		$gen_much_sus64 = {((5f 2e 3d 24 5f) | (5f 00 2e 00 3d 00 24 00 5f 00))}
		$gen_much_sus70 = {((2d 70 65 72 6d 20 2d 30 34 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 34 00 30 00 30 00 30 00))}
		$gen_much_sus71 = {((2d 70 65 72 6d 20 2d 30 32 30 30 30) | (2d 00 70 00 65 00 72 00 6d 00 20 00 2d 00 30 00 32 00 30 00 30 00 30 00))}
		$gen_much_sus72 = {((67 72 65 70 20 2d 6c 69 20 70 61 73 73 77 6f 72 64) | (67 00 72 00 65 00 70 00 20 00 2d 00 6c 00 69 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$gen_much_sus73 = {((2d 6e 61 6d 65 20 63 6f 6e 66 69 67 2e 69 6e 63 2e 70 68 70) | (2d 00 6e 00 61 00 6d 00 65 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 63 00 2e 00 70 00 68 00 70 00))}
		$gen_much_sus75 = {((70 61 73 73 77 6f 72 64 20 63 72 61 63 6b) | (70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 63 00 72 00 61 00 63 00 6b 00))}
		$gen_much_sus76 = {((6d 79 73 71 6c 44 6c 6c 2e 64 6c 6c) | (6d 00 79 00 73 00 71 00 6c 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00))}
		$gen_much_sus77 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$gen_much_sus80 = {((66 6f 70 65 6e 28 22 2e 68 74 61 63 63 65 73 73 22 2c 22 77) | (66 00 6f 00 70 00 65 00 6e 00 28 00 22 00 2e 00 68 00 74 00 61 00 63 00 63 00 65 00 73 00 73 00 22 00 2c 00 22 00 77 00))}
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = {((50 48 50 53 68 65 6c 6c) | (50 00 48 00 50 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus821 = {((50 48 50 20 53 68 65 6c 6c) | (50 00 48 00 50 00 20 00 53 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus83 = {((70 68 70 73 68 65 6c 6c) | (70 00 68 00 70 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus84 = {((50 48 50 73 68 65 6c 6c) | (50 00 48 00 50 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus87 = {((64 65 66 61 63 65) | (64 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus88 = {((44 65 66 61 63 65) | (44 00 65 00 66 00 61 00 63 00 65 00))}
		$gen_much_sus89 = {((62 61 63 6b 64 6f 6f 72) | (62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00))}
		$gen_much_sus90 = {((72 30 30 74) | (72 00 30 00 30 00 74 00))}
		$gen_much_sus91 = {((78 70 5f 63 6d 64 73 68 65 6c 6c) | (78 00 70 00 5f 00 63 00 6d 00 64 00 73 00 68 00 65 00 6c 00 6c 00))}
		$gen_much_sus92 = {((44 45 46 41 43 45) | (44 00 45 00 46 00 41 00 43 00 45 00))}
		$gen_much_sus93 = {((42 79 70 61 73 73) | (42 00 79 00 70 00 61 00 73 00 73 00))}
		$gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
		$gen_much_sus100 = {((72 6f 74 31 33) | (72 00 6f 00 74 00 31 00 33 00))}
		$gen_much_sus101 = {((69 6e 69 5f 73 65 74 28 27 65 72 72 6f 72 5f 6c 6f 67 27) | (69 00 6e 00 69 00 5f 00 73 00 65 00 74 00 28 00 27 00 65 00 72 00 72 00 6f 00 72 00 5f 00 6c 00 6f 00 67 00 27 00))}
		$gen_much_sus102 = {((62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28) | (62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00))}
		$gen_much_sus103 = {((3d 24 5f 43 4f 4f 4b 49 45 3b) | (3d 00 24 00 5f 00 43 00 4f 00 4f 00 4b 00 49 00 45 00 3b 00))}
		$gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
		$gen_much_sus105 = {((24 47 4c 4f 42 41 4c 53 5b 22 5f 5f) | (24 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 53 00 5b 00 22 00 5f 00 5f 00))}
		$gen_much_sus106 = {((29 2d 30 29) | (29 00 2d 00 30 00 29 00))}
		$gen_much_sus107 = {((2d 30 29 2b) | (2d 00 30 00 29 00 2b 00))}
		$gen_much_sus108 = {((2b 30 29 2b) | (2b 00 30 00 29 00 2b 00))}
		$gen_much_sus109 = {((2b 28 30 2f) | (2b 00 28 00 30 00 2f 00))}
		$gen_much_sus110 = {((2b 28 30 2b) | (2b 00 28 00 30 00 2b 00))}
		$gen_much_sus111 = {((65 78 74 72 61 63 74 28 24 5f 52 45 51 55 45 53 54 29) | (65 00 78 00 74 00 72 00 61 00 63 00 74 00 28 00 24 00 5f 00 52 00 45 00 51 00 55 00 45 00 53 00 54 00 29 00))}
		$gen_much_sus112 = {((3c 3f 70 68 70 09 09 09 09 09 09 09 09 09 09 09) | (3c 00 3f 00 70 00 68 00 70 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00))}
		$gen_much_sus113 = {((09 09 09 09 09 09 09 09 09 09 09 65 78 74 72 61 63 74) | (09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 09 00 65 00 78 00 74 00 72 00 61 00 63 00 74 00))}
		$gen_much_sus114 = {((22 20 2e 22) | (22 00 20 00 2e 00 22 00))}
		$gen_much_sus115 = {((65 6e 64 28 24 5f 50 4f 53 54) | (65 00 6e 00 64 00 28 00 24 00 5f 00 50 00 4f 00 53 00 54 00))}
		$weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
		$weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii
		$weevely3 = /';\$\w{1,2}='/ wide ascii
		$weevely4 = {((73 74 72 5f 72 65 70 6c 61 63 65) | (73 00 74 00 72 00 5f 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00))}
		$gif = { 47 49 46 38 }
		$fp1 = {23 20 53 6f 6d 65 20 65 78 61 6d 70 6c 65 73 20 66 72 6f 6d 20 6f 62 66 75 73 63 61 74 65 64 20 6d 61 6c 77 61 72 65 3a}
		$fp2 = {2a 20 40 70 61 63 6b 61 67 65 20 20 20 50 48 50 5f 43 6f 64 65 53 6e 69 66 66 65 72}
		$fp3 = {2e 6a 51 75 65 72 79 3d 3d 3d}
		$fp4 = {2a 20 40 70 61 72 61 6d 20 73 74 72 69 6e 67 20 24 6c 73 74 61 74 20 65 6e 63 6f 64 65 64 20 4c 53 74 61 74 20 73 74 72 69 6e 67}

	condition:
		not ( uint16( 0 ) == 0x5a4d or uint32be( 0 ) == 0x3c3f786d or uint32be( 0 ) == 0x3c3f584d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 or 1 of ( $fp* ) ) and ( any of ( $new_php* ) or $php_short at 0 ) and ( any of ( $dynamic* ) ) and ( $gif at 0 or ( ( filesize < 1KB and ( 1 of ( $gen_much_sus* ) ) ) or ( filesize < 2KB and ( ( #weevely1 + #weevely2 + #weevely3 ) > 2 and #weevely4 > 1 ) ) or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) or ( filesize < 50KB and ( 3 of ( $gen_much_sus* ) or 5 of ( $gen_bit_sus* ) ) ) or ( filesize < 100KB and ( 3 of ( $gen_much_sus* ) or 6 of ( $gen_bit_sus* ) ) ) or ( filesize < 160KB and ( 3 of ( $gen_much_sus* ) or 7 of ( $gen_bit_sus* ) or ( math.deviation ( 500 , filesize - 500 , 89.0 ) > 70 ) ) ) or ( filesize < 500KB and ( 4 of ( $gen_much_sus* ) or 8 of ( $gen_bit_sus* ) or #gen_much_sus104 > 4 ) ) ) or ( filesize > 2KB and filesize < 1MB and ( ( math.entropy ( 500 , filesize - 500 ) >= 5.7 and math.mean ( 500 , filesize - 500 ) > 80 and math.deviation ( 500 , filesize - 500 , 89.0 ) < 23 ) or ( math.entropy ( 500 , filesize - 500 ) >= 7.7 and math.mean ( 500 , filesize - 500 ) > 120 and math.mean ( 500 , filesize - 500 ) < 136 and math.deviation ( 500 , filesize - 500 , 89.0 ) > 65 ) ) ) )
}

import "math"

rule WEBSHELL_PHP_Encoded_Big : hardened limited
{
	meta:
		description = "PHP webshell using some kind of eval with encoded blob to decode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/02/07"
		modified = "2023-07-05"
		score = 50
		hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
		hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
		hash = "b15b073801067429a93e116af1147a21b928b215"
		hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
		hash = "042245ee0c54996608ff8f442c8bafb8"
		id = "c3bb7b8b-c554-5802-8955-c83722498f8b"

	strings:
		$new_php1 = /<\?=[\w\s@$]/ wide ascii
		$new_php2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$new_php3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$php_short = {3c 3f}
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}

	condition:
		filesize < 1000KB and ( any of ( $new_php* ) or $php_short at 0 ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( filesize > 2KB and ( math.entropy ( 500 , filesize - 500 ) >= 5.7 and math.mean ( 500 , filesize - 500 ) > 80 and math.deviation ( 500 , filesize - 500 , 89.0 ) < 24 ) or ( math.entropy ( 500 , filesize - 500 ) >= 7.7 and math.mean ( 500 , filesize - 500 ) > 120 and math.mean ( 500 , filesize - 500 ) < 136 and math.deviation ( 500 , filesize - 500 , 89.0 ) > 65 ) )
}

rule WEBSHELL_PHP_Generic_Backticks : hardened limited
{
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
		hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
		hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"

	strings:
		$backtick = /`\s*{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		(( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and $backtick and filesize < 200
}

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC : hardened limited
{
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
		hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
		hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		id = "5ecb329f-0755-536d-8bfa-e36158474a0b"

	strings:
		$s1 = /echo[\t ]*\(?`\$/ wide ascii
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		filesize < 500 and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and $s1
}

rule WEBSHELL_PHP_By_String_Known_Webshell : hardened limited
{
	meta:
		description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021-01-09"
		modified = "2023-04-05"
		score = 70
		hash = "d889da22893536d5965541c30896f4ed4fdf461d"
		hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
		hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
		hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
		hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
		hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
		hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
		hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
		hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
		hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
		hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
		hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
		hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
		hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
		hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
		hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
		hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
		hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
		hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"
		id = "05ac0e0a-3a19-5c60-b89a-4a300d8c22e7"

	strings:
		$pbs1 = {((62 33 37 34 6b 20 73 68 65 6c 6c) | (62 00 33 00 37 00 34 00 6b 00 20 00 73 00 68 00 65 00 6c 00 6c 00))}
		$pbs2 = {((62 33 37 34 6b 2f 62 33 37 34 6b) | (62 00 33 00 37 00 34 00 6b 00 2f 00 62 00 33 00 37 00 34 00 6b 00))}
		$pbs3 = {((22 62 33 37 34 6b) | (22 00 62 00 33 00 37 00 34 00 6b 00))}
		$pbs4 = {((24 62 33 37 34 6b 28 22) | (24 00 62 00 33 00 37 00 34 00 6b 00 28 00 22 00))}
		$pbs5 = {((62 33 37 34 6b 20) | (62 00 33 00 37 00 34 00 6b 00 20 00))}
		$pbs6 = {((30 64 65 36 36 34 65 63 64 32 62 65 30 32 63 64 64 35 34 32 33 34 61 30 64 31 32 32 39 62 34 33) | (30 00 64 00 65 00 36 00 36 00 34 00 65 00 63 00 64 00 32 00 62 00 65 00 30 00 32 00 63 00 64 00 64 00 35 00 34 00 32 00 33 00 34 00 61 00 30 00 64 00 31 00 32 00 32 00 39 00 62 00 34 00 33 00))}
		$pbs7 = {((70 77 6e 73 68 65 6c 6c) | (70 00 77 00 6e 00 73 00 68 00 65 00 6c 00 6c 00))}
		$pbs8 = {((72 65 47 65 6f 72 67) | (72 00 65 00 47 00 65 00 6f 00 72 00 67 00))}
		$pbs9 = {((47 65 6f 72 67 20 73 61 79 73 2c 20 27 41 6c 6c 20 73 65 65 6d 73 20 66 69 6e 65) | (47 00 65 00 6f 00 72 00 67 00 20 00 73 00 61 00 79 00 73 00 2c 00 20 00 27 00 41 00 6c 00 6c 00 20 00 73 00 65 00 65 00 6d 00 73 00 20 00 66 00 69 00 6e 00 65 00))}
		$pbs10 = {((4d 79 20 50 48 50 20 53 68 65 6c 6c 20 2d 20 41 20 76 65 72 79 20 73 69 6d 70 6c 65 20 77 65 62 20 73 68 65 6c 6c) | (4d 00 79 00 20 00 50 00 48 00 50 00 20 00 53 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 20 00 41 00 20 00 76 00 65 00 72 00 79 00 20 00 73 00 69 00 6d 00 70 00 6c 00 65 00 20 00 77 00 65 00 62 00 20 00 73 00 68 00 65 00 6c 00 6c 00))}
		$pbs11 = {((3c 74 69 74 6c 65 3e 4d 79 20 50 48 50 20 53 68 65 6c 6c 20 3c 3f 65 63 68 6f 20 56 45 52 53 49 4f 4e) | (3c 00 74 00 69 00 74 00 6c 00 65 00 3e 00 4d 00 79 00 20 00 50 00 48 00 50 00 20 00 53 00 68 00 65 00 6c 00 6c 00 20 00 3c 00 3f 00 65 00 63 00 68 00 6f 00 20 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00))}
		$pbs12 = {((46 34 63 6b 54 65 61 6d) | (46 00 34 00 63 00 6b 00 54 00 65 00 61 00 6d 00))}
		$pbs15 = {((4d 75 6c 43 69 53 68 65 6c 6c) | (4d 00 75 00 6c 00 43 00 69 00 53 00 68 00 65 00 6c 00 6c 00))}
		$pbs30 = {((62 6f 74 7c 73 70 69 64 65 72 7c 63 72 61 77 6c 65 72 7c 73 6c 75 72 70 7c 74 65 6f 6d 61 7c 61 72 63 68 69 76 65 7c 74 72 61 63 6b 7c 73 6e 6f 6f 70 79 7c 6a 61 76 61 7c 6c 77 70 7c 77 67 65 74 7c 63 75 72 6c 7c 63 6c 69 65 6e 74 7c 70 79 74 68 6f 6e 7c 6c 69 62 77 77 77) | (62 00 6f 00 74 00 7c 00 73 00 70 00 69 00 64 00 65 00 72 00 7c 00 63 00 72 00 61 00 77 00 6c 00 65 00 72 00 7c 00 73 00 6c 00 75 00 72 00 70 00 7c 00 74 00 65 00 6f 00 6d 00 61 00 7c 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 7c 00 74 00 72 00 61 00 63 00 6b 00 7c 00 73 00 6e 00 6f 00 6f 00 70 00 79 00 7c 00 6a 00 61 00 76 00 61 00 7c 00 6c 00 77 00 70 00 7c 00 77 00 67 00 65 00 74 00 7c 00 63 00 75 00 72 00 6c 00 7c 00 63 00 6c 00 69 00 65 00 6e 00 74 00 7c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 7c 00 6c 00 69 00 62 00 77 00 77 00 77 00))}
		$pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
		$pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
		$pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
		$pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
		$pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
		$pbs42 = {((61 72 72 61 79 28 22 66 69 6e 64 20 63 6f 6e 66 69 67 2e 69 6e 63 2e 70 68 70 20 66 69 6c 65 73 22 2c 20 22 66 69 6e 64 20 2f 20 2d 74 79 70 65 20 66 20 2d 6e 61 6d 65 20 63 6f 6e 66 69 67 2e 69 6e 63 2e 70 68 70 22 29) | (61 00 72 00 72 00 61 00 79 00 28 00 22 00 66 00 69 00 6e 00 64 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 63 00 2e 00 70 00 68 00 70 00 20 00 66 00 69 00 6c 00 65 00 73 00 22 00 2c 00 20 00 22 00 66 00 69 00 6e 00 64 00 20 00 2f 00 20 00 2d 00 74 00 79 00 70 00 65 00 20 00 66 00 20 00 2d 00 6e 00 61 00 6d 00 65 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 63 00 2e 00 70 00 68 00 70 00 22 00 29 00))}
		$pbs43 = {((24 5f 53 45 52 56 45 52 5b 22 5c 78 34 38 5c 78 35 34 5c 78 35 34 5c 78 35 30) | (24 00 5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 22 00 5c 00 78 00 34 00 38 00 5c 00 78 00 35 00 34 00 5c 00 78 00 35 00 34 00 5c 00 78 00 35 00 30 00))}
		$pbs52 = {70 72 65 67 5f 72 65 70 6c 61 63 65 28 22 2f 5b 63 68 65 63 6b 73 71 6c 5d 2f 65 22}
		$pbs53 = {3d 27 68 74 74 70 3a 2f 2f 77 77 77 2e 7a 6a 6a 76 2e 63 6f 6d 27}
		$pbs54 = {3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 7a 6a 6a 76 2e 63 6f 6d 22}
		$pbs60 = /setting\["AccountType"\]\s?=\s?3/
		$pbs61 = {7e 2b 64 28 29 22 5e 22 21 7b 2b 7b 7d}
		$pbs62 = {75 73 65 20 66 75 6e 63 74 69 6f 6e 20 5c 65 76 61 6c 20 61 73 20}
		$pbs63 = {75 73 65 20 66 75 6e 63 74 69 6f 6e 20 5c 61 73 73 65 72 74 20 61 73 20}
		$pbs64 = {((65 76 61 6c 28 60 2f 2a) | (65 00 76 00 61 00 6c 00 28 00 60 00 2f 00 2a 00))}
		$pbs65 = {((2f 2a 20 52 65 76 65 72 73 65 20 65 6e 67 69 6e 65 65 72 69 6e 67 20 6f 66 20 74 68 69 73 20 66 69 6c 65 20 69 73 20 73 74 72 69 63 74 6c 79 20 70 72 6f 68 69 62 69 74 65 64 2e 20 46 69 6c 65 20 70 72 6f 74 65 63 74 65 64 20 62 79 20 63 6f 70 79 72 69 67 68 74 20 6c 61 77 20 61 6e 64 20 70 72 6f 76 69 64 65 64 20 75 6e 64 65 72 20 6c 69 63 65 6e 73 65 2e 20 2a 2f) | (2f 00 2a 00 20 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 20 00 65 00 6e 00 67 00 69 00 6e 00 65 00 65 00 72 00 69 00 6e 00 67 00 20 00 6f 00 66 00 20 00 74 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 69 00 73 00 20 00 73 00 74 00 72 00 69 00 63 00 74 00 6c 00 79 00 20 00 70 00 72 00 6f 00 68 00 69 00 62 00 69 00 74 00 65 00 64 00 2e 00 20 00 46 00 69 00 6c 00 65 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 63 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 6c 00 61 00 77 00 20 00 61 00 6e 00 64 00 20 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 64 00 20 00 75 00 6e 00 64 00 65 00 72 00 20 00 6c 00 69 00 63 00 65 00 6e 00 73 00 65 00 2e 00 20 00 2a 00 2f 00))}
		$pbs66 = {((54 61 73 39 65 72) | (54 00 61 00 73 00 39 00 65 00 72 00))}
		$pbs67 = {((22 54 53 4f 50 5f 22 3b) | (22 00 54 00 53 00 4f 00 50 00 5f 00 22 00 3b 00))}
		$pbs68 = {((73 74 72 5f 72 6f 74 31 33 28 27 6e 66 66 72 65 67 27 29) | (73 00 74 00 72 00 5f 00 72 00 6f 00 74 00 31 00 33 00 28 00 27 00 6e 00 66 00 66 00 72 00 65 00 67 00 27 00 29 00))}
		$pbs69 = {((3c 3f 3d 60 7b 24 27) | (3c 00 3f 00 3d 00 60 00 7b 00 24 00 27 00))}
		$pbs70 = {((7b 27 5f 27 2e 24 5f 7d 5b 22 5f 22 5d 28 24 7b 27 5f 27 2e 24 5f 7d 5b 22 5f) | (7b 00 27 00 5f 00 27 00 2e 00 24 00 5f 00 7d 00 5b 00 22 00 5f 00 22 00 5d 00 28 00 24 00 7b 00 27 00 5f 00 27 00 2e 00 24 00 5f 00 7d 00 5b 00 22 00 5f 00))}
		$pbs71 = {((22 65 34 35 65 33 32 39 66 65 62 35 64 39 32 35 62 22) | (22 00 65 00 34 00 35 00 65 00 33 00 32 00 39 00 66 00 65 00 62 00 35 00 64 00 39 00 32 00 35 00 62 00 22 00))}
		$pbs72 = {((7c 20 50 48 50 20 46 49 4c 45 20 4d 41 4e 41 47 45 52) | (7c 00 20 00 50 00 48 00 50 00 20 00 46 00 49 00 4c 00 45 00 20 00 4d 00 41 00 4e 00 41 00 47 00 45 00 52 00))}
		$pbs73 = {((0a 65 76 61 6c 28 68 74 6d 6c 73 70 65 63 69 61 6c 63 68 61 72 73 5f 64 65 63 6f 64 65 28 67 7a 69 6e 66 6c 61 74 65 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24) | (0a 00 65 00 76 00 61 00 6c 00 28 00 68 00 74 00 6d 00 6c 00 73 00 70 00 65 00 63 00 69 00 61 00 6c 00 63 00 68 00 61 00 72 00 73 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 67 00 7a 00 69 00 6e 00 66 00 6c 00 61 00 74 00 65 00 28 00 62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 24 00))}
		$pbs74 = {((2f 2a 0a 0a 53 68 65 6c 6c 69 6e 64 69 72 2e 6f 72 67 0a 0a 2a 2f) | (2f 00 2a 00 0a 00 0a 00 53 00 68 00 65 00 6c 00 6c 00 69 00 6e 00 64 00 69 00 72 00 2e 00 6f 00 72 00 67 00 0a 00 0a 00 2a 00 2f 00))}
		$pbs75 = {((24 73 68 65 6c 6c 20 3d 20 27 75 6e 61 6d 65 20 2d 61 3b 20 77 3b 20 69 64 3b 20 2f 62 69 6e 2f 73 68 20 2d 69 27 3b) | (24 00 73 00 68 00 65 00 6c 00 6c 00 20 00 3d 00 20 00 27 00 75 00 6e 00 61 00 6d 00 65 00 20 00 2d 00 61 00 3b 00 20 00 77 00 3b 00 20 00 69 00 64 00 3b 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 20 00 2d 00 69 00 27 00 3b 00))}
		$pbs76 = {((27 70 61 73 73 77 6f 72 64 27 20 2e 20 27 2f 27 20 2e 20 27 69 64 27 20 2e 20 27 2f 27 20 2e 20) | (27 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 27 00 20 00 2e 00 20 00 27 00 2f 00 27 00 20 00 2e 00 20 00 27 00 69 00 64 00 27 00 20 00 2e 00 20 00 27 00 2f 00 27 00 20 00 2e 00 20 00))}
		$pbs77 = {((3d 20 63 72 65 61 74 65 5f 66 75 6e 63 74 69 6f 6e 20 2f 2a) | (3d 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 5f 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 2f 00 2a 00))}
		$pbs78 = {((57 33 4c 4c 20 4d 21 4e 21 20 53 48 33 4c 4c) | (57 00 33 00 4c 00 4c 00 20 00 4d 00 21 00 4e 00 21 00 20 00 53 00 48 00 33 00 4c 00 4c 00))}
		$pbs79 = {((65 78 74 72 61 63 74 28 24 5f 52 45 51 55 45 53 54 29 26 26 40 24) | (65 00 78 00 74 00 72 00 61 00 63 00 74 00 28 00 24 00 5f 00 52 00 45 00 51 00 55 00 45 00 53 00 54 00 29 00 26 00 26 00 40 00 24 00))}
		$pbs80 = {((22 50 2d 68 2d 70 2d 53 2d 70 2d 79 22) | (22 00 50 00 2d 00 68 00 2d 00 70 00 2d 00 53 00 2d 00 70 00 2d 00 79 00 22 00))}
		$pbs81 = {((5c 78 35 66 5c 78 37 32 5c 78 36 66 5c 78 37 34 5c 78 33 31 5c 78 33 33) | (5c 00 78 00 35 00 66 00 5c 00 78 00 37 00 32 00 5c 00 78 00 36 00 66 00 5c 00 78 00 37 00 34 00 5c 00 78 00 33 00 31 00 5c 00 78 00 33 00 33 00))}
		$pbs82 = {((5c 78 36 32 5c 78 36 31 5c 78 37 33 5c 78 36 35 5c 78 33 36 5c 78 33 34 5c 78 35 66) | (5c 00 78 00 36 00 32 00 5c 00 78 00 36 00 31 00 5c 00 78 00 37 00 33 00 5c 00 78 00 36 00 35 00 5c 00 78 00 33 00 36 00 5c 00 78 00 33 00 34 00 5c 00 78 00 35 00 66 00))}
		$pbs83 = {((2a 2f 62 61 73 65 36 34 5f 64 65 63 6f 64 65 2f 2a) | (2a 00 2f 00 62 00 61 00 73 00 65 00 36 00 34 00 5f 00 64 00 65 00 63 00 6f 00 64 00 65 00 2f 00 2a 00))}
		$pbs84 = {((0a 40 65 76 61 6c 2f 2a) | (0a 00 40 00 65 00 76 00 61 00 6c 00 2f 00 2a 00))}
		$pbs85 = {((2a 2f 65 76 61 6c 2f 2a) | (2a 00 2f 00 65 00 76 00 61 00 6c 00 2f 00 2a 00))}
		$pbs86 = {((2a 2f 20 61 72 72 61 79 20 2f 2a) | (2a 00 2f 00 20 00 61 00 72 00 72 00 61 00 79 00 20 00 2f 00 2a 00))}
		$pbs87 = {((32 6a 74 66 66 73 7a 4a 65) | (32 00 6a 00 74 00 66 00 66 00 73 00 7a 00 4a 00 65 00))}
		$pbs88 = {((65 64 6f 63 6e 65 5f 34 36 65 73 61 62) | (65 00 64 00 6f 00 63 00 6e 00 65 00 5f 00 34 00 36 00 65 00 73 00 61 00 62 00))}
		$pbs89 = {((65 76 61 6c 28 24 5f 48 45 41 44 45 52 53) | (65 00 76 00 61 00 6c 00 28 00 24 00 5f 00 48 00 45 00 41 00 44 00 45 00 52 00 53 00))}
		$pbs90 = {3e 49 6e 66 69 6e 69 74 79 2d 53 68 33 6c 6c 3c}
		$front1 = {((3c 3f 70 68 70 20 65 76 61 6c 28) | (3c 00 3f 00 70 00 68 00 70 00 20 00 65 00 76 00 61 00 6c 00 28 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }

	condition:
		filesize < 1000KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and not ( uint16( 0 ) == 0x5a4d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 ) and ( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}

rule WEBSHELL_PHP_Strings_SUSP : hardened limited
{
	meta:
		description = "typical webshell strings, suspicious"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/01/12"
		modified = "2023-07-05"
		score = 50
		hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
		hash = "dde2bdcde95730510b22ae8d52e4344997cb1e74"
		hash = "499db4d70955f7d40cf5cbaf2ecaf7a2"
		hash = "281b66f62db5caab2a6eb08929575ad95628a690"
		hash = "1ab3ae4d613b120f9681f6aa8933d66fa38e4886"
		id = "25f25df5-4398-562b-9383-e01ccb17e8de"

	strings:
		$sstring1 = {((65 76 61 6c 28 22 3f 3e 22) | (65 00 76 00 61 00 6c 00 28 00 22 00 3f 00 3e 00 22 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$inp1 = {((70 68 70 3a 2f 2f 69 6e 70 75 74) | (70 00 68 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 70 00 75 00 74 00))}
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = {((5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 27 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp16 = {((5f 53 45 52 56 45 52 5b 22 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 22 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = {((61 72 72 61 79 5f 76 61 6c 75 65 73 28 24 5f 53 45 52 56 45 52 29) | (61 00 72 00 72 00 61 00 79 00 5f 00 76 00 61 00 6c 00 75 00 65 00 73 00 28 00 24 00 5f 00 53 00 45 00 52 00 56 00 45 00 52 00 29 00))}
		$inp19 = /file_get_contents\("https?:\/\// wide ascii

	condition:
		filesize < 700KB and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and not ( any of ( $gfp* ) ) and ( 1 of ( $sstring* ) and ( any of ( $inp* ) ) )
}

rule WEBSHELL_PHP_In_Htaccess : hardened
{
	meta:
		description = "Use Apache .htaccess to execute php code inside .htaccess"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-07-05"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
		hash = "e1d1091fee6026829e037b2c70c228344955c263"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"
		id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"

	strings:
		$hta = {((41 64 64 54 79 70 65 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 68 74 74 70 64 2d 70 68 70 20 2e 68 74 61 63 63 65 73 73) | (41 00 64 00 64 00 54 00 79 00 70 00 65 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 68 00 74 00 74 00 70 00 64 00 2d 00 70 00 68 00 70 00 20 00 2e 00 68 00 74 00 61 00 63 00 63 00 65 00 73 00 73 00))}

	condition:
		filesize < 100KB and $hta
}

rule WEBSHELL_PHP_Function_Via_Get : hardened
{
	meta:
		description = "Webshell which sends eval/assert via GET"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/09"
		modified = "2023-04-05"
		hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
		hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
		hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"
		id = "5fef1063-2f9f-516e-86f6-cfd98bb05e6e"

	strings:
		$sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
		$sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
		$sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
		$sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
		$sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
		$sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}

	condition:
		filesize < 500KB and not ( any of ( $gfp* ) ) and any of ( $sr* )
}

rule WEBSHELL_PHP_Writer : hardened limited
{
	meta:
		description = "PHP webshell which only writes an uploaded file to disk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/04/17"
		modified = "2023-07-05"
		score = 50
		hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
		hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
		hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
		hash = "0ce760131787803bbef216d0ee9b5eb062633537"
		hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"
		id = "05bb3e0c-69b2-5176-a3eb-e6ba2d72a205"

	strings:
		$sus3 = {((27 75 70 6c 6f 61 64 27) | (27 00 75 00 70 00 6c 00 6f 00 61 00 64 00 27 00))}
		$sus4 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$sus5 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$sus6 = {((67 69 66 38 39) | (67 00 69 00 66 00 38 00 39 00))}
		$sus16 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$sus17 = {((65 72 72 6f 72 5f 72 65 70 6f 72 74 69 6e 67 28 20 30 20 29) | (65 00 72 00 72 00 6f 00 72 00 5f 00 72 00 65 00 70 00 6f 00 72 00 74 00 69 00 6e 00 67 00 28 00 20 00 30 00 20 00 29 00))}
		$sus18 = {((27 20 2e 20 27) | (27 00 20 00 2e 00 20 00 27 00))}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$inp1 = {((70 68 70 3a 2f 2f 69 6e 70 75 74) | (70 00 68 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 70 00 75 00 74 00))}
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = {((5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 27 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp16 = {((5f 53 45 52 56 45 52 5b 22 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 22 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = {((61 72 72 61 79 5f 76 61 6c 75 65 73 28 24 5f 53 45 52 56 45 52 29) | (61 00 72 00 72 00 61 00 79 00 5f 00 76 00 61 00 6c 00 75 00 65 00 73 00 28 00 24 00 5f 00 53 00 45 00 52 00 56 00 45 00 52 00 29 00))}
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$php_multi_write1 = {((66 6f 70 65 6e 28) | (66 00 6f 00 70 00 65 00 6e 00 28 00))}
		$php_multi_write2 = {((66 77 72 69 74 65 28) | (66 00 77 00 72 00 69 00 74 00 65 00 28 00))}
		$php_write1 = {((6d 6f 76 65 5f 75 70 6c 6f 61 64 65 64 5f 66 69 6c 65) | (6d 00 6f 00 76 00 65 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 65 00 64 00 5f 00 66 00 69 00 6c 00 65 00))}
		$php_write2 = {((63 6f 70 79) | (63 00 6f 00 70 00 79 00))}

	condition:
		(( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $inp* ) ) and ( any of ( $php_write* ) or all of ( $php_multi_write* ) ) and ( filesize < 400 or ( filesize < 4000 and 1 of ( $sus* ) ) )
}

rule WEBSHELL_ASP_Writer : hardened limited
{
	meta:
		description = "ASP webshell which only writes an uploaded file to disk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/03/07"
		modified = "2023-07-05"
		score = 60
		hash = "df6eaba8d643c49c6f38016531c88332e80af33c"
		hash = "83642a926291a499916e8c915dacadd0d5a8b91f"
		hash = "5417fad68a6f7320d227f558bf64657fe3aa9153"
		hash = "97d9f6c411f54b56056a145654cd00abca2ff871"
		hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
		id = "a1310e22-f485-5f06-8f1a-4cf9ae8413a1"

	strings:
		$sus1 = {((70 61 73 73 77 6f 72 64) | (70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$sus2 = {((70 77 64) | (70 00 77 00 64 00))}
		$sus3 = {((3c 61 73 70 3a 54 65 78 74 42 6f 78) | (3c 00 61 00 73 00 70 00 3a 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00))}
		$sus4 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$sus5 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$sus6 = {((67 69 66 38 39) | (67 00 69 00 66 00 38 00 39 00))}
		$sus7 = {((22 26 22) | (22 00 26 00 22 00))}
		$sus8 = {((61 75 74 68 6b 65 79) | (61 00 75 00 74 00 68 00 6b 00 65 00 79 00))}
		$sus9 = {((41 55 54 48 4b 45 59) | (41 00 55 00 54 00 48 00 4b 00 45 00 59 00))}
		$sus10 = {((74 65 73 74 2e 61 73 70) | (74 00 65 00 73 00 74 00 2e 00 61 00 73 00 70 00))}
		$sus11 = {((63 6d 64 2e 61 73 70) | (63 00 6d 00 64 00 2e 00 61 00 73 00 70 00))}
		$sus12 = {((2e 57 72 69 74 65 28 52 65 71 75 65 73 74 2e) | (2e 00 57 00 72 00 69 00 74 00 65 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00))}
		$sus13 = {((3c 74 65 78 74 61 72 65 61 20) | (3c 00 74 00 65 00 78 00 74 00 61 00 72 00 65 00 61 00 20 00))}
		$sus14 = {((22 75 6e 73 61 66 65) | (22 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$sus15 = {((27 75 6e 73 61 66 65) | (27 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$sus16 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = {((53 61 76 65 54 6f 46 69 6c 65) | (53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00))}
		$asp_write_way_one3 = {((43 52 45 41 74 45 74 45 78 74 46 69 4c 45) | (43 00 52 00 45 00 41 00 74 00 45 00 74 00 45 00 78 00 74 00 46 00 69 00 4c 00 45 00))}
		$asp_cr_write1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00))}
		$asp_cr_write2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 20 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 28 00))}
		$asp_streamwriter1 = {((73 74 72 65 61 6d 77 72 69 74 65 72) | (73 00 74 00 72 00 65 00 61 00 6d 00 77 00 72 00 69 00 74 00 65 00 72 00))}
		$asp_streamwriter2 = {((66 69 6c 65 73 74 72 65 61 6d) | (66 00 69 00 6c 00 65 00 73 00 74 00 72 00 65 00 61 00 6d 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and ( any of ( $asp_always_write* ) and ( any of ( $asp_write_way_one* ) and any of ( $asp_cr_write* ) ) or ( any of ( $asp_streamwriter* ) ) ) and ( filesize < 400 or ( filesize < 6000 and 1 of ( $sus* ) ) )
}

rule WEBSHELL_ASP_OBFUSC : hardened limited
{
	meta:
		description = "ASP webshell obfuscated"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/12"
		modified = "2023-07-05"
		hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
		hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
		hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
		hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
		hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
		hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
		hash = "d6b96d844ac395358ee38d4524105d331af42ede"
		hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"
		id = "3960b692-9f6f-52c5-b881-6f9e1b3ac555"

	strings:
		$asp_obf1 = {((2f 2a 2d 2f 2a 2d 2a 2f) | (2f 00 2a 00 2d 00 2f 00 2a 00 2d 00 2a 00 2f 00))}
		$asp_obf2 = {((75 22 2b 22 6e 22 2b 22 73) | (75 00 22 00 2b 00 22 00 6e 00 22 00 2b 00 22 00 73 00))}
		$asp_obf3 = {((22 65 22 2b 22 76) | (22 00 65 00 22 00 2b 00 22 00 76 00))}
		$asp_obf4 = {((61 22 2b 22 6c 22) | (61 00 22 00 2b 00 22 00 6c 00 22 00))}
		$asp_obf5 = {((22 2b 22 28 22 2b 22) | (22 00 2b 00 22 00 28 00 22 00 2b 00 22 00))}
		$asp_obf6 = {((71 22 2b 22 75 22) | (71 00 22 00 2b 00 22 00 75 00 22 00))}
		$asp_obf7 = {((22 75 22 2b 22 65) | (22 00 75 00 22 00 2b 00 22 00 65 00))}
		$asp_obf8 = {((2f 2a 2f 2f 2a 2f) | (2f 00 2a 00 2f 00 2f 00 2a 00 2f 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_payload0 = {((65 76 61 6c 5f 72) | (65 00 76 00 61 00 6c 00 5f 00 72 00))}
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = {((57 53 43 52 49 50 54 2e 53 48 45 4c 4c) | (57 00 53 00 43 00 52 00 49 00 50 00 54 00 2e 00 53 00 48 00 45 00 4c 00 4c 00))}
		$asp_payload13 = {((45 78 65 63 75 74 65 47 6c 6f 62 61 6c) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 47 00 6c 00 6f 00 62 00 61 00 6c 00))}
		$asp_payload14 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_payload15 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_multi_payload_one1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_one2 = {((61 64 64 63 6f 64 65) | (61 00 64 00 64 00 63 00 6f 00 64 00 65 00))}
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = {((43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 46 72 6f 6d 56 69 72 74 75 61 6c 50 61 74 68) | (43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 46 00 72 00 6f 00 6d 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 61 00 74 00 68 00))}
		$asp_multi_payload_two2 = {((50 72 6f 63 65 73 73 52 65 71 75 65 73 74) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_multi_payload_two3 = {((42 75 69 6c 64 4d 61 6e 61 67 65 72) | (42 00 75 00 69 00 6c 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00))}
		$asp_multi_payload_three1 = {((53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00))}
		$asp_multi_payload_three2 = {((50 72 6f 63 65 73 73) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$asp_multi_payload_three3 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_four1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_four2 = {((54 72 61 6e 73 66 6f 72 6d 4e 6f 64 65) | (54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00 4e 00 6f 00 64 00 65 00))}
		$asp_multi_payload_four3 = {((6c 6f 61 64 78 6d 6c) | (6c 00 6f 00 61 00 64 00 78 00 6d 00 6c 00))}
		$asp_multi_payload_five1 = {((50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 53 00 74 00 61 00 72 00 74 00 49 00 6e 00 66 00 6f 00))}
		$asp_multi_payload_five2 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_five3 = {((2e 46 69 6c 65 6e 61 6d 65) | (2e 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00))}
		$asp_multi_payload_five4 = {((2e 41 72 67 75 6d 65 6e 74 73) | (2e 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00))}
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = {((53 61 76 65 54 6f 46 69 6c 65) | (53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00))}
		$asp_write_way_one3 = {((43 52 45 41 74 45 74 45 78 74 46 69 4c 45) | (43 00 52 00 45 00 41 00 74 00 45 00 74 00 45 00 78 00 74 00 46 00 69 00 4c 00 45 00))}
		$asp_cr_write1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00))}
		$asp_cr_write2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 20 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 28 00))}
		$asp_streamwriter1 = {((73 74 72 65 61 6d 77 72 69 74 65 72) | (73 00 74 00 72 00 65 00 61 00 6d 00 77 00 72 00 69 00 74 00 65 00 72 00))}
		$asp_streamwriter2 = {((66 69 6c 65 73 74 72 65 61 6d) | (66 00 69 00 6c 00 65 00 73 00 74 00 72 00 65 00 61 00 6d 00))}
		$o4 = {((5c 78 38) | (5c 00 78 00 38 00))}
		$o5 = {((5c 78 39) | (5c 00 78 00 39 00))}
		$o6 = {((5c 36 31) | (5c 00 36 00 31 00))}
		$o7 = {((5c 34 34) | (5c 00 34 00 34 00))}
		$o8 = {((5c 31 31 32) | (5c 00 31 00 31 00 32 00))}
		$o9 = {((5c 31 32 30) | (5c 00 31 00 32 00 30 00))}
		$m_multi_one1 = {((52 65 70 6c 61 63 65 28) | (52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00))}
		$m_multi_one2 = {((4c 65 6e 28) | (4c 00 65 00 6e 00 28 00))}
		$m_multi_one3 = {((4d 69 64 28) | (4d 00 69 00 64 00 28 00))}
		$m_multi_one4 = {((6d 69 64 28) | (6d 00 69 00 64 00 28 00))}
		$m_multi_one5 = {((2e 54 6f 53 74 72 69 6e 67 28) | (2e 00 54 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00))}
		$m_fp1 = {41 75 74 68 6f 72 3a 20 41 6e 64 72 65 20 54 65 69 78 65 69 72 61 20 2d 20 61 6e 64 72 65 74 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d}
		$m_fp2 = {((44 61 74 61 42 69 6e 64 65 72 2e 45 76 61 6c 28 43 6f 6e 74 61 69 6e 65 72 2e 44 61 74 61 49 74 65 6d) | (44 00 61 00 74 00 61 00 42 00 69 00 6e 00 64 00 65 00 72 00 2e 00 45 00 76 00 61 00 6c 00 28 00 43 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 2e 00 44 00 61 00 74 00 61 00 49 00 74 00 65 00 6d 00))}
		$oo1 = /\w\"&\"\w/ wide ascii
		$oo2 = {((2a 2f 22 29 2e 52 65 70 6c 61 63 65 28 22 2f 2a) | (2a 00 2f 00 22 00 29 00 2e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 22 00 2f 00 2a 00))}

	condition:
		filesize < 100KB and ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( ( ( any of ( $asp_payload* ) or all of ( $asp_multi_payload_one* ) or all of ( $asp_multi_payload_two* ) or all of ( $asp_multi_payload_three* ) or all of ( $asp_multi_payload_four* ) or all of ( $asp_multi_payload_five* ) ) or ( any of ( $asp_always_write* ) and ( any of ( $asp_write_way_one* ) and any of ( $asp_cr_write* ) ) or ( any of ( $asp_streamwriter* ) ) ) ) and ( ( ( filesize < 100KB and ( ( #o4 + #o5 + #o6 + #o7 + #o8 + #o9 ) > 20 ) ) or ( filesize < 5KB and ( ( #o4 + #o5 + #o6 + #o7 + #o8 + #o9 ) > 5 or ( ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3 ) ) ) or ( filesize < 700 and ( ( #o4 + #o5 + #o6 + #o7 + #o8 + #o9 ) > 3 or ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2 ) ) ) or any of ( $asp_obf* ) ) or ( ( filesize < 100KB and ( ( #oo1 ) > 2 or $oo2 ) ) or ( filesize < 25KB and ( ( #oo1 ) > 1 ) ) or ( filesize < 1KB and ( ( #oo1 ) > 0 ) ) ) ) and not any of ( $m_fp* )
}

rule WEBSHELL_ASP_Nano : hardened limited
{
	meta:
		description = "Generic ASP webshell which uses any eval/exec function"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/13"
		modified = "2023-04-05"
		hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
		hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
		hash = "22345e956bce23304f5e8e356c423cee60b0912c"
		hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
		hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
		hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
		hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
		hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
		hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
		hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
		hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
		hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
		hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
		hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
		hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"
		id = "5f2f24c2-159d-51e1-80d9-11eeb77e8760"

	strings:
		$susasp1 = {2f 2a 2d 2f 2a 2d 2a 2f}
		$susasp2 = {28 22 25 31}
		$susasp3 = /[Cc]hr\([Ss]tr\(/
		$susasp4 = {63 6d 64 2e 65 78 65}
		$susasp5 = {63 6d 64 20 2f 63}
		$susasp7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}
		$susasp8 = {55 6d 56 78 64 57 56 7a 64 43}
		$susasp9 = {63 6d 56 78 64 57 56 7a 64 41}
		$susasp10 = {2f 2a 2f 2f 2a 2f}
		$susasp11 = {28 22 2f 2a 2f 22}
		$susasp12 = {65 76 61 6c 28 65 76 61 6c 28}
		$fp1 = {65 76 61 6c 20 61}
		$fp2 = {27 45 76 61 6c 27}
		$fp3 = {45 76 61 6c 28 22}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_payload0 = {((65 76 61 6c 5f 72) | (65 00 76 00 61 00 6c 00 5f 00 72 00))}
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = {((57 53 43 52 49 50 54 2e 53 48 45 4c 4c) | (57 00 53 00 43 00 52 00 49 00 50 00 54 00 2e 00 53 00 48 00 45 00 4c 00 4c 00))}
		$asp_payload13 = {((45 78 65 63 75 74 65 47 6c 6f 62 61 6c) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 47 00 6c 00 6f 00 62 00 61 00 6c 00))}
		$asp_payload14 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_payload15 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_multi_payload_one1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_one2 = {((61 64 64 63 6f 64 65) | (61 00 64 00 64 00 63 00 6f 00 64 00 65 00))}
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = {((43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 46 72 6f 6d 56 69 72 74 75 61 6c 50 61 74 68) | (43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 46 00 72 00 6f 00 6d 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 61 00 74 00 68 00))}
		$asp_multi_payload_two2 = {((50 72 6f 63 65 73 73 52 65 71 75 65 73 74) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_multi_payload_two3 = {((42 75 69 6c 64 4d 61 6e 61 67 65 72) | (42 00 75 00 69 00 6c 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00))}
		$asp_multi_payload_three1 = {((53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00))}
		$asp_multi_payload_three2 = {((50 72 6f 63 65 73 73) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$asp_multi_payload_three3 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_four1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_four2 = {((54 72 61 6e 73 66 6f 72 6d 4e 6f 64 65) | (54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00 4e 00 6f 00 64 00 65 00))}
		$asp_multi_payload_four3 = {((6c 6f 61 64 78 6d 6c) | (6c 00 6f 00 61 00 64 00 78 00 6d 00 6c 00))}
		$asp_multi_payload_five1 = {((50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 53 00 74 00 61 00 72 00 74 00 49 00 6e 00 66 00 6f 00))}
		$asp_multi_payload_five2 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_five3 = {((2e 46 69 6c 65 6e 61 6d 65) | (2e 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00))}
		$asp_multi_payload_five4 = {((2e 41 72 67 75 6d 65 6e 74 73) | (2e 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00))}
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = {((53 61 76 65 54 6f 46 69 6c 65) | (53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00))}
		$asp_write_way_one3 = {((43 52 45 41 74 45 74 45 78 74 46 69 4c 45) | (43 00 52 00 45 00 41 00 74 00 45 00 74 00 45 00 78 00 74 00 46 00 69 00 4c 00 45 00))}
		$asp_cr_write1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00))}
		$asp_cr_write2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 20 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 28 00))}
		$asp_streamwriter1 = {((73 74 72 65 61 6d 77 72 69 74 65 72) | (73 00 74 00 72 00 65 00 61 00 6d 00 77 00 72 00 69 00 74 00 65 00 72 00))}
		$asp_streamwriter2 = {((66 69 6c 65 73 74 72 65 61 6d) | (66 00 69 00 6c 00 65 00 73 00 74 00 72 00 65 00 61 00 6d 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( ( any of ( $asp_payload* ) or all of ( $asp_multi_payload_one* ) or all of ( $asp_multi_payload_two* ) or all of ( $asp_multi_payload_three* ) or all of ( $asp_multi_payload_four* ) or all of ( $asp_multi_payload_five* ) ) or ( any of ( $asp_always_write* ) and ( any of ( $asp_write_way_one* ) and any of ( $asp_cr_write* ) ) or ( any of ( $asp_streamwriter* ) ) ) ) and not any of ( $fp* ) and ( filesize < 200 or ( filesize < 1000 and any of ( $susasp* ) ) )
}

rule WEBSHELL_ASP_Encoded : hardened limited
{
	meta:
		description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/03/14"
		modified = "2023-07-05"
		hash = "1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399"
		hash = "9885ee1952b5ad9f84176c9570ad4f0e32461c92"
		hash = "27a020c5bc0dbabe889f436271df129627b02196"
		hash = "f41f8c82b155c3110fc1325e82b9ee92b741028b"
		hash = "af40f4c36e3723236c59dc02f28a3efb047d67dd"
		id = "67c0e1f6-6da5-569c-ab61-8b8607429471"

	strings:
		$encoded1 = {((56 42 53 63 72 69 70 74 2e 45 6e 63 6f 64 65) | (56 00 42 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 65 00))}
		$encoded2 = {((4a 53 63 72 69 70 74 2e 45 6e 63 6f 64 65) | (4a 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 65 00))}
		$data1 = {((23 40 7e 5e) | (23 00 40 00 7e 00 5e 00))}
		$sus1 = {((73 68 65 6c 6c) | (73 00 68 00 65 00 6c 00 6c 00))}
		$sus2 = {((63 6d 64) | (63 00 6d 00 64 00))}
		$sus3 = {((70 61 73 73 77 6f 72 64) | (70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$sus4 = {((55 73 65 72 50 61 73 73) | (55 00 73 00 65 00 72 00 50 00 61 00 73 00 73 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}

	condition:
		filesize < 500KB and ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and any of ( $encoded* ) and any of ( $data* ) and ( any of ( $sus* ) or ( filesize < 20KB and #data1 > 4 ) or ( filesize < 700 and #data1 > 0 ) )
}

rule WEBSHELL_ASP_Encoded_AspCoding : hardened limited
{
	meta:
		description = "ASP Webshell encoded using ASPEncodeDLL.AspCoding"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/03/14"
		modified = "2023-07-05"
		score = 60
		hash = "7cfd184ab099c4d60b13457140493b49c8ba61ee"
		hash = "f5095345ee085318235c11ae5869ae564d636a5342868d0935de7582ba3c7d7a"
		id = "788a8dae-bcb8-547c-ba17-e1f14bc28f34"

	strings:
		$encoded1 = {((41 53 50 45 6e 63 6f 64 65 44 4c 4c) | (41 00 53 00 50 00 45 00 6e 00 63 00 6f 00 64 00 65 00 44 00 4c 00 4c 00))}
		$encoded2 = {((2e 52 75 6e 74) | (2e 00 52 00 75 00 6e 00 74 00))}
		$encoded3 = {((52 65 71 75 65 73 74) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$encoded4 = {((52 65 73 70 6f 6e 73 65) | (52 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00))}
		$data1 = {((41 73 70 43 6f 64 69 6e 67 2e 45 6e 43 6f 64 65) | (41 00 73 00 70 00 43 00 6f 00 64 00 69 00 6e 00 67 00 2e 00 45 00 6e 00 43 00 6f 00 64 00 65 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}

	condition:
		filesize < 500KB and ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and all of ( $encoded* ) and any of ( $data* )
}

rule WEBSHELL_ASP_By_String : hardened limited
{
	meta:
		description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021-01-13"
		modified = "2023-04-05"
		hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
		hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
		hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
		hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
		hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
		hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
		hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
		hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
		hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
		hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
		hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
		hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"
		id = "4705b28b-2ffa-53d1-b727-1a9fc2a7dd69"

	strings:
		$asp_string1 = {((74 73 65 75 71 65 72 20 6c 61 76 65) | (74 00 73 00 65 00 75 00 71 00 65 00 72 00 20 00 6c 00 61 00 76 00 65 00))}
		$asp_string2 = {((3a 65 76 61 6c 20 72 65 71 75 65 73 74 28) | (3a 00 65 00 76 00 61 00 6c 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 28 00))}
		$asp_string3 = {((3a 65 76 61 6c 20 72 65 71 75 65 73 74 28) | (3a 00 65 00 76 00 61 00 6c 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 28 00))}
		$asp_string4 = {((53 49 74 45 75 52 6c 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 7a 6a 6a 76 2e 63 6f 6d 22) | (53 00 49 00 74 00 45 00 75 00 52 00 6c 00 3d 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 7a 00 6a 00 6a 00 76 00 2e 00 63 00 6f 00 6d 00 22 00))}
		$asp_string5 = {((53 65 72 76 65 72 56 61 72 69 61 62 6c 65 73 28 22 48 54 54 50 5f 48 4f 53 54 22 29 2c 22 67 6f 76 2e 63 6e 22) | (53 00 65 00 72 00 76 00 65 00 72 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 73 00 28 00 22 00 48 00 54 00 54 00 50 00 5f 00 48 00 4f 00 53 00 54 00 22 00 29 00 2c 00 22 00 67 00 6f 00 76 00 2e 00 63 00 6e 00 22 00))}
		$asp_string6 = /e\+.-v\+.-a\+.-l/ wide ascii
		$asp_string7 = {((72 2b 78 2d 65 2b 78 2d 71 2b 78 2d 75) | (72 00 2b 00 78 00 2d 00 65 00 2b 00 78 00 2d 00 71 00 2b 00 78 00 2d 00 75 00))}
		$asp_string8 = {((61 64 64 36 62 62 35 38 65 31 33 39 62 65 31 30) | (61 00 64 00 64 00 36 00 62 00 62 00 35 00 38 00 65 00 31 00 33 00 39 00 62 00 65 00 31 00 30 00))}
		$asp_string9 = {((57 65 62 41 64 6d 69 6e 32 59 2e 78 2e 79 28 22) | (57 00 65 00 62 00 41 00 64 00 6d 00 69 00 6e 00 32 00 59 00 2e 00 78 00 2e 00 79 00 28 00 22 00))}
		$asp_string10 = {((3c 25 69 66 20 28 52 65 71 75 65 73 74 2e 46 69 6c 65 73 2e 43 6f 75 6e 74 21 3d 30 29 20 7b 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 5b 30 5d 2e 53 61 76 65 41 73 28 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28 52 65 71 75 65 73 74 5b) | (3c 00 25 00 69 00 66 00 20 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 46 00 69 00 6c 00 65 00 73 00 2e 00 43 00 6f 00 75 00 6e 00 74 00 21 00 3d 00 30 00 29 00 20 00 7b 00 20 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 46 00 69 00 6c 00 65 00 73 00 5b 00 30 00 5d 00 2e 00 53 00 61 00 76 00 65 00 41 00 73 00 28 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 4d 00 61 00 70 00 50 00 61 00 74 00 68 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 5b 00))}
		$asp_string11 = {((3c 25 20 49 66 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 2e 43 6f 75 6e 74 20 3c 3e 20 30 20 54 68 65 6e 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 28 30 29 2e 53 61 76 65 41 73 28 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28 52 65 71 75 65 73 74 28) | (3c 00 25 00 20 00 49 00 66 00 20 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 46 00 69 00 6c 00 65 00 73 00 2e 00 43 00 6f 00 75 00 6e 00 74 00 20 00 3c 00 3e 00 20 00 30 00 20 00 54 00 68 00 65 00 6e 00 20 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 46 00 69 00 6c 00 65 00 73 00 28 00 30 00 29 00 2e 00 53 00 61 00 76 00 65 00 41 00 73 00 28 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 4d 00 61 00 70 00 50 00 61 00 74 00 68 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 28 00))}
		$asp_string12 = {((55 6d 56 78 64 57 56 7a 64 43 35 4a 64 47 56 74 57 79 4a) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 4a 00 64 00 47 00 56 00 74 00 57 00 79 00 4a 00))}
		$asp_string13 = {((55 41 64 67 42 68 41 47 77 41 4b 41) | (55 00 41 00 64 00 67 00 42 00 68 00 41 00 47 00 77 00 41 00 4b 00 41 00))}
		$asp_string14 = {((6c 41 48 59 41 59 51 42 73 41 43 67 41) | (6c 00 41 00 48 00 59 00 41 00 59 00 51 00 42 00 73 00 41 00 43 00 67 00 41 00))}
		$asp_string15 = {((5a 51 42 32 41 47 45 41 62 41 41 6f 41) | (5a 00 51 00 42 00 32 00 41 00 47 00 45 00 41 00 62 00 41 00 41 00 6f 00 41 00))}
		$asp_string16 = {((49 41 5a 51 42 78 41 48 55 41 5a 51 42 7a 41 48 51 41 4b 41) | (49 00 41 00 5a 00 51 00 42 00 78 00 41 00 48 00 55 00 41 00 5a 00 51 00 42 00 7a 00 41 00 48 00 51 00 41 00 4b 00 41 00))}
		$asp_string17 = {((79 41 47 55 41 63 51 42 31 41 47 55 41 63 77 42 30 41 43 67 41) | (79 00 41 00 47 00 55 00 41 00 63 00 51 00 42 00 31 00 41 00 47 00 55 00 41 00 63 00 77 00 42 00 30 00 41 00 43 00 67 00 41 00))}
		$asp_string18 = {((63 67 42 6c 41 48 45 41 64 51 42 6c 41 48 4d 41 64 41 41 6f 41) | (63 00 67 00 42 00 6c 00 41 00 48 00 45 00 41 00 64 00 51 00 42 00 6c 00 41 00 48 00 4d 00 41 00 64 00 41 00 41 00 6f 00 41 00))}
		$asp_string19 = {((22 65 76 22 26 22 61 6c) | (22 00 65 00 76 00 22 00 26 00 22 00 61 00 6c 00))}
		$asp_string20 = {((22 53 63 22 26 22 72 69 22 26 22 70) | (22 00 53 00 63 00 22 00 26 00 22 00 72 00 69 00 22 00 26 00 22 00 70 00))}
		$asp_string21 = {((43 22 26 22 6f 6e 74 22 26 22) | (43 00 22 00 26 00 22 00 6f 00 6e 00 74 00 22 00 26 00 22 00))}
		$asp_string22 = {((22 76 62 22 26 22 73 63) | (22 00 76 00 62 00 22 00 26 00 22 00 73 00 63 00))}
		$asp_string23 = {((22 41 22 26 22 64 6f 22 26 22 64) | (22 00 41 00 22 00 26 00 22 00 64 00 6f 00 22 00 26 00 22 00 64 00))}
		$asp_string24 = {((53 74 22 26 22 72 65 22 26 22 61 6d 22) | (53 00 74 00 22 00 26 00 22 00 72 00 65 00 22 00 26 00 22 00 61 00 6d 00 22 00))}
		$asp_string25 = {((2a 2f 65 76 61 6c 28) | (2a 00 2f 00 65 00 76 00 61 00 6c 00 28 00))}
		$asp_string26 = {22 65 22 26 22 76 22 26 22 61 22 26 22 6c}
		$asp_string27 = {((3c 25 65 76 61 6c 22 22 26 28 22) | (3c 00 25 00 65 00 76 00 61 00 6c 00 22 00 22 00 26 00 28 00 22 00))}
		$asp_string28 = {((36 38 37 37 36 35 36 44 32 42 37 33 36 39 37 32 37 38 36 36 37 37 37 35 32 42 32 33 37 45 32 33 32 43 32 41) | (36 00 38 00 37 00 37 00 36 00 35 00 36 00 44 00 32 00 42 00 37 00 33 00 36 00 39 00 37 00 32 00 37 00 38 00 36 00 36 00 37 00 37 00 37 00 35 00 32 00 42 00 32 00 33 00 37 00 45 00 32 00 33 00 32 00 43 00 32 00 41 00))}
		$asp_string29 = {((77 73 22 26 22 63 72 69 70 74 2e 73 68 65 6c 6c) | (77 00 73 00 22 00 26 00 22 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00))}
		$asp_string30 = {((53 65 72 56 65 72 2e 43 72 65 41 74 45 6f 42 6a 45 43 54 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29) | (53 00 65 00 72 00 56 00 65 00 72 00 2e 00 43 00 72 00 65 00 41 00 74 00 45 00 6f 00 42 00 6a 00 45 00 43 00 54 00 28 00 22 00 41 00 44 00 4f 00 44 00 42 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 22 00 29 00))}
		$asp_string31 = {((41 53 50 53 68 65 6c 6c 20 2d 20 77 65 62 20 62 61 73 65 64 20 73 68 65 6c 6c) | (41 00 53 00 50 00 53 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 20 00 77 00 65 00 62 00 20 00 62 00 61 00 73 00 65 00 64 00 20 00 73 00 68 00 65 00 6c 00 6c 00))}
		$asp_string32 = {((3c 2b 2b 20 43 6d 64 41 73 70 2e 61 73 70 20 2b 2b 3e) | (3c 00 2b 00 2b 00 20 00 43 00 6d 00 64 00 41 00 73 00 70 00 2e 00 61 00 73 00 70 00 20 00 2b 00 2b 00 3e 00))}
		$asp_string33 = {((22 73 63 72 22 26 22 69 70 74 22) | (22 00 73 00 63 00 72 00 22 00 26 00 22 00 69 00 70 00 74 00 22 00))}
		$asp_string34 = {((52 65 67 65 78 20 72 65 67 49 6d 67 20 3d 20 6e 65 77 20 52 65 67 65 78 28 22 5b 61 2d 7a 7c 41 2d 5a 5d 7b 31 7d 3a 5c 5c 5c 5c 5b 61 2d 7a 7c 41 2d 5a 7c 20 7c 30 2d 39 7c 5c 75 34 65 30 30 2d 5c 75 39 66 61 35 7c 5c 5c 7e 7c 5c 5c 5c 5c 7c 5f 7c 7b 7c 7d 7c 5c 5c 2e 5d 2a 22 29 3b) | (52 00 65 00 67 00 65 00 78 00 20 00 72 00 65 00 67 00 49 00 6d 00 67 00 20 00 3d 00 20 00 6e 00 65 00 77 00 20 00 52 00 65 00 67 00 65 00 78 00 28 00 22 00 5b 00 61 00 2d 00 7a 00 7c 00 41 00 2d 00 5a 00 5d 00 7b 00 31 00 7d 00 3a 00 5c 00 5c 00 5c 00 5c 00 5b 00 61 00 2d 00 7a 00 7c 00 41 00 2d 00 5a 00 7c 00 20 00 7c 00 30 00 2d 00 39 00 7c 00 5c 00 75 00 34 00 65 00 30 00 30 00 2d 00 5c 00 75 00 39 00 66 00 61 00 35 00 7c 00 5c 00 5c 00 7e 00 7c 00 5c 00 5c 00 5c 00 5c 00 7c 00 5f 00 7c 00 7b 00 7c 00 7d 00 7c 00 5c 00 5c 00 2e 00 5d 00 2a 00 22 00 29 00 3b 00))}
		$asp_string35 = {((22 73 68 65 22 26 22 6c 6c 2e) | (22 00 73 00 68 00 65 00 22 00 26 00 22 00 6c 00 6c 00 2e 00))}
		$asp_string36 = {((4c 48 22 26 22 54 54 50) | (4c 00 48 00 22 00 26 00 22 00 54 00 54 00 50 00))}
		$asp_string37 = {((3c 74 69 74 6c 65 3e 57 65 62 20 53 6e 69 66 66 65 72 3c 2f 74 69 74 6c 65 3e) | (3c 00 74 00 69 00 74 00 6c 00 65 00 3e 00 57 00 65 00 62 00 20 00 53 00 6e 00 69 00 66 00 66 00 65 00 72 00 3c 00 2f 00 74 00 69 00 74 00 6c 00 65 00 3e 00))}
		$asp_string38 = {((3c 74 69 74 6c 65 3e 57 65 62 53 6e 69 66 66) | (3c 00 74 00 69 00 74 00 6c 00 65 00 3e 00 57 00 65 00 62 00 53 00 6e 00 69 00 66 00 66 00))}
		$asp_string39 = {((63 72 69 70 74 22 26 22 69 6e 67) | (63 00 72 00 69 00 70 00 74 00 22 00 26 00 22 00 69 00 6e 00 67 00))}
		$asp_string40 = {((74 63 65 6a 62 4f 6d 65 74 73 79 53 65 6c 69 46 2e 67 6e 69 74 70 69 72 63 53) | (74 00 63 00 65 00 6a 00 62 00 4f 00 6d 00 65 00 74 00 73 00 79 00 53 00 65 00 6c 00 69 00 46 00 2e 00 67 00 6e 00 69 00 74 00 70 00 69 00 72 00 63 00 53 00))}
		$asp_string41 = {((74 63 65 6a 62 4f 65 74 61 65 72 43 2e 72 65 76 72 65 53) | (74 00 63 00 65 00 6a 00 62 00 4f 00 65 00 74 00 61 00 65 00 72 00 43 00 2e 00 72 00 65 00 76 00 72 00 65 00 53 00))}
		$asp_string42 = {((54 68 69 73 20 66 69 6c 65 20 69 73 20 70 61 72 74 20 6f 66 20 41 20 42 6c 61 63 6b 20 50 61 74 68 20 54 6f 77 61 72 64 20 54 68 65 20 53 75 6e 20 28 22 41 42 50 54 54 53 22 29) | (54 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 69 00 73 00 20 00 70 00 61 00 72 00 74 00 20 00 6f 00 66 00 20 00 41 00 20 00 42 00 6c 00 61 00 63 00 6b 00 20 00 50 00 61 00 74 00 68 00 20 00 54 00 6f 00 77 00 61 00 72 00 64 00 20 00 54 00 68 00 65 00 20 00 53 00 75 00 6e 00 20 00 28 00 22 00 41 00 42 00 50 00 54 00 54 00 53 00 22 00 29 00))}
		$asp_string43 = {((69 66 20 28 28 52 65 71 75 65 73 74 2e 48 65 61 64 65 72 73 5b 68 65 61 64 65 72 4e 61 6d 65 4b 65 79 5d 20 21 3d 20 6e 75 6c 6c 29 20 26 26 20 28 52 65 71 75 65 73 74 2e 48 65 61 64 65 72 73 5b 68 65 61 64 65 72 4e 61 6d 65 4b 65 79 5d 2e 54 72 69 6d 28 29 20 3d 3d 20 68 65 61 64 65 72 56 61 6c 75 65 4b 65 79 2e 54 72 69 6d 28 29 29 29) | (69 00 66 00 20 00 28 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 5b 00 68 00 65 00 61 00 64 00 65 00 72 00 4e 00 61 00 6d 00 65 00 4b 00 65 00 79 00 5d 00 20 00 21 00 3d 00 20 00 6e 00 75 00 6c 00 6c 00 29 00 20 00 26 00 26 00 20 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 5b 00 68 00 65 00 61 00 64 00 65 00 72 00 4e 00 61 00 6d 00 65 00 4b 00 65 00 79 00 5d 00 2e 00 54 00 72 00 69 00 6d 00 28 00 29 00 20 00 3d 00 3d 00 20 00 68 00 65 00 61 00 64 00 65 00 72 00 56 00 61 00 6c 00 75 00 65 00 4b 00 65 00 79 00 2e 00 54 00 72 00 69 00 6d 00 28 00 29 00 29 00 29 00))}
		$asp_string44 = {((69 66 20 28 72 65 71 75 65 73 74 2e 67 65 74 48 65 61 64 65 72 28 68 65 61 64 65 72 4e 61 6d 65 4b 65 79 29 2e 74 6f 53 74 72 69 6e 67 28 29 2e 74 72 69 6d 28 29 2e 65 71 75 61 6c 73 28 68 65 61 64 65 72 56 61 6c 75 65 4b 65 79 2e 74 72 69 6d 28 29 29 29) | (69 00 66 00 20 00 28 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 28 00 68 00 65 00 61 00 64 00 65 00 72 00 4e 00 61 00 6d 00 65 00 4b 00 65 00 79 00 29 00 2e 00 74 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 29 00 2e 00 74 00 72 00 69 00 6d 00 28 00 29 00 2e 00 65 00 71 00 75 00 61 00 6c 00 73 00 28 00 68 00 65 00 61 00 64 00 65 00 72 00 56 00 61 00 6c 00 75 00 65 00 4b 00 65 00 79 00 2e 00 74 00 72 00 69 00 6d 00 28 00 29 00 29 00 29 00))}
		$asp_string45 = {((52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 53 65 72 76 65 72 2e 48 74 6d 6c 45 6e 63 6f 64 65 28 45 78 63 75 74 65 6d 65 75 43 6d 64 28 74 78 74 41 72 67 2e 54 65 78 74 29 29 29 3b) | (52 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 2e 00 57 00 72 00 69 00 74 00 65 00 28 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 48 00 74 00 6d 00 6c 00 45 00 6e 00 63 00 6f 00 64 00 65 00 28 00 45 00 78 00 63 00 75 00 74 00 65 00 6d 00 65 00 75 00 43 00 6d 00 64 00 28 00 74 00 78 00 74 00 41 00 72 00 67 00 2e 00 54 00 65 00 78 00 74 00 29 00 29 00 29 00 3b 00))}
		$asp_string46 = {((22 63 22 20 2b 20 22 6d 22 20 2b 20 22 64 22) | (22 00 63 00 22 00 20 00 2b 00 20 00 22 00 6d 00 22 00 20 00 2b 00 20 00 22 00 64 00 22 00))}
		$asp_string47 = {((22 2e 22 2b 22 65 22 2b 22 78 22 2b 22 65 22) | (22 00 2e 00 22 00 2b 00 22 00 65 00 22 00 2b 00 22 00 78 00 22 00 2b 00 22 00 65 00 22 00))}
		$asp_string48 = {((54 61 73 39 65 72) | (54 00 61 00 73 00 39 00 65 00 72 00))}
		$asp_string49 = {((3c 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 5c 75) | (3c 00 25 00 40 00 20 00 50 00 61 00 67 00 65 00 20 00 4c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 5c 00 75 00))}
		$asp_string50 = {((42 69 6e 61 72 79 52 65 61 64 28 5c 75) | (42 00 69 00 6e 00 61 00 72 00 79 00 52 00 65 00 61 00 64 00 28 00 5c 00 75 00))}
		$asp_string51 = {((52 65 71 75 65 73 74 2e 5c 75) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 5c 00 75 00))}
		$asp_string52 = {((53 79 73 74 65 6d 2e 42 75 66 66 65 72 2e 5c 75) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 42 00 75 00 66 00 66 00 65 00 72 00 2e 00 5c 00 75 00))}
		$asp_string53 = {((53 79 73 74 65 6d 2e 4e 65 74 2e 5c 75) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 5c 00 75 00))}
		$asp_string54 = {((2e 5c 75 30 30 35 32 5c 75 30 30 36 35 5c 75 30 30 36 36 5c 75 30 30 36 63 5c 75 30 30 36 35 5c 75 30 30 36 33 5c 75 30 30 37 34 5c 75 30 30 36 39 5c 75 30 30 36 66 5c 75 30 30 36 65 22) | (2e 00 5c 00 75 00 30 00 30 00 35 00 32 00 5c 00 75 00 30 00 30 00 36 00 35 00 5c 00 75 00 30 00 30 00 36 00 36 00 5c 00 75 00 30 00 30 00 36 00 63 00 5c 00 75 00 30 00 30 00 36 00 35 00 5c 00 75 00 30 00 30 00 36 00 33 00 5c 00 75 00 30 00 30 00 37 00 34 00 5c 00 75 00 30 00 30 00 36 00 39 00 5c 00 75 00 30 00 30 00 36 00 66 00 5c 00 75 00 30 00 30 00 36 00 65 00 22 00))}
		$asp_string55 = {((5c 75 30 30 34 31 5c 75 30 30 37 33 5c 75 30 30 37 33 5c 75 30 30 36 35 5c 75 30 30 36 64 5c 75 30 30 36 32 5c 75 30 30 36 63 5c 75 30 30 37 39 2e 5c 75 30 30 34 63 5c 75 30 30 36 66 5c 75 30 30 36 31 5c 75 30 30 36 34) | (5c 00 75 00 30 00 30 00 34 00 31 00 5c 00 75 00 30 00 30 00 37 00 33 00 5c 00 75 00 30 00 30 00 37 00 33 00 5c 00 75 00 30 00 30 00 36 00 35 00 5c 00 75 00 30 00 30 00 36 00 64 00 5c 00 75 00 30 00 30 00 36 00 32 00 5c 00 75 00 30 00 30 00 36 00 63 00 5c 00 75 00 30 00 30 00 37 00 39 00 2e 00 5c 00 75 00 30 00 30 00 34 00 63 00 5c 00 75 00 30 00 30 00 36 00 66 00 5c 00 75 00 30 00 30 00 36 00 31 00 5c 00 75 00 30 00 30 00 36 00 34 00))}
		$asp_string56 = {((5c 55 30 30 30 30 30 30 35 32 5c 55 30 30 30 30 30 30 36 35 5c 55 30 30 30 30 30 30 37 31 5c 55 30 30 30 30 30 30 37 35 5c 55 30 30 30 30 30 30 36 35 5c 55 30 30 30 30 30 30 37 33 5c 55 30 30 30 30 30 30 37 34 5b 22) | (5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 35 00 32 00 5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 36 00 35 00 5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 37 00 31 00 5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 37 00 35 00 5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 36 00 35 00 5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 37 00 33 00 5c 00 55 00 30 00 30 00 30 00 30 00 30 00 30 00 37 00 34 00 5b 00 22 00))}
		$asp_string57 = {((2a 2f 5c 55 30 30 30 30) | (2a 00 2f 00 5c 00 55 00 30 00 30 00 30 00 30 00))}
		$asp_string58 = {((5c 55 30 30 30 30 46 46 46 41) | (5c 00 55 00 30 00 30 00 30 00 30 00 46 00 46 00 46 00 41 00))}
		$asp_string59 = {((22 65 34 35 65 33 32 39 66 65 62 35 64 39 32 35 62 22) | (22 00 65 00 34 00 35 00 65 00 33 00 32 00 39 00 66 00 65 00 62 00 35 00 64 00 39 00 32 00 35 00 62 00 22 00))}
		$asp_string60 = {((3e 50 4f 57 45 52 21 73 68 65 6c 6c 65 64 3c) | (3e 00 50 00 4f 00 57 00 45 00 52 00 21 00 73 00 68 00 65 00 6c 00 6c 00 65 00 64 00 3c 00))}
		$asp_string61 = {((40 72 65 71 75 69 72 65 73 20 78 68 45 64 69 74 6f 72) | (40 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 73 00 20 00 78 00 68 00 45 00 64 00 69 00 74 00 6f 00 72 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}

	condition:
		filesize < 200KB and ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and any of ( $asp_string* )
}

rule WEBSHELL_ASP_Sniffer : hardened limited
{
	meta:
		description = "ASP webshell which can sniff local traffic"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/03/14"
		modified = "2023-07-05"
		hash = "1206c22de8d51055a5e3841b4542fb13aa0f97dd"
		hash = "60d131af1ed23810dbc78f85ee32ffd863f8f0f4"
		hash = "c3bc4ab8076ef184c526eb7f16e08d41b4cec97e"
		hash = "ed5938c04f61795834751d44a383f8ca0ceac833"
		id = "b5704c19-fce1-5210-8185-4839c1c5a344"

	strings:
		$sniff1 = {((53 6f 63 6b 65 74 28) | (53 00 6f 00 63 00 6b 00 65 00 74 00 28 00))}
		$sniff2 = {((2e 42 69 6e 64 28) | (2e 00 42 00 69 00 6e 00 64 00 28 00))}
		$sniff3 = {((2e 53 65 74 53 6f 63 6b 65 74 4f 70 74 69 6f 6e 28) | (2e 00 53 00 65 00 74 00 53 00 6f 00 63 00 6b 00 65 00 74 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 28 00))}
		$sniff4 = {((2e 49 4f 43 6f 6e 74 72 6f 6c 28) | (2e 00 49 00 4f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 28 00))}
		$sniff5 = {((50 61 63 6b 65 74 43 61 70 74 75 72 65 57 72 69 74 65 72) | (50 00 61 00 63 00 6b 00 65 00 74 00 43 00 61 00 70 00 74 00 75 00 72 00 65 00 57 00 72 00 69 00 74 00 65 00 72 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and filesize < 30KB and all of ( $sniff* )
}

rule WEBSHELL_ASP_Generic_Tiny : hardened limited
{
	meta:
		description = "Generic tiny ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-07-05"
		hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
		hash = "52ce724580e533da983856c4ebe634336f5fd13a"
		hash = "0864f040a37c3e1cef0213df273870ed6a61e4bc"
		hash = "b184dc97b19485f734e3057e67007a16d47b2a62"
		id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"

	strings:
		$fp1 = {6e 65 74 2e 72 69 6d 2e 61 70 70 6c 69 63 61 74 69 6f 6e 2e 69 70 70 72 6f 78 79 73 65 72 76 69 63 65 2e 41 64 6d 69 6e 43 6f 6d 6d 61 6e 64 2e 65 78 65 63 75 74 65}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
		$asp_payload0 = {((65 76 61 6c 5f 72) | (65 00 76 00 61 00 6c 00 5f 00 72 00))}
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = {((57 53 43 52 49 50 54 2e 53 48 45 4c 4c) | (57 00 53 00 43 00 52 00 49 00 50 00 54 00 2e 00 53 00 48 00 45 00 4c 00 4c 00))}
		$asp_payload13 = {((45 78 65 63 75 74 65 47 6c 6f 62 61 6c) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 47 00 6c 00 6f 00 62 00 61 00 6c 00))}
		$asp_payload14 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_payload15 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_multi_payload_one1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_one2 = {((61 64 64 63 6f 64 65) | (61 00 64 00 64 00 63 00 6f 00 64 00 65 00))}
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = {((43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 46 72 6f 6d 56 69 72 74 75 61 6c 50 61 74 68) | (43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 46 00 72 00 6f 00 6d 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 61 00 74 00 68 00))}
		$asp_multi_payload_two2 = {((50 72 6f 63 65 73 73 52 65 71 75 65 73 74) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_multi_payload_two3 = {((42 75 69 6c 64 4d 61 6e 61 67 65 72) | (42 00 75 00 69 00 6c 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00))}
		$asp_multi_payload_three1 = {((53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00))}
		$asp_multi_payload_three2 = {((50 72 6f 63 65 73 73) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$asp_multi_payload_three3 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_four1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_four2 = {((54 72 61 6e 73 66 6f 72 6d 4e 6f 64 65) | (54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00 4e 00 6f 00 64 00 65 00))}
		$asp_multi_payload_four3 = {((6c 6f 61 64 78 6d 6c) | (6c 00 6f 00 61 00 64 00 78 00 6d 00 6c 00))}
		$asp_multi_payload_five1 = {((50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 53 00 74 00 61 00 72 00 74 00 49 00 6e 00 66 00 6f 00))}
		$asp_multi_payload_five2 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_five3 = {((2e 46 69 6c 65 6e 61 6d 65) | (2e 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00))}
		$asp_multi_payload_five4 = {((2e 41 72 67 75 6d 65 6e 74 73) | (2e 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00))}
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = {((53 61 76 65 54 6f 46 69 6c 65) | (53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00))}
		$asp_write_way_one3 = {((43 52 45 41 74 45 74 45 78 74 46 69 4c 45) | (43 00 52 00 45 00 41 00 74 00 45 00 74 00 45 00 78 00 74 00 46 00 69 00 4c 00 45 00))}
		$asp_cr_write1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00))}
		$asp_cr_write2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 20 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 28 00))}
		$asp_streamwriter1 = {((73 74 72 65 61 6d 77 72 69 74 65 72) | (73 00 74 00 72 00 65 00 61 00 6d 00 77 00 72 00 69 00 74 00 65 00 72 00))}
		$asp_streamwriter2 = {((66 69 6c 65 73 74 72 65 61 6d) | (66 00 69 00 6c 00 65 00 73 00 74 00 72 00 65 00 61 00 6d 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and not 1 of ( $fp* ) and not ( uint16( 0 ) == 0x5a4d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 ) and ( filesize < 700 and ( ( any of ( $asp_payload* ) or all of ( $asp_multi_payload_one* ) or all of ( $asp_multi_payload_two* ) or all of ( $asp_multi_payload_three* ) or all of ( $asp_multi_payload_four* ) or all of ( $asp_multi_payload_five* ) ) or ( any of ( $asp_always_write* ) and ( any of ( $asp_write_way_one* ) and any of ( $asp_cr_write* ) ) or ( any of ( $asp_streamwriter* ) ) ) ) )
}

rule WEBSHELL_ASP_Generic : FILE hardened limited
{
	meta:
		description = "Generic ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021-03-07"
		modified = "2023-07-05"
		score = 60
		hash = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
		hash = "4cf6fbad0411b7d33e38075f5e00d4c8ae9ce2f6f53967729974d004a183b25c"
		hash = "a91320483df0178eb3cafea830c1bd94585fc896"
		hash = "f3398832f697e3db91c3da71a8e775ebf66c7e73"
		id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"

	strings:
		$asp_much_sus7 = {57 65 62 20 53 68 65 6c 6c}
		$asp_much_sus8 = {57 65 62 53 68 65 6c 6c}
		$asp_much_sus3 = {68 69 64 64 65 64 20 73 68 65 6c 6c}
		$asp_much_sus4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c 2e 31}
		$asp_much_sus5 = {41 73 70 45 78 65 63}
		$asp_much_sus14 = {5c 70 63 41 6e 79 77 68 65 72 65 5c}
		$asp_much_sus15 = {61 6e 74 69 76 69 72 75 73}
		$asp_much_sus16 = {4d 63 41 66 65 65}
		$asp_much_sus17 = {6e 69 73 68 61 6e 67}
		$asp_much_sus18 = {((22 75 6e 73 61 66 65) | (22 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$asp_much_sus19 = {((27 75 6e 73 61 66 65) | (27 00 75 00 6e 00 73 00 61 00 66 00 65 00))}
		$asp_much_sus28 = {((65 78 70 6c 6f 69 74) | (65 00 78 00 70 00 6c 00 6f 00 69 00 74 00))}
		$asp_much_sus30 = {((54 56 71 51 41 41 4d 41 41 41) | (54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00))}
		$asp_much_sus31 = {((48 41 43 4b 45 44) | (48 00 41 00 43 00 4b 00 45 00 44 00))}
		$asp_much_sus32 = {((68 61 63 6b 65 64) | (68 00 61 00 63 00 6b 00 65 00 64 00))}
		$asp_much_sus33 = {((68 61 63 6b 65 72) | (68 00 61 00 63 00 6b 00 65 00 72 00))}
		$asp_much_sus34 = {((67 72 61 79 68 61 74) | (67 00 72 00 61 00 79 00 68 00 61 00 74 00))}
		$asp_much_sus35 = {((4d 69 63 72 6f 73 6f 66 74 20 46 72 6f 6e 74 50 61 67 65) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 46 00 72 00 6f 00 6e 00 74 00 50 00 61 00 67 00 65 00))}
		$asp_much_sus36 = {((52 6f 6f 74 6b 69 74) | (52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$asp_much_sus37 = {((72 6f 6f 74 6b 69 74) | (72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00))}
		$asp_much_sus38 = {((2f 2a 2d 2f 2a 2d 2a 2f) | (2f 00 2a 00 2d 00 2f 00 2a 00 2d 00 2a 00 2f 00))}
		$asp_much_sus39 = {((75 22 2b 22 6e 22 2b 22 73) | (75 00 22 00 2b 00 22 00 6e 00 22 00 2b 00 22 00 73 00))}
		$asp_much_sus40 = {((22 65 22 2b 22 76) | (22 00 65 00 22 00 2b 00 22 00 76 00))}
		$asp_much_sus41 = {((61 22 2b 22 6c 22) | (61 00 22 00 2b 00 22 00 6c 00 22 00))}
		$asp_much_sus42 = {((22 2b 22 28 22 2b 22) | (22 00 2b 00 22 00 28 00 22 00 2b 00 22 00))}
		$asp_much_sus43 = {((71 22 2b 22 75 22) | (71 00 22 00 2b 00 22 00 75 00 22 00))}
		$asp_much_sus44 = {((22 75 22 2b 22 65) | (22 00 75 00 22 00 2b 00 22 00 65 00))}
		$asp_much_sus45 = {((2f 2a 2f 2f 2a 2f) | (2f 00 2a 00 2f 00 2f 00 2a 00 2f 00))}
		$asp_much_sus46 = {((28 22 2f 2a 2f 22) | (28 00 22 00 2f 00 2a 00 2f 00 22 00))}
		$asp_much_sus47 = {((65 76 61 6c 28 65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00 65 00 76 00 61 00 6c 00 28 00))}
		$asp_much_sus48 = {((53 68 65 6c 6c 2e 55 73 65 72 73) | (53 00 68 00 65 00 6c 00 6c 00 2e 00 55 00 73 00 65 00 72 00 73 00))}
		$asp_much_sus49 = {((50 61 73 73 77 6f 72 64 54 79 70 65 3d 52 65 67 75 6c 61 72) | (50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 54 00 79 00 70 00 65 00 3d 00 52 00 65 00 67 00 75 00 6c 00 61 00 72 00))}
		$asp_much_sus50 = {((2d 45 78 70 69 72 65 3d 30) | (2d 00 45 00 78 00 70 00 69 00 72 00 65 00 3d 00 30 00))}
		$asp_much_sus51 = {((73 68 22 26 22 65 6c) | (73 00 68 00 22 00 26 00 22 00 65 00 6c 00))}
		$asp_gen_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$asp_gen_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$asp_gen_sus6 = {73 65 6c 66 2e 64 65 6c 65 74 65}
		$asp_gen_sus9 = {22 63 6d 64 20 2f 63}
		$asp_gen_sus10 = {22 63 6d 64 22}
		$asp_gen_sus11 = {22 63 6d 64 2e 65 78 65}
		$asp_gen_sus12 = {((25 63 6f 6d 73 70 65 63 25) | (25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00))}
		$asp_gen_sus13 = {((25 43 4f 4d 53 50 45 43 25) | (25 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 25 00))}
		$asp_gen_sus18 = {48 6b 6c 6d 2e 47 65 74 56 61 6c 75 65 4e 61 6d 65 73 28 29 3b}
		$asp_gen_sus19 = {((68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 78 63 68 61 6e 67 65 2f) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 68 00 65 00 6d 00 61 00 73 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2f 00))}
		$asp_gen_sus21 = {((22 75 70 6c 6f 61 64 22) | (22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$asp_gen_sus22 = {((22 55 70 6c 6f 61 64 22) | (22 00 55 00 70 00 6c 00 6f 00 61 00 64 00 22 00))}
		$asp_gen_sus25 = {((73 68 65 6c 6c 5f) | (73 00 68 00 65 00 6c 00 6c 00 5f 00))}
		$asp_gen_sus29 = {((41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39) | (41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00))}
		$asp_gen_sus30 = {((61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 32 33 34 35 36 37) | (61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 32 00 33 00 34 00 35 00 36 00 37 00))}
		$asp_gen_sus31 = {((73 65 72 76 2d 75) | (73 00 65 00 72 00 76 00 2d 00 75 00))}
		$asp_gen_sus32 = {((53 65 72 76 2d 75) | (53 00 65 00 72 00 76 00 2d 00 75 00))}
		$asp_gen_sus33 = {((41 72 6d 79) | (41 00 72 00 6d 00 79 00))}
		$asp_slightly_sus1 = {((3c 70 72 65 3e) | (3c 00 70 00 72 00 65 00 3e 00))}
		$asp_slightly_sus2 = {((3c 50 52 45 3e) | (3c 00 50 00 52 00 45 00 3e 00))}
		$asp_gen_obf1 = {((22 2b 22) | (22 00 2b 00 22 00))}
		$fp1 = {44 61 74 61 42 69 6e 64 65 72 2e 45 76 61 6c}
		$fp2 = {42 32 42 54 6f 6f 6c 73}
		$fp3 = {3c 62 3e 46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 63 61 63 68 65 20 75 70 64 61 74 65 2e 20 53 65 65 20 74 68 65 20 6c 6f 67 20 66 69 6c 65 20 66 6f 72 20 6d 6f 72 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e}
		$fp4 = {4d 69 63 72 6f 73 6f 66 74 2e 20 41 6c 6c 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2e}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}
		$asp_payload0 = {((65 76 61 6c 5f 72) | (65 00 76 00 61 00 6c 00 5f 00 72 00))}
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = {((57 53 43 52 49 50 54 2e 53 48 45 4c 4c) | (57 00 53 00 43 00 52 00 49 00 50 00 54 00 2e 00 53 00 48 00 45 00 4c 00 4c 00))}
		$asp_payload13 = {((45 78 65 63 75 74 65 47 6c 6f 62 61 6c) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 47 00 6c 00 6f 00 62 00 61 00 6c 00))}
		$asp_payload14 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_payload15 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_multi_payload_one1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_one2 = {((61 64 64 63 6f 64 65) | (61 00 64 00 64 00 63 00 6f 00 64 00 65 00))}
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = {((43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 46 72 6f 6d 56 69 72 74 75 61 6c 50 61 74 68) | (43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 46 00 72 00 6f 00 6d 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 61 00 74 00 68 00))}
		$asp_multi_payload_two2 = {((50 72 6f 63 65 73 73 52 65 71 75 65 73 74) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_multi_payload_two3 = {((42 75 69 6c 64 4d 61 6e 61 67 65 72) | (42 00 75 00 69 00 6c 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00))}
		$asp_multi_payload_three1 = {((53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00))}
		$asp_multi_payload_three2 = {((50 72 6f 63 65 73 73) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$asp_multi_payload_three3 = {((53 74 61 72 74) | (53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_four1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_four2 = {((54 72 61 6e 73 66 6f 72 6d 4e 6f 64 65) | (54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00 4e 00 6f 00 64 00 65 00))}
		$asp_multi_payload_four3 = {((6c 6f 61 64 78 6d 6c) | (6c 00 6f 00 61 00 64 00 78 00 6d 00 6c 00))}
		$asp_multi_payload_five1 = {((50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 53 00 74 00 61 00 72 00 74 00 49 00 6e 00 66 00 6f 00))}
		$asp_multi_payload_five2 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_five3 = {((2e 46 69 6c 65 6e 61 6d 65) | (2e 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00))}
		$asp_multi_payload_five4 = {((2e 41 72 67 75 6d 65 6e 74 73) | (2e 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00))}
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = {((53 61 76 65 54 6f 46 69 6c 65) | (53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00))}
		$asp_write_way_one3 = {((43 52 45 41 74 45 74 45 78 74 46 69 4c 45) | (43 00 52 00 45 00 41 00 74 00 45 00 74 00 45 00 78 00 74 00 46 00 69 00 4c 00 45 00))}
		$asp_cr_write1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00))}
		$asp_cr_write2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 20 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 28 00))}
		$asp_streamwriter1 = {((73 74 72 65 61 6d 77 72 69 74 65 72) | (73 00 74 00 72 00 65 00 61 00 6d 00 77 00 72 00 69 00 74 00 65 00 72 00))}
		$asp_streamwriter2 = {((66 69 6c 65 73 74 72 65 61 6d) | (66 00 69 00 6c 00 65 00 73 00 74 00 72 00 65 00 61 00 6d 00))}
		$tagasp_capa_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_capa_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_capa_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_capa_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_capa_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and not ( uint16( 0 ) == 0x5a4d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and ( any of ( $asp_payload* ) or all of ( $asp_multi_payload_one* ) or all of ( $asp_multi_payload_two* ) or all of ( $asp_multi_payload_three* ) or all of ( $asp_multi_payload_four* ) or all of ( $asp_multi_payload_five* ) ) and not any of ( $fp* ) and ( ( filesize < 3KB and ( 1 of ( $asp_slightly_sus* ) ) ) or ( filesize < 25KB and ( 1 of ( $asp_much_sus* ) or 1 of ( $asp_gen_sus* ) or ( #asp_gen_obf1 > 2 ) ) ) or ( filesize < 50KB and ( 1 of ( $asp_much_sus* ) or 3 of ( $asp_gen_sus* ) or ( #asp_gen_obf1 > 6 ) ) ) or ( filesize < 150KB and ( 1 of ( $asp_much_sus* ) or 4 of ( $asp_gen_sus* ) or ( #asp_gen_obf1 > 6 ) or ( ( any of ( $asp_always_write* ) and ( any of ( $asp_write_way_one* ) and any of ( $asp_cr_write* ) ) or ( any of ( $asp_streamwriter* ) ) ) and ( 1 of ( $asp_much_sus* ) or 2 of ( $asp_gen_sus* ) or ( #asp_gen_obf1 > 3 ) ) ) ) ) or ( filesize < 100KB and ( any of ( $tagasp_capa_classid* ) ) ) )
}

rule WEBSHELL_ASP_Generic_Registry_Reader : hardened limited
{
	meta:
		description = "Generic ASP webshell which reads the registry (might look for passwords, license keys, database settings, general recon, ..."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/03/14"
		modified = "2023-07-05"
		score = 50
		hash = "4d53416398a89aef3a39f63338a7c1bf2d3fcda4"
		hash = "f85cf490d7eb4484b415bea08b7e24742704bdda"
		hash = "898ebfa1757dcbbecb2afcdab1560d72ae6940de"
		id = "02d6f95f-1801-5fb0-8ab8-92176cf2fdd7"

	strings:
		$asp_reg2 = {((4c 6f 63 61 6c 4d 61 63 68 69 6e 65) | (4c 00 6f 00 63 00 61 00 6c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00))}
		$asp_reg3 = {((43 6c 61 73 73 65 73 52 6f 6f 74) | (43 00 6c 00 61 00 73 00 73 00 65 00 73 00 52 00 6f 00 6f 00 74 00))}
		$asp_reg4 = {((43 75 72 72 65 6e 74 55 73 65 72) | (43 00 75 00 72 00 72 00 65 00 6e 00 74 00 55 00 73 00 65 00 72 00))}
		$asp_reg5 = {((55 73 65 72 73) | (55 00 73 00 65 00 72 00 73 00))}
		$asp_reg6 = {((43 75 72 72 65 6e 74 43 6f 6e 66 69 67) | (43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 66 00 69 00 67 00))}
		$asp_reg7 = {((4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 33 32) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 57 00 69 00 6e 00 33 00 32 00))}
		$asp_reg8 = {((4f 70 65 6e 53 75 62 4b 65 79) | (4f 00 70 00 65 00 6e 00 53 00 75 00 62 00 4b 00 65 00 79 00))}
		$sus1 = {((73 68 65 6c 6c) | (73 00 68 00 65 00 6c 00 6c 00))}
		$sus2 = {((63 6d 64 2e 65 78 65) | (63 00 6d 00 64 00 2e 00 65 00 78 00 65 00))}
		$sus3 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$sus4 = {((3c 74 61 62 6c 65 20) | (3c 00 74 00 61 00 62 00 6c 00 65 00 20 00))}
		$sus5 = {((53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 53 65 63 75 72 69 74 79 45 78 63 65 70 74 69 6f 6e) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00))}
		$fp1 = {41 00 76 00 69 00 72 00 61 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 20 00 47 00 6d 00 62 00 48 00}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and all of ( $asp_reg* ) and any of ( $sus* ) and not any of ( $fp* ) and ( filesize < 10KB or ( filesize < 150KB and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) ) )
}

rule WEBSHELL_ASPX_Regeorg_CSHARP : hardened limited
{
	meta:
		description = "Webshell regeorg aspx c# version"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/sensepost/reGeorg"
		hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
		author = "Arnim Rupp (https://github.com/ruppde)"
		score = 75
		date = "2021/01/11"
		modified = "2023-07-05"
		hash = "479c1e1f1c263abe339de8be99806c733da4e8c1"
		hash = "38a1f1fc4e30c0b4ad6e7f0e1df5a92a7d05020b"
		hash = "e54f1a3eab740201feda235835fc0aa2e0c44ba9"
		hash = "aea0999c6e5952ec04bf9ee717469250cddf8a6f"
		id = "0a53d368-5f1b-55b7-b08f-36b0f8c5612f"

	strings:
		$input_sa1 = {((52 65 71 75 65 73 74 2e 51 75 65 72 79 53 74 72 69 6e 67 2e 47 65 74) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 51 00 75 00 65 00 72 00 79 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 47 00 65 00 74 00))}
		$input_sa2 = {((52 65 71 75 65 73 74 2e 48 65 61 64 65 72 73 2e 47 65 74) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 2e 00 47 00 65 00 74 00))}
		$sa1 = {((41 64 64 72 65 73 73 46 61 6d 69 6c 79 2e 49 6e 74 65 72 4e 65 74 77 6f 72 6b) | (41 00 64 00 64 00 72 00 65 00 73 00 73 00 46 00 61 00 6d 00 69 00 6c 00 79 00 2e 00 49 00 6e 00 74 00 65 00 72 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00))}
		$sa2 = {((52 65 73 70 6f 6e 73 65 2e 41 64 64 48 65 61 64 65 72) | (52 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 2e 00 41 00 64 00 64 00 48 00 65 00 61 00 64 00 65 00 72 00))}
		$sa3 = {((52 65 71 75 65 73 74 2e 49 6e 70 75 74 53 74 72 65 61 6d 2e 52 65 61 64) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00 2e 00 52 00 65 00 61 00 64 00))}
		$sa4 = {((52 65 73 70 6f 6e 73 65 2e 42 69 6e 61 72 79 57 72 69 74 65) | (52 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 2e 00 42 00 69 00 6e 00 61 00 72 00 79 00 57 00 72 00 69 00 74 00 65 00))}
		$sa5 = {((53 6f 63 6b 65 74) | (53 00 6f 00 63 00 6b 00 65 00 74 00))}
		$georg = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 22 47 65 6f 72 67 20 73 61 79 73 2c 20 27 41 6c 6c 20 73 65 65 6d 73 20 66 69 6e 65 27 22 29}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}

	condition:
		filesize < 300KB and ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( $georg or ( all of ( $sa* ) and any of ( $input_sa* ) ) )
}

rule WEBSHELL_CSHARP_Generic : hardened limited
{
	meta:
		description = "Webshell in c#"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
		date = "2021/01/11"
		modified = "2023-07-05"
		hash = "4b365fc9ddc8b247a12f4648cd5c91ee65e33fae"
		hash = "019eb61a6b5046502808fb5ab2925be65c0539b4"
		hash = "620ee444517df8e28f95e4046cd7509ac86cd514"
		hash = "a91320483df0178eb3cafea830c1bd94585fc896"
		id = "6d38a6b0-b1d2-51b0-9239-319f1fea7cae"

	strings:
		$input_http = {((52 65 71 75 65 73 74 2e) | (52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00))}
		$input_form1 = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$input_form2 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$exec_proc1 = {((6e 65 77 20 50 72 6f 63 65 73 73) | (6e 00 65 00 77 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$exec_proc2 = {((73 74 61 72 74 28) | (73 00 74 00 61 00 72 00 74 00 28 00))}
		$exec_shell1 = {((63 6d 64 2e 65 78 65) | (63 00 6d 00 64 00 2e 00 65 00 78 00 65 00))}
		$exec_shell2 = {((70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65) | (70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and filesize < 300KB and ( $input_http or all of ( $input_form* ) ) and all of ( $exec_proc* ) and any of ( $exec_shell* )
}

rule WEBSHELL_ASP_Runtime_Compile : FILE hardened limited
{
	meta:
		description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "https://github.com/antonioCoco/SharPyShell"
		date = "2021/01/11"
		modified = "2023-04-05"
		score = 75
		hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
		hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
		hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
		hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
		hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
		hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
		hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
		hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
		hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
		id = "5da9318d-f542-5603-a111-5b240f566d47"

	strings:
		$payload_reflection1 = {((53 79 73 74 65 6d) | (53 00 79 00 73 00 74 00 65 00 6d 00))}
		$payload_reflection2 = {((52 65 66 6c 65 63 74 69 6f 6e) | (52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$payload_reflection3 = {((41 73 73 65 6d 62 6c 79) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00))}
		$payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
		$payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
		$payload_compile1 = {((47 65 6e 65 72 61 74 65 49 6e 4d 65 6d 6f 72 79) | (47 00 65 00 6e 00 65 00 72 00 61 00 74 00 65 00 49 00 6e 00 4d 00 65 00 6d 00 6f 00 72 00 79 00))}
		$payload_compile2 = {((43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65) | (43 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 46 00 72 00 6f 00 6d 00 53 00 6f 00 75 00 72 00 63 00 65 00))}
		$payload_invoke1 = {((49 6e 76 6f 6b 65) | (49 00 6e 00 76 00 6f 00 6b 00 65 00))}
		$payload_invoke2 = {((43 72 65 61 74 65 49 6e 73 74 61 6e 63 65) | (43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00))}
		$payload_xamlreader1 = {((58 61 6d 6c 52 65 61 64 65 72) | (58 00 61 00 6d 00 6c 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$payload_xamlreader2 = {((50 61 72 73 65) | (50 00 61 00 72 00 73 00 65 00))}
		$payload_xamlreader3 = {((61 73 73 65 6d 62 6c 79 3d) | (61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 3d 00))}
		$payload_powershell1 = {((50 53 4f 62 6a 65 63 74) | (50 00 53 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$payload_powershell2 = {((49 6e 76 6f 6b 65) | (49 00 6e 00 76 00 6f 00 6b 00 65 00))}
		$payload_powershell3 = {((43 72 65 61 74 65 52 75 6e 73 70 61 63 65) | (43 00 72 00 65 00 61 00 74 00 65 00 52 00 75 00 6e 00 73 00 70 00 61 00 63 00 65 00))}
		$rc_fp1 = {52 65 71 75 65 73 74 2e 4d 61 70 50 61 74 68}
		$rc_fp2 = {((3c 62 6f 64 79 3e 3c 6d 6f 6e 6f 3a 4d 6f 6e 6f 53 61 6d 70 6c 65 73 48 65 61 64 65 72 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 2f 3e) | (3c 00 62 00 6f 00 64 00 79 00 3e 00 3c 00 6d 00 6f 00 6e 00 6f 00 3a 00 4d 00 6f 00 6e 00 6f 00 53 00 61 00 6d 00 70 00 6c 00 65 00 73 00 48 00 65 00 61 00 64 00 65 00 72 00 20 00 72 00 75 00 6e 00 61 00 74 00 3d 00 22 00 73 00 65 00 72 00 76 00 65 00 72 00 22 00 2f 00 3e 00))}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_input4 = {((5c 75 30 30 36 35 5c 75 30 30 37 31 5c 75 30 30 37 35) | (5c 00 75 00 30 00 30 00 36 00 35 00 5c 00 75 00 30 00 30 00 37 00 31 00 5c 00 75 00 30 00 30 00 37 00 35 00))}
		$asp_input5 = {((5c 75 30 30 36 35 5c 75 30 30 37 33 5c 75 30 30 37 34) | (5c 00 75 00 30 00 30 00 36 00 35 00 5c 00 75 00 30 00 30 00 37 00 33 00 5c 00 75 00 30 00 30 00 37 00 34 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}
		$sus_refl1 = {((20 5e 3d 20) | (20 00 5e 00 3d 00 20 00))}
		$sus_refl2 = {((53 68 61 72 50 79) | (53 00 68 00 61 00 72 00 50 00 79 00))}

	condition:
		(( filesize < 50KB and any of ( $sus_refl* ) ) or filesize < 10KB ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and not any of ( $rc_fp* ) and ( ( all of ( $payload_reflection* ) and any of ( $payload_load_reflection* ) ) or ( all of ( $payload_compile* ) and any of ( $payload_invoke* ) ) or all of ( $payload_xamlreader* ) or all of ( $payload_powershell* ) )
}

rule WEBSHELL_ASP_SQL : hardened limited
{
	meta:
		description = "ASP webshell giving SQL access. Might also be a dual use tool."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/03/14"
		modified = "2023-07-05"
		hash = "216c1dd950e0718e35bc4834c5abdc2229de3612"
		hash = "ffe44e9985d381261a6e80f55770833e4b78424bn"
		hash = "3d7cd32d53abc7f39faed133e0a8f95a09932b64"
		hash = "f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e"
		hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"
		id = "e534dcb9-40ab-544f-ae55-89fb21c422e9"

	strings:
		$sql1 = {((53 71 6c 43 6f 6e 6e 65 63 74 69 6f 6e) | (53 00 71 00 6c 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$sql2 = {((53 51 4c 43 6f 6e 6e 65 63 74 69 6f 6e) | (53 00 51 00 4c 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$sql3 = {((53 79 73 74 65 6d) | (53 00 79 00 73 00 74 00 65 00 6d 00))}
		$sql4 = {((44 61 74 61) | (44 00 61 00 74 00 61 00))}
		$sql5 = {((53 71 6c 43 6c 69 65 6e 74) | (53 00 71 00 6c 00 43 00 6c 00 69 00 65 00 6e 00 74 00))}
		$sql6 = {((53 51 4c 43 6c 69 65 6e 74) | (53 00 51 00 4c 00 43 00 6c 00 69 00 65 00 6e 00 74 00))}
		$sql7 = {((4f 70 65 6e) | (4f 00 70 00 65 00 6e 00))}
		$sql8 = {((53 71 6c 43 6f 6d 6d 61 6e 64) | (53 00 71 00 6c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$sql9 = {((53 51 4c 43 6f 6d 6d 61 6e 64) | (53 00 51 00 4c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$o_sql1 = {((53 51 4c 4f 4c 45 44 42) | (53 00 51 00 4c 00 4f 00 4c 00 45 00 44 00 42 00))}
		$o_sql2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$o_sql3 = {((6f 70 65 6e) | (6f 00 70 00 65 00 6e 00))}
		$a_sql1 = {((41 44 4f 44 42 2e 43 6f 6e 6e 65 63 74 69 6f 6e) | (41 00 44 00 4f 00 44 00 42 00 2e 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$a_sql2 = {((61 64 6f 64 62 2e 63 6f 6e 6e 65 63 74 69 6f 6e) | (61 00 64 00 6f 00 64 00 62 00 2e 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$a_sql3 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$a_sql4 = {((63 72 65 61 74 65 6f 62 6a 65 63 74) | (63 00 72 00 65 00 61 00 74 00 65 00 6f 00 62 00 6a 00 65 00 63 00 74 00))}
		$a_sql5 = {((6f 70 65 6e) | (6f 00 70 00 65 00 6e 00))}
		$c_sql1 = {((53 79 73 74 65 6d 2e 44 61 74 61 2e 53 71 6c 43 6c 69 65 6e 74) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 61 00 74 00 61 00 2e 00 53 00 71 00 6c 00 43 00 6c 00 69 00 65 00 6e 00 74 00))}
		$c_sql2 = {((73 71 6c 43 6f 6e 6e 65 63 74 69 6f 6e) | (73 00 71 00 6c 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$c_sql3 = {((6f 70 65 6e) | (6f 00 70 00 65 00 6e 00))}
		$sus1 = {((73 68 65 6c 6c) | (73 00 68 00 65 00 6c 00 6c 00))}
		$sus2 = {((78 70 5f 63 6d 64 73 68 65 6c 6c) | (78 00 70 00 5f 00 63 00 6d 00 64 00 73 00 68 00 65 00 6c 00 6c 00))}
		$sus3 = {((61 73 70 78 73 70 79) | (61 00 73 00 70 00 78 00 73 00 70 00 79 00))}
		$sus4 = {((5f 4b 69 6c 6c 4d 65) | (5f 00 4b 00 69 00 6c 00 6c 00 4d 00 65 00))}
		$sus5 = {((63 6d 64 2e 65 78 65) | (63 00 6d 00 64 00 2e 00 65 00 78 00 65 00))}
		$sus6 = {((63 6d 64 20 2f 63) | (63 00 6d 00 64 00 20 00 2f 00 63 00))}
		$sus7 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$sus8 = {((5c 78 32 44 5c 78 33 45 5c 78 37 43) | (5c 00 78 00 32 00 44 00 5c 00 78 00 33 00 45 00 5c 00 78 00 37 00 43 00))}
		$sus9 = {((48 61 63 6b 65 72) | (48 00 61 00 63 00 6b 00 65 00 72 00))}
		$sus10 = {((68 61 63 6b 65 72) | (68 00 61 00 63 00 6b 00 65 00 72 00))}
		$sus11 = {((48 41 43 4b 45 52) | (48 00 41 00 43 00 4b 00 45 00 52 00))}
		$sus12 = {((77 65 62 73 68 65 6c 6c) | (77 00 65 00 62 00 73 00 68 00 65 00 6c 00 6c 00))}
		$sus13 = {((65 71 75 65 73 74 5b 22 73 71 6c 22 5d) | (65 00 71 00 75 00 65 00 73 00 74 00 5b 00 22 00 73 00 71 00 6c 00 22 00 5d 00))}
		$sus14 = {((65 71 75 65 73 74 28 22 73 71 6c 22 29) | (65 00 71 00 75 00 65 00 73 00 74 00 28 00 22 00 73 00 71 00 6c 00 22 00 29 00))}
		$sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
		$sus16 = {((22 73 71 6c 43 6f 6d 6d 61 6e 64 22) | (22 00 73 00 71 00 6c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 22 00))}
		$sus17 = {((22 73 71 6c 63 6f 6d 6d 61 6e 64 22) | (22 00 73 00 71 00 6c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 22 00))}
		$slightly_sus3 = {((53 48 4f 57 20 43 4f 4c 55 4d 4e 53 20 46 52 4f 4d 20) | (53 00 48 00 4f 00 57 00 20 00 43 00 4f 00 4c 00 55 00 4d 00 4e 00 53 00 20 00 46 00 52 00 4f 00 4d 00 20 00))}
		$slightly_sus4 = {((73 68 6f 77 20 63 6f 6c 75 6d 6e 73 20 66 72 6f 6d 20) | (73 00 68 00 6f 00 77 00 20 00 63 00 6f 00 6c 00 75 00 6d 00 6e 00 73 00 20 00 66 00 72 00 6f 00 6d 00 20 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}

	condition:
		(( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and ( 6 of ( $sql* ) or all of ( $o_sql* ) or 3 of ( $a_sql* ) or all of ( $c_sql* ) ) and ( ( filesize < 150KB and any of ( $sus* ) ) or ( filesize < 5KB and any of ( $slightly_sus* ) ) )
}

rule WEBSHELL_ASP_Scan_Writable : hardened limited
{
	meta:
		description = "ASP webshell searching for writable directories (to hide more webshells ...)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/03/14"
		modified = "2023-04-05"
		hash = "2409eda9047085baf12e0f1b9d0b357672f7a152"
		hash = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"
		id = "1766e081-0591-59ab-b546-b13207764b4d"

	strings:
		$scan1 = {((44 69 72 65 63 74 6f 72 79 49 6e 66 6f) | (44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 49 00 6e 00 66 00 6f 00))}
		$scan2 = {((47 65 74 44 69 72 65 63 74 6f 72 69 65 73) | (47 00 65 00 74 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 69 00 65 00 73 00))}
		$scan3 = {((43 72 65 61 74 65) | (43 00 72 00 65 00 61 00 74 00 65 00))}
		$scan4 = {((46 69 6c 65) | (46 00 69 00 6c 00 65 00))}
		$scan5 = {((53 79 73 74 65 6d 2e 49 4f) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00))}
		$scan6 = {((43 61 6e 57 72 69 74 65) | (43 00 61 00 6e 00 57 00 72 00 69 00 74 00 65 00))}
		$scan7 = {((44 65 6c 65 74 65) | (44 00 65 00 6c 00 65 00 74 00 65 00))}
		$sus1 = {((75 70 6c 6f 61 64) | (75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$sus2 = {((73 68 65 6c 6c) | (73 00 68 00 65 00 6c 00 6c 00))}
		$sus3 = {((6f 72 6b 69 6e 67 20 64 69 72 65 63 74 6f 72 79) | (6f 00 72 00 6b 00 69 00 6e 00 67 00 20 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00))}
		$sus4 = {((73 63 61 6e) | (73 00 63 00 61 00 6e 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_input1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_input2 = {((50 61 67 65 5f 4c 6f 61 64) | (50 00 61 00 67 00 65 00 5f 00 4c 00 6f 00 61 00 64 00))}
		$asp_input3 = {((55 6d 56 78 64 57 56 7a 64 43 35 47 62 33 4a 74 4b) | (55 00 6d 00 56 00 78 00 64 00 57 00 56 00 7a 00 64 00 43 00 35 00 47 00 62 00 33 00 4a 00 74 00 4b 00))}
		$asp_xml_http = {((4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50) | (4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00))}
		$asp_xml_method1 = {((47 45 54) | (47 00 45 00 54 00))}
		$asp_xml_method2 = {((50 4f 53 54) | (50 00 4f 00 53 00 54 00))}
		$asp_xml_method3 = {((48 45 41 44) | (48 00 45 00 41 00 44 00))}
		$asp_form1 = {((3c 66 6f 72 6d 20) | (3c 00 66 00 6f 00 72 00 6d 00 20 00))}
		$asp_form2 = {((3c 46 6f 72 6d 20) | (3c 00 46 00 6f 00 72 00 6d 00 20 00))}
		$asp_form3 = {((3c 46 4f 52 4d 20) | (3c 00 46 00 4f 00 52 00 4d 00 20 00))}
		$asp_asp = {((3c 61 73 70 3a) | (3c 00 61 00 73 00 70 00 3a 00))}
		$asp_text1 = {((2e 74 65 78 74) | (2e 00 74 00 65 00 78 00 74 00))}
		$asp_text2 = {((2e 54 65 78 74) | (2e 00 54 00 65 00 78 00 74 00))}

	condition:
		filesize < 10KB and ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( any of ( $asp_input* ) or ( $asp_xml_http and any of ( $asp_xml_method* ) ) or ( any of ( $asp_form* ) and any of ( $asp_text* ) and $asp_asp ) ) and 6 of ( $scan* ) and any of ( $sus* )
}

rule WEBSHELL_JSP_ReGeorg : hardened limited
{
	meta:
		description = "Webshell regeorg JSP version"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/sensepost/reGeorg"
		hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021/01/24"
		modified = "2023-04-05"
		score = 75
		hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
		hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
		hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
		hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"
		id = "cbb90005-d8f8-5c64-85d1-29e466f48c25"

	strings:
		$jgeorg1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$jgeorg2 = {((67 65 74 48 65 61 64 65 72) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00))}
		$jgeorg3 = {((58 2d 43 4d 44) | (58 00 2d 00 43 00 4d 00 44 00))}
		$jgeorg4 = {((58 2d 53 54 41 54 55 53) | (58 00 2d 00 53 00 54 00 41 00 54 00 55 00 53 00))}
		$jgeorg5 = {((73 6f 63 6b 65 74) | (73 00 6f 00 63 00 6b 00 65 00 74 00))}
		$jgeorg6 = {((46 4f 52 57 41 52 44) | (46 00 4f 00 52 00 57 00 41 00 52 00 44 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}

	condition:
		filesize < 300KB and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and all of ( $jgeorg* )
}

rule WEBSHELL_JSP_HTTP_Proxy : hardened limited
{
	meta:
		description = "Webshell JSP HTTP proxy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash = "2f9b647660923c5262636a5344e2665512a947a4"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2023-07-05"
		hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
		hash = "2f9b647660923c5262636a5344e2665512a947a4"
		id = "55be246e-30a8-52ed-bc5f-507e63bbfe16"

	strings:
		$jh1 = {((4f 75 74 70 75 74 53 74 72 65 61 6d) | (4f 00 75 00 74 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$jh2 = {((49 6e 70 75 74 53 74 72 65 61 6d) | (49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$jh3 = {((42 75 66 66 65 72 65 64 52 65 61 64 65 72) | (42 00 75 00 66 00 66 00 65 00 72 00 65 00 64 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$jh4 = {((48 74 74 70 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$jh5 = {((6f 70 65 6e 43 6f 6e 6e 65 63 74 69 6f 6e) | (6f 00 70 00 65 00 6e 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$jh6 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}

	condition:
		filesize < 10KB and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and all of ( $jh* )
}

rule WEBSHELL_JSP_Writer_Nano : hardened limited
{
	meta:
		description = "JSP file writer"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2023-04-05"
		hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
		hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
		hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
		hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"
		id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"

	strings:
		$payload1 = {((2e 77 72 69 74 65) | (2e 00 77 00 72 00 69 00 74 00 65 00))}
		$payload2 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$payload3 = {((2e 64 65 63 6f 64 65 42 75 66 66 65 72) | (2e 00 64 00 65 00 63 00 6f 00 64 00 65 00 42 00 75 00 66 00 66 00 65 00 72 00))}
		$payload4 = {((46 69 6c 65 4f 75 74 70 75 74 53 74 72 65 61 6d) | (46 00 69 00 6c 00 65 00 4f 00 75 00 74 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$logger1 = {((67 65 74 4c 6f 67 67 65 72) | (67 00 65 00 74 00 4c 00 6f 00 67 00 67 00 65 00 72 00))}
		$logger2 = {((46 69 6c 65 48 61 6e 64 6c 65 72) | (46 00 69 00 6c 00 65 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00))}
		$logger3 = {((61 64 64 48 61 6e 64 6c 65 72) | (61 00 64 00 64 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$jw_sus1 = /getParameter\("."\)/ ascii wide
		$jw_sus4 = {((79 6f 63 6f) | (79 00 6f 00 63 00 6f 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}

	condition:
		( any of ( $input* ) and any of ( $req* ) ) and ( filesize < 200 or ( filesize < 1000 and any of ( $jw_sus* ) ) ) and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and ( 2 of ( $payload* ) or all of ( $logger* ) )
}

rule WEBSHELL_JSP_Generic_Tiny : hardened limited
{
	meta:
		description = "Generic JSP webshell tiny"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "8fd343db0442136e693e745d7af1018a99b042af"
		hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
		hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"
		id = "7535ade8-fc65-5558-a72c-cc14c3306390"

	strings:
		$payload1 = {((50 72 6f 63 65 73 73 42 75 69 6c 64 65 72) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00))}
		$payload2 = {((55 52 4c 43 6c 61 73 73 4c 6f 61 64 65 72) | (55 00 52 00 4c 00 43 00 6c 00 61 00 73 00 73 00 4c 00 6f 00 61 00 64 00 65 00 72 00))}
		$payload_rt1 = {((52 75 6e 74 69 6d 65) | (52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$payload_rt2 = {((67 65 74 52 75 6e 74 69 6d 65) | (67 00 65 00 74 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$payload_rt3 = {((65 78 65 63) | (65 00 78 00 65 00 63 00))}
		$jg_sus1 = {((78 65 20 2f 63) | (78 00 65 00 20 00 2f 00 63 00))}
		$jg_sus2 = /getParameter\("."\)/ ascii wide
		$jg_sus3 = {((3c 2f 70 72 65 3e) | (3c 00 2f 00 70 00 72 00 65 00 3e 00))}
		$jg_sus4 = {((42 41 53 45 36 34 44 65 63 6f 64 65 72) | (42 00 41 00 53 00 45 00 36 00 34 00 44 00 65 00 63 00 6f 00 64 00 65 00 72 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$fixed_cmd1 = {((62 61 73 68 20 2d 69 20 3e 26 20 2f 64 65 76 2f) | (62 00 61 00 73 00 68 00 20 00 2d 00 69 00 20 00 3e 00 26 00 20 00 2f 00 64 00 65 00 76 00 2f 00))}

	condition:
		(( filesize < 1000 and any of ( $jg_sus* ) ) or filesize < 250 ) and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and ( ( any of ( $input* ) and any of ( $req* ) ) or ( any of ( $fixed_cmd* ) ) ) and ( 1 of ( $payload* ) or all of ( $payload_rt* ) )
}

rule WEBSHELL_JSP_Generic : hardened limited
{
	meta:
		description = "Generic JSP webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
		hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
		hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"
		id = "7535ade8-fc65-5558-a72c-cc14c3306390"

	strings:
		$susp0 = {((63 6d 64) | (63 00 6d 00 64 00))}
		$susp1 = {((63 6f 6d 6d 61 6e 64) | (63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$susp2 = {((73 68 65 6c 6c) | (73 00 68 00 65 00 6c 00 6c 00))}
		$susp3 = {((64 6f 77 6e 6c 6f 61 64) | (64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00))}
		$susp4 = {((75 70 6c 6f 61 64) | (75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$susp5 = {((45 78 65 63 75 74 65) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00))}
		$susp6 = {((22 70 77 64 22) | (22 00 70 00 77 00 64 00 22 00))}
		$susp7 = {((22 3c 2f 70 72 65 3e) | (22 00 3c 00 2f 00 70 00 72 00 65 00 3e 00))}
		$susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii wide
		$susp9 = {((2a 2f 5c 75 30 30) | (2a 00 2f 00 5c 00 75 00 30 00 30 00))}
		$fp1 = {63 6f 6d 6d 61 6e 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 65 74 22 3b}
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$payload1 = {((50 72 6f 63 65 73 73 42 75 69 6c 64 65 72) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00))}
		$payload2 = {((70 72 6f 63 65 73 73 43 6d 64) | (70 00 72 00 6f 00 63 00 65 00 73 00 73 00 43 00 6d 00 64 00))}
		$rt_payload1 = {((52 75 6e 74 69 6d 65) | (52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$rt_payload2 = {((67 65 74 52 75 6e 74 69 6d 65) | (67 00 65 00 74 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$rt_payload3 = {((65 78 65 63) | (65 00 78 00 65 00 63 00))}

	condition:
		filesize < 300KB and not ( uint16( 0 ) == 0x5a4d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 ) and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and ( any of ( $input* ) and any of ( $req* ) ) and ( 1 of ( $payload* ) or all of ( $rt_payload* ) ) and not any of ( $fp* ) and any of ( $susp* )
}

rule WEBSHELL_JSP_Generic_Base64 : hardened limited
{
	meta:
		description = "Generic JSP webshell with base64 encoded payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2023-04-05"
		hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
		hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"
		id = "2eabbad2-7d10-573a-9120-b9b763fa2352"

	strings:
		$one1 = {((53 64 57 35 30 61 57 31 6c) | (53 00 64 00 57 00 35 00 30 00 61 00 57 00 31 00 6c 00))}
		$one2 = {((4a 31 62 6e 52 70 62 57) | (4a 00 31 00 62 00 6e 00 52 00 70 00 62 00 57 00))}
		$one3 = {((55 6e 56 75 64 47 6c 74 5a) | (55 00 6e 00 56 00 75 00 64 00 47 00 6c 00 74 00 5a 00))}
		$one4 = {((49 41 64 51 42 75 41 48 51 41 61 51 42 74 41 47 55 41) | (49 00 41 00 64 00 51 00 42 00 75 00 41 00 48 00 51 00 41 00 61 00 51 00 42 00 74 00 41 00 47 00 55 00 41 00))}
		$one5 = {((53 41 48 55 41 62 67 42 30 41 47 6b 41 62 51 42 6c 41) | (53 00 41 00 48 00 55 00 41 00 62 00 67 00 42 00 30 00 41 00 47 00 6b 00 41 00 62 00 51 00 42 00 6c 00 41 00))}
		$one6 = {((55 67 42 31 41 47 34 41 64 41 42 70 41 47 30 41 5a 51) | (55 00 67 00 42 00 31 00 41 00 47 00 34 00 41 00 64 00 41 00 42 00 70 00 41 00 47 00 30 00 41 00 5a 00 51 00))}
		$two1 = {((6c 65 47 56 6a) | (6c 00 65 00 47 00 56 00 6a 00))}
		$two2 = {((56 34 5a 57) | (56 00 34 00 5a 00 57 00))}
		$two3 = {((5a 58 68 6c 59) | (5a 00 58 00 68 00 6c 00 59 00))}
		$two4 = {((55 41 65 41 42 6c 41 47 4d 41) | (55 00 41 00 65 00 41 00 42 00 6c 00 41 00 47 00 4d 00 41 00))}
		$two5 = {((6c 41 48 67 41 5a 51 42 6a 41) | (6c 00 41 00 48 00 67 00 41 00 5a 00 51 00 42 00 6a 00 41 00))}
		$two6 = {((5a 51 42 34 41 47 55 41 59 77) | (5a 00 51 00 42 00 34 00 41 00 47 00 55 00 41 00 59 00 77 00))}
		$three1 = {((54 59 33 4a 70 63 48 52 46 62 6d 64 70 62 6d 56 47 59 57 4e 30 62 33 4a 35) | (54 00 59 00 33 00 4a 00 70 00 63 00 48 00 52 00 46 00 62 00 6d 00 64 00 70 00 62 00 6d 00 56 00 47 00 59 00 57 00 4e 00 30 00 62 00 33 00 4a 00 35 00))}
		$three2 = {((4e 6a 63 6d 6c 77 64 45 56 75 5a 32 6c 75 5a 55 5a 68 59 33 52 76 63 6e) | (4e 00 6a 00 63 00 6d 00 6c 00 77 00 64 00 45 00 56 00 75 00 5a 00 32 00 6c 00 75 00 5a 00 55 00 5a 00 68 00 59 00 33 00 52 00 76 00 63 00 6e 00))}
		$three3 = {((55 32 4e 79 61 58 42 30 52 57 35 6e 61 57 35 6c 52 6d 46 6a 64 47 39 79 65) | (55 00 32 00 4e 00 79 00 61 00 58 00 42 00 30 00 52 00 57 00 35 00 6e 00 61 00 57 00 35 00 6c 00 52 00 6d 00 46 00 6a 00 64 00 47 00 39 00 79 00 65 00))}
		$three4 = {((4d 41 59 77 42 79 41 47 6b 41 63 41 42 30 41 45 55 41 62 67 42 6e 41 47 6b 41 62 67 42 6c 41 45 59 41 59 51 42 6a 41 48 51 41 62 77 42 79 41 48 6b 41) | (4d 00 41 00 59 00 77 00 42 00 79 00 41 00 47 00 6b 00 41 00 63 00 41 00 42 00 30 00 41 00 45 00 55 00 41 00 62 00 67 00 42 00 6e 00 41 00 47 00 6b 00 41 00 62 00 67 00 42 00 6c 00 41 00 45 00 59 00 41 00 59 00 51 00 42 00 6a 00 41 00 48 00 51 00 41 00 62 00 77 00 42 00 79 00 41 00 48 00 6b 00 41 00))}
		$three5 = {((54 41 47 4d 41 63 67 42 70 41 48 41 41 64 41 42 46 41 47 34 41 5a 77 42 70 41 47 34 41 5a 51 42 47 41 47 45 41 59 77 42 30 41 47 38 41 63 67 42 35 41) | (54 00 41 00 47 00 4d 00 41 00 63 00 67 00 42 00 70 00 41 00 48 00 41 00 41 00 64 00 41 00 42 00 46 00 41 00 47 00 34 00 41 00 5a 00 77 00 42 00 70 00 41 00 47 00 34 00 41 00 5a 00 51 00 42 00 47 00 41 00 47 00 45 00 41 00 59 00 77 00 42 00 30 00 41 00 47 00 38 00 41 00 63 00 67 00 42 00 35 00 41 00))}
		$three6 = {((55 77 42 6a 41 48 49 41 61 51 42 77 41 48 51 41 52 51 42 75 41 47 63 41 61 51 42 75 41 47 55 41 52 67 42 68 41 47 4d 41 64 41 42 76 41 48 49 41 65 51) | (55 00 77 00 42 00 6a 00 41 00 48 00 49 00 41 00 61 00 51 00 42 00 77 00 41 00 48 00 51 00 41 00 52 00 51 00 42 00 75 00 41 00 47 00 63 00 41 00 61 00 51 00 42 00 75 00 41 00 47 00 55 00 41 00 52 00 67 00 42 00 68 00 41 00 47 00 4d 00 41 00 64 00 41 00 42 00 76 00 41 00 48 00 49 00 41 00 65 00 51 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }

	condition:
		($cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( uint16( 0 ) == 0x5a4d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 ) and filesize < 300KB and ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule WEBSHELL_JSP_Generic_ProcessBuilder : hardened
{
	meta:
		description = "Generic JSP webshell which uses processbuilder to execute user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
		hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
		hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
		hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"
		id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"

	strings:
		$exec = {((50 72 6f 63 65 73 73 42 75 69 6c 64 65 72) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00))}
		$start = {((73 74 61 72 74) | (73 00 74 00 61 00 72 00 74 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}

	condition:
		filesize < 2000 and ( any of ( $input* ) and any of ( $req* ) ) and $exec and $start
}

import "math"

rule WEBSHELL_JSP_Generic_Reflection : hardened limited
{
	meta:
		description = "Generic JSP webshell which uses reflection to execute user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
		hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"
		id = "806ffc8b-1dc8-5e28-ae94-12ad3fee18cd"

	strings:
		$ws_exec = {((69 6e 76 6f 6b 65) | (69 00 6e 00 76 00 6f 00 6b 00 65 00))}
		$ws_class = {((43 6c 61 73 73) | (43 00 6c 00 61 00 73 00 73 00))}
		$fp = {53 4f 41 50 43 6f 6e 6e 65 63 74 69 6f 6e}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$cj_encoded1 = {((22 6a 61 76 61 2e 75 74 69 6c 2e 42 61 73 65 36 34 24 44 65 63 6f 64 65 72 22) | (22 00 6a 00 61 00 76 00 61 00 2e 00 75 00 74 00 69 00 6c 00 2e 00 42 00 61 00 73 00 65 00 36 00 34 00 24 00 44 00 65 00 63 00 6f 00 64 00 65 00 72 00 22 00))}

	condition:
		all of ( $ws_* ) and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not $fp and ( filesize < 10KB and ( any of ( $input* ) and any of ( $req* ) ) or ( filesize < 30KB and any of ( $cj_encoded* ) and math.entropy ( 500 , filesize - 500 ) >= 5.5 and math.mean ( 500 , filesize - 500 ) > 80 and math.deviation ( 500 , filesize - 500 , 89.0 ) < 23 ) )
}

rule WEBSHELL_JSP_Generic_Encoded_Shell : hardened
{
	meta:
		description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-07-05"
		hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
		hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
		hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
		id = "359949d7-1793-5e13-9fdc-fe995ae12117"

	strings:
		$sj0 = /{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
		$sj1 = /{ ?99, 109, 100}/ wide ascii
		$sj2 = /{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
		$sj3 = /{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
		$sj4 = /{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
		$sj5 = /{ ?101, 120, 101, 99 }/ wide ascii
		$sj6 = /{ ?103, 101, 116, 82, 117, 110/ wide ascii

	condition:
		filesize < 300KB and any of ( $sj* )
}

rule WEBSHELL_JSP_NetSpy : hardened limited
{
	meta:
		description = "JSP netspy webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2023-04-05"
		hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
		hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"
		id = "41f5c171-878d-579f-811d-91d74f7e3e24"

	strings:
		$scan1 = {((73 63 61 6e) | (73 00 63 00 61 00 6e 00))}
		$scan2 = {((70 6f 72 74) | (70 00 6f 00 72 00 74 00))}
		$scan3 = {((77 65 62) | (77 00 65 00 62 00))}
		$scan4 = {((70 72 6f 78 79) | (70 00 72 00 6f 00 78 00 79 00))}
		$scan5 = {((68 74 74 70) | (68 00 74 00 74 00 70 00))}
		$scan6 = {((68 74 74 70 73) | (68 00 74 00 74 00 70 00 73 00))}
		$write1 = {((6f 73 2e 77 72 69 74 65) | (6f 00 73 00 2e 00 77 00 72 00 69 00 74 00 65 00))}
		$write2 = {((46 69 6c 65 4f 75 74 70 75 74 53 74 72 65 61 6d) | (46 00 69 00 6c 00 65 00 4f 00 75 00 74 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$write3 = {((50 72 69 6e 74 57 72 69 74 65 72) | (50 00 72 00 69 00 6e 00 74 00 57 00 72 00 69 00 74 00 65 00 72 00))}
		$http = {((6a 61 76 61 2e 6e 65 74 2e 48 74 74 70 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e) | (6a 00 61 00 76 00 61 00 2e 00 6e 00 65 00 74 00 2e 00 48 00 74 00 74 00 70 00 55 00 52 00 4c 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}

	condition:
		filesize < 30KB and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and ( any of ( $input* ) and any of ( $req* ) ) and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule WEBSHELL_JSP_By_String : hardened limited
{
	meta:
		description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/09"
		modified = "2023-04-05"
		hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
		hash = "4c2464503237beba54f66f4a099e7e75028707aa"
		hash = "06b42d4707e7326aff402ecbb585884863c6351a"
		hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
		hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
		hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
		hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
		hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"
		id = "8d64e40b-5583-5887-afe1-b926d9880913"

	strings:
		$jstring1 = {((3c 74 69 74 6c 65 3e 42 6f 6f 74 20 53 68 65 6c 6c 3c 2f 74 69 74 6c 65 3e) | (3c 00 74 00 69 00 74 00 6c 00 65 00 3e 00 42 00 6f 00 6f 00 74 00 20 00 53 00 68 00 65 00 6c 00 6c 00 3c 00 2f 00 74 00 69 00 74 00 6c 00 65 00 3e 00))}
		$jstring2 = {((53 74 72 69 6e 67 20 6f 72 61 50 57 44 3d 22) | (53 00 74 00 72 00 69 00 6e 00 67 00 20 00 6f 00 72 00 61 00 50 00 57 00 44 00 3d 00 22 00))}
		$jstring3 = {((4f 77 6e 65 64 20 62 79 20 43 68 69 6e 65 73 65 20 48 61 63 6b 65 72 73 21) | (4f 00 77 00 6e 00 65 00 64 00 20 00 62 00 79 00 20 00 43 00 68 00 69 00 6e 00 65 00 73 00 65 00 20 00 48 00 61 00 63 00 6b 00 65 00 72 00 73 00 21 00))}
		$jstring4 = {((41 6e 74 53 77 6f 72 64 20 4a 53 50) | (41 00 6e 00 74 00 53 00 77 00 6f 00 72 00 64 00 20 00 4a 00 53 00 50 00))}
		$jstring5 = {((4a 53 50 20 57 65 62 73 68 65 6c 6c 3c 2f) | (4a 00 53 00 50 00 20 00 57 00 65 00 62 00 73 00 68 00 65 00 6c 00 6c 00 3c 00 2f 00))}
		$jstring6 = {((6d 6f 74 6f 4d 45 37 32 32 72 65 6d 69 6e 64 32 30 31 32) | (6d 00 6f 00 74 00 6f 00 4d 00 45 00 37 00 32 00 32 00 72 00 65 00 6d 00 69 00 6e 00 64 00 32 00 30 00 31 00 32 00))}
		$jstring7 = {((45 43 28 67 65 74 46 72 6f 6d 42 61 73 65 36 34 28 74 6f 53 74 72 69 6e 67 48 65 78 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 70 61 73 73 77 6f 72 64) | (45 00 43 00 28 00 67 00 65 00 74 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 28 00 74 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 48 00 65 00 78 00 28 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 28 00 22 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$jstring8 = {((68 74 74 70 3a 2f 2f 6a 6d 6d 6d 2e 63 6f 6d 2f 77 65 62 2f 69 6e 64 65 78 2e 6a 73 70) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6a 00 6d 00 6d 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 65 00 62 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 6a 00 73 00 70 00))}
		$jstring9 = {((6c 69 73 74 2e 6a 73 70 20 3d 20 44 69 72 65 63 74 6f 72 79 20 26 20 46 69 6c 65 20 56 69 65 77) | (6c 00 69 00 73 00 74 00 2e 00 6a 00 73 00 70 00 20 00 3d 00 20 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 20 00 26 00 20 00 46 00 69 00 6c 00 65 00 20 00 56 00 69 00 65 00 77 00))}
		$jstring10 = {((6a 64 62 63 52 6f 77 53 65 74 2e 73 65 74 44 61 74 61 53 6f 75 72 63 65 4e 61 6d 65 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28) | (6a 00 64 00 62 00 63 00 52 00 6f 00 77 00 53 00 65 00 74 00 2e 00 73 00 65 00 74 00 44 00 61 00 74 00 61 00 53 00 6f 00 75 00 72 00 63 00 65 00 4e 00 61 00 6d 00 65 00 28 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 28 00))}
		$jstring11 = {((4d 72 2e 55 6e 31 6b 30 64 33 72 20 52 69 6e 67 5a 65 72 30 20 54 65 61 6d) | (4d 00 72 00 2e 00 55 00 6e 00 31 00 6b 00 30 00 64 00 33 00 72 00 20 00 52 00 69 00 6e 00 67 00 5a 00 65 00 72 00 30 00 20 00 54 00 65 00 61 00 6d 00))}
		$jstring12 = {((4d 69 6e 69 57 65 62 43 6d 64 53 68 65 6c 6c) | (4d 00 69 00 6e 00 69 00 57 00 65 00 62 00 43 00 6d 00 64 00 53 00 68 00 65 00 6c 00 6c 00))}
		$jstring13 = {((70 77 6e 73 68 65 6c 6c 2e 6a 73 70) | (70 00 77 00 6e 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 6a 00 73 00 70 00))}
		$jstring14 = {((73 65 73 73 69 6f 6e 20 73 65 74 20 26 6c 74 3b 6b 65 79 26 67 74 3b 20 26 6c 74 3b 76 61 6c 75 65 26 67 74 3b 20 5b 63 6c 61 73 73 5d 3c 62 72 3e) | (73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 73 00 65 00 74 00 20 00 26 00 6c 00 74 00 3b 00 6b 00 65 00 79 00 26 00 67 00 74 00 3b 00 20 00 26 00 6c 00 74 00 3b 00 76 00 61 00 6c 00 75 00 65 00 26 00 67 00 74 00 3b 00 20 00 5b 00 63 00 6c 00 61 00 73 00 73 00 5d 00 3c 00 62 00 72 00 3e 00))}
		$jstring15 = {((52 75 6e 74 69 6d 65 2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28) | (52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 2e 00 67 00 65 00 74 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 28 00 29 00 2e 00 65 00 78 00 65 00 63 00 28 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 28 00))}
		$jstring16 = {((47 49 46 39 38 61 3c 25 40 70 61 67 65) | (47 00 49 00 46 00 39 00 38 00 61 00 3c 00 25 00 40 00 70 00 61 00 67 00 65 00))}
		$jstring17 = {((54 61 73 39 65 72) | (54 00 61 00 73 00 39 00 65 00 72 00))}
		$jstring18 = {((75 75 30 30 32 38 5c 75) | (75 00 75 00 30 00 30 00 32 00 38 00 5c 00 75 00))}
		$jstring19 = {((75 75 30 30 36 35 5c 75) | (75 00 75 00 30 00 30 00 36 00 35 00 5c 00 75 00))}
		$jstring20 = {((75 75 30 30 37 33 5c 75) | (75 00 75 00 30 00 30 00 37 00 33 00 5c 00 75 00))}
		$jstring21 = /\\uuu{0,50}00/ wide ascii
		$jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii
		$jstring23 = {((22 65 34 35 65 33 32 39 66 65 62 35 64 39 32 35 62 22) | (22 00 65 00 34 00 35 00 65 00 33 00 32 00 39 00 66 00 65 00 62 00 35 00 64 00 39 00 32 00 35 00 62 00 22 00))}
		$jstring24 = {((75 3c 21 5b 43 44 41 54 41 5b 6e) | (75 00 3c 00 21 00 5b 00 43 00 44 00 41 00 54 00 41 00 5b 00 6e 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }

	condition:
		not ( uint16( 0 ) == 0x5a4d or $dex at 0 or $pack at 0 or uint16( 0 ) == 0x4b50 ) and ( ( filesize < 100KB and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and any of ( $jstring* ) ) or ( filesize < 500KB and ( #jstring21 > 20 or $jstring18 or $jstring19 or $jstring20 ) ) )
}

rule WEBSHELL_JSP_Input_Upload_Write : hardened limited
{
	meta:
		description = "JSP uploader which gets input, writes files and contains upload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2023-04-05"
		hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
		hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
		hash = "19eca79163259d80375ebebbc440b9545163e6a3"
		id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"

	strings:
		$upload = {((75 70 6c 6f 61 64) | (75 00 70 00 6c 00 6f 00 61 00 64 00))}
		$write1 = {((6f 73 2e 77 72 69 74 65) | (6f 00 73 00 2e 00 77 00 72 00 69 00 74 00 65 00))}
		$write2 = {((46 69 6c 65 4f 75 74 70 75 74 53 74 72 65 61 6d) | (46 00 69 00 6c 00 65 00 4f 00 75 00 74 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$input1 = {((67 65 74 50 61 72 61 6d 65 74 65 72) | (67 00 65 00 74 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00))}
		$input2 = {((67 65 74 48 65 61 64 65 72 73) | (67 00 65 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00))}
		$input3 = {((67 65 74 49 6e 70 75 74 53 74 72 65 61 6d) | (67 00 65 00 74 00 49 00 6e 00 70 00 75 00 74 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$input4 = {((67 65 74 52 65 61 64 65 72) | (67 00 65 00 74 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$req1 = {((72 65 71 75 65 73 74) | (72 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req2 = {((48 74 74 70 53 65 72 76 6c 65 74 52 65 71 75 65 73 74) | (48 00 74 00 74 00 70 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$req3 = {((67 65 74 52 65 71 75 65 73 74) | (67 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}

	condition:
		filesize < 10KB and ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and ( any of ( $input* ) and any of ( $req* ) ) and $upload and 1 of ( $write* )
}

rule WEBSHELL_Generic_OS_Strings : FILE hardened limited
{
	meta:
		description = "typical webshell strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/01/12"
		modified = "2023-07-05"
		score = 50
		hash = "d5bfe40283a28917fcda0cefd2af301f9a7ecdad"
		hash = "fd45a72bda0a38d5ad81371d68d206035cb71a14"
		hash = "b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3"
		hash = "569259aafe06ba3cef9e775ee6d142fed6edff5f"
		hash = "48909d9f4332840b4e04b86f9723d7427e33ac67"
		hash = "0353ae68b12b8f6b74794d3273967b530d0d526f"
		id = "ea85e415-4774-58ac-b063-0f5eb535ec49"

	strings:
		$fp1 = {((68 74 74 70 3a 2f 2f 65 76 69 6c 2e 63 6f 6d 2f) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 76 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00))}
		$fp2 = {((64 65 6e 6f 72 6d 61 6c 69 7a 65 28 27 2f 65 74 63 2f 73 68 61 64 6f 77) | (64 00 65 00 6e 00 6f 00 72 00 6d 00 61 00 6c 00 69 00 7a 00 65 00 28 00 27 00 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00))}
		$fp3 = {76 69 6d 2e 6f 72 67 3e}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$cjsp_short1 = {((3c 25) | (3c 00 25 00))}
		$cjsp_short2 = {((25 3e) | (25 00 3e 00))}
		$cjsp_long1 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$cjsp_long4 = {((3c 25 40 70) | (3c 00 25 00 40 00 70 00))}
		$cjsp_long5 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$cjsp_long6 = {((3c 25 20) | (3c 00 25 00 20 00))}
		$cjsp_long7 = {((3c 20 25) | (3c 00 20 00 25 00))}
		$w1 = {((6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73) | (6e 00 65 00 74 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 20 00 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00))}
		$w2 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$w3 = {((2f 61 64 64) | (2f 00 61 00 64 00 64 00))}
		$l1 = {((2f 65 74 63 2f 73 68 61 64 6f 77) | (2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00))}
		$l2 = {((2f 65 74 63 2f 73 73 68 2f 73 73 68 64 5f 63 6f 6e 66 69 67) | (2f 00 65 00 74 00 63 00 2f 00 73 00 73 00 68 00 2f 00 73 00 73 00 68 00 64 00 5f 00 63 00 6f 00 6e 00 66 00 69 00 67 00))}
		$take_two1 = {((6e 65 74 20 75 73 65 72) | (6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00))}
		$take_two2 = {((2f 61 64 64) | (2f 00 61 00 64 00 64 00))}

	condition:
		filesize < 70KB and ( ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) or ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) or ( $cjsp_short1 at 0 or any of ( $cjsp_long* ) or $cjsp_short2 in ( filesize - 100 .. filesize ) or ( $cjsp_short2 and ( $cjsp_short1 in ( 0 .. 1000 ) or $cjsp_short1 in ( filesize - 1000 .. filesize ) ) ) ) ) and ( filesize < 300KB and not uint16( 0 ) == 0x5a4d and ( all of ( $w* ) or all of ( $l* ) or 2 of ( $take_two* ) ) ) and not any of ( $fp* )
}

rule WEBSHELL_In_Image : hardened limited
{
	meta:
		description = "Webshell in GIF, PNG or JPG"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
		hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
		hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
		date = "2021/02/27"
		modified = "2023-04-05"
		score = 75
		id = "b1185b69-9b08-5925-823a-829fee6fa4cf"

	strings:
		$png = { 89 50 4E 47 }
		$jpg = { FF D8 FF E0 }
		$gif = {((47 49 46 38) | (47 00 49 00 46 00 38 00))}
		$gif2 = {67 69 66 38 39}
		$gif3 = {47 69 66 38 39}
		$mdb = { 00 01 00 00 53 74 }
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}
		$php_multi_write1 = {((66 6f 70 65 6e 28) | (66 00 6f 00 70 00 65 00 6e 00 28 00))}
		$php_multi_write2 = {((66 77 72 69 74 65 28) | (66 00 77 00 72 00 69 00 74 00 65 00 28 00))}
		$php_write1 = {((6d 6f 76 65 5f 75 70 6c 6f 61 64 65 64 5f 66 69 6c 65) | (6d 00 6f 00 76 00 65 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 65 00 64 00 5f 00 66 00 69 00 6c 00 65 00))}
		$cjsp1 = {((3c 25) | (3c 00 25 00))}
		$cjsp2 = {((3c 6a 73 70 3a) | (3c 00 6a 00 73 00 70 00 3a 00))}
		$cjsp3 = /language=[\"']java[\"\']/ ascii wide
		$cjsp4 = {((2f 6a 73 74 6c 2f 63 6f 72 65) | (2f 00 6a 00 73 00 74 00 6c 00 2f 00 63 00 6f 00 72 00 65 00))}
		$payload1 = {((50 72 6f 63 65 73 73 42 75 69 6c 64 65 72) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00))}
		$payload2 = {((70 72 6f 63 65 73 73 43 6d 64) | (70 00 72 00 6f 00 63 00 65 00 73 00 73 00 43 00 6d 00 64 00))}
		$rt_payload1 = {((52 75 6e 74 69 6d 65) | (52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$rt_payload2 = {((67 65 74 52 75 6e 74 69 6d 65) | (67 00 65 00 74 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$rt_payload3 = {((65 78 65 63) | (65 00 78 00 65 00 63 00))}
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = {((25 3e) | (25 00 3e 00))}
		$tagasp_classid1 = {((37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38) | (37 00 32 00 43 00 32 00 34 00 44 00 44 00 35 00 2d 00 44 00 37 00 30 00 41 00 2d 00 34 00 33 00 38 00 42 00 2d 00 38 00 41 00 34 00 32 00 2d 00 39 00 38 00 34 00 32 00 34 00 42 00 38 00 38 00 41 00 46 00 42 00 38 00))}
		$tagasp_classid2 = {((46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 32 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid3 = {((30 39 33 46 46 39 39 39 2d 31 45 41 30 2d 34 30 37 39 2d 39 35 32 35 2d 39 36 31 34 43 33 35 30 34 42 37 34) | (30 00 39 00 33 00 46 00 46 00 39 00 39 00 39 00 2d 00 31 00 45 00 41 00 30 00 2d 00 34 00 30 00 37 00 39 00 2d 00 39 00 35 00 32 00 35 00 2d 00 39 00 36 00 31 00 34 00 43 00 33 00 35 00 30 00 34 00 42 00 37 00 34 00))}
		$tagasp_classid4 = {((46 39 33 35 44 43 32 36 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42) | (46 00 39 00 33 00 35 00 44 00 43 00 32 00 36 00 2d 00 31 00 43 00 46 00 30 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 44 00 42 00 39 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 35 00 38 00 41 00 30 00 42 00))}
		$tagasp_classid5 = {((30 44 34 33 46 45 30 31 2d 46 30 39 33 2d 31 31 43 46 2d 38 39 34 30 2d 30 30 41 30 43 39 30 35 34 32 32 38) | (30 00 44 00 34 00 33 00 46 00 45 00 30 00 31 00 2d 00 46 00 30 00 39 00 33 00 2d 00 31 00 31 00 43 00 46 00 2d 00 38 00 39 00 34 00 30 00 2d 00 30 00 30 00 41 00 30 00 43 00 39 00 30 00 35 00 34 00 32 00 32 00 38 00))}
		$tagasp_long10 = {((3c 25 40 20) | (3c 00 25 00 40 00 20 00))}
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = {((3c 25 65 78) | (3c 00 25 00 65 00 78 00))}
		$tagasp_long13 = {((3c 25 65 76) | (3c 00 25 00 65 00 76 00))}
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = {3c 3f 70 68 70}
		$php2 = {3c 3f 3d}
		$jsp1 = {((3d 22 6a 61 76 61 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 2e 00))}
		$jsp2 = {((3d 22 6a 61 76 61 78 2e) | (3d 00 22 00 6a 00 61 00 76 00 61 00 78 00 2e 00))}
		$jsp3 = {((6a 61 76 61 2e 6c 61 6e 67 2e) | (6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00))}
		$jsp4 = {((70 75 62 6c 69 63) | (70 00 75 00 62 00 6c 00 69 00 63 00))}
		$jsp5 = {((74 68 72 6f 77 73) | (74 00 68 00 72 00 6f 00 77 00 73 00))}
		$jsp6 = {((67 65 74 56 61 6c 75 65) | (67 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$jsp7 = {((67 65 74 42 79 74 65 73) | (67 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00))}
		$perl1 = {50 65 72 6c 53 63 72 69 70 74}
		$asp_payload0 = {((65 76 61 6c 5f 72) | (65 00 76 00 61 00 6c 00 5f 00 72 00))}
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = {((57 53 43 52 49 50 54 2e 53 48 45 4c 4c) | (57 00 53 00 43 00 52 00 49 00 50 00 54 00 2e 00 53 00 48 00 45 00 4c 00 4c 00))}
		$asp_payload13 = {((45 78 65 63 75 74 65 47 6c 6f 62 61 6c) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 47 00 6c 00 6f 00 62 00 61 00 6c 00))}
		$asp_payload14 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_payload15 = {((45 78 65 63 75 74 65 53 74 61 74 65 6d 65 6e 74) | (45 00 78 00 65 00 63 00 75 00 74 00 65 00 53 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00))}
		$asp_multi_payload_one1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_one2 = {((61 64 64 63 6f 64 65) | (61 00 64 00 64 00 63 00 6f 00 64 00 65 00))}
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = {((43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 46 72 6f 6d 56 69 72 74 75 61 6c 50 61 74 68) | (43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 46 00 72 00 6f 00 6d 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 61 00 74 00 68 00))}
		$asp_multi_payload_two2 = {((50 72 6f 63 65 73 73 52 65 71 75 65 73 74) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00))}
		$asp_multi_payload_two3 = {((42 75 69 6c 64 4d 61 6e 61 67 65 72) | (42 00 75 00 69 00 6c 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00))}
		$asp_multi_payload_three1 = {((53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00))}
		$asp_multi_payload_three2 = {((50 72 6f 63 65 73 73) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$asp_multi_payload_three3 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_four1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}
		$asp_multi_payload_four2 = {((54 72 61 6e 73 66 6f 72 6d 4e 6f 64 65) | (54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00 4e 00 6f 00 64 00 65 00))}
		$asp_multi_payload_four3 = {((6c 6f 61 64 78 6d 6c) | (6c 00 6f 00 61 00 64 00 78 00 6d 00 6c 00))}
		$asp_multi_payload_five1 = {((50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 53 00 74 00 61 00 72 00 74 00 49 00 6e 00 66 00 6f 00))}
		$asp_multi_payload_five2 = {((2e 53 74 61 72 74) | (2e 00 53 00 74 00 61 00 72 00 74 00))}
		$asp_multi_payload_five3 = {((2e 46 69 6c 65 6e 61 6d 65) | (2e 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00))}
		$asp_multi_payload_five4 = {((2e 41 72 67 75 6d 65 6e 74 73) | (2e 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00))}
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = {((53 61 76 65 54 6f 46 69 6c 65) | (53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00))}
		$asp_write_way_one3 = {((43 52 45 41 74 45 74 45 78 74 46 69 4c 45) | (43 00 52 00 45 00 41 00 74 00 45 00 74 00 45 00 78 00 74 00 46 00 69 00 4c 00 45 00))}
		$asp_cr_write1 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00))}
		$asp_cr_write2 = {((43 72 65 61 74 65 4f 62 6a 65 63 74 20 28) | (43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 28 00))}
		$asp_streamwriter1 = {((73 74 72 65 61 6d 77 72 69 74 65 72) | (73 00 74 00 72 00 65 00 61 00 6d 00 77 00 72 00 69 00 74 00 65 00 72 00))}
		$asp_streamwriter2 = {((66 69 6c 65 73 74 72 65 61 6d) | (66 00 69 00 6c 00 65 00 73 00 74 00 72 00 65 00 61 00 6d 00))}

	condition:
		filesize < 5MB and ( $png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0 ) and ( ( ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) or ( any of ( $php_write* ) or all of ( $php_multi_write* ) ) ) ) or ( ( any of ( $cjsp* ) ) and ( 1 of ( $payload* ) or all of ( $rt_payload* ) ) ) or ( ( ( any of ( $tagasp_long* ) or any of ( $tagasp_classid* ) or ( $tagasp_short1 and $tagasp_short2 in ( filesize - 100 .. filesize ) ) or ( $tagasp_short2 and ( $tagasp_short1 in ( 0 .. 1000 ) or $tagasp_short1 in ( filesize - 1000 .. filesize ) ) ) ) and not ( ( any of ( $perl* ) or $php1 at 0 or $php2 at 0 ) or ( ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0 ) ) ) and ( ( any of ( $asp_payload* ) or all of ( $asp_multi_payload_one* ) or all of ( $asp_multi_payload_two* ) or all of ( $asp_multi_payload_three* ) or all of ( $asp_multi_payload_four* ) or all of ( $asp_multi_payload_five* ) ) or ( any of ( $asp_always_write* ) and ( any of ( $asp_write_way_one* ) and any of ( $asp_cr_write* ) ) or ( any of ( $asp_streamwriter* ) ) ) ) ) )
}

rule WEBSHELL_Mixed_OBFUSC : hardened
{
	meta:
		description = "Detects webshell with mixed obfuscation commands"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		date = "2023-01-28"
		modified = "2023-04-05"
		hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
		hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
		hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
		hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
		hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
		score = 50
		id = "dcb4054b-0c87-5cd0-9297-7fd5f2e37437"

	strings:
		$s1 = {72 61 77 75 72 6c 64 65 63 6f 64 65 2f 2a}
		$s2 = {70 72 65 67 5f 72 65 70 6c 61 63 65 2f 2a}
		$s3 = {20 5f 5f 46 49 4c 45 5f 5f 2f 2a}
		$s4 = {73 74 72 6c 65 6e 2f 2a}
		$s5 = {73 74 72 5f 72 65 70 65 61 74 2f 2a}
		$s6 = {62 61 73 65 6e 61 6d 65 2f 2a}

	condition:
		( uint16( 0 ) == 0x3f3c and filesize < 200KB and ( 4 of them ) )
}

rule WEBSHELL_Cookie_Post_Obfuscation : hardened
{
	meta:
		description = "Detects webshell using cookie POST"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2023-01-28"
		modified = "2023-04-05"
		license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
		hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
		hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
		hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
		hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
		hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
		hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
		hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
		hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
		hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"
		id = "cc5ded80-5e58-5b25-86d1-1c492042c740"

	strings:
		$s1 = {5d 28 24 5f 43 4f 4f 4b 49 45 2c 20 24 5f 50 4f 53 54 29 20 61 73 20 24}
		$s2 = {66 75 6e 63 74 69 6f 6e}
		$s3 = {41 72 72 61 79}

	condition:
		( uint16( 0 ) == 0x3f3c and filesize < 100KB and ( all of them ) )
}

