rule asp_file : hardened
{
	meta:
		description = "Laudanum Injector Tools - file file.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"
		id = "e2a80d1f-f2bb-573b-b68c-71e4dfa6e1fa"

	strings:
		$s1 = {27 20 2a 2a 2a 20 57 72 69 74 74 65 6e 20 62 79 20 54 69 6d 20 4d 65 64 69 6e 20 3c 74 69 6d 40 63 6f 75 6e 74 65 72 68 61 63 6b 2e 63 6f 6d 3e}
		$s2 = {52 65 73 70 6f 6e 73 65 2e 42 69 6e 61 72 79 57 72 69 74 65 28 73 74 72 65 61 6d 2e 52 65 61 64 29}
		$s3 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 52 65 73 70 6f 6e 73 65 2e 53 74 61 74 75 73 20 26 20 52 65 71 75 65 73 74 2e 53 65 72 76 65 72 56 61 72 69 61 62 6c 65 73 28 22 52 45 4d 4f 54 45 5f 41 44 44 52 22 29 29}
		$s4 = {25 3e 3c 61 20 68 72 65 66 3d 22 3c 25 3d 52 65 71 75 65 73 74 2e 53 65 72 76 65 72 56 61 72 69 61 62 6c 65 73 28 22 55 52 4c 22 29 25 3e 22 3e 77 65 62 20 72 6f 6f 74 3c 2f 61 3e 3c 62 72 2f 3e 3c 25}
		$s5 = {73 65 74 20 66 6f 6c 64 65 72 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 70 61 74 68 29}
		$s6 = {53 65 74 20 66 69 6c 65 20 3d 20 66 73 6f 2e 47 65 74 46 69 6c 65 28 66 69 6c 65 70 61 74 68 29}

	condition:
		uint16( 0 ) == 0x253c and filesize < 30KB and 5 of them
}

rule php_killnc : hardened
{
	meta:
		description = "Laudanum Injector Tools - file killnc.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		id = "241611d3-3636-5a25-b3c3-d45d6cb81c78"

	strings:
		$s1 = {69 66 20 28 24 5f 53 45 52 56 45 52 5b 22 52 45 4d 4f 54 45 5f 41 44 44 52 22 5d 20 3d 3d 20 24 49 50 29}
		$s2 = {68 65 61 64 65 72 28 22 48 54 54 50 2f 31 2e 30 20 34 30 34 20 4e 6f 74 20 46 6f 75 6e 64 22 29 3b}
		$s3 = {3c 3f 70 68 70 20 65 63 68 6f 20 65 78 65 63 28 27 6b 69 6c 6c 61 6c 6c 20 6e 63 27 29 3b 3f 3e}
		$s4 = {3c 74 69 74 6c 65 3e 4c 61 75 64 61 6e 75 6d 20 4b 69 6c 6c 20 6e 63 3c 2f 74 69 74 6c 65 3e}
		$s5 = {66 6f 72 65 61 63 68 20 28 24 61 6c 6c 6f 77 65 64 49 50 73 20 61 73 20 24 49 50 29 20 7b}

	condition:
		filesize < 15KB and 4 of them
}

rule asp_shell : hardened
{
	meta:
		description = "Laudanum Injector Tools - file shell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
		id = "3ae27254-325a-5358-b5aa-ab24b43ad5a6"

	strings:
		$s1 = {3c 66 6f 72 6d 20 61 63 74 69 6f 6e 3d 22 73 68 65 6c 6c 2e 61 73 70 22 20 6d 65 74 68 6f 64 3d 22 50 4f 53 54 22 20 6e 61 6d 65 3d 22 73 68 65 6c 6c 22 3e}
		$s2 = {25 43 6f 6d 53 70 65 63 25 20 2f 63 20 64 69 72}
		$s3 = {53 65 74 20 6f 62 6a 43 6d 64 20 3d 20 77 53 68 65 6c 6c 2e 45 78 65 63 28 63 6d 64 29}
		$s4 = {53 65 72 76 65 72 2e 53 63 72 69 70 74 54 69 6d 65 6f 75 74 20 3d 20 31 38 30}
		$s5 = {63 6d 64 20 3d 20 52 65 71 75 65 73 74 2e 46 6f 72 6d 28 22 63 6d 64 22 29}
		$s6 = {27 20 2a 2a 2a 20 20 68 74 74 70 3a 2f 2f 6c 61 75 64 61 6e 75 6d 2e 73 65 63 75 72 65 69 64 65 61 73 2e 6e 65 74}
		$s7 = {44 69 6d 20 77 73 68 65 6c 6c 2c 20 69 6e 74 52 65 74 75 72 6e 2c 20 73 74 72 50 52 65 73 75 6c 74}

	condition:
		filesize < 15KB and 4 of them
}

rule settings : hardened
{
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		id = "054b8723-fdfa-51dc-91ae-b915e40b2e54"

	strings:
		$s1 = {50 6f 72 74 3a 20 3c 69 6e 70 75 74 20 6e 61 6d 65 3d 22 70 6f 72 74 22 20 74 79 70 65 3d 22 74 65 78 74 22 20 76 61 6c 75 65 3d 22 38 38 38 38 22 3e}
		$s2 = {3c 6c 69 3e 52 65 76 65 72 73 65 20 53 68 65 6c 6c 20 2d 20}
		$s3 = {3c 6c 69 3e 3c 61 20 68 72 65 66 3d 22 3c 3f 70 68 70 20 65 63 68 6f 20 70 6c 75 67 69 6e 73 5f 75 72 6c 28 27 66 69 6c 65 2e 70 68 70 27 2c 20 5f 5f 46 49 4c 45 5f 5f 29 3b 3f 3e 22 3e 46 69 6c 65 20 42 72 6f 77 73 65 72 3c 2f 61 3e}

	condition:
		filesize < 13KB and all of them
}

rule asp_proxy : hardened
{
	meta:
		description = "Laudanum Injector Tools - file proxy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
		id = "6193b48a-b3da-5c1e-84e8-0035d9e7ade6"

	strings:
		$s1 = {27 72 65 73 70 6f 6e 73 65 2e 77 72 69 74 65 20 22 3c 62 72 2f 3e 20 20 2d 76 61 6c 75 65 3a 22 20 26 20 72 65 71 75 65 73 74 2e 71 75 65 72 79 73 74 72 69 6e 67 28 6b 65 79 29 28 6a 29}
		$s2 = {71 20 3d 20 71 20 26 20 22 26 22 20 26 20 6b 65 79 20 26 20 22 3d 22 20 26 20 72 65 71 75 65 73 74 2e 71 75 65 72 79 73 74 72 69 6e 67 28 6b 65 79 29 28 6a 29}
		$s3 = {66 6f 72 20 65 61 63 68 20 69 20 69 6e 20 53 70 6c 69 74 28 68 74 74 70 2e 67 65 74 41 6c 6c 52 65 73 70 6f 6e 73 65 48 65 61 64 65 72 73 2c 20 76 62 4c 66 29}
		$s4 = {27 75 72 6c 71 75 65 72 79 20 3d 20 6d 69 64 28 75 72 6c 74 65 6d 70 2c 20 69 6e 73 74 72 28 75 72 6c 74 65 6d 70 2c 20 22 3f 22 29 20 2b 20 31 29}
		$s5 = {73 20 3d 20 75 72 6c 73 63 68 65 6d 65 20 26 20 75 72 6c 68 6f 73 74 20 26 20 75 72 6c 70 6f 72 74 20 26 20 75 72 6c 70 61 74 68}
		$s6 = {53 65 74 20 68 74 74 70 20 3d 20 53 65 72 76 65 72 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29}

	condition:
		filesize < 50KB and all of them
}

rule cfm_shell : hardened
{
	meta:
		description = "Laudanum Injector Tools - file shell.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "885e1783b07c73e7d47d3283be303c9719419b92"
		id = "5308eecf-a59f-5100-ab60-5034c5b73e7e"

	strings:
		$s1 = {45 78 65 63 75 74 61 62 6c 65 3a 20 3c 49 6e 70 75 74 20 74 79 70 65 3d 22 74 65 78 74 22 20 6e 61 6d 65 3d 22 63 6d 64 22 20 76 61 6c 75 65 3d 22 63 6d 64 2e 65 78 65 22 3e 3c 62 72 3e}
		$s2 = {3c 63 66 69 66 20 28 20 23 73 75 70 70 6c 69 65 64 43 6f 64 65 23 20 6e 65 71 20 73 65 63 72 65 74 43 6f 64 65 20 29 3e}
		$s3 = {3c 63 66 69 66 20 49 73 44 65 66 69 6e 65 64 28 22 66 6f 72 6d 2e 63 6d 64 22 29 3e}

	condition:
		filesize < 20KB and 2 of them
}

rule aspx_shell : hardened
{
	meta:
		description = "Laudanum Injector Tools - file shell.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		id = "d4287007-79af-59fa-b8c8-3ac08d75b3bd"

	strings:
		$s1 = {72 65 6d 6f 74 65 49 70 20 3d 20 48 74 74 70 43 6f 6e 74 65 78 74 2e 43 75 72 72 65 6e 74 2e 52 65 71 75 65 73 74 2e 48 65 61 64 65 72 73 5b 22 58 2d 46 6f 72 77 61 72 64 65 64 2d 46 6f 72 22 5d 2e 53 70 6c 69 74 28 6e 65 77}
		$s2 = {72 65 6d 6f 74 65 49 70 20 3d 20 52 65 71 75 65 73 74 2e 55 73 65 72 48 6f 73 74 41 64 64 72 65 73 73 3b}
		$s3 = {3c 66 6f 72 6d 20 6d 65 74 68 6f 64 3d 22 70 6f 73 74 22 20 6e 61 6d 65 3d 22 73 68 65 6c 6c 22 3e}
		$s4 = {3c 62 6f 64 79 20 6f 6e 6c 6f 61 64 3d 22 64 6f 63 75 6d 65 6e 74 2e 73 68 65 6c 6c 2e 63 2e 66 6f 63 75 73 28 29 22 3e}

	condition:
		filesize < 20KB and all of them
}

rule php_shell : hardened
{
	meta:
		description = "Laudanum Injector Tools - file shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		id = "8d3dcb16-090b-5a9f-b3d2-3822ec467f69"

	strings:
		$s1 = {63 6f 6d 6d 61 6e 64 5f 68 69 73 74 5b 63 75 72 72 65 6e 74 5f 6c 69 6e 65 5d 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 73 68 65 6c 6c 2e 63 6f 6d 6d 61 6e 64 2e 76 61 6c 75 65 3b}
		$s2 = {69 66 20 28 65 2e 6b 65 79 43 6f 64 65 20 3d 3d 20 33 38 20 26 26 20 63 75 72 72 65 6e 74 5f 6c 69 6e 65 20 3c 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 2e 6c 65 6e 67 74 68 2d 31 29 20 7b}
		$s3 = {61 72 72 61 79 5f 75 6e 73 68 69 66 74 28 24 5f 53 45 53 53 49 4f 4e 5b 27 68 69 73 74 6f 72 79 27 5d 2c 20 24 63 6f 6d 6d 61 6e 64 29 3b}
		$s4 = {69 66 20 28 70 72 65 67 5f 6d 61 74 63 68 28 27 2f 5e 5b 5b 3a 62 6c 61 6e 6b 3a 5d 5d 2a 63 64 5b 5b 3a 62 6c 61 6e 6b 3a 5d 5d 2a 24 2f 27 2c 20 24 63 6f 6d 6d 61 6e 64 29 29 20 7b}

	condition:
		filesize < 40KB and all of them
}

rule php_reverse_shell : hardened
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
		id = "306d150f-95a8-57fd-8f5e-786c429af6b3"

	strings:
		$s1 = {24 70 72 6f 63 65 73 73 20 3d 20 70 72 6f 63 5f 6f 70 65 6e 28 24 73 68 65 6c 6c 2c 20 24 64 65 73 63 72 69 70 74 6f 72 73 70 65 63 2c 20 24 70 69 70 65 73 29 3b}
		$s2 = {70 72 69 6e 74 69 74 28 22 53 75 63 63 65 73 73 66 75 6c 6c 79 20 6f 70 65 6e 65 64 20 72 65 76 65 72 73 65 20 73 68 65 6c 6c 20 74 6f 20 24 69 70 3a 24 70 6f 72 74 22 29 3b}
		$s3 = {24 69 6e 70 75 74 20 3d 20 66 72 65 61 64 28 24 70 69 70 65 73 5b 31 5d 2c 20 24 63 68 75 6e 6b 5f 73 69 7a 65 29 3b}

	condition:
		filesize < 15KB and all of them
}

rule php_dns : hardened
{
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		id = "a52e453b-07aa-58b9-91e7-f2426a8e8976"

	strings:
		$s1 = {24 71 75 65 72 79 20 3d 20 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 27 71 75 65 72 79 27 5d 29 20 3f 20 24 5f 50 4f 53 54 5b 27 71 75 65 72 79 27 5d 20 3a 20 27 27 3b}
		$s2 = {24 72 65 73 75 6c 74 20 3d 20 64 6e 73 5f 67 65 74 5f 72 65 63 6f 72 64 28 24 71 75 65 72 79 2c 20 24 74 79 70 65 73 5b 24 74 79 70 65 5d 2c 20 24 61 75 74 68 6e 73 2c 20 24 61 64 64 74 6c 29 3b}
		$s3 = {69 66 20 28 24 5f 53 45 52 56 45 52 5b 22 52 45 4d 4f 54 45 5f 41 44 44 52 22 5d 20 3d 3d 20 24 49 50 29}
		$s4 = {66 6f 72 65 61 63 68 20 28 61 72 72 61 79 5f 6b 65 79 73 28 24 74 79 70 65 73 29 20 61 73 20 24 74 29 20 7b}

	condition:
		filesize < 15KB and all of them
}

rule WEB_INF_web : hardened
{
	meta:
		description = "Laudanum Injector Tools - file web.xml"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
		id = "8d0a008c-56d1-59ef-8521-0697add21ba9"

	strings:
		$s1 = {3c 73 65 72 76 6c 65 74 2d 6e 61 6d 65 3e 43 6f 6d 6d 61 6e 64 3c 2f 73 65 72 76 6c 65 74 2d 6e 61 6d 65 3e}
		$s2 = {3c 6a 73 70 2d 66 69 6c 65 3e 2f 63 6d 64 2e 6a 73 70 3c 2f 6a 73 70 2d 66 69 6c 65 3e}

	condition:
		filesize < 1KB and all of them
}

rule jsp_cmd : hardened
{
	meta:
		description = "Laudanum Injector Tools - file cmd.war"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
		id = "74db62b8-82d5-5a34-aa72-2f85053715a4"

	strings:
		$s0 = {63 6d 64 2e 6a 73 70 7d}
		$s1 = {63 6d 64 2e 6a 73 70 50 4b}
		$s2 = {57 45 42 2d 49 4e 46 2f 77 65 62 2e 78 6d 6c}
		$s3 = {57 45 42 2d 49 4e 46 2f 77 65 62 2e 78 6d 6c 50 4b}
		$s4 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46}

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 2KB and all of them
}

rule laudanum : hardened
{
	meta:
		description = "Laudanum Injector Tools - file laudanum.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		id = "8c836aba-3644-5914-a3ff-937d0a6cd378"

	strings:
		$s1 = {70 75 62 6c 69 63 20 66 75 6e 63 74 69 6f 6e 20 5f 5f 61 63 74 69 76 61 74 65 28 29}
		$s2 = {72 65 67 69 73 74 65 72 5f 61 63 74 69 76 61 74 69 6f 6e 5f 68 6f 6f 6b 28 5f 5f 46 49 4c 45 5f 5f 2c 20 61 72 72 61 79 28 27 57 50 5f 4c 61 75 64 61 6e 75 6d 27 2c 20 27 61 63 74 69 76 61 74 65 27 29 29 3b}

	condition:
		filesize < 5KB and all of them
}

rule php_file : hardened
{
	meta:
		description = "Laudanum Injector Tools - file file.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		id = "68456891-6828-5e42-b8a0-67ecaf83cdc0"

	strings:
		$s1 = {24 61 6c 6c 6f 77 65 64 49 50 73 20 3d}
		$s2 = {3c 61 20 68 72 65 66 3d 22 3c 3f 70 68 70 20 65 63 68 6f 20 24 5f 53 45 52 56 45 52 5b 27 50 48 50 5f 53 45 4c 46 27 5d 20 20 3f 3e 22 3e 48 6f 6d 65 3c 2f 61 3e 3c 62 72 2f 3e}
		$s3 = {24 64 69 72 20 20 3d 20 69 73 73 65 74 28 24 5f 47 45 54 5b 22 64 69 72 22 5d 29 20 20 3f 20 24 5f 47 45 54 5b 22 64 69 72 22 5d 20 20 3a 20 22 2e 22 3b}
		$s4 = {24 63 75 72 64 69 72 20 2e 3d 20 73 75 62 73 74 72 28 24 63 75 72 64 69 72 2c 20 2d 31 29 20 21 3d 20 22 2f 22 20 3f 20 22 2f 22 20 3a 20 22 22 3b}

	condition:
		filesize < 10KB and all of them
}

rule warfiles_cmd : hardened
{
	meta:
		description = "Laudanum Injector Tools - file cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"
		id = "f974255b-cfbe-57b0-af1f-eddb7f12f5ed"

	strings:
		$s1 = {50 72 6f 63 65 73 73 20 70 20 3d 20 52 75 6e 74 69 6d 65 2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 63 6d 64 22 29 29 3b}
		$s2 = {6f 75 74 2e 70 72 69 6e 74 6c 6e 28 22 43 6f 6d 6d 61 6e 64 3a 20 22 20 2b 20 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 63 6d 64 22 29 20 2b 20 22 3c 42 52 3e 22 29 3b}
		$s3 = {3c 46 4f 52 4d 20 4d 45 54 48 4f 44 3d 22 47 45 54 22 20 4e 41 4d 45 3d 22 6d 79 66 6f 72 6d 22 20 41 43 54 49 4f 4e 3d 22 22 3e}
		$s4 = {53 74 72 69 6e 67 20 64 69 73 72 20 3d 20 64 69 73 2e 72 65 61 64 4c 69 6e 65 28 29 3b}

	condition:
		filesize < 2KB and all of them
}

rule asp_dns : hardened
{
	meta:
		description = "Laudanum Injector Tools - file dns.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
		id = "b0e30ca0-7163-5731-98c5-5a1893b8ea80"

	strings:
		$s1 = {63 6f 6d 6d 61 6e 64 20 3d 20 22 6e 73 6c 6f 6f 6b 75 70 20 2d 74 79 70 65 3d 22 20 26 20 71 74 79 70 65 20 26 20 22 20 22 20 26 20 71 75 65 72 79 20}
		$s2 = {53 65 74 20 6f 62 6a 43 6d 64 20 3d 20 6f 62 6a 57 53 68 65 6c 6c 2e 45 78 65 63 28 63 6f 6d 6d 61 6e 64 29}
		$s3 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 20 63 6f 6d 6d 61 6e 64 20 26 20 22 3c 62 72 3e 22}
		$s4 = {3c 66 6f 72 6d 20 6e 61 6d 65 3d 22 64 6e 73 22 20 6d 65 74 68 6f 64 3d 22 50 4f 53 54 22 3e}

	condition:
		filesize < 21KB and all of them
}

rule php_reverse_shell_2 : hardened
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
		id = "f10cc33e-0cb6-5d08-af1f-5ef76368de9d"

	strings:
		$s1 = {24 70 72 6f 63 65 73 73 20 3d 20 70 72 6f 63 5f 6f 70 65 6e 28 24 73 68 65 6c 6c 2c 20 24 64 65 73 63 72 69 70 74 6f 72 73 70 65 63 2c 20 24 70 69 70 65 73 29 3b}
		$s7 = {24 73 68 65 6c 6c 20 3d 20 27 75 6e 61 6d 65 20 2d 61 3b 20 77 3b 20 69 64 3b 20 2f 62 69 6e 2f 73 68 20 2d 69 27 3b}

	condition:
		filesize < 10KB and all of them
}

rule Laudanum_Tools_Generic : hardened
{
	meta:
		description = "Laudanum Injector Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		super_rule = 1
		hash0 = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
		hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		hash4 = "f49291aef9165ee4904d2d8c3cf5a6515ca0794f"
		hash5 = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		hash6 = "f32b9c2cc3a61fa326e9caebce28ef94a7a00c9a"
		hash7 = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		hash8 = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		hash9 = "b50ae35fcf767466f6ca25984cc008b7629676b8"
		hash10 = "5570d10244d90ef53b74e2ac287fc657e38200f0"
		hash11 = "42bcb491a11b4703c125daf1747cf2a40a1b36f3"
		hash12 = "83e4eaaa2cf6898d7f83ab80158b64b1d48096f4"
		hash13 = "dec7ea322898690a7f91db9377f035ad7072b8d7"
		hash14 = "a2272b8a4221c6cc373915f0cc555fe55d65ac4d"
		hash15 = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		hash16 = "43320dc23fb2ed26b882512e7c0bfdc64e2c1849"
		id = "15738788-5f34-54d0-92fe-f7024c998a54"

	strings:
		$s1 = {2a 2a 2a 20 20 6c 61 75 64 61 6e 75 6d 40 73 65 63 75 72 65 69 64 65 61 73 2e 6e 65 74}
		$s2 = {2a 2a 2a 20 4c 61 75 64 61 6e 75 6d 20 50 72 6f 6a 65 63 74}

	condition:
		filesize < 60KB and all of them
}

