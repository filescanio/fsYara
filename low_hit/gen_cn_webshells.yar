rule Tools_cmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file cmd.jSp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"
		id = "27c3cb44-9351-52a2-8e14-afade14e3384"

	strings:
		$s0 = {69 66 28 22 31 37 35 32 33 39 33 22 2e 65 71 75 61 6c 73 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 43 6f 6e 66 70 77 64 22 29 29 29 7b}
		$s1 = {6a 61 76 61 2e 69 6f 2e 49 6e 70 75 74 53 74 72 65 61 6d 20 69 6e 20 3d 20 52 75 6e 74 69 6d 65 2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 43 6f 6e 6e 22}
		$s2 = {3c 25 40 20 70 61 67 65 20 69 6d 70 6f 72 74 3d 22 6a 61 76 61 2e 69 6f 2e 2a 22 20 25 3e}
		$s3 = {6f 75 74 2e 70 72 69 6e 74 28 22 48 69 2c 4d 61 6e 20 32 30 31 35 3c 62 72 20 2f 3e 3c 21 2d 2d 3f 43 6f 6e 66 70 77 64 3d 30 32 33 26 43 6f 6e 6e 3d 6c 73 2d 2d 3e 22 29 3b}
		$s4 = {77 68 69 6c 65 28 28 61 3d 69 6e 2e 72 65 61 64 28 62 29 29 21 3d 2d 31 29 7b}
		$s5 = {6f 75 74 2e 70 72 69 6e 74 6c 6e 28 6e 65 77 20 53 74 72 69 6e 67 28 62 29 29 3b}
		$s6 = {6f 75 74 2e 70 72 69 6e 74 28 22 3c 2f 70 72 65 3e 22 29 3b}
		$s7 = {6f 75 74 2e 70 72 69 6e 74 28 22 3c 70 72 65 3e 22 29 3b}
		$s8 = {69 6e 74 20 61 20 3d 20 2d 31 3b}
		$s9 = {62 79 74 65 5b 5d 20 62 20 3d 20 6e 65 77 20 62 79 74 65 5b 32 30 34 38 5d 3b}

	condition:
		filesize < 3KB and 7 of them
}

rule trigger_drop : hardened
{
	meta:
		description = "Chinese Hacktool Set - file trigger_drop.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
		id = "3b4f32ff-2de2-5689-869a-8a8f55e7fa0c"

	strings:
		$s0 = {24 5f 47 45 54 5b 27 72 65 74 75 72 6e 74 6f 27 5d 20 3d 20 27 64 61 74 61 62 61 73 65 5f 70 72 6f 70 65 72 74 69 65 73 2e 70 68 70 27 3b}
		$s1 = {65 63 68 6f 28 27 3c 6d 65 74 61 20 68 74 74 70 2d 65 71 75 69 76 3d 22 72 65 66 72 65 73 68 22 20 63 6f 6e 74 65 6e 74 3d 22 30 3b 75 72 6c 3d 27 20 2e 20 24 5f 47 45 54 5b 27 72 65 74 75 72 6e 74 6f 27 5d 20 2e 20 27 22 3e 27}
		$s2 = {40 6d 73 73 71 6c 5f 71 75 65 72 79 28 27 44 52 4f 50 20 54 52 49 47 47 45 52}
		$s3 = {69 66 28 65 6d 70 74 79 28 24 5f 47 45 54 5b 27 72 65 74 75 72 6e 74 6f 27 5d 29 29}

	condition:
		filesize < 5KB and all of them
}

rule InjectionParameters : hardened
{
	meta:
		description = "Chinese Hacktool Set - file InjectionParameters.vb"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
		id = "a77bd0c6-8857-577f-831a-0fcf2537667e"

	strings:
		$s0 = {50 75 62 6c 69 63 20 53 68 61 72 65 64 20 52 65 61 64 4f 6e 6c 79 20 45 6d 70 74 79 20 41 73 20 4e 65 77 20 49 6e 6a 65 63 74 69 6f 6e 50 61 72 61 6d 65 74 65 72 73 28 2d 31 2c 20 22 22 29}
		$s1 = {50 75 62 6c 69 63 20 43 6c 61 73 73 20 49 6e 6a 65 63 74 69 6f 6e 50 61 72 61 6d 65 74 65 72 73}

	condition:
		filesize < 13KB and all of them
}

rule users_list : hardened
{
	meta:
		description = "Chinese Hacktool Set - file users_list.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
		id = "2d90b593-6b65-502c-aeb0-8f2a3d65afd3"

	strings:
		$s0 = {3c 61 20 68 72 65 66 3d 22 75 73 65 72 73 5f 63 72 65 61 74 65 2e 70 68 70 22 3e 43 72 65 61 74 65 20 55 73 65 72 3c 2f 61 3e}
		$s7 = {24 73 6b 69 70 6c 69 73 74 20 3d 20 61 72 72 61 79 28 27 23 23 4d 53 5f 41 67 65 6e 74 53 69 67 6e 69 6e 67 43 65 72 74 69 66 69 63 61 74 65 23 23 27 2c 27 4e 54 20 41 55 54 48 4f 52 49 54 59 5c 4e 45 54 57 4f 52 4b 20 53 45 52 56 49 43}
		$s11 = {26 6e 62 73 70 3b 3c 62 3e 44 65 66 61 75 6c 74 20 44 42 3c 2f 62 3e 26 6e 62 73 70 3b}

	condition:
		filesize < 12KB and all of them
}

rule trigger_modify : hardened
{
	meta:
		description = "Chinese Hacktool Set - file trigger_modify.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"
		id = "a7d65a9f-82de-554c-8f20-7560d2160041"

	strings:
		$s1 = {3c 66 6f 72 6d 20 6e 61 6d 65 3d 22 66 6f 72 6d 31 22 20 6d 65 74 68 6f 64 3d 22 70 6f 73 74 22 20 61 63 74 69 6f 6e 3d 22 74 72 69 67 67 65 72 5f 6d 6f 64 69 66 79 2e 70 68 70 3f 74 72 69 67 67 65 72 3d 3c 3f 70 68 70 20 65}
		$s2 = {24 64 61 74 61 5f 71 75 65 72 79 20 3d 20 40 6d 73 73 71 6c 5f 71 75 65 72 79 28 27 73 70 5f 68 65 6c 70 74 65 78 74 20 5c 27 27 20 2e 20 75 72 6c 64 65 63 6f 64 65 28 24 5f 47 45 54 5b 27 74 72 69 67 67 65 72 27 5d 29 20 2e 20 27}
		$s3 = {69 66 28 24 5f 50 4f 53 54 5b 27 71 75 65 72 79 27 5d 20 21 3d 20 27 27 29}
		$s4 = {24 6c 69 6e 65 73 5b 5d 20 3d 20 27 49 20 61 6d 20 75 6e 61 62 6c 65 20 74 6f 20 72 65 61 64 20 74 68 69 73 20 74 72 69 67 67 65 72 2e 27 3b}
		$s5 = {3c 62 3e 4d 6f 64 69 66 79 20 54 72 69 67 67 65 72 3c 2f 62 3e}

	condition:
		filesize < 15KB and all of them
}

rule Customize : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Customize.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "db556879dff9a0101a7a26260a5d0dc471242af2"
		id = "a69e1234-cc85-5295-a45c-693afdfc368e"

	strings:
		$s1 = {64 73 2e 43 6c 65 61 72 28 29 3b 64 73 2e 44 69 73 70 6f 73 65 28 29 3b 7d 65 6c 73 65 7b 53 71 6c 43 6f 6d 6d 61 6e 64 20 63 6d 20 3d 20 43 6f 6e 6e 2e 43 72 65 61 74 65 43 6f 6d 6d 61 6e 64 28 29 3b 63 6d 2e 43 6f 6d 6d 61 6e 64 54 65 78}
		$s2 = {63 2e 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 3d 66 61 6c 73 65 3b 63 2e 52 65 64 69 72 65 63 74 53 74 61 6e 64 61 72 64 4f 75 74 70 75 74 3d 74 72 75 65 3b 63 2e 52 65 64 69 72 65 63 74 53 74 61 6e 64 61 72 64 45 72 72 6f 72 3d 74 72}
		$s3 = {53 74 72 65 61 6d 20 57 46 3d 57 42 2e 47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d 28 29 3b 46 69 6c 65 53 74 72 65 61 6d 20 46 53 3d 6e 65 77 20 46 69 6c 65 53 74 72 65 61 6d 28 5a 32 2c 46 69 6c 65 4d 6f 64 65 2e 43 72 65 61 74 65}
		$s4 = {52 3d 22 52 65 73 75 6c 74 5c 74 7c 5c 74 5c 72 5c 6e 45 78 65 63 75 74 65 20 53 75 63 63 65 73 73 66 75 6c 6c 79 21 5c 74 7c 5c 74 5c 72 5c 6e 22 3b 7d 43 6f 6e 6e 2e 43 6c 6f 73 65 28 29 3b 62 72 65 61 6b 3b}

	condition:
		filesize < 24KB and all of them
}

rule oracle_data : hardened
{
	meta:
		description = "Chinese Hacktool Set - file oracle_data.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6cf070017be117eace4752650ba6cf96d67d2106"
		id = "faa62dcc-0f59-573c-8722-d07216de151f"

	strings:
		$s0 = {24 74 78 74 3d 66 6f 70 65 6e 28 22 6f 72 61 63 6c 65 5f 69 6e 66 6f 2e 74 78 74 22 2c 22 77 22 29 3b}
		$s1 = {69 66 28 69 73 73 65 74 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 29}
		$s2 = {24 69 64 3d 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 3b}

	condition:
		all of them
}

rule reDuhServers_reDuh : hardened
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "377886490a86290de53d696864e41d6a547223b0"
		id = "c87d971a-a16f-5593-88fb-6bcd207e0841"

	strings:
		$s1 = {6f 75 74 2e 70 72 69 6e 74 6c 6e 28 22 5b 45 72 72 6f 72 5d 55 6e 61 62 6c 65 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 72 65 44 75 68 2e 6a 73 70 20 6d 61 69 6e 20 70 72 6f 63 65 73 73 20 6f 6e 20 70 6f 72 74 20 22 20 2b 73 65 72}
		$s4 = {53 79 73 74 65 6d 2e 6f 75 74 2e 70 72 69 6e 74 6c 6e 28 22 49 50 43 20 73 65 72 76 69 63 65 20 66 61 69 6c 65 64 20 74 6f 20 62 69 6e 64 20 74 6f 20 22 20 2b 20 73 65 72 76 69 63 65 50 6f 72 74 29 3b}
		$s17 = {53 79 73 74 65 6d 2e 6f 75 74 2e 70 72 69 6e 74 6c 6e 28 22 42 6f 75 6e 64 20 6f 6e 20 22 20 2b 20 73 65 72 76 69 63 65 50 6f 72 74 29 3b}
		$s5 = {6f 75 74 70 75 74 46 72 6f 6d 53 6f 63 6b 65 74 73 2e 61 64 64 28 22 5b 64 61 74 61 5d 22 2b 74 61 72 67 65 74 2b 22 3a 22 2b 70 6f 72 74 2b 22 3a 22 2b 73 6f 63 6b 4e 75 6d 2b 22 3a 22 2b 6e 65 77 20 53 74 72 69 6e}

	condition:
		filesize < 116KB and all of them
}

rule item_old : hardened
{
	meta:
		description = "Chinese Hacktool Set - file item-old.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"
		id = "c32bbd48-a363-53c7-84c6-c47581e2f9da"

	strings:
		$s1 = {24 73 43 6d 64 20 3d 20 22 77 67 65 74 20 2d 71 63 20 22 2e 65 73 63 61 70 65 73 68 65 6c 6c 61 72 67 28 24 73 55 52 4c 29 2e 22 20 2d 4f 20 22 2e 24 73 46 69 6c 65 3b}
		$s2 = {24 73 43 6d 64 20 3d 20 22 63 6f 6e 76 65 72 74 20 22 2e 24 73 46 69 6c 65 2e 22 20 2d 66 6c 69 70 20 2d 71 75 61 6c 69 74 79 20 38 30 20 22 2e 24 73 46 69 6c 65 4f 75 74 3b}
		$s3 = {24 73 48 61 73 68 20 3d 20 6d 64 35 28 24 73 55 52 4c 29 3b}

	condition:
		filesize < 7KB and 2 of them
}

rule Tools_2014 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file 2014.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "74518faf08637c53095697071db09d34dbe8d676"
		id = "bb76321b-003d-5f6b-a84b-425477abe91c"

	strings:
		$s0 = {28 28 49 6e 76 6f 6b 65 72 29 20 69 6e 73 2e 67 65 74 28 22 6c 6f 67 69 6e 22 29 29 2e 69 6e 76 6f 6b 65 28 72 65 71 75 65 73 74 2c 20 72 65 73 70 6f 6e 73 65 2c}
		$s4 = {70 72 6f 67 72 61 6d 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 3e 20 22 20 2b 20 53 48 45 4c 4c 5f 44 49 52}
		$s5 = {3a 20 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 63 6d 64 2e 65 78 65 22 29}

	condition:
		filesize < 715KB and all of them
}

rule reDuhServers_reDuh_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
		id = "6050dfde-6c79-5dd8-a772-508668177aa5"

	strings:
		$s1 = {65 72 72 6f 72 6c 6f 67 28 22 46 52 4f 4e 54 45 4e 44 3a 20 73 65 6e 64 5f 63 6f 6d 6d 61 6e 64 20 27 22 2e 24 64 61 74 61 2e 22 27 20 6f 6e 20 70 6f 72 74 20 22 2e 24 70 6f 72 74 2e 22 20 72 65 74 75 72 6e 65 64 20 22 2e}
		$s2 = {24 6d 73 67 20 3d 20 22 6e 65 77 44 61 74 61 3a 22 2e 24 73 6f 63 6b 65 74 4e 75 6d 62 65 72 2e 22 3a 22 2e 24 74 61 72 67 65 74 48 6f 73 74 2e 22 3a 22 2e 24 74 61 72 67 65 74 50 6f 72 74 2e 22 3a 22 2e 24 73 65 71}
		$s3 = {65 72 72 6f 72 6c 6f 67 28 22 42 41 43 4b 45 4e 44 3a 20 2a 2a 2a 20 53 6f 63 6b 65 74 20 6b 65 79 20 69 73 20 22 2e 24 73 6f 63 6b 6b 65 79 29 3b}

	condition:
		filesize < 57KB and all of them
}

rule Customize_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Customize.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "37cd17543e14109d3785093e150652032a85d734"
		id = "1f7e9063-33d8-5df4-89d5-7d8fc1be61f0"

	strings:
		$s1 = {77 68 69 6c 65 28 28 6c 3d 62 72 2e 72 65 61 64 4c 69 6e 65 28 29 29 21 3d 6e 75 6c 6c 29 7b 73 62 2e 61 70 70 65 6e 64 28 6c 2b 22 5c 72 5c 6e 22 29 3b 7d 7d}
		$s2 = {53 74 72 69 6e 67 20 5a 3d 45 43 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 50 77 64 29 2b 22 22 2c 63 73 29 3b 53 74 72 69 6e 67 20 7a 31 3d 45 43 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72}

	condition:
		filesize < 30KB and all of them
}

rule ChinaChopper_one : hardened
{
	meta:
		description = "Chinese Hacktool Set - file one.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6cd28163be831a58223820e7abe43d5eacb14109"
		id = "854fb5c9-38c7-5fd2-a473-66ae297070f5"

	strings:
		$s0 = {3c 25 65 76 61 6c 20 72 65 71 75 65 73 74 28}

	condition:
		filesize < 50 and all of them
}

rule CN_Tools_old : hardened
{
	meta:
		description = "Chinese Hacktool Set - file old.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
		id = "bfdb84e8-e5a8-53a4-ae71-e0d1b38d38ef"

	strings:
		$s0 = {24 73 43 6d 64 20 3d 20 22 77 67 65 74 20 2d 71 63 20 22 2e 65 73 63 61 70 65 73 68 65 6c 6c 61 72 67 28 24 73 55 52 4c 29 2e 22 20 2d 4f 20 22 2e 24 73 46 69 6c 65 3b}
		$s1 = {24 73 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 22 2e 24 73 53 65 72 76 65 72 2e 22 2f 22 2e 24 73 46 69 6c 65 3b}
		$s2 = {63 68 6d 6f 64 28 22 2f 22 2e 73 75 62 73 74 72 28 24 73 48 61 73 68 2c 20 30 2c 20 32 29 2c 20 30 37 37 37 29 3b}
		$s3 = {24 73 43 6d 64 20 3d 20 22 65 63 68 6f 20 31 32 33 3e 20 22 2e 24 73 46 69 6c 65 4f 75 74 3b}

	condition:
		filesize < 6KB and all of them
}

rule item_301 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file item-301.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
		id = "4ee9a089-313f-53c1-8196-1348d721dbf4"

	strings:
		$s1 = {24 73 55 52 4c 20 3d 20 22 33 30 31 3a 68 74 74 70 3a 2f 2f 22 2e 24 73 53 65 72 76 65 72 2e 22 2f 69 6e 64 65 78 2e 61 73 70 22 3b}
		$s2 = {28 67 6f 76 29 5c 5c 2e 28 63 6e 29 24 2f 69 22 2c 20 24 61 55 52 4c 5b 22 68 6f 73 74 22 5d 29}
		$s3 = {24 61 41 72 67 20 3d 20 65 78 70 6c 6f 64 65 28 22 20 22 2c 20 24 73 43 6f 6e 74 65 6e 74 2c 20 35 29 3b}
		$s4 = {24 73 55 52 4c 20 3d 20 24 61 41 72 67 5b 30 5d 3b}

	condition:
		filesize < 3KB and 3 of them
}

rule CN_Tools_item : hardened
{
	meta:
		description = "Chinese Hacktool Set - file item.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a584db17ad93f88e56fd14090fae388558be08e4"
		id = "954f24c9-d7d5-56d3-86f0-0cf8832640dd"

	strings:
		$s1 = {24 73 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 22 2e 24 73 53 65 72 76 65 72 2e 22 2f 22 2e 24 73 57 67 65 74 3b}
		$s2 = {24 73 55 52 4c 20 3d 20 22 33 30 31 3a 68 74 74 70 3a 2f 2f 22 2e 24 73 53 65 72 76 65 72 2e 22 2f 22 2e 24 73 57 67 65 74 3b}
		$s3 = {24 73 57 67 65 74 3d 22 69 6e 64 65 78 2e 61 73 70 22 3b}
		$s4 = {24 61 55 52 4c 20 2b 3d 20 61 72 72 61 79 28 22 73 63 68 65 6d 65 22 20 3d 3e 20 22 22 2c 20 22 68 6f 73 74 22 20 3d 3e 20 22 22 2c 20 22 70 61 74 68 22 20 3d 3e 20 22 22 29 3b}

	condition:
		filesize < 4KB and all of them
}

rule f3_diy : hardened
{
	meta:
		description = "Chinese Hacktool Set - file diy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
		id = "9f36c6dd-89e8-511b-a499-131f1e8a420a"

	strings:
		$s0 = {3c 25 40 4c 41 4e 47 55 41 47 45 3d 22 56 42 53 63 72 69 70 74 2e 45 6e 63 6f 64 65 22 20 43 4f 44 45 50 41 47 45 3d 22 39 33 36 22 25 3e}
		$s5 = {2e 62 6c 61 63 6b 20 7b}

	condition:
		uint16( 0 ) == 0x253c and filesize < 10KB and all of them
}

rule ChinaChopper_temp : hardened
{
	meta:
		description = "Chinese Hacktool Set - file temp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b0561ea52331c794977d69704345717b4eb0a2a7"
		id = "f163787f-fcc9-568a-a12d-4057cb4f0d29"

	strings:
		$s0 = {6f 2e 72 75 6e 20 22 66 66 22 2c 53 65 72 76 65 72 2c 52 65 73 70 6f 6e 73 65 2c 52 65 71 75 65 73 74 2c 41 70 70 6c 69 63 61 74 69 6f 6e 2c 53 65 73 73 69 6f 6e 2c 45 72 72 6f 72}
		$s1 = {53 65 74 20 6f 20 3d 20 53 65 72 76 65 72 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 43 6f 6e 74 72 6f 6c 22 29}
		$s2 = {6f 2e 6c 61 6e 67 75 61 67 65 20 3d 20 22 76 62 73 63 72 69 70 74 22}
		$s3 = {6f 2e 61 64 64 63 6f 64 65 28 52 65 71 75 65 73 74 28 22 53 43 22 29 29}

	condition:
		filesize < 1KB and all of them
}

rule Tools_2015 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file 2015.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
		id = "eb2826ab-ef8d-5a93-9ede-f5bbd7ab4ff4"

	strings:
		$s0 = {43 6f 6e 66 69 67 62 69 73 20 3d 20 6e 65 77 20 42 75 66 66 65 72 65 64 49 6e 70 75 74 53 74 72 65 61 6d 28 68 74 74 70 55 72 6c 2e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 28 29 29 3b}
		$s4 = {53 79 73 74 65 6d 2e 6f 75 74 2e 70 72 69 6e 74 6c 6e 28 4f 75 74 65 2e 74 6f 53 74 72 69 6e 67 28 29 29 3b}
		$s5 = {53 74 72 69 6e 67 20 43 6f 6e 66 69 67 46 69 6c 65 20 3d 20 4f 75 74 70 61 74 68 20 2b 20 22 2f 22 20 2b 20 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 43 6f 6e 46 69 6c 65 22 29 3b}
		$s8 = {48 74 74 70 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e 20 68 74 74 70 55 72 6c 20 3d 20 6e 75 6c 6c 3b}
		$s19 = {43 6f 6e 66 69 67 62 6f 73 20 3d 20 6e 65 77 20 42 75 66 66 65 72 65 64 4f 75 74 70 75 74 53 74 72 65 61 6d 28 6e 65 77 20 46 69 6c 65 4f 75 74 70 75 74 53 74 72 65 61 6d 28 4f 75 74 66 29 29 3b 3b}

	condition:
		filesize < 7KB and all of them
}

rule ChinaChopper_temp_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file temp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
		id = "3952ed2b-fb27-5c45-9cd7-b7a300b37c0e"

	strings:
		$s0 = {40 65 76 61 6c 28 24 5f 50 4f 53 54 5b 73 74 72 74 6f 75 70 70 65 72 28 6d 64 35 28 67 6d 64 61 74 65 28}

	condition:
		filesize < 150 and all of them
}

rule templatr : hardened
{
	meta:
		description = "Chinese Hacktool Set - file templatr.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
		id = "b361a49d-1e05-5597-bf8b-735e04397ffa"

	strings:
		$s0 = {65 76 61 6c 28 67 7a 69 6e 66 6c 61 74 65 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 27}

	condition:
		filesize < 70KB and all of them
}

rule reDuhServers_reDuh_3 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
		id = "69f5fd6b-a9b3-500b-8723-d1c82494903d"

	strings:
		$s1 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 22 5b 45 72 72 6f 72 5d 55 6e 61 62 6c 65 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 72 65 44 75 68 2e 6a 73 70 20 6d 61 69 6e 20 70 72 6f 63 65 73 73 20 6f 6e 20 70 6f 72 74 20 22 20 2b}
		$s2 = {68 6f 73 74 20 3d 20 53 79 73 74 65 6d 2e 4e 65 74 2e 44 6e 73 2e 52 65 73 6f 6c 76 65 28 22 31 32 37 2e 30 2e 30 2e 31 22 29 3b}
		$s3 = {72 77 2e 57 72 69 74 65 4c 69 6e 65 28 22 5b 6e 65 77 44 61 74 61 5d 22 20 2b 20 74 61 72 67 65 74 48 6f 73 74 20 2b 20 22 3a 22 20 2b 20 74 61 72 67 65 74 50 6f 72 74 20 2b 20 22 3a 22 20 2b 20 73 6f 63 6b 65 74 4e 75 6d}
		$s4 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 22 45 72 72 6f 72 3a 20 42 61 64 20 70 6f 72 74 20 6f 72 20 68 6f 73 74 20 6f 72 20 73 6f 63 6b 65 74 6e 75 6d 62 65 72 20 66 6f 72 20 63 72 65 61 74 69 6e 67 20 6e 65 77 20 73 6f 63 6b 65 74}

	condition:
		filesize < 40KB and all of them
}

rule ChinaChopper_temp_3 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file temp.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
		id = "573e7da6-f58f-5814-b3e8-a0db3ecfe558"

	strings:
		$s0 = {3c 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 4a 73 63 72 69 70 74 22 25 3e 3c 25 65 76 61 6c 28 52 65 71 75 65 73 74 2e 49 74 65 6d 5b 22}
		$s1 = {22 5d 2c 22 75 6e 73 61 66 65 22 29 3b 25 3e}

	condition:
		uint16( 0 ) == 0x253c and filesize < 150 and all of them
}

rule Shell_Asp : hardened
{
	meta:
		description = "Chinese Hacktool Set Webshells - file Asp.html"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
		id = "52089205-8f36-5a0b-a1ae-67c91a253ad2"

	strings:
		$s1 = {53 65 73 73 69 6f 6e 2e 43 6f 6e 74 65 6e 74 73 2e 52 65 6d 6f 76 65 28 6d 20 26 20 22 75 73 65 72 50 61 73 73 77 6f 72 64 22 29}
		$s2 = {70 61 73 73 57 6f 72 64 20 3d 20 45 6e 63 6f 64 65 28 47 65 74 50 6f 73 74 28 22 70 61 73 73 77 6f 72 64 22 29 29}
		$s3 = {66 75 6e 63 74 69 6f 6e 20 43 6f 6d 6d 61 6e 64 28 63 6d 64 2c 20 73 74 72 29 7b}

	condition:
		filesize < 100KB and all of them
}

rule Txt_aspxtag : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "42cb272c02dbd49856816d903833d423d3759948"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"

	strings:
		$s1 = {53 74 72 69 6e 67 20 77 47 65 74 55 72 6c 3d 52 65 71 75 65 73 74 2e 51 75 65 72 79 53 74 72 69 6e 67 5b}
		$s2 = {73 77 2e 57 72 69 74 65 28 77 67 65 74 29 3b}
		$s3 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 22 48 69 2c 4d 61 6e 20 32 30 31 35 22 29 3b 20}

	condition:
		filesize < 2KB and all of them
}

rule Txt_php : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"
		id = "65d5c46f-006d-58f9-bb7f-0a2e1f1853bd"

	strings:
		$s1 = {24 43 6f 6e 66 69 67 3d 24 5f 53 45 52 56 45 52 5b 27 51 55 45 52 59 5f 53 54 52 49 4e 47 27 5d 3b}
		$s2 = {67 7a 75 6e 63 6f 6d 70 72 65 73 73 28 24 5f 53 45 53 53 49 4f 4e 5b 27 61 70 69 27 5d 29 2c 6e 75 6c 6c 29 3b}
		$s3 = {73 70 72 69 6e 74 66 28 27 25 73 3f 25 73 27 2c 70 61 63 6b 28 22 48 2a 22 2c}
		$s4 = {69 66 28 65 6d 70 74 79 28 24 5f 53 45 53 53 49 4f 4e 5b 27 61 70 69 27 5d 29 29}

	condition:
		filesize < 1KB and all of them
}

rule Txt_aspx1 : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"

	strings:
		$s0 = {3c 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 4a 73 63 72 69 70 74 22 25 3e 3c 25 65 76 61 6c 28 52 65 71 75 65 73 74 2e 49 74 65 6d 5b}
		$s1 = {5d 2c 22 75 6e 73 61 66 65 22 29 3b 25 3e}

	condition:
		filesize < 150 and all of them
}

rule Txt_shell : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file shell.c"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"
		id = "3e4c5928-346e-541b-b1a8-b37d5e3abc98"

	strings:
		$s1 = {70 72 69 6e 74 66 28 22 43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 72 65 6d 6f 74 65 20 73 68 65 6c 6c 21 5c 6e 22 29 3b}
		$s2 = {70 72 69 6e 74 66 28 22 55 73 61 67 65 3a 20 25 73 20 3c 72 65 66 6c 65 63 74 20 69 70 3e 20 3c 70 6f 72 74 3e 5c 6e 22 2c 20 70 72 6f 67 29 3b}
		$s3 = {65 78 65 63 6c 28 73 68 65 6c 6c 2c 22 2f 62 69 6e 2f 73 68 22 2c 28 63 68 61 72 20 2a 29 30 29 3b}
		$s4 = {63 68 61 72 20 73 68 65 6c 6c 5b 5d 3d 22 2f 62 69 6e 2f 73 68 22 3b}
		$s5 = {63 6f 6e 6e 65 63 74 20 62 61 63 6b 20 64 6f 6f 72 5c 6e 5c 6e 22 29 3b}

	condition:
		filesize < 2KB and 2 of them
}

rule Txt_asp : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "a63549f749f4d9d0861825764e042e299e06a705"
		id = "39a2ba9a-c429-574f-8820-5e0270a4b84c"

	strings:
		$s1 = {53 65 72 76 65 72 2e 53 63 72 69 70 74 54 69 6d 65 6f 75 74 3d 39 39 39 39 39 39 39 39 39 3a 52 65 73 70 6f 6e 73 65 2e 42 75 66 66 65 72 3d 74 72 75 65 3a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 3a 42 6f 64 79 43 6f 6c}
		$s2 = {3c 25 40 20 4c 41 4e 47 55 41 47 45 20 3d 20 56 42 53 63 72 69 70 74 2e 45 6e 63 6f 64 65 20 25 3e 3c 25}

	condition:
		uint16( 0 ) == 0x253c and filesize < 100KB and all of them
}

rule Txt_asp1 : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file asp1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "95934d05f0884e09911ea9905c74690ace1ef653"
		id = "b00ab02c-c767-568c-be99-6cc731c3f1dc"

	strings:
		$s1 = {69 66 20 53 68 65 6c 6c 50 61 74 68 3d 22 22 20 54 68 65 6e 20 53 68 65 6c 6c 50 61 74 68 20 3d 20 22 63 6d 64 2e 65 78 65 22}
		$s2 = {61 75 74 6f 4c 6f 67 69 6e 45 6e 61 62 6c 65 3d 57 53 48 53 68 65 6c 6c 2e 52 65 67 52 65 61 64 28 61 75 74 6f 4c 6f 67 69 6e 50 61 74 68 20 26 20 61 75 74 6f 4c 6f 67 69 6e 45 6e 61 62 6c 65 4b 65 79 29}
		$s3 = {53 65 74 20 44 44 3d 43 4d 2e 65 78 65 63 28 53 68 65 6c 6c 50 61 74 68 26 22 20 2f 63 20 22 26 44 65 66 43 6d 64 29}
		$s4 = {73 7a 54 65 6d 70 46 69 6c 65 20 3d 20 73 65 72 76 65 72 2e 6d 61 70 70 61 74 68 28 22 63 6d 64 2e 74 78 74 22 29}

	condition:
		filesize < 70KB and 2 of them
}

rule Txt_php_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file php.html"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"
		id = "66916e32-9471-54bd-944e-bb751b38d3b0"

	strings:
		$s1 = {66 75 6e 63 74 69 6f 6e 20 63 6f 6e 6e 65 63 74 28 24 64 62 68 6f 73 74 2c 20 24 64 62 75 73 65 72 2c 20 24 64 62 70 61 73 73 2c 20 24 64 62 6e 61 6d 65 3d 27 27 29 20 7b}
		$s2 = {73 63 6f 6f 6b 69 65 28 27 6c 6f 67 69 6e 70 61 73 73 27 2c 20 27 27 2c 20 2d 38 36 34 30 30 20 2a 20 33 36 35 29 3b}
		$s3 = {3c 74 69 74 6c 65 3e 3c 3f 70 68 70 20 65 63 68 6f 20 24 61 63 74 2e 27 20 2d 20 27 2e 24 5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f 48 4f 53 54 27 5d 3b 3f 3e 3c 2f 74 69 74 6c 65 3e}
		$s4 = {50 6f 77 65 72 65 64 20 62 79 20 3c 61 20 74 69 74 6c 65 3d 22 42 75 69 6c 64 20 32 30 31 33 30 31 31 32 22 20 68 72 65 66 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 34 6e 67 65 6c 2e 6e 65 74 22 20 74 61 72 67 65 74 3d 22 5f 62}
		$s5 = {66 6f 72 6d 68 65 61 64 28 61 72 72 61 79 28 27 74 69 74 6c 65 27 3d 3e 27 45 78 65 63 75 74 65 20 43 6f 6d 6d 61 6e 64 27 2c 20 27 6f 6e 73 75 62 6d 69 74 27 3d 3e 27 67 28 5c 27 73 68 65 6c 6c 5c 27 2c 6e 75 6c 6c 2c 74 68 69 73 2e}
		$s6 = {73 65 63 70 61 72 61 6d 28 27 49 50 20 43 6f 6e 66 69 67 75 72 61 74 65 27 2c 65 78 65 63 75 74 65 28 27 69 70 63 6f 6e 66 69 67 20 2d 61 6c 6c 27 29 29 3b}
		$s7 = {73 65 63 70 61 72 61 6d 28 27 48 6f 73 74 73 27 2c 20 40 66 69 6c 65 5f 67 65 74 5f 63 6f 6e 74 65 6e 74 73 28 27 2f 65 74 63 2f 68 6f 73 74 73 27 29 29 3b}
		$s8 = {70 28 27 3c 70 3e 3c 61 20 68 72 65 66 3d 22 68 74 74 70 3a 2f 2f 77 27 2e 27 77 77 2e 34 27 2e 27 6e 67 27 2e 27 65 6c 2e 6e 65 74 2f 70 68 70 27 2e 27 73 70 27 2e 27 79 2f 70 6c 27 2e 27 75 67 69 6e 2f 22 20 74 61 72 67 65 74 3d}

	condition:
		filesize < 100KB and 4 of them
}

rule Txt_ftp : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file ftp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d"
		id = "311de4b0-fa19-545a-8a65-a40b255b5b39"

	strings:
		$s1 = {27 3b 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 65 63 68 6f 20 6f 70 65 6e 20}
		$s2 = {27 3b 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 66 74 70 20 2d 73 3a 27 3b}
		$s3 = {27 3b 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 65 63 68 6f 20 67 65 74 20 6c 63 78 2e 65 78 65}
		$s4 = {27 3b 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 65 63 68 6f 20 67 65 74 20 70 68 70 2e 65 78 65}
		$s5 = {27 3b 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 63 6f 70 79 20}
		$s6 = {66 74 70 20 2d 73 3a 64 3a 5c 66 74 70 2e 74 78 74 20}
		$s7 = {65 63 68 6f 20 62 79 65 3e 3e 64 3a 5c 66 74 70 2e 74 78 74 20}

	condition:
		filesize < 2KB and 2 of them
}

rule Txt_lcx : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file lcx.c"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"
		id = "4a4e8810-6dae-526e-86f0-43de45d1c87a"

	strings:
		$s1 = {70 72 69 6e 74 66 28 22 55 73 61 67 65 3a 25 73 20 2d 6d 20 6d 65 74 68 6f 64 20 5b 2d 68 31 20 68 6f 73 74 31 5d 20 2d 70 31 20 70 6f 72 74 31 20 5b 2d 68 32 20 68 6f 73 74 32 5d 20 2d 70 32 20 70 6f 72 74 32 20 5b 2d 76 5d 20 5b 2d 6c}
		$s2 = {73 70 72 69 6e 74 66 28 74 6d 70 62 75 66 32 2c 22 5c 72 5c 6e 23 23 23 23 23 23 23 23 23 23 23 20 72 65 70 6c 79 20 66 72 6f 6d 20 25 73 3a 25 64 20 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 5c 72 5c 6e}
		$s3 = {70 72 69 6e 74 66 28 22 20 33 3a 20 63 6f 6e 6e 65 63 74 20 74 6f 20 48 4f 53 54 31 3a 50 4f 52 54 31 20 61 6e 64 20 48 4f 53 54 32 3a 50 4f 52 54 32 5c 72 5c 6e 22 29 3b}
		$s4 = {70 72 69 6e 74 66 28 22 67 6f 74 2c 69 70 3a 25 73 2c 70 6f 72 74 3a 25 64 5c 72 5c 6e 22 2c 69 6e 65 74 5f 6e 74 6f 61 28 63 6c 69 65 6e 74 31 2e 73 69 6e 5f 61 64 64 72 29 2c 6e 74 6f 68 73 28 63 6c 69 65 6e 74 31 2e 73 69 6e}
		$s5 = {70 72 69 6e 74 66 28 22 5b 2d 5d 20 63 6f 6e 6e 65 63 74 20 74 6f 20 68 6f 73 74 31 20 66 61 69 6c 65 64 5c 72 5c 6e 22 29 3b}

	condition:
		filesize < 25KB and 2 of them
}

rule Txt_jspcmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "1d4e789031b15adde89a4628afc759859e53e353"
		id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"

	strings:
		$s0 = {69 66 28 22 31 37 35 32 33 39 33 22 2e 65 71 75 61 6c 73 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 43 6f 6e 66 70 77 64 22 29 29 29 7b}
		$s4 = {6f 75 74 2e 70 72 69 6e 74 28 22 48 69 2c 4d 61 6e 20 32 30 31 35 22 29 3b}

	condition:
		filesize < 1KB and 1 of them
}

rule Txt_jsp : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file jsp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "74518faf08637c53095697071db09d34dbe8d676"
		id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"

	strings:
		$s1 = {70 72 6f 67 72 61 6d 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 3e 20 22 20 2b 20 53 48 45 4c 4c 5f 44 49 52}
		$s2 = {50 72 6f 63 65 73 73 20 70 72 6f 20 3d 20 52 75 6e 74 69 6d 65 2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28 65 78 65 29 3b}
		$s3 = {3c 6f 70 74 69 6f 6e 20 76 61 6c 75 65 3d 5c 5c 22 6e 63 20 2d 65 20 63 6d 64 2e 65 78 65 20 31 39 32 2e 31 36 38 2e 32 33 30 2e 31 20 34 34 34 34 5c 5c 22 3e 6e 63 3c 2f 6f 70 74 69 6f 6e 3e 22}
		$s4 = {63 6d 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 65 74 22 3b}

	condition:
		filesize < 715KB and 2 of them
}

rule Txt_aspxlcx : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "453dd3160db17d0d762e032818a5a10baf234e03"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"

	strings:
		$s1 = {70 75 62 6c 69 63 20 73 74 72 69 6e 67 20 72 65 6d 6f 74 65 69 70 20 3d 20}
		$s2 = {3d 44 6e 73 2e 52 65 73 6f 6c 76 65 28 68 6f 73 74 29 3b}
		$s3 = {70 75 62 6c 69 63 20 73 74 72 69 6e 67 20 72 65 6d 6f 74 65 70 6f 72 74 20 3d 20}
		$s4 = {70 75 62 6c 69 63 20 63 6c 61 73 73 20 50 6f 72 74 46 6f 72 77 61 72 64}

	condition:
		uint16( 0 ) == 0x253c and filesize < 18KB and all of them
}

rule Txt_xiao : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file xiao.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"
		id = "cd375597-c343-5f7d-8574-23f700ff432b"

	strings:
		$s1 = {53 65 73 73 69 6f 6e 2e 43 6f 6e 74 65 6e 74 73 2e 52 65 6d 6f 76 65 28 6d 20 26 20 22 75 73 65 72 50 61 73 73 77 6f 72 64 22 29}
		$s2 = {70 61 73 73 57 6f 72 64 20 3d 20 45 6e 63 6f 64 65 28 47 65 74 50 6f 73 74 28 22 70 61 73 73 77 6f 72 64 22 29 29}
		$s3 = {63 6f 6e 6e 2e 45 78 65 63 75 74 65 28 22 43 72 65 61 74 65 20 54 61 62 6c 65 20 46 69 6c 65 44 61 74 61 28 49 64 20 69 6e 74 20 49 44 45 4e 54 49 54 59 28 30 2c 31 29 20 50 52 49 4d 41 52 59 20 4b 45 59 20 43 4c 55 53 54 45 52 45 44 2c}
		$s4 = {66 75 6e 63 74 69 6f 6e 20 43 6f 6d 6d 61 6e 64 28 63 6d 64 2c 20 73 74 72 29 7b}
		$s5 = {65 63 68 6f 20 22 69 66 28 6f 62 6a 2e 76 61 6c 75 65 3d 3d 27 50 61 67 65 57 65 62 50 72 6f 78 79 27 29 6f 62 6a 2e 66 6f 72 6d 2e 74 61 72 67 65 74 3d 27 5f 62 6c 61 6e 6b 27 3b 22}

	condition:
		filesize < 100KB and all of them
}

rule Txt_aspx : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"

	strings:
		$s1 = {53 51 4c 45 78 65 63 20 3a 20 3c 61 73 70 3a 44 72 6f 70 44 6f 77 6e 4c 69 73 74 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 20 49 44 3d 22 46 47 45 79 22 20 41 75 74 6f 50 6f 73 74 42 61 63 6b 3d 22 54 72 75 65 22 20 4f}
		$s2 = {50 72 6f 63 65 73 73 5b 5d 20 70 3d 50 72 6f 63 65 73 73 2e 47 65 74 50 72 6f 63 65 73 73 65 73 28 29 3b}
		$s3 = {43 6f 70 79 72 69 67 68 74 20 26 63 6f 70 79 3b 20 32 30 30 39 20 42 69 6e}
		$s4 = {3c 74 64 20 63 6f 6c 73 70 61 6e 3d 22 35 22 3e 43 6d 64 53 68 65 6c 6c 26 6e 62 73 70 3b 26 6e 62 73 70 3b 3a 26 6e 62 73 70 3b 3c 69 6e 70 75 74 20 63 6c 61 73 73 3d 22 69 6e 70 75 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76}

	condition:
		filesize < 100KB and all of them
}

rule Txt_Sql : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file Sql.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"
		id = "586f23d4-3a04-520d-b75b-f9bbcf67ceeb"

	strings:
		$s1 = {63 6d 64 3d 63 68 72 28 33 34 29 26 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 26 72 65 71 75 65 73 74 2e 66 6f 72 6d 28 22 63 6d 64 22 29 26 22 20 3e 20 38 36 31 37 2e 74 6d 70 22 26 63 68 72 28 33 34 29}
		$s2 = {73 74 72 51 75 65 72 79 3d 22 64 62 63 63 20 61 64 64 65 78 74 65 6e 64 65 64 70 72 6f 63 20 28 27 78 70 5f 72 65 67 77 72 69 74 65 27 2c 27 78 70 73 74 61 72 2e 64 6c 6c 27 29 22}
		$s3 = {73 74 72 51 75 65 72 79 20 3d 20 22 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 22 20 26 20 72 65 71 75 65 73 74 2e 66 6f 72 6d 28 22 63 6d 64 22 29 20 26 20 22 27 22 20}
		$s4 = {73 65 73 73 69 6f 6e 28 22 6c 6f 67 69 6e 22 29 3d 22 22}

	condition:
		filesize < 15KB and all of them
}

rule Txt_hello : hardened
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file hello.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"
		id = "42d01411-e333-543d-84a2-758c13bad2df"

	strings:
		$s0 = {44 69 6d 20 6d 79 50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f 20 41 73 20 4e 65 77 20 50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f 28 22 63 6d 64 2e 65 78 65 22 29}
		$s1 = {6d 79 50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f 2e 41 72 67 75 6d 65 6e 74 73 3d 22 2f 63 20 22 20 26 20 43 6d 64 2e 74 65 78 74}
		$s2 = {6d 79 50 72 6f 63 65 73 73 2e 53 74 61 72 74 28 29}
		$s3 = {3c 70 20 61 6c 69 67 6e 3d 22 63 65 6e 74 65 72 22 3e 3c 61 20 68 72 65 66 3d 22 3f 61 63 74 69 6f 6e 3d 63 6d 64 22 20 74 61 72 67 65 74 3d 22 5f 62 6c 61 6e 6b 22 3e}

	condition:
		filesize < 25KB and all of them
}

