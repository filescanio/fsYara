rule WiltedTulip_Tools_back : hardened
{
	meta:
		description = "Detects Chrome password dumper used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		modified = "2022-12-21"
		hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"
		id = "3f57bd66-b269-5f59-ade1-f881b1d7dadd"

	strings:
		$x1 = {25 73 2e 65 78 65 20 2d 66 20 22 43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 54 65 73 74 50 72 6f 66 69 6c 65 22 20 2d 6f 20 22 63 3a 5c 70 61 73 73 6c 69 73 74 2e 74 78 74 22}
		$x2 = {5c 43 68 72 6f 6d 65 50 61 73 73 77 6f 72 64 44 75 6d 70 5c 52 65 6c 65 61 73 65 5c 46 69 72 65 4d 61 73 74 65 72 2e 70 64 62}
		$x3 = {2f 2f 44 75 6d 70 20 43 68 72 6f 6d 65 20 50 61 73 73 77 6f 72 64 73 20 74 6f 20 61 20 4f 75 74 70 75 74 20 66 69 6c 65 20 22 63 3a 5c 70 61 73 73 6c 69 73 74 2e 74 78 74 22}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule WiltedTulip_Tools_clrlg : hardened
{
	meta:
		description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"
		id = "6957c97d-2c2d-50ac-8fd5-2f299fc7b5c8"

	strings:
		$s1 = {28 27 77 65 76 74 75 74 69 6c 2e 65 78 65 20 65 6c 27 29 20 44 4f 20 28 63 61 6c 6c 20 3a 64 6f 5f 63 6c 65 61 72}
		$s2 = {77 65 76 74 75 74 69 6c 2e 65 78 65 20 63 6c 20 25 31}

	condition:
		filesize < 1KB and 1 of them
}

rule WiltedTulip_powershell : hardened
{
	meta:
		description = "Detects powershell script used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "e5ee1f45cbfdb54b02180e158c3c1f080d89bce6a7d1fe99dd0ff09d47a36787"
		id = "b6246508-a6ff-5a02-a0de-9cde139f0acc"
		score = 80

	strings:
		$x1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 63 20 69 66 28 5b 49 6e 74 50 74 72 5d 3a 3a 53 69 7a 65 20 2d 65 71 20 34 29 7b 24 62 3d 27 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 27 7d 65 6c 73 65 7b 24 62 3d 24 65 6e 76 3a 77 69 6e 64 69 72 2b}

	condition:
		1 of them
}

rule WiltedTulip_vminst : hardened
{
	meta:
		description = "Detects malware used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "930118fdf1e6fbffff579e65e1810c8d91d4067cbbce798c5401cf05d7b4c911"
		id = "5d21e515-eb7b-56ab-acc2-f09065769b2d"

	strings:
		$x1 = {5c 43 2b 2b 5c 54 72 6f 6a 61 6e 5c 54 61 72 67 65 74 5c}
		$s1 = {25 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$s2 = {24 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 6c 00 2e 00 74 00 6d 00 70 00}
		$s3 = {25 00 73 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}
		$s4 = {61 72 67 73 5b 31 30 5d 20 69 73 20 25 53 20 61 6e 64 20 63 6f 6d 6d 61 6e 64 20 69 73 20 25 53}
		$s5 = {4c 4f 47 4f 4e 20 55 53 45 52 20 46 41 49 4c 44 20}
		$s6 = {76 00 6d 00 69 00 6e 00 73 00 74 00 2e 00 74 00 6d 00 70 00}
		$s7 = {6f 70 65 72 61 74 6f 72 20 63 6f 5f 61 77 61 69 74}
		$s8 = {3f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 40 59 47 4b 50 41 58 40 5a}
		$s9 = {25 00 73 00 20 00 2d 00 6b 00 20 00 25 00 73 00}
		$s10 = {45 52 52 4f 52 20 69 6e 20 25 53 2f 25 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and ( 1 of ( $x* ) or 5 of ( $s* ) )
}

rule WiltedTulip_Windows_UM_Task : hardened
{
	meta:
		description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"
		id = "d827584e-8298-56e4-8466-90950d1f286e"
		score = 75

	strings:
		$r1 = {3c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 77 00 6f 00 77 00 36 00 34 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 3c 00 2f 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00}
		$p1 = {3c 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 3e 00 22 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00}
		$c1 = {((73 76 63 68 6f 73 74 36 34 2e 73 77 70 22 2c 63 68 65 63 6b 55 70 64 61 74 65) | (73 00 76 00 63 00 68 00 6f 00 73 00 74 00 36 00 34 00 2e 00 73 00 77 00 70 00 22 00 2c 00 63 00 68 00 65 00 63 00 6b 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$c2 = {((73 76 63 68 6f 73 74 36 34 2e 73 77 70 2c 63 68 65 63 6b 55 70 64 61 74 65) | (73 00 76 00 63 00 68 00 6f 00 73 00 74 00 36 00 34 00 2e 00 73 00 77 00 70 00 2c 00 63 00 68 00 65 00 63 00 6b 00 55 00 70 00 64 00 61 00 74 00 65 00))}

	condition:
		($r1 and $p1 ) or 1 of ( $c* )
}

rule WiltedTulip_WindowsTask : refined hardened
{
	meta:
		description = "Detects hack tool used in Operation Wilted Tulip - Windows Tasks"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		score = 60
		hash1 = "c3cbe88b82cd0ea46868fb4f2e8ed226f3419fc6d4d6b5f7561e70f4cd33822c"
		hash2 = "340cbbffbb7685133fc318fa20e4620ddf15e56c0e65d4cf1b2d606790d4425d"
		hash3 = "b6f515b3f713b70b808fc6578232901ffdeadeb419c9c4219fbfba417bba9f01"
		hash4 = "5046e7c28f5f2781ed7a63b0871f4a2b3065b70d62de7254491339e8fe2fa14a"
		hash5 = "984c7e1f76c21daf214b3f7e131ceb60c14abf1b0f4066eae563e9c184372a34"
		id = "ad8193f0-e664-50a8-ab05-38027a2e33cd"

	strings:
		$x1 = {3c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 3c 00 2f 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00}
		$x2 = {3c 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 3e 00 2d 00 6e 00 6f 00 70 00 20 00 2d 00 77 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 2d 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}

	condition:
		1 of them
}

rule WiltedTulip_tdtess : hardened
{
	meta:
		description = "Detects malicious service used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"
		id = "0ecb391b-a4f9-5362-bb65-73801ae497de"

	strings:
		$x1 = {64 00 32 00 6c 00 75 00 62 00 47 00 39 00 6e 00 61 00 57 00 34 00 6b 00}
		$x2 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 45 78 70 6f 72 74 5c 54 44 54 45 53 53 5f 53 68 6f 72 74 4f 6e 65 5c 57 69 6e 53 65 72 76 69 63 65 20 54 65 6d 70 6c 61 74 65 5c}
		$s1 = {5c 57 69 6e 53 65 72 76 69 63 65 20 54 65 6d 70 6c 61 74 65 5c 6f 62 6a 5c 78 36 34 5c 78 36 34 5c 77 69 6e 6c 6f 67 69 6e}
		$s2 = {77 00 69 00 6e 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 65 00 78 00 65 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or 2 of them ) )
}

rule WiltedTulip_SilverlightMSI : hardened
{
	meta:
		description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"
		id = "6430d464-b9c7-5f19-b89d-3c70f99af688"

	strings:
		$x1 = {2e 5c 47 65 74 5f 41 44 5f 55 73 65 72 73 5f 4c 6f 67 6f 6e 5f 48 69 73 74 6f 72 79 2e 70 73 31 20 2d 4d 61 78 45 76 65 6e 74}
		$x2 = {69 66 20 28 28 52 65 73 6f 6c 76 65 2d 64 6e 73 6e 61 6d 65 20 24 5f 2e 22 49 50 20 41 64 64 72 65 73 73 22 20 2d 54 79 70 65 20 50 54 52 20 2d 54 63 70 4f 6e 6c 79 20 2d 44 6e 73 4f 6e 6c 79 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 22 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 22 29 2e 54 79 70 65 20 2d 65 71 20 22 50 54 52 22 29}
		$x3 = {24 43 6c 69 65 6e 74 5f 4e 61 6d 65 20 3d 20 28 52 65 73 6f 6c 76 65 2d 64 6e 73 6e 61 6d 65 20 24 5f 2e 22 49 50 20 41 64 64 72 65 73 73 22 20 2d 54 79 70 65 20 50 54 52 20 2d 54 63 70 4f 6e 6c 79 20 2d 44 6e 73 4f 6e 6c 79 29 2e 4e 61 6d 65 48 6f 73 74 20 20}
		$x4 = {23 23 23 23 23 23 23 23 23 23 20 46 69 6e 64 20 74 68 65 20 43 6f 6d 70 75 74 65 72 20 61 63 63 6f 75 6e 74 20 69 6e 20 41 44 20 61 6e 64 20 69 66 20 6e 6f 74 20 66 6f 75 6e 64 2c 20 74 68 72 6f 77 20 61 6e 20 65 78 63 65 70 74 69 6f 6e 20 23 23 23 23 23 23 23 23 23 23 23}

	condition:
		( filesize < 20KB and 1 of them )
}

import "pe"

rule WiltedTulip_matryoshka_Injector : hardened
{
	meta:
		description = "Detects hack tool used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "c41e97b3b22a3f0264f10af2e71e3db44e53c6633d0d690ac4d2f8f5005708ed"
		hash2 = "b93b5d6716a4f8eee450d9f374d0294d1800784bc99c6934246570e4baffe509"
		id = "e4cf2a31-33c8-5db1-84ca-f63b65a0a0a3"

	strings:
		$s1 = {49 6e 6a 65 63 74 6f 72 2e 64 6c 6c}
		$s2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them ) or ( pe.exports ( "__dec" ) and pe.exports ( "_check" ) and pe.exports ( "_dec" ) and pe.exports ( "start" ) and pe.exports ( "test" ) )
}

rule WiltedTulip_Zpp : hardened
{
	meta:
		description = "Detects hack tool used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		modified = "2022-12-21"
		hash1 = "10ec585dc1304436821a11e35473c0710e844ba18727b302c6bd7f8ebac574bb"
		hash2 = "7d046a3ed15035ea197235980a72d133863c372cc27545af652e1b2389c23918"
		hash3 = "6d6816e0b9c24e904bc7c5fea5951d53465c478cc159ab900d975baf8a0921cf"
		id = "7d833cb2-485e-5a26-be2f-aaebde7fdef2"

	strings:
		$x1 = {5b 00 45 00 52 00 52 00 4f 00 52 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 4d 00 61 00 69 00 6e 00 20 00 2d 00 69 00 20 00 2d 00 73 00 20 00 2d 00 64 00 20 00 2d 00 67 00 74 00 20 00 2d 00 6c 00 74 00 20 00 2d 00 6d 00 62 00}
		$x2 = {5b 00 45 00 52 00 52 00 4f 00 52 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 4d 00 61 00 69 00 6e 00 20 00 2d 00 69 00 28 00 77 00 69 00 74 00 68 00 2e 00 29 00 20 00 2d 00 73 00 20 00 2d 00 64 00 20 00 2d 00 67 00 74 00 20 00 2d 00 6c 00 74 00 20 00 2d 00 6d 00 62 00 20 00 2d 00 6f 00 20 00 2d 00 65 00}
		$s1 = {4c 00 54 00 20 00 54 00 69 00 6d 00 65 00 20 00 69 00 6e 00 76 00 61 00 6c 00 69 00 64 00}
		$s2 = {64 6f 43 6f 6d 70 72 65 73 73 49 6e 4e 65 74 57 6f 72 6b 44 69 72 65 63 74 6f 72 79}
		$s3 = {66 00 69 00 6c 00 65 00 73 00 20 00 72 00 65 00 6d 00 61 00 69 00 6e 00 69 00 6e 00 67 00 20 00 2c 00 74 00 6f 00 74 00 61 00 6c 00 20 00 66 00 69 00 6c 00 65 00 20 00 73 00 61 00 76 00 65 00 20 00 3d 00 20 00}
		$s4 = {24 65 63 39 39 36 33 35 30 2d 37 39 61 34 2d 34 37 37 62 2d 38 37 61 65 2d 32 64 35 62 39 64 62 65 32 30 66 64}
		$s5 = {44 00 65 00 73 00 74 00 69 00 6e 00 69 00 74 00 69 00 6f 00 6e 00 20 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 20 00 4e 00 6f 00 74 00 20 00 46 00 6f 00 75 00 6e 00 64 00}
		$s6 = {5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 5a 50 50 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and ( 1 of ( $x* ) or 3 of them )
}

rule WiltedTulip_Netsrv_netsrvs : hardened
{
	meta:
		description = "Detects sample from Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "a062cb4364125427b54375d51e9e9afb0baeb09b05a600937f70c9d6d365f4e5"
		hash2 = "afa563221aac89f96c383f9f9f4ef81d82c69419f124a80b7f4a8c437d83ce77"
		hash3 = "acf24620e544f79e55fd8ae6022e040257b60b33cf474c37f2877c39fbf2308a"
		hash4 = "bff115d5fb4fd8a395d158fb18175d1d183c8869d54624c706ee48a1180b2361"
		hash5 = "07ab795eeb16421a50c36257e6e703188a0fef9ed87647e588d0cd2fcf56fe43"
		id = "4b58bb08-88da-535c-8ce5-e7113e5b7045"

	strings:
		$s1 = {50 72 6f 63 65 73 73 20 25 64 20 43 72 65 61 74 65 64}
		$s2 = {25 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$s3 = {25 00 73 00 5c 00 53 00 79 00 73 00 57 00 4f 00 57 00 36 00 34 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$c1 = {73 6c 62 68 74 74 70 73}
		$c2 = {2f 00 73 00 6c 00 62 00 68 00 74 00 74 00 70 00 73 00}
		$c3 = {2f 00 73 00 6c 00 62 00 64 00 6e 00 73 00 6b 00 31 00}
		$c4 = {6e 00 65 00 74 00 73 00 72 00 76 00}
		$c5 = {2f 00 73 00 6c 00 62 00 68 00 74 00 74 00 70 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( all of ( $s* ) and 1 of ( $c* ) ) )
}

import "pe"

rule WiltedTulip_ReflectiveLoader : hardened
{
	meta:
		description = "Detects reflective loader (Cobalt Strike) used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		score = 70
		hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
		hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
		hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
		hash4 = "cf7c754ceece984e6fa0d799677f50d93133db609772c7a2226e7746e6d046f0"
		hash5 = "eee430003e7d59a431d1a60d45e823d4afb0d69262cc5e0c79f345aa37333a89"
		id = "0c7dfb44-8acb-5f36-9683-745560f1f795"

	strings:
		$x1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22}
		$x2 = {25 64 20 69 73 20 61 6e 20 78 38 36 20 70 72 6f 63 65 73 73 20 28 63 61 6e 27 74 20 69 6e 6a 65 63 74 20 78 36 34 20 63 6f 6e 74 65 6e 74 29}
		$x3 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 75 2f 27 29 3b 20 25 73}
		$x4 = {46 61 69 6c 65 64 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 74 6f 6b 65 6e 20 66 72 6f 6d 20 25 64 20 28 25 75 29}
		$x5 = {46 61 69 6c 65 64 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 6c 6f 67 67 65 64 20 6f 6e 20 75 73 65 72 20 25 64 20 28 25 75 29}
		$x6 = {25 73 2e 34 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and 1 of them ) or ( 2 of them ) or pe.exports ( "_ReflectiveLoader@4" )
}

rule WiltedTulip_Matryoshka_RAT : hardened
{
	meta:
		description = "Detects Matryoshka RAT used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "6f208473df0d31987a4999eeea04d24b069fdb6a8245150aa91dfdc063cd64ab"
		hash2 = "6cc1f4ecd28b833c978c8e21a20a002459b4a6c21a4fbaad637111aa9d5b1a32"
		id = "e851e212-bb71-55c9-9bc1-0041bb04bef5"

	strings:
		$s1 = {25 00 53 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00}
		$s2 = {6e 00 74 00 75 00 73 00 65 00 72 00 2e 00 64 00 61 00 74 00 2e 00 73 00 77 00 70 00}
		$s3 = {4a 00 6f 00 62 00 20 00 53 00 61 00 76 00 65 00 20 00 2f 00 20 00 4c 00 6f 00 61 00 64 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00}
		$s4 = {2e 3f 41 56 50 53 43 4c 5f 43 4c 41 53 53 5f 4a 4f 42 5f 53 41 56 45 5f 43 4f 4e 46 49 47 40 40}
		$s5 = {77 69 6e 75 70 64 61 74 65 36 34 2e 63 6f 6d}
		$s6 = {4a 00 6f 00 62 00 20 00 53 00 61 00 76 00 65 00 20 00 4b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and 3 of them )
}

