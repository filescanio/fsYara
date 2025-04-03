rule Ransom_Babuk : hardened limited
{
	meta:
		description = "Rule to detect Babuk Locker"
		author = "TS @ McAfee ATR"
		date = "2021-01-19"
		hash = "e10713a4a5f635767dcd54d609bed977"
		rule_version = "v2"
		malware_family = "Ransom:Win/Babuk"
		malware_type = "Ransom"
		mitre_attack = "T1027, T1083, T1057, T1082, T1129, T1490, T1543.003"

	strings:
		$s1 = {005C0048006F007700200054006F00200052006500730074006F0072006500200059006F00750072002000460069006C00650073002E007400780074}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$pattern1 = {006D656D74617300006D65706F63730000736F70686F730000766565616D0000006261636B7570000047785673730000004778426C7200000047784657440000004778435644000000477843494D67720044656657617463680000000063634576744D67720000000063635365744D677200000000536176526F616D005254567363616E0051424643536572766963650051424944505365727669636500000000496E747569742E517569636B426F6F6B732E46435300}
		$pattern2 = {004163725363683253766300004163726F6E69734167656E74000000004341534144324457656253766300000043414152435570646174655376630000730071}
		$pattern3 = {FFB0154000C78584FDFFFFB8154000C78588FDFFFFC0154000C7858CFDFFFFC8154000C78590FDFFFFD0154000C78594FDFFFFD8154000C78598FDFFFFE0154000C7859CFDFFFFE8154000C785A0FDFFFFF0154000C785A4FDFFFFF8154000C785A8FDFFFF00164000C785ACFDFFFF08164000C785B0FDFFFF10164000C785B4FDFFFF18164000C785B8FDFFFF20164000C785BCFDFFFF28164000C785C0FDFFFF30164000C785C4FDFFFF38164000C785C8FDFFFF40164000C785CCFDFFFF48164000C785D0FDFFFF50164000C785D4FDFFFF581640}
		$pattern4 = {400010104000181040002010400028104000301040003810400040104000481040005010400058104000601040006C10400078104000841040008C10400094104000A0104000B0104000C8104000DC104000E8104000F01040000011400008114000181140002411400038114000501140005C11400064114000741140008C114000A8114000C0114000E0114000F4114000101240002812400034124000441240005412400064124000741240008C124000A0124000B8124000D4124000EC1240000C1340002813400054134000741340008C134000A4134000C4134000E8134000FC134000141440003C144000501440006C144000881440009C144000B4144000CC144000E8144000FC144000141540003415400048154000601540007815}

	condition:
		filesize >= 15KB and filesize <= 90KB and 1 of ( $s* ) and 3 of ( $pattern* )
}

