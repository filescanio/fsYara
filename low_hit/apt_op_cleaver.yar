rule OPCLEAVER_BackDoorLogger : hardened
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e9149baa-83c0-597f-833c-ea0241bb60e6"

	strings:
		$s1 = {42 61 63 6b 44 6f 6f 72 4c 6f 67 67 65 72}
		$s2 = {7a 68 75 41 64 64 72 65 73 73}

	condition:
		all of them
}

rule OPCLEAVER_Jasus : hardened
{
	meta:
		description = "ARP cache poisoner used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "8e04b258-e071-5974-9778-b9d0b97be8d5"

	strings:
		$s1 = {70 63 61 70 5f 64 75 6d 70 5f 6f 70 65 6e}
		$s2 = {52 65 73 6f 6c 76 69 6e 67 20 49 50 73 20 74 6f 20 70 6f 69 73 6f 6e 2e 2e 2e}
		$s3 = {57 41 52 4e 4e 49 4e 47 3a 20 47 61 74 65 77 61 79 20 49 50 20 63 61 6e 20 6e 6f 74 20 62 65 20 66 6f 75 6e 64}

	condition:
		all of them
}

rule OPCLEAVER_LoggerModule : hardened
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "949e7ff4-2102-5c89-83c9-f7ba64745661"

	strings:
		$s1 = {25 73 2d 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 72}
		$s2 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 43 6f 6f 6b 69 65 73 5c}

	condition:
		all of them
}

rule OPCLEAVER_NetC : hardened
{
	meta:
		description = "Net Crawler used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "68f32662-0d7d-5dfa-8bfd-ca41d383e19c"

	strings:
		$s1 = {4e 00 65 00 74 00 43 00 2e 00 65 00 78 00 65 00}
		$s2 = {4e 65 74 20 53 65 72 76 69 63 65}

	condition:
		all of them
}

rule OPCLEAVER_ShellCreator2 : hardened
{
	meta:
		description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "b62336c3-39e5-55f8-98df-6c2a2cb0764a"

	strings:
		$s1 = {53 68 65 6c 6c 43 72 65 61 74 6f 72 32 2e 50 72 6f 70 65 72 74 69 65 73}
		$s2 = {73 65 74 5f 49 56}

	condition:
		all of them
}

rule OPCLEAVER_SmartCopy2 : hardened
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "898d9060-208a-5dfb-a452-50ab49b80a9d"

	strings:
		$s1 = {53 6d 61 72 74 43 6f 70 79 32 2e 50 72 6f 70 65 72 74 69 65 73}
		$s2 = {5a 68 75 46 72 61 6d 65 57 6f 72 6b}

	condition:
		all of them
}

rule OPCLEAVER_SynFlooder : hardened
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "bdaf02f4-1226-569b-9f55-999be7ff397a"

	strings:
		$s1 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 73 6f 6c 76 65 20 5b 20 25 73 20 5d 2e 20 45 72 72 6f 72 43 6f 64 65 20 25 64}
		$s2 = {73 20 49 50 20 69 73 20 3a 20 25 73}
		$s3 = {52 61 77 20 54 43 50 20 53 6f 63 6b 65 74 20 43 72 65 61 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e}

	condition:
		all of them
}

rule OPCLEAVER_TinyZBot : hardened
{
	meta:
		description = "Tiny Bot used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "4fad21a6-a900-5afb-876d-99a6d93e0c2c"

	strings:
		$s1 = {4e 00 65 00 74 00 53 00 63 00 70 00}
		$s2 = {54 69 6e 79 5a 42 6f 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}
		$s3 = {41 6f 61 6f 20 57 61 74 65 72 4d 61 72 6b}
		$s4 = {52 75 6e 5f 61 5f 65 78 65}
		$s5 = {6e 65 74 73 63 70 2e 65 78 65}
		$s6 = {67 65 74 5f 4d 61 69 6e 4d 6f 64 75 6c 65 5f 57 65 62 52 65 66 65 72 65 6e 63 65 5f 44 65 66 61 75 6c 74 57 53}
		$s7 = {72 65 6d 6f 76 65 5f 43 68 65 63 6b 46 69 6c 65 4d 44 35 43 6f 6d 70 6c 65 74 65 64}
		$s8 = {68 74 74 70 3a 2f 2f 74 65 6d 70 75 72 69 2e 6f 72 67 2f}
		$s9 = {5a 68 6f 75 70 69 6e 5f 43 6c 65 61 76 65 72}

	condition:
		(( $s1 and $s2 ) or ( $s3 and $s4 and $s5 ) or ( $s6 and $s7 and $s8 ) or $s9 )
}

rule OPCLEAVER_ZhoupinExploitCrew : hardened limited
{
	meta:
		description = "Keywords used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "4e7457a0-e6e1-535c-b04b-ad313b496ce1"

	strings:
		$s1 = {7a 68 6f 75 70 69 6e 20 65 78 70 6c 6f 69 74 20 63 72 65 77}
		$s2 = {7a 68 6f 70 69 6e 20 65 78 70 6c 6f 69 74 20 63 72 65 77}

	condition:
		1 of them
}

rule OPCLEAVER_antivirusdetector : hardened
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "25ab4eaf-eae7-5a55-bed4-42f621d5f06c"

	strings:
		$s1 = {67 65 74 53 68 61 64 79 50 72 6f 63 65 73 73}
		$s2 = {67 65 74 53 79 73 74 65 6d 41 6e 74 69 76 69 72 75 73 65 73}
		$s3 = {41 6e 74 69 56 69 72 75 73 44 65 74 65 63 74 6f 72}

	condition:
		all of them
}

rule OPCLEAVER_csext : hardened
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "f865eae5-9988-5533-a004-e1694761a557"

	strings:
		$s1 = {43 4f 4d 2b 20 53 79 73 74 65 6d 20 45 78 74 65 6e 74 69 6f 6e 73}
		$s2 = {63 73 65 78 74 2e 65 78 65}
		$s3 = {43 4f 4d 5f 45 78 74 65 6e 74 69 6f 6e 73 5f 62 69 6e}

	condition:
		all of them
}

rule OPCLEAVER_kagent : hardened
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "32d20495-eeed-5b2b-915d-cad60fa991f6"

	strings:
		$s1 = {6b 69 6c 6c 20 63 6f 6d 6d 61 6e 64 20 69 73 20 69 6e 20 6c 61 73 74 20 6d 61 63 68 69 6e 65 2c 20 67 6f 69 6e 67 20 62 61 63 6b}
		$s2 = {6d 65 73 73 61 67 65 20 64 61 74 61 20 6c 65 6e 67 74 68 20 69 6e 20 42 36 34 3a 20 25 64 20 42 79 74 65 73}

	condition:
		all of them
}

rule OPCLEAVER_mimikatzWrapper : hardened
{
	meta:
		description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e9427e29-e581-5a5b-8f1d-4b9bfeec0946"

	strings:
		$s1 = {6d 69 6d 69 6b 61 74 7a 57 72 61 70 70 65 72}
		$s2 = {67 65 74 5f 6d 69 6d 69 6b 61 74 7a}

	condition:
		all of them
}

rule OPCLEAVER_pvz_in : hardened
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "dede12b3-f1dd-58ba-a860-829b2331b740"

	strings:
		$s1 = {4c 41 53 54 5f 54 49 4d 45 3d 30 30 2f 30 30 2f 30 30 30 30 3a 30 30 3a 30 30 50 4d 24}
		$s2 = {69 66 20 25 25 45 52 52 4f 52 4c 45 56 45 4c 25 25 20 3d 3d 20 31 20 47 4f 54 4f 20 6c 69 6e 65}

	condition:
		all of them
}

rule OPCLEAVER_pvz_out : hardened
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "46b51bff-dfd9-5f56-897c-422112bc837b"

	strings:
		$s1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00}
		$s2 = {4f 00 53 00 50 00 50 00 53 00 56 00 43 00}

	condition:
		all of them
}

rule OPCLEAVER_wndTest : hardened
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "f8daa0a8-f0f0-5bf7-b9ab-eaf5335ff2b9"

	strings:
		$s1 = {5b 00 41 00 6c 00 74 00 5d 00}
		$s2 = {3c 00 3c 00 20 00 25 00 73 00 20 00 3e 00 3e 00 3a 00}
		$s3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 69 6e 6c 69 6e 65 3b 20 63 6f 6d 70 3d 25 73 3b 20 61 63 63 6f 75 6e 74 3d 25 73 3b 20 70 72 6f 64 75 63 74 3d 25 64 3b}

	condition:
		all of them
}

rule OPCLEAVER_zhCat : hardened limited
{
	meta:
		description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e1f1bc48-b895-5e23-8ffd-b6ea9c8eb26f"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 20 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 41 4f 4c 20 38 2e 30 20 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 42 00 43 00 20 00 28 00 20 00 41 00 20 00 42 00 69 00 67 00 20 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 20 00 29 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		all of them
}

rule OPCLEAVER_zhLookUp : hardened
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "45ef9a90-db4c-59c3-b694-da3f539b118b"

	strings:
		$s1 = {7a 68 4c 6f 6f 6b 55 70 2e 50 72 6f 70 65 72 74 69 65 73}

	condition:
		all of them
}

rule OPCLEAVER_zhmimikatz : hardened
{
	meta:
		description = "Mimikatz wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "fba8ab6e-3b61-53a1-b4df-178442e3cf24"

	strings:
		$s1 = {4d 69 6d 69 6b 61 74 7a 52 75 6e 6e 65 72}
		$s2 = {7a 68 6d 69 6d 69 6b 61 74 7a}

	condition:
		all of them
}

rule OPCLEAVER_Parviz_Developer : hardened limited
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "2bfa90a0-0495-5b21-98f7-5ed7ebc74b2d"

	strings:
		$s1 = {55 73 65 72 73 5c 70 61 72 76 69 7a 5c 64 6f 63 75 6d 65 6e 74 73 5c}

	condition:
		$s1
}

rule OPCLEAVER_CCProxy_Config : hardened limited
{
	meta:
		description = "CCProxy config known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "c4d80a2a-2a32-585e-bc20-1c5118e4ee48"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 73 65 72 4e 61 6d 65 3d 55 73 65 72 2d 30 30 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 65 62 3d 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 61 69 6c 3d 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 54 50 3d 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 50 41 64 64 72 65 73 73 4c 6f 77 3d 37 38 2e 31 30 39 2e 31 39 34 2e 31 31 34 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of ( $s* ) or $x1
}

