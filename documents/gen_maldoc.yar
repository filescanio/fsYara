rule SUSP_Doc_WindowsInstaller_Call_Feb22_1 : hardened
{
	meta:
		author = "Nils Kuhnert"
		date = "2022-02-26"
		description = "Triggers on docfiles executing windows installer. Used for deploying ThinBasic scripts."
		tlp = "white"
		reference = "https://inquest.net/blog/2022/02/24/dangerously-thinbasic"
		reference2 = "https://twitter.com/threatinsight/status/1497355737844133895"
		id = "8f2e8f91-74e0-5574-9c0a-1479d6114212"
		score = 75

	strings:
		$ = {57 69 6e 64 6f 77 73 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 73 74 61 6c 6c 65 72 24}
		$ = {43 72 65 61 74 65 4f 62 6a 65 63 74}
		$ = {49 6e 73 74 61 6c 6c 50 72 6f 64 75 63 74}

	condition:
		uint32be( 0 ) == 0xd0cf11e0 and all of them
}

