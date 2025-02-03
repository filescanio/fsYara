rule VULN_Confluence_Questions_Plugin_CVE_2022_26138_Jul22_1 : hardened
{
	meta:
		description = "Detects properties file of Confluence Questions plugin with static user name and password (backdoor) CVE-2022-26138"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.bleepingcomputer.com/news/security/atlassian-fixes-critical-confluence-hardcoded-credentials-flaw/"
		date = "2022-07-21"
		score = 50
		id = "1443c673-2a86-5431-876a-c8fccba52190"

	strings:
		$x_plain_1 = {70 72 65 64 65 66 69 6e 65 64 2e 75 73 65 72 2e 70 61 73 73 77 6f 72 64 3d 64 69 73 61 62 6c 65 64 31 73 79 73 74 65 6d 31 75 73 65 72 36 37 30 38}
		$jar_marker = {2f 63 6f 6e 66 6c 75 65 6e 63 65 2f 70 6c 75 67 69 6e 73 2f 71 75 65 73 74 69 6f 6e 73 2f}
		$jar_size_1 = { 00 CC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
      /*    here starts default.properties v                          */
                      ?? ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70
                      72 6F 70 65 72 74 69 65 73 50 4B }
		$jar_size_2 = { 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74
                      2E 70 72 6F 70 65 72 74 69 65 73 }

	condition:
		1 of ( $x* ) or ( $jar_marker and 1 of ( $jar_size* ) )
}

