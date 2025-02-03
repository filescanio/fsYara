rule EXPL_Log4j_CallBackDomain_IOCs_Dec21_1 : hardened
{
	meta:
		description = "Detects IOCs found in Log4Shell incidents that indicate exploitation attempts of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8"
		date = "2021-12-12"
		score = 60
		id = "474afa96-1758-587e-8cab-41c5205e245e"

	strings:
		$xr1 = /\b(ldap|rmi):\/\/([a-z0-9\.]{1,16}\.bingsearchlib\.com|[a-z0-9\.]{1,40}\.interact\.sh|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}\/([aZ]|ua|Exploit|callback|[0-9]{10}|http443useragent|http80useragent)\b/

	condition:
		1 of them
}

rule EXPL_JNDI_Exploit_Patterns_Dec21_1 : hardened
{
	meta:
		description = "Detects JNDI Exploit Kit patterns in files"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/pimps/JNDI-Exploit-Kit"
		date = "2021-12-12"
		score = 60
		id = "a9127dd2-b818-5ca8-877a-3c47b1e92606"

	strings:
		$x01 = {2f 42 61 73 69 63 2f 43 6f 6d 6d 61 6e 64 2f 42 61 73 65 36 34 2f}
		$x02 = {2f 42 61 73 69 63 2f 52 65 76 65 72 73 65 53 68 65 6c 6c 2f}
		$x03 = {2f 42 61 73 69 63 2f 54 6f 6d 63 61 74 4d 65 6d 73 68 65 6c 6c}
		$x04 = {2f 42 61 73 69 63 2f 4a 65 74 74 79 4d 65 6d 73 68 65 6c 6c}
		$x05 = {2f 42 61 73 69 63 2f 57 65 62 6c 6f 67 69 63 4d 65 6d 73 68 65 6c 6c}
		$x06 = {2f 42 61 73 69 63 2f 4a 42 6f 73 73 4d 65 6d 73 68 65 6c 6c}
		$x07 = {2f 42 61 73 69 63 2f 57 65 62 73 70 68 65 72 65 4d 65 6d 73 68 65 6c 6c}
		$x08 = {2f 42 61 73 69 63 2f 53 70 72 69 6e 67 4d 65 6d 73 68 65 6c 6c}
		$x09 = {2f 44 65 73 65 72 69 61 6c 69 7a 61 74 69 6f 6e 2f 55 52 4c 44 4e 53 2f}
		$x10 = {2f 44 65 73 65 72 69 61 6c 69 7a 61 74 69 6f 6e 2f 43 6f 6d 6d 6f 6e 73 43 6f 6c 6c 65 63 74 69 6f 6e 73 31 2f 44 6e 73 6c 6f 67 2f}
		$x11 = {2f 44 65 73 65 72 69 61 6c 69 7a 61 74 69 6f 6e 2f 43 6f 6d 6d 6f 6e 73 43 6f 6c 6c 65 63 74 69 6f 6e 73 32 2f 43 6f 6d 6d 61 6e 64 2f 42 61 73 65 36 34 2f}
		$x12 = {2f 44 65 73 65 72 69 61 6c 69 7a 61 74 69 6f 6e 2f 43 6f 6d 6d 6f 6e 73 42 65 61 6e 75 74 69 6c 73 31 2f 52 65 76 65 72 73 65 53 68 65 6c 6c 2f}
		$x13 = {2f 44 65 73 65 72 69 61 6c 69 7a 61 74 69 6f 6e 2f 4a 72 65 38 75 32 30 2f 54 6f 6d 63 61 74 4d 65 6d 73 68 65 6c 6c}
		$x14 = {2f 54 6f 6d 63 61 74 42 79 70 61 73 73 2f 44 6e 73 6c 6f 67 2f}
		$x15 = {2f 54 6f 6d 63 61 74 42 79 70 61 73 73 2f 43 6f 6d 6d 61 6e 64 2f}
		$x16 = {2f 54 6f 6d 63 61 74 42 79 70 61 73 73 2f 52 65 76 65 72 73 65 53 68 65 6c 6c 2f}
		$x17 = {2f 54 6f 6d 63 61 74 42 79 70 61 73 73 2f 54 6f 6d 63 61 74 4d 65 6d 73 68 65 6c 6c}
		$x18 = {2f 54 6f 6d 63 61 74 42 79 70 61 73 73 2f 53 70 72 69 6e 67 4d 65 6d 73 68 65 6c 6c}
		$x19 = {2f 47 72 6f 6f 76 79 42 79 70 61 73 73 2f 43 6f 6d 6d 61 6e 64 2f}
		$x20 = {2f 57 65 62 73 70 68 65 72 65 42 79 70 61 73 73 2f 55 70 6c 6f 61 64 2f}
		$fp1 = {3c 68 74 6d 6c}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* )
}

rule EXPL_Log4j_CVE_2021_44228_JAVA_Exception_Dec21_1 : hardened
{
	meta:
		description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
		date = "2021-12-12"
		score = 60
		id = "82cf337e-4ea1-559b-a7b8-512a07adf06f"

	strings:
		$xa1 = {68 65 61 64 65 72 20 77 69 74 68 20 76 61 6c 75 65 20 6f 66 20 42 61 64 41 74 74 72 69 62 75 74 65 56 61 6c 75 65 45 78 63 65 70 74 69 6f 6e 3a 20}
		$sa1 = {2e 6c 6f 67 34 6a 2e 63 6f 72 65 2e 6e 65 74 2e 4a 6e 64 69 4d 61 6e 61 67 65 72 2e 6c 6f 6f 6b 75 70 28 4a 6e 64 69 4d 61 6e 61 67 65 72}
		$sa2 = {45 72 72 6f 72 20 6c 6f 6f 6b 69 6e 67 20 75 70 20 4a 4e 44 49 20 72 65 73 6f 75 72 63 65}

	condition:
		$xa1 or all of ( $sa* )
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Soft : FILE hardened
{
	meta:
		description = "Detects indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		date = "2021-12-10"
		modified = "2021-12-20"
		score = 60
		id = "87e536a5-cc11-528a-b100-4fa3b2b7bc0c"

	strings:
		$x01 = {24 7b 6a 6e 64 69 3a 6c 64 61 70 3a 2f}
		$x02 = {24 7b 6a 6e 64 69 3a 72 6d 69 3a 2f}
		$x03 = {24 7b 6a 6e 64 69 3a 6c 64 61 70 73 3a 2f}
		$x04 = {24 7b 6a 6e 64 69 3a 64 6e 73 3a 2f}
		$x05 = {24 7b 6a 6e 64 69 3a 69 69 6f 70 3a 2f}
		$x06 = {24 7b 6a 6e 64 69 3a 68 74 74 70 3a 2f}
		$x07 = {24 7b 6a 6e 64 69 3a 6e 69 73 3a 2f}
		$x08 = {24 7b 6a 6e 64 69 3a 6e 64 73 3a 2f}
		$x09 = {24 7b 6a 6e 64 69 3a 63 6f 72 62 61 3a 2f}
		$fp1 = {3c 68 74 6d 6c}
		$fp2 = {2f 6e 65 73 73 75 73 7d}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* )
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_OBFUSC : hardened
{
	meta:
		description = "Detects obfuscated indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		date = "2021-12-12"
		modified = "2021-12-13"
		score = 60
		id = "d7c4092a-6ffc-5a89-b73a-f7f0ac984cbd"

	strings:
		$x1 = {24 25 37 42 6a 6e 64 69 3a}
		$x2 = {25 32 35 32 34 25 32 35 37 42 6a 6e 64 69}
		$x3 = {25 32 46 25 32 35 32 35 32 34 25 32 35 32 35 37 42 6a 6e 64 69 25 33 41}
		$x4 = {24 7b 6a 6e 64 69 3a 24 7b 6c 6f 77 65 72 3a}
		$x5 = {24 7b 3a 3a 2d 6a 7d 24 7b}
		$x6 = {24 7b 24 7b 65 6e 76 3a 42 41 52 46 4f 4f 3a 2d 6a 7d}
		$x7 = {24 7b 3a 3a 2d 6c 7d 24 7b 3a 3a 2d 64 7d 24 7b 3a 3a 2d 61 7d 24 7b 3a 3a 2d 70 7d}
		$x8 = {24 7b 62 61 73 65 36 34 3a 4a 48 74 71 62 6d 52 70}
		$fp1 = {3c 68 74 6d 6c}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* )
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Hard : FILE hardened
{
	meta:
		description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
		author = "Florian Roth"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		date = "2021-12-10"
		modified = "2023-10-23"
		score = 75
		id = "5297c42d-7138-507d-a3eb-153afe522816"

	strings:
		$x1 = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/
		$x2 = {52 65 66 65 72 65 6e 63 65 20 43 6c 61 73 73 20 4e 61 6d 65 3a 20 66 6f 6f}
		$fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/
		$fpg2 = {3c 68 74 6d 6c}
		$fpg3 = {3c 48 54 4d 4c}
		$fp1 = {2f 51 55 41 4c 59 53 54 45 53 54}
		$fp2 = {77 2e 6e 65 73 73 75 73 2e 6f 72 67 2f 6e 65 73 73 75 73}
		$fp3 = {2f 6e 65 73 73 75 73 7d}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* )
}

rule SUSP_Base64_Encoded_Exploit_Indicators_Dec21 : hardened
{
	meta:
		description = "Detects base64 encoded strings found in payloads of exploits against log4j CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/Reelix/status/1469327487243071493"
		date = "2021-12-10"
		modified = "2021-12-13"
		score = 70
		id = "09abc4f0-ace7-5f53-b1d3-5f5c6bf3bdba"

	strings:
		$sa1 = {59 33 56 79 62 43 41 74 63 79}
		$sa2 = {4e 31 63 6d 77 67 4c 58 4d 67}
		$sa3 = {6a 64 58 4a 73 49 43 31 7a 49}
		$sb1 = {66 48 64 6e 5a 58 51 67 4c 58 45 67 4c 55 38 74 49}
		$sb2 = {78 33 5a 32 56 30 49 43 31 78 49 43 31 50 4c 53}
		$sb3 = {38 64 32 64 6c 64 43 41 74 63 53 41 74 54 79 30 67}
		$fp1 = {3c 68 74 6d 6c}

	condition:
		1 of ( $sa* ) and 1 of ( $sb* ) and not 1 of ( $fp* )
}

rule SUSP_JDNIExploit_Indicators_Dec21 : hardened
{
	meta:
		description = "Detects indicators of JDNI usage in log files and other payloads"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/flypig5211/JNDIExploit"
		date = "2021-12-10"
		modified = "2021-12-12"
		score = 70
		id = "2df8b8f3-8d8d-5982-8c85-692b7d91ebb2"

	strings:
		$xr1 = /(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/\/[a-zA-Z0-9\.]{7,80}:[0-9]{2,5}\/(Basic\/Command\/Base64|Basic\/ReverseShell|Basic\/TomcatMemshell|Basic\/JBossMemshell|Basic\/WebsphereMemshell|Basic\/SpringMemshell|Basic\/Command|Deserialization\/CommonsCollectionsK|Deserialization\/CommonsBeanutils|Deserialization\/Jre8u20\/TomcatMemshell|Deserialization\/CVE_2020_2555\/WeblogicMemshell|TomcatBypass|GroovyBypass|WebsphereBypass)\//

	condition:
		filesize < 100MB and $xr1
}

rule SUSP_EXPL_OBFUSC_Dec21_1 : hardened
{
	meta:
		description = "Detects obfuscation methods used to evade detection in log4j exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/testanull/status/1469549425521348609"
		date = "2021-12-11"
		modified = "2022-11-08"
		score = 60
		id = "b8f56711-7922-54b9-9ce2-6ba05d64c80d"

	strings:
		$f1 = { 24 7B 6C 6F 77 65 72 3A ?? 7D }
		$f2 = { 24 7B 75 70 70 65 72 3A ?? 7D }
		$x3 = {24 25 37 62 6c 6f 77 65 72 3a}
		$x4 = {24 25 37 62 75 70 70 65 72 3a}
		$x5 = {25 32 34 25 37 62 6a 6e 64 69 3a}
		$x6 = {24 25 37 42 6c 6f 77 65 72 3a}
		$x7 = {24 25 37 42 75 70 70 65 72 3a}
		$x8 = {25 32 34 25 37 42 6a 6e 64 69 3a}
		$fp1 = {3c 68 74 6d 6c}

	condition:
		(1 of ( $x* ) or filesize < 200KB and 1 of ( $f* ) ) and not 1 of ( $fp* )
}

rule SUSP_JDNIExploit_Error_Indicators_Dec21_1 : hardened
{
	meta:
		description = "Detects error messages related to JDNI usage in log files that can indicate a Log4Shell / Log4j exploitation"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/marcioalm/status/1470361495405875200?s=20"
		date = "2021-12-10"
		modified = "2023-06-23"
		score = 70
		id = "68bcf043-58b4-54a9-b024-64871b5d535f"

	strings:
		$x1 = {46 41 54 41 4c 20 6c 6f 67 34 6a 20 2d 20 4d 65 73 73 61 67 65 3a 20 42 61 64 41 74 74 72 69 62 75 74 65 56 61 6c 75 65 45 78 63 65 70 74 69 6f 6e 3a 20}

	condition:
		1 of them
}

