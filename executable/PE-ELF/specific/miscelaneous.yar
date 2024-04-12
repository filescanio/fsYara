rule PUP_InstallRex_AntiFWb {
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth"
		date = "2015-05-13"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		score = 65
	strings:
		$s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
		$s7 = "GetModuleFileName() failed => %u" fullword ascii
		$s8 = "TSULoader.exe" fullword wide
		$s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
		$s17 = "Tsu%08lX.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule LightFTP_fftp_x86_64 {
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 4 of them
}

rule LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide
	condition:
		uint16(0) == 0xfeff and filesize < 1KB and all of them
}