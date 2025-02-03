rule DarkComet_1 : RAT hardened
{
	meta:
		description = "DarkComet RAT"
		author = "botherder https://github.com/botherder"
		vetted_family = "DarkComet"

	strings:
		$bot1 = /(#)BOT#OpenUrl/ wide ascii
		$bot2 = /(#)BOT#Ping/ wide ascii
		$bot3 = /(#)BOT#RunPrompt/ wide ascii
		$bot4 = /(#)BOT#SvrUninstall/ wide ascii
		$bot5 = /(#)BOT#URLDownload/ wide ascii
		$bot6 = /(#)BOT#URLUpdate/ wide ascii
		$bot7 = /(#)BOT#VisitUrl/ wide ascii
		$bot8 = /(#)BOT#CloseServer/ wide ascii
		$ddos1 = /(D)DOSHTTPFLOOD/ wide ascii
		$ddos2 = /(D)DOSSYNFLOOD/ wide ascii
		$ddos3 = /(D)DOSUDPFLOOD/ wide ascii
		$keylogger1 = /(A)ctiveOnlineKeylogger/ wide ascii
		$keylogger2 = /(U)nActiveOnlineKeylogger/ wide ascii
		$keylogger3 = /(A)ctiveOfflineKeylogger/ wide ascii
		$keylogger4 = /(U)nActiveOfflineKeylogger/ wide ascii
		$shell1 = /(A)CTIVEREMOTESHELL/ wide ascii
		$shell2 = /(S)UBMREMOTESHELL/ wide ascii
		$shell3 = /(K)ILLREMOTESHELL/ wide ascii

	condition:
		4 of ( $bot* ) or all of ( $ddos* ) or all of ( $keylogger* ) or all of ( $shell* )
}

rule DarkComet_2 : rat hardened
{
	meta:
		description = "DarkComet"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0"

	strings:
		$a = {23 42 45 47 49 4e 20 44 41 52 4b 43 4f 4d 45 54 20 44 41 54 41 20 2d 2d}
		$b = {23 45 4f 46 20 44 41 52 4b 43 4f 4d 45 54 20 44 41 54 41 20 2d 2d}
		$c = {44 43 5f 4d 55 54 45 58 2d}
		$k1 = {23 4b 43 4d 44 44 43 35 23 2d 38 39 30}
		$k2 = {23 4b 43 4d 44 44 43 35 31 23 2d 38 39 30}

	condition:
		2 of them
}

rule DarkComet_3 : RAT hardened
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a1 = {23 42 4f 54 23 55 52 4c 55 70 64 61 74 65}
		$a2 = {43 6f 6d 6d 61 6e 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 65 78 65 63 75 74 65 64 21}
		$a3 = {4d 00 55 00 54 00 45 00 58 00 4e 00 41 00 4d 00 45 00}
		$a4 = {4e 00 45 00 54 00 44 00 41 00 54 00 41 00}
		$b1 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e}
		$b2 = {25 73 2c 20 43 6c 61 73 73 49 44 3a 20 25 73}
		$b3 = {49 20 77 61 73 6e 27 74 20 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 74 68 65 20 68 6f 73 74 73 20 66 69 6c 65}
		$b4 = {23 42 4f 54 23 56 69 73 69 74 55 72 6c}
		$b5 = {23 4b 43 4d 44 44 43}

	condition:
		all of ( $a* ) or all of ( $b* )
}

rule DarkComet_Keylogger_File : RAT hardened
{
	meta:
		author = "Florian Roth"
		description = "Looks like a keylogger file created by DarkComet Malware"
		date = "25.07.14"
		reference = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		score = 50

	strings:
		$magic = {3a 3a}
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/

	condition:
		($magic at 0 ) and #entry > 10 and #timestamp > 10
}

rule DarkComet_4 : RAT hardened
{
	meta:
		reference = "https://github.com/bwall/bamfdetect/blob/master/BAMF_Detect/modules/yara/darkcomet.yara"

	strings:
		$a1 = {23 42 4f 54 23}
		$a2 = {57 45 42 43 41 4d 53 54 4f 50}
		$a3 = {55 6e 41 63 74 69 76 65 4f 6e 6c 69 6e 65 4b 65 79 53 74 72 6f 6b 65 73}
		$a4 = {23 53 65 6e 64 54 61 73 6b 4d 67 72}
		$a5 = {23 52 65 6d 6f 74 65 53 63 72 65 65 6e 53 69 7a 65}
		$a6 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 34 20 3e 20 4e 55 4c 20 26 26}

	condition:
		all of them
}

rule DarkComet_5 : hardened
{
	meta:
		maltype = "DarkComet RAT"
		author = "https://github.com/reed1713"
		description = "Malware creates the MSDCSC directory, which is a common path utilized by DarkComet, as well as the mutex pattern."

	strings:
		$type = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid = {34 36 38 38}
		$data = /AppData\\Local\\Temp\\MSDCSC\\.+\.exe/
		$type1 = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid1 = {34 36 37 34}
		$data1 = /DC_MUTEX-[0-9A-Z]{7}/

	condition:
		($type and $eventid and $data ) or ( $type1 and $eventid1 and $data1 )
}

