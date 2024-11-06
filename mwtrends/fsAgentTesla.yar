rule AgentTesla
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla Payload"
		cape_type = "AgentTesla Payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$string1 = "smtp" wide
		$string2 = "appdata" wide
		$string3 = "76487-337-8429955-22614" wide
		$string4 = "yyyy-MM-dd HH:mm:ss" wide
		$string6 = "webpanel" wide
		$string7 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide
		$string8 = "<br>IP Address&nbsp;&nbsp;:" wide
		$agt1 = "IELibrary.dll" ascii
		$agt2 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii
		$agt3 = "GetSavedPasswords" ascii
		$agt4 = "GetSavedCookies" ascii

	condition:
		uint16(0)==0x5A4D and 
		( all of ($string*) or 
			3 of ($agt*))
}

rule AgentTeslaV2
{
	meta:
		author = "ditekshen"
		description = "AgenetTesla Type 2 Keylogger payload"
		cape_type = "AgentTesla Payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$s1 = "get_kbHook" ascii
		$s2 = "GetPrivateProfileString" ascii
		$s3 = "get_OSFullName" ascii
		$s4 = "get_PasswordHash" ascii
		$s5 = "remove_Key" ascii
		$s6 = "FtpWebRequest" ascii
		$s7 = "logins" fullword wide
		$s8 = "keylog" fullword wide
		$s9 = "1.85 (Hash, version 2, native byte-order)" wide
		$cl1 = "Postbox" fullword ascii
		$cl2 = "BlackHawk" fullword ascii
		$cl3 = "WaterFox" fullword ascii
		$cl4 = "CyberFox" fullword ascii
		$cl5 = "IceDragon" fullword ascii
		$cl6 = "Thunderbird" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 
			6 of ($s*)) or 
		(6 of ($s*) and 
			2 of ($cl*))
}

rule AgentTeslaV3
{
	meta:
		author = "ditekshen"
		description = "AgentTeslaV3 infostealer payload"
		cape_type = "AgentTesla payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$s1 = "get_kbok" fullword ascii
		$s2 = "get_CHoo" fullword ascii
		$s3 = "set_passwordIsSet" fullword ascii
		$s4 = "get_enableLog" fullword ascii
		$s5 = "bot%telegramapi%" wide
		$s6 = "KillTorProcess" fullword ascii
		$s7 = "GetMozilla" ascii
		$s8 = "torbrowser" wide
		$s9 = "%chatid%" wide
		$s10 = "logins" fullword wide
		$s11 = "credential" fullword wide
		$s12 = "AccountConfiguration+" wide
		$s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide
		$s14 = "set_Lenght" fullword ascii
		$s15 = "get_Keys" fullword ascii
		$s16 = "set_AllowAutoRedirect" fullword ascii
		$s17 = "set_wtqQe" fullword ascii
		$s18 = "set_UseShellExecute" fullword ascii
		$s19 = "set_IsBodyHtml" fullword ascii
		$s20 = "set_FElvMn" fullword ascii
		$s21 = "set_RedirectStandardOutput" fullword ascii
		$g1 = "get_Clipboard" fullword ascii
		$g2 = "get_Keyboard" fullword ascii
		$g3 = "get_Password" fullword ascii
		$g4 = "get_CtrlKeyDown" fullword ascii
		$g5 = "get_ShiftKeyDown" fullword ascii
		$g6 = "get_AltKeyDown" fullword ascii
		$m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
		$m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
		$m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
		$m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
		$m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii

	condition:
		( uint16(0)==0x5a4d and 
			(8 of ($s*) or 
				(6 of ($s*) and 
					4 of ($g*)))) or 
		(2 of ($m*))
}

rule AgentTeslaXor
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla xor-based config decoding"
		cape_type = "AgentTesla Payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}

	condition:
		uint16(0)==0x5A4D and 
		any of them
}

rule AgentTeslaV4
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla Payload"
		cape_type = "AgentTesla Payload"
		packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$decode1 = {(07|FE 0C 01 00) (07|FE 0C 01 00) 8E 69 (17|20 01 00 00 00) 63 8F ?? 00 00 01 25 47 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A D2 61 D2 52}
		$decode2 = {(07|FE 0C 01 00) (08|FE 0C 02 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (11 07|FE 0C 07 00) 91 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A 61 D2 61 D2 52}
		$decode3 = {(07|FE 0C 01 00) (11 07|FE 0C 07 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (08|FE 0C 02 00) 91 61 D2 52}

	condition:
		uint16(0)==0x5A4D and 
		all of them
}

rule AgentTeslaV4JIT
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla JIT-compiled native code"
		cape_type = "AgentTesla Payload"
		packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
		$decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
		$decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}

	condition:
		2 of them
}

rule AgentTeslaV5
{
	meta:
		author = "ClaudioWayne"
		description = "AgentTeslaV5 infostealer payload"
		cape_type = "AgentTesla payload"
		sample = "893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$template1 = "<br>User Name: " fullword wide
		$template2 = "<br>Username: " fullword wide
		$template3 = "<br>RAM: " fullword wide
		$template4 = "<br>Password: " fullword wide
		$template5 = "<br>OSFullName: " fullword wide
		$template6 = "<br><hr>Copied Text: <br>" fullword wide
		$template7 = "<br>CPU: " fullword wide
		$template8 = "<br>Computer Name: " fullword wide
		$template9 = "<br>Application: " fullword wide
		$chromium_browser1 = "Comodo\\Dragon\\User Data" fullword wide
		$chromium_browser2 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" fullword wide
		$chromium_browser3 = "Google\\Chrome\\User Data" fullword wide
		$chromium_browser4 = "Elements Browser\\User Data" fullword wide
		$chromium_browser5 = "Yandex\\YandexBrowser\\User Data" fullword wide
		$chromium_browser6 = "MapleStudio\\ChromePlus\\User Data" fullword wide
		$mozilla_browser1 = "\\Mozilla\\SeaMonkey\\" fullword wide
		$mozilla_browser2 = "\\K-Meleon\\" fullword wide
		$mozilla_browser3 = "\\NETGATE Technologies\\BlackHawk\\" fullword wide
		$mozilla_browser4 = "\\Thunderbird\\" fullword wide
		$mozilla_browser5 = "\\8pecxstudios\\Cyberfox\\" fullword wide
		$mozilla_browser6 = "360Chrome\\Chrome\\User Data" fullword wide
		$mozilla_browser7 = "\\Mozilla\\Firefox\\" fullword wide
		$database1 = "Berkelet DB" fullword wide
		$database2 = " 1.85 (Hash, version 2, native byte-order)" fullword wide
		$database3 = "00061561" fullword wide
		$database4 = "key4.db" fullword wide
		$database5 = "key3.db" fullword wide
		$database6 = "global-salt" fullword wide
		$database7 = "password-check" fullword wide
		$software1 = "\\FileZilla\\recentservers.xml" fullword wide
		$software2 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
		$software3 = "\\The Bat!" fullword wide
		$software4 = "\\Apple Computer\\Preferences\\keychain.plist" fullword wide
		$software5 = "\\MySQL\\Workbench\\workbench_user_data.dat" fullword wide
		$software6 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
		$software7 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" fullword wide
		$software8 = "FTP Navigator\\Ftplist.txt" fullword wide
		$software9 = "NordVPN" fullword wide
		$software10 = "JDownloader 2.0\\cfg" fullword wide

	condition:
		uint16(0)==0x5a4d and 
		4 of ($template*) and 
		3 of ($chromium_browser*) and 
		3 of ($mozilla_browser*) and 
		3 of ($database*) and 
		5 of ($software*)
}

rule Windows_Trojan_AgentTesla_d3ac2b2f
{
	meta:
		author = "Elastic Security"
		id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
		fingerprint = "cbbb56fe6cd7277ae9595a10e05e2ce535a4e6bf205810be0bbce3a883b6f8bc"
		creation_date = "2021-03-22"
		last_modified = "2022-06-20"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a1 = "GetMozillaFromLogins" ascii fullword
		$a2 = "AccountConfiguration+username" wide fullword
		$a3 = "MailAccountConfiguration" ascii fullword
		$a4 = "KillTorProcess" ascii fullword
		$a5 = "SmtpAccountConfiguration" ascii fullword
		$a6 = "GetMozillaFromSQLite" ascii fullword
		$a7 = "Proxy-Agent: HToS5x" wide fullword
		$a8 = "set_BindingAccountConfiguration" ascii fullword
		$a9 = "doUsernamePasswordAuth" ascii fullword
		$a10 = "SafariDecryptor" ascii fullword
		$a11 = "get_securityProfile" ascii fullword
		$a12 = "get_useSeparateFolderTree" ascii fullword
		$a13 = "get_DnsResolver" ascii fullword
		$a14 = "get_archivingScope" ascii fullword
		$a15 = "get_providerName" ascii fullword
		$a16 = "get_ClipboardHook" ascii fullword
		$a17 = "get_priority" ascii fullword
		$a18 = "get_advancedParameters" ascii fullword
		$a19 = "get_disabledByRestriction" ascii fullword
		$a20 = "get_LastAccessed" ascii fullword
		$a21 = "get_avatarType" ascii fullword
		$a22 = "get_signaturePresets" ascii fullword
		$a23 = "get_enableLog" ascii fullword
		$a24 = "TelegramLog" ascii fullword
		$a25 = "generateKeyV75" ascii fullword
		$a26 = "set_accountName" ascii fullword
		$a27 = "set_InternalServerPort" ascii fullword
		$a28 = "set_bindingConfigurationUID" ascii fullword
		$a29 = "set_IdnAddress" ascii fullword
		$a30 = "set_GuidMasterKey" ascii fullword
		$a31 = "set_username" ascii fullword
		$a32 = "set_version" ascii fullword
		$a33 = "get_Clipboard" ascii fullword
		$a34 = "get_Keyboard" ascii fullword
		$a35 = "get_ShiftKeyDown" ascii fullword
		$a36 = "get_AltKeyDown" ascii fullword
		$a37 = "get_Password" ascii fullword
		$a38 = "get_PasswordHash" ascii fullword
		$a39 = "get_DefaultCredentials" ascii fullword

	condition:
		8 of ($a*)
}

rule Windows_Trojan_AgentTesla_e577e17e
{
	meta:
		author = "Elastic Security"
		id = "e577e17e-5c42-4431-8c2d-0c1153128226"
		fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }

	condition:
		all of them
}

rule Windows_Trojan_AgentTesla_f2a90d14
{
	meta:
		author = "Elastic Security"
		id = "f2a90d14-7212-41a5-a2cd-a6a6dedce96e"
		fingerprint = "829c827069846ba1e1378aba8ee6cdc801631d769dc3dce15ccaacd4068a88a6"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }

	condition:
		all of them
}

rule Windows_Trojan_AgentTesla_a2d69e48
{
	meta:
		author = "Elastic Security"
		id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
		fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
		creation_date = "2023-05-01"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
		$a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }

	condition:
		all of them
}

rule Windows_Trojan_AgentTesla_ebf431a8
{
	meta:
		author = "Elastic Security"
		id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
		fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
		creation_date = "2023-12-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a1 = "MozillaBrowserList"
		$a2 = "EnableScreenLogger"
		$a3 = "VaultGetItem_WIN7"
		$a4 = "PublicIpAddressGrab"
		$a5 = "EnableTorPanel"
		$a6 = "get_GuidMasterKey"

	condition:
		4 of them
}

rule Win32_Trojan_AgentTesla
{
	meta:
		description = "Identifies AgentTesla samples."
		author = "Netskope Threat Labs"
		ruleset = "Win32_Trojan_AgentTesla.yar"
		repository = "netskopeoss/NetskopeThreatLabsIOCs"
		source_url = "https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/52c780db6106d0c0e8deb04653e036cdd4408e56/Malware/AgentTesla/Yara/Win32_Trojan_AgentTesla.yar"
		license = "MIT License"
		score = 75

	strings:
		$bin00 = "#Blob"
		$bin01 = "#GUID"
		$bin02 = "#Strings"
		$str00 = "get_AccountCredential"
		$str01 = "get_accountName"
		$str02 = "get_Address"
		$str03 = "get_AltKeyDown"
		$str04 = "get_Assembly"
		$str05 = "get_Attachments"
		$str06 = "get_Clipboard"
		$str07 = "get_Computer"
		$str08 = "get_ComputerName"
		$str09 = "get_Connected"
		$str10 = "get_ExecutablePath"
		$str11 = "get_Host"
		$str12 = "get_Key"
		$str13 = "get_Keyboard"
		$str14 = "get_ProcessName"
		$str15 = "set_UserAgent"
		$str16 = "set_UserName"
		$str17 = "set_IsBodyHtml"
		$str18 = "set_IV"

	condition:
		uint16(0)==0x5a4d and 
		all of ($bin*) and 
		10 of ($str*)
}

rule agenttesla_smtp_variant
{
	meta:
		author = "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
		date = "2018/2"
		reference1 = "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
		reference2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
		reference3 = "Agent Tesla == negasteal -- @coldshell"
		version = 1
		maltype = "Stealer"
		filetype = "memory"
		ruleset = "MALW_AgentTesla_SMTP.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MALW_AgentTesla_SMTP.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$a = "type={"
		$b = "hwid={"
		$c = "time={"
		$d = "pcname={"
		$e = "logdata={"
		$f = "screen={"
		$g = "ipadd={"
		$h = "webcam_link={"
		$i = "screen_link={"
		$j = "site_username={"
		$k = "[passwords]"

	condition:
		6 of them
}

rule AgentTeslaV3_1
{
	meta:
		author = "ditekshen"
		description = "AgentTeslaV3 infostealer payload"
		cape_type = "AgentTeslaV3 payload"
		original_yara_name = "AgentTeslaV3"
		ruleset = "CAPE_AgentTesla.yara"
		repository = "CYB3RMX/Qu1cksc0pe"
		source_url = "https://github.com/CYB3RMX/Qu1cksc0pe/blob/8d74a4116951b46b9284102850f28f1082c17c04/Systems/Windows/YaraRules_Windows/CAPE_AgentTesla.yara"
		license = "GNU General Public License v3.0"
		score = 75

	strings:
		$s1 = "get_kbok" fullword ascii
		$s2 = "get_CHoo" fullword ascii
		$s3 = "set_passwordIsSet" fullword ascii
		$s4 = "get_enableLog" fullword ascii
		$s5 = "bot%telegramapi%" wide
		$s6 = "KillTorProcess" fullword ascii
		$s7 = "GetMozilla" ascii
		$s8 = "torbrowser" wide
		$s9 = "%chatid%" wide
		$s10 = "logins" fullword wide
		$s11 = "credential" fullword wide
		$s12 = "AccountConfiguration+" wide
		$s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide
		$g1 = "get_Clipboard" fullword ascii
		$g2 = "get_Keyboard" fullword ascii
		$g3 = "get_Password" fullword ascii
		$g4 = "get_CtrlKeyDown" fullword ascii
		$g5 = "get_ShiftKeyDown" fullword ascii
		$g6 = "get_AltKeyDown" fullword ascii
		$m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
		$m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
		$m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
		$m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
		$m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii

	condition:
		( uint16(0)==0x5a4d and 
			(8 of ($s*) or 
				(6 of ($s*) and 
					all of ($g*)))) or 
		(2 of ($m*))
}

rule Agenttesla_type1
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		ruleset = "rule.yara"
		repository = "JPCERTCC/MalConfScan"
		source_url = "https://github.com/JPCERTCC/MalConfScan/blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara"
		license = "Other"
		score = 75

	strings:
		$iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb"
		$atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb"
		$sqlitestr = "Not a valid SQLite 3 Database File" wide

	condition:
		all of them
}

rule Agenttesla_type2
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		hash1 = "670a00c65eb6f7c48c1e961068a1cb7fd3653bd29377161cd04bf15c9d010da2 "
		ruleset = "rule.yara"
		repository = "JPCERTCC/MalConfScan"
		source_url = "https://github.com/JPCERTCC/MalConfScan/blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara"
		license = "Other"
		score = 75

	strings:
		$type2db1 = "1.85 (Hash, version 2, native byte-order)" wide
		$type2db2 = "Unknow database format" wide
		$type2db3 = "SQLite format 3" wide
		$type2db4 = "Berkelet DB" wide

	condition:
		( uint16(0)==0x5A4D) and 
		3 of them
}

rule Windows_Trojan_AgentTesla_d3ac2b2f_1
{
	meta:
		id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
		fingerprint = "60c031526f8c3099f324b9dccaad3e8e7fb60c85ef79237aa9917e128b072c14"
		creation_date = "2021-03-22"
		last_modified = "2021-04-12"
		os = "Windows"
		arch = "x86"
		category_type = "Trojan"
		family = "AgentTesla"
		threat_name = "Windows.Trojan.AgentTesla"
		source = "Manual"
		maturity = "Diagnostic"
		reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
		scan_type = "File, Memory"
		severity = 100
		original_yara_name = "Windows_Trojan_AgentTesla_d3ac2b2f"
		ruleset = "elastic-agent-rules.yara"
		repository = "SpecterOps/Nemesis"
		source_url = "https://github.com/SpecterOps/Nemesis/blob/84d5986f759161f60dc2e5b538ec88d95b289e43/cmd/enrichment/enrichment/lib/public_yara/elastic-agent-rules.yara"
		license = "Other"
		score = 75

	strings:
		$a1 = "GetMozillaFromLogins" ascii fullword
		$a2 = "AccountConfiguration+username" wide fullword
		$a3 = "MailAccountConfiguration" ascii fullword
		$a4 = "KillTorProcess" ascii fullword
		$a5 = "SmtpAccountConfiguration" ascii fullword
		$a6 = "GetMozillaFromSQLite" ascii fullword
		$a7 = "Proxy-Agent: HToS5x" wide fullword
		$a8 = "set_BindingAccountConfiguration" ascii fullword
		$a9 = "doUsernamePasswordAuth" ascii fullword
		$a10 = "SafariDecryptor" ascii fullword
		$a11 = "get_securityProfile" ascii fullword
		$a12 = "get_useSeparateFolderTree" ascii fullword
		$a13 = "get_DnsResolver" ascii fullword
		$a14 = "get_archivingScope" ascii fullword
		$a15 = "get_providerName" ascii fullword
		$a16 = "get_ClipboardHook" ascii fullword
		$a17 = "get_priority" ascii fullword
		$a18 = "get_advancedParameters" ascii fullword
		$a19 = "get_disabledByRestriction" ascii fullword
		$a20 = "get_LastAccessed" ascii fullword
		$a21 = "get_avatarType" ascii fullword
		$a22 = "get_signaturePresets" ascii fullword
		$a23 = "get_enableLog" ascii fullword
		$a24 = "TelegramLog" ascii fullword
		$a25 = "generateKeyV75" ascii fullword
		$a26 = "set_accountName" ascii fullword
		$a27 = "set_InternalServerPort" ascii fullword
		$a28 = "set_bindingConfigurationUID" ascii fullword
		$a29 = "set_IdnAddress" ascii fullword
		$a30 = "set_GuidMasterKey" ascii fullword
		$a31 = "m_MyWebServicesObjectProvider" ascii fullword
		$a32 = "m_UserObjectProvider" ascii fullword
		$a33 = "m_ComputerObjectProvider" ascii fullword
		$a34 = "m_ThreadStaticValue" ascii fullword
		$a35 = "set_username" ascii fullword
		$a36 = "set_version" ascii fullword

	condition:
		8 of ($a*)
}

rule fsAgentTesla
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "agenttesla"
		score = 75

	condition:
		AgentTesla or 
		AgentTeslaV2 or 
		AgentTeslaV3 or 
		AgentTeslaXor or 
		AgentTeslaV4 or 
		AgentTeslaV4JIT or 
		AgentTeslaV5 or 
		Windows_Trojan_AgentTesla_d3ac2b2f or 
		Windows_Trojan_AgentTesla_e577e17e or 
		Windows_Trojan_AgentTesla_f2a90d14 or 
		Windows_Trojan_AgentTesla_a2d69e48 or 
		Windows_Trojan_AgentTesla_ebf431a8 or 
		Win32_Trojan_AgentTesla or 
		agenttesla_smtp_variant or 
		AgentTeslaV3_1 or 
		Agenttesla_type1 or 
		Agenttesla_type2 or 
		Windows_Trojan_AgentTesla_d3ac2b2f_1
}

