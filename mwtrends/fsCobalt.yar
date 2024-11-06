rule Cobalt_functions
{
	meta:
		author = "@j0sm1"
		url = "https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/"
		description = "Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"
		ruleset = "APT_Cobalt.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/APT_Cobalt.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$h1 = {58 A4 53 E5}
		$h2 = {4C 77 26 07}
		$h3 = {6A C9 9C C9}
		$h4 = {44 F0 35 E0}
		$h5 = {F4 00 8E CC}

	condition:
		2 of ($h*)
}

rule cobalt_strike_indicator : high
{
	meta:
		description = "CobaltStrike indicator"
		author = "Florian Roth"
		hash_2024_2018_04_Common_Malware_Carrier_payload = "8cdd29e28daf040965d4cad8bf3c73d00dde3f2968bab44c7d8fe482ba2057f9"
		ruleset = "cobalt_strike.yara"
		repository = "chainguard-dev/bincapz"
		source_url = "https://github.com/chainguard-dev/bincapz/blob/641688a57cdfb271ec78be8a931e69b336513074/rules/tools/backdoor/cobalt_strike.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$ref = "%s as %s\\%s: %d" ascii xor

	condition:
		any of them
}

rule CobaltStrikeBeacon
{
	meta:
		author = "ditekshen, enzo & Elastic"
		description = "Cobalt Strike Beacon Payload"
		cape_type = "CobaltStrikeBeacon Payload"
		ruleset = "CobaltStrikeBeacon.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/CobaltStrikeBeacon.yar"
		license = "Other"
		score = 75

	strings:
		$s1 = "%%IMPORT%%" fullword ascii
		$s2 = "www6.%x%x.%s" fullword ascii
		$s3 = "cdn.%x%x.%s" fullword ascii
		$s4 = "api.%x%x.%s" fullword ascii
		$s5 = "%s (admin)" fullword ascii
		$s6 = "could not spawn %s: %d" fullword ascii
		$s7 = "Could not kill %d: %d" fullword ascii
		$s8 = "Could not connect to pipe (%s): %d" fullword ascii
		$s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii
		$pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
		$pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
		$ver3a = {69 68 69 68 69 6b ?? ?? 69}
		$ver3b = {69 69 69 69}
		$ver4a = {2e 2f 2e 2f 2e 2c ?? ?? 2e}
		$ver4b = {2e 2e 2e 2e}
		$a1 = "%02d/%02d/%02d %02d:%02d:%02d" xor
		$a2 = "Started service %s on %s" xor
		$a3 = "%s as %s\\%s: %d" xor
		$b_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
		$b_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}

	condition:
		all of ($ver3*) or 
		all of ($ver4*) or 
		2 of ($a*) or 
		any of ($b*) or 
		5 of ($s*) or 
		( all of ($pwsh*) and 
			2 of ($s*)) or 
		(#s9>6 and 
			4 of them )
}

rule MALW_cobaltrike
{
	meta:
		description = "Rule to detect CobaltStrike beacon"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2020-07-19"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/CobaltStrike"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "f47a627880bfa4a117fec8be74ab206690e5eb0e9050331292e032cd22883f5b"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
		ruleset = "MALW_cobaltstrike.yar"
		repository = "advanced-threat-research/Yara-Rules"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules/blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_cobaltstrike.yar"
		license = "Apache License 2.0"
		score = 75
		vetted_family = "cobalt"

	strings:
		$pattern_0 = { e9???????? eb0a b801000000 e9???????? }
		$pattern_1 = { 3bc7 750d ff15???????? 3d33270000 }
		$pattern_2 = { 8bd0 e8???????? 85c0 7e0e }
		$pattern_3 = { 50 8d8d24efffff 51 e8???????? }
		$pattern_4 = { 03b5d4eeffff 89b5c8eeffff 3bf7 72bd 3bf7 }
		$pattern_5 = { 8b450c 8945f4 8d45f4 50 }
		$pattern_6 = { 33c5 8945fc 8b4508 53 56 ff750c 33db }
		$pattern_7 = { e8???????? e9???????? 833d????????01 7505 e8???????? }
		$pattern_8 = { 53 53 8d85f4faffff 50 }
		$pattern_9 = { 68???????? 53 50 e8???????? 83c424 }
		$pattern_10 = { 488b4c2420 8b0401 8b4c2408 33c8 8bc1 89442408 }
		$pattern_11 = { 488d4d97 e8???????? 4c8d9c24d0000000 418bc7 498b5b20 498b7328 498b7b30 }
		$pattern_12 = { bd08000000 85d2 7459 ffcf 4d85ed }
		$pattern_13 = { 4183c9ff 33d2 ff15???????? 4c63c0 4983f8ff }
		$pattern_14 = { 49c1e002 e8???????? 03f3 4d8d349e 3bf5 7d13 }
		$pattern_15 = { 752c 4c8d45af 488d55af 488d4d27 }

	condition:
		7 of them and 
		filesize <696320
}

rule cobaltstrike_beacon_raw
{
	meta:
		score = 75

	strings:
		$s1 = "%d is an x64 process (can't inject x86 content)" fullword
		$s2 = "Failed to impersonate logged on user %d (%u)" fullword
		$s3 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword
		$s4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword
		$s5 = "could not run command (w/ token) because of its length of %d bytes!" fullword
		$s6 = "could not write to process memory: %d" fullword
		$s7 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword
		$s8 = "Could not connect to pipe (%s): %d" fullword
		$b1 = "beacon.dll" fullword
		$b2 = "beacon.x86.dll" fullword
		$b3 = "beacon.x64.dll" fullword

	condition:
		uint16(0)==0x5a4d and 
		filesize <1000KB and 
		( any of ($b*) or 
			5 of ($s*))
}

rule cobaltstrike_beacon_b64
{
	meta:
		score = 75

	strings:
		$s1a = "JWQgaXMgYW4geDY0IHByb2Nlc3MgKGNhbid0IGluam"
		$s1b = "ZCBpcyBhbiB4NjQgcHJvY2VzcyAoY2FuJ3QgaW5qZW"
		$s1c = "IGlzIGFuIHg2NCBwcm9jZXNzIChjYW4ndCBpbmplY3"
		$s2a = "RmFpbGVkIHRvIGltcGVyc29uYXRlIGxvZ2dlZCBvbi"
		$s2b = "YWlsZWQgdG8gaW1wZXJzb25hdGUgbG9nZ2VkIG9uIH"
		$s2c = "aWxlZCB0byBpbXBlcnNvbmF0ZSBsb2dnZWQgb24gdX"
		$s3a = "cG93ZXJzaGVsbCAtbm9wIC1leGVjIGJ5cGFzcyAtRW"
		$s3b = "b3dlcnNoZWxsIC1ub3AgLWV4ZWMgYnlwYXNzIC1Fbm"
		$s3c = "d2Vyc2hlbGwgLW5vcCAtZXhlYyBieXBhc3MgLUVuY2"
		$s4a = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLk"
		$s4b = "RVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG"
		$s4c = "WCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3"

	condition:
		filesize <1000KB and 
		5 of ($s*)
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		hash = "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		$core_sig and 
		not $deobfuscator
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		hash = "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
		hash = "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
		hash = "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		$core_sig and 
		not $deobfuscator
}

rule MAL_CobaltStrike_Oct_2021_1
{
	meta:
		description = "Detect Cobalt Strike implant"
		author = "Arkbird_SOLG"
		reference = "https://twitter.com/malwrhunterteam/status/1454154412902002692"
		date = "2021-10-30"
		hash1 = "f520f97e3aa065efc4b7633735530a7ea341f3b332122921cb9257bf55147fb7"
		hash2 = "7370c09d07b4695aa11e299a9c17007e9267e1578ce2753259c02a8cf27b18b6"
		hash3 = "bfbc1c27a73c33e375eeea164dc876c23bca1fbc0051bb48d3ed3e50df6fa0e8"
		tlp = "white"
		adversary = "-"
		ruleset = "MAL_CobaltStrike_Oct_2021_1.yara"
		repository = "StrangerealIntel/DailyIOC"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-10-29/Hive/MAL_CobaltStrike_Oct_2021_1.yara"
		score = 75

	strings:
		$s1 = { 48 83 ec 10 4c 89 14 24 4c 89 5c 24 08 4d 33 db 4c 8d 54 24 18 4c 2b d0 4d 0f 42 d3 65 4c 8b 1c 25 10 00 00 00 4d 3b d3 f2 73 17 66 41 81 e2 00 f0 4d 8d 9b 00 f0 ff ff 41 c6 03 00 4d 3b d3 f2 75 ef 4c 8b 14 24 4c 8b 5c 24 08 48 83 c4 10 f2 c3 }
		$s2 = { 89 ?? 24 ?? 8b ?? 24 0c 89 ?? 24 ?? 8b ?? 24 ?? c1 ?? 0d 89 ?? 24 0c 48 8b ?? 24 10 89 ?? 24 [2] 8b ?? 24 10 }
		$s3 = { b8 10 00 00 00 48 89 45 ?? e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 8b 55 f8 89 11 4c 8b 45 ?? 4c 8b 4d f0 4d 89 08 4c 8b 55 ?? 4c 8b 5d e8 4d 89 1a 48 8b 75 ?? 48 8b 7d e0 48 89 3e c7 00 ?? 00 00 00 48 8b 05 [3] 00 48 05 [2] 00 00 8b 19 4d 8b 00 4d 8b 32 48 8b 0e 48 83 ec 20 4c 89 f2 41 89 d9 ff d0 48 83 c4 20 ?? 45 }
		$s4 = { 48 83 ec 48 44 89 4c 24 44 4c 89 44 24 38 48 89 54 24 30 48 89 4c 24 28 c7 44 24 24 ?? 00 00 00 48 8b 05 [3] 00 48 05 [2] 00 00 44 8b 4c 24 44 4c 8b 44 24 38 48 8b 54 24 30 48 8b 4c 24 28 ff d0 90 48 83 c4 }

	condition:
		uint16(0)==0x5A4D and 
		filesize >20KB and 
		3 of ($s*)
}

rule Windows_Trojan_CobaltStrike_c851687a
{
	meta:
		author = "Elastic Security"
		id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
		fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC Bypass module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "bypassuac.dll" ascii fullword
		$a2 = "bypassuac.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
		$b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
		$b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
		$b3 = "[*] Cleanup successful" ascii fullword
		$b4 = "\\System32\\cliconfg.exe" wide fullword
		$b5 = "\\System32\\eventvwr.exe" wide fullword
		$b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
		$b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
		$b8 = "\\System32\\sysprep\\" wide fullword
		$b9 = "[-] COM initialization failed." ascii fullword
		$b10 = "[-] Privileged file copy failed: %S" ascii fullword
		$b11 = "[-] Failed to start %S: %d" ascii fullword
		$b12 = "ReflectiveLoader"
		$b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
		$b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
		$b15 = "[+] %S ran and exited." ascii fullword
		$b16 = "[+] Privileged file copy success! %S" ascii fullword

	condition:
		2 of ($a*) or 
		10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_0b58325e
{
	meta:
		author = "Elastic Security"
		id = "0b58325e-2538-434d-9a2c-26e2c32db039"
		fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Keylogger module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "keylogger.dll" ascii fullword
		$a2 = "keylogger.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\keylogger" ascii fullword
		$a4 = "%cE=======%c" ascii fullword
		$a5 = "[unknown: %02X]" ascii fullword
		$b1 = "ReflectiveLoader"
		$b2 = "%c2%s%c" ascii fullword
		$b3 = "[numlock]" ascii fullword
		$b4 = "%cC%s" ascii fullword
		$b5 = "[backspace]" ascii fullword
		$b6 = "[scroll lock]" ascii fullword
		$b7 = "[control]" ascii fullword
		$b8 = "[left]" ascii fullword
		$b9 = "[page up]" ascii fullword
		$b10 = "[page down]" ascii fullword
		$b11 = "[prtscr]" ascii fullword
		$b12 = "ZRich9" ascii fullword
		$b13 = "[ctrl]" ascii fullword
		$b14 = "[home]" ascii fullword
		$b15 = "[pause]" ascii fullword
		$b16 = "[clear]" ascii fullword

	condition:
		1 of ($a*) and 
		14 of ($b*)
}

rule Windows_Trojan_CobaltStrike_2b8cddf8
{
	meta:
		author = "Elastic Security"
		id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
		fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies dll load module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
		$b1 = "__imp_BeaconErrorDD" ascii fullword
		$b2 = "__imp_BeaconErrorNA" ascii fullword
		$b3 = "__imp_BeaconErrorD" ascii fullword
		$b4 = "__imp_BeaconDataInt" ascii fullword
		$b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
		$b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
		$b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
		$b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
		$c1 = "__imp__BeaconErrorDD" ascii fullword
		$c2 = "__imp__BeaconErrorNA" ascii fullword
		$c3 = "__imp__BeaconErrorD" ascii fullword
		$c4 = "__imp__BeaconDataInt" ascii fullword
		$c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
		$c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
		$c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
		$c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword

	condition:
		1 of ($a*) or 
		5 of ($b*) or 
		5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59b44767
{
	meta:
		author = "Elastic Security"
		id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
		fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies getsystem module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
		$b1 = "getsystem failed." ascii fullword
		$b2 = "_isSystemSID" ascii fullword
		$b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
		$c1 = "getsystem failed." ascii fullword
		$c2 = "$pdata$isSystemSID" ascii fullword
		$c3 = "$unwind$isSystemSID" ascii fullword
		$c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword

	condition:
		1 of ($a*) or 
		3 of ($b*) or 
		3 of ($c*)
}

rule Windows_Trojan_CobaltStrike_7efd3c3f
{
	meta:
		author = "Elastic Security"
		id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
		fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Hashdump module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 70
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "hashdump.dll" ascii fullword
		$a2 = "hashdump.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\hashdump" ascii fullword
		$a4 = "ReflectiveLoader"
		$a5 = "Global\\SAM" ascii fullword
		$a6 = "Global\\FREE" ascii fullword
		$a7 = "[-] no results." ascii fullword

	condition:
		4 of ($a*)
}

rule Windows_Trojan_CobaltStrike_6e971281
{
	meta:
		author = "Elastic Security"
		id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
		fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Interfaces module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
		$b1 = "__imp_BeaconFormatAlloc" ascii fullword
		$b2 = "__imp_BeaconFormatPrintf" ascii fullword
		$b3 = "__imp_BeaconOutput" ascii fullword
		$b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
		$b5 = "__imp_KERNEL32$LocalFree" ascii fullword
		$b6 = "__imp_LoadLibraryA" ascii fullword
		$c1 = "__imp__BeaconFormatAlloc" ascii fullword
		$c2 = "__imp__BeaconFormatPrintf" ascii fullword
		$c3 = "__imp__BeaconOutput" ascii fullword
		$c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
		$c5 = "__imp__KERNEL32$LocalFree" ascii fullword
		$c6 = "__imp__LoadLibraryA" ascii fullword

	condition:
		1 of ($a*) or 
		4 of ($b*) or 
		4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_09b79efa
{
	meta:
		author = "Elastic Security"
		id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
		fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Invoke Assembly module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "invokeassembly.x64.dll" ascii fullword
		$a2 = "invokeassembly.dll" ascii fullword
		$b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
		$b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
		$b3 = "[-] Failed to create the runtime host" ascii fullword
		$b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
		$b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
		$b6 = "ReflectiveLoader"
		$b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
		$b8 = "[-] No .NET runtime found. :(" ascii fullword
		$b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
		$c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }

	condition:
		1 of ($a*) or 
		3 of ($b*) or 
		1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_6e77233e
{
	meta:
		author = "Elastic Security"
		id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
		fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Kerberos module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
		$a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
		$a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
		$a4 = "command_kerberos_ticket_use" ascii fullword
		$a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
		$a6 = "command_kerberos_ticket_purge" ascii fullword
		$a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
		$a8 = "$unwind$kerberos_init" ascii fullword
		$a9 = "$unwind$KerberosTicketUse" ascii fullword
		$a10 = "KerberosTicketUse" ascii fullword
		$a11 = "$unwind$KerberosTicketPurge" ascii fullword
		$b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
		$b2 = "_command_kerberos_ticket_use" ascii fullword
		$b3 = "_command_kerberos_ticket_purge" ascii fullword
		$b4 = "_kerberos_init" ascii fullword
		$b5 = "_KerberosTicketUse" ascii fullword
		$b6 = "_KerberosTicketPurge" ascii fullword
		$b7 = "_LsaCallKerberosPackage" ascii fullword

	condition:
		5 of ($a*) or 
		3 of ($b*)
}

rule Windows_Trojan_CobaltStrike_de42495a
{
	meta:
		author = "Elastic Security"
		id = "de42495a-0002-466e-98b9-19c9ebb9240e"
		fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Mimikatz module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
		$b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
		$b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
		$b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
		$b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
		$b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
		$b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
		$b7 = "mimikatz(powershell) # %s" wide fullword
		$b8 = "powershell_reflective_mimikatz" ascii fullword
		$b9 = "mimikatz_dpapi_cache.ndr" wide fullword
		$b10 = "mimikatz.log" wide fullword
		$b11 = "ERROR mimikatz_doLocal" wide
		$b12 = "mimikatz_x64.compressed" wide

	condition:
		1 of ($a*) and 
		7 of ($b*)
}

rule Windows_Trojan_CobaltStrike_72f68375
{
	meta:
		author = "Elastic Security"
		id = "72f68375-35ab-49cc-905d-15302389a236"
		fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Netdomain module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
		$b1 = "__imp_BeaconPrintf" ascii fullword
		$b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
		$b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
		$c1 = "__imp__BeaconPrintf" ascii fullword
		$c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
		$c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword

	condition:
		1 of ($a*) or 
		2 of ($b*) or 
		2 of ($c*)
}

rule Windows_Trojan_CobaltStrike_15f680fb
{
	meta:
		author = "Elastic Security"
		id = "15f680fb-a04f-472d-a182-0b9bee111351"
		fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Netview module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "netview.x64.dll" ascii fullword
		$a2 = "netview.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\netview" ascii fullword
		$b1 = "Sessions for \\\\%s:" ascii fullword
		$b2 = "Account information for %s on \\\\%s:" ascii fullword
		$b3 = "Users for \\\\%s:" ascii fullword
		$b4 = "Shares at \\\\%s:" ascii fullword
		$b5 = "ReflectiveLoader" ascii fullword
		$b6 = "Password changeable" ascii fullword
		$b7 = "User's Comment" wide fullword
		$b8 = "List of hosts for domain '%s':" ascii fullword
		$b9 = "Password changeable" ascii fullword
		$b10 = "Logged on users at \\\\%s:" ascii fullword

	condition:
		2 of ($a*) or 
		6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec
{
	meta:
		author = "Elastic Security"
		id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
		fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Portscan module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "portscan.x64.dll" ascii fullword
		$a2 = "portscan.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\portscan" ascii fullword
		$b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
		$b2 = "(ARP) Target '%s' is alive. " ascii fullword
		$b3 = "TARGETS!12345" ascii fullword
		$b4 = "ReflectiveLoader" ascii fullword
		$b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
		$b6 = "Scanner module is complete" ascii fullword
		$b7 = "pingpong" ascii fullword
		$b8 = "PORTS!12345" ascii fullword
		$b9 = "%s:%d (%s)" ascii fullword
		$b10 = "PREFERENCES!12345" ascii fullword

	condition:
		2 of ($a*) or 
		6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059
{
	meta:
		author = "Elastic Security"
		id = "91e08059-46a8-47d0-91c9-e86874951a4a"
		fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Post Ex module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "postex.x64.dll" ascii fullword
		$a2 = "postex.dll" ascii fullword
		$a3 = "RunAsAdminCMSTP" ascii fullword
		$a4 = "KerberosTicketPurge" ascii fullword
		$b1 = "GetSystem" ascii fullword
		$b2 = "HelloWorld" ascii fullword
		$b3 = "KerberosTicketUse" ascii fullword
		$b4 = "SpawnAsAdmin" ascii fullword
		$b5 = "RunAsAdmin" ascii fullword
		$b6 = "NetDomain" ascii fullword

	condition:
		2 of ($a*) or 
		4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_ee756db7
{
	meta:
		author = "Elastic Security"
		id = "ee756db7-e177-41f0-af99-c44646d334f7"
		fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
		$a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
		$a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
		$a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
		$a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
		$a11 = "Could not open service control manager on %s: %d" ascii fullword
		$a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
		$a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
		$a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
		$a15 = "could not create remote thread in %d: %d" ascii fullword
		$a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a17 = "could not write to process memory: %d" ascii fullword
		$a18 = "Could not create service %s on %s: %d" ascii fullword
		$a19 = "Could not delete service %s on %s: %d" ascii fullword
		$a20 = "Could not open process token: %d (%u)" ascii fullword
		$a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a22 = "Could not start service %s on %s: %d" ascii fullword
		$a23 = "Could not query service %s on %s: %d" ascii fullword
		$a24 = "Could not connect to pipe (%s): %d" ascii fullword
		$a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a26 = "could not spawn %s (token): %d" ascii fullword
		$a27 = "could not open process %d: %d" ascii fullword
		$a28 = "could not run %s as %s\\%s: %d" ascii fullword
		$a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a30 = "kerberos ticket use failed:" ascii fullword
		$a31 = "Started service %s on %s" ascii fullword
		$a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
		$a33 = "I'm already in SMB mode" ascii fullword
		$a34 = "could not spawn %s: %d" ascii fullword
		$a35 = "could not open %s: %d" ascii fullword
		$a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
		$a37 = "Could not open '%s'" ascii fullword
		$a38 = "%s.1%08x.%x%x.%s" ascii fullword
		$a39 = "%s as %s\\%s: %d" ascii fullword
		$a40 = "%s.1%x.%x%x.%s" ascii fullword
		$a41 = "beacon.x64.dll" ascii fullword
		$a42 = "%s on %s: %d" ascii fullword
		$a43 = "www6.%x%x.%s" ascii fullword
		$a44 = "cdn.%x%x.%s" ascii fullword
		$a45 = "api.%x%x.%s" ascii fullword
		$a46 = "%s (admin)" ascii fullword
		$a47 = "beacon.dll" ascii fullword
		$a48 = "%s%s: %s" ascii fullword
		$a49 = "@%d.%s" ascii fullword
		$a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
		$a51 = "Content-Length: %d" ascii fullword

	condition:
		6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_9c0d5561
{
	meta:
		author = "Elastic Security"
		id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
		fingerprint = "01d53fcdb320f0cd468a2521c3e96dcb0b9aa00e7a7a9442069773c6b3759059"
		creation_date = "2021-03-23"
		last_modified = "2021-10-04"
		description = "Identifies PowerShell Runner module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "PowerShellRunner.dll" wide fullword
		$a2 = "powershell.x64.dll" ascii fullword
		$a3 = "powershell.dll" ascii fullword
		$a4 = "\\\\.\\pipe\\powershell" ascii fullword
		$b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
		$b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
		$b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
		$b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
		$b5 = "CustomPSHostUserInterface" ascii fullword
		$b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
		$b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
		$c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
		$c2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword

	condition:
		(1 of ($a*) and 
			4 of ($b*)) or 
		1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59ed9124
{
	meta:
		author = "Elastic Security"
		id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
		fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies PsExec module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
		$b1 = "__imp_BeaconDataExtract" ascii fullword
		$b2 = "__imp_BeaconDataParse" ascii fullword
		$b3 = "__imp_BeaconDataParse" ascii fullword
		$b4 = "__imp_BeaconDataParse" ascii fullword
		$b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
		$b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
		$b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
		$b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
		$c1 = "__imp__BeaconDataExtract" ascii fullword
		$c2 = "__imp__BeaconDataParse" ascii fullword
		$c3 = "__imp__BeaconDataParse" ascii fullword
		$c4 = "__imp__BeaconDataParse" ascii fullword
		$c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
		$c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
		$c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
		$c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword

	condition:
		1 of ($a*) or 
		5 of ($b*) or 
		5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_8a791eb7
{
	meta:
		author = "Elastic Security"
		id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
		fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Registry module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
		$b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
		$b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
		$b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
		$b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
		$b5 = "__imp_BeaconFormatAlloc" ascii fullword
		$b6 = "__imp_BeaconOutput" ascii fullword
		$b7 = "__imp_BeaconFormatFree" ascii fullword
		$b8 = "__imp_BeaconDataPtr" ascii fullword
		$c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
		$c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
		$c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
		$c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
		$c5 = "__imp__BeaconFormatAlloc" ascii fullword
		$c6 = "__imp__BeaconOutput" ascii fullword
		$c7 = "__imp__BeaconFormatFree" ascii fullword
		$c8 = "__imp__BeaconDataPtr" ascii fullword

	condition:
		1 of ($a*) or 
		5 of ($b*) or 
		5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_d00573a3
{
	meta:
		author = "Elastic Security"
		id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
		fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Screenshot module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "screenshot.x64.dll" ascii fullword
		$a2 = "screenshot.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\screenshot" ascii fullword
		$b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
		$b2 = "GetDesktopWindow" ascii fullword
		$b3 = "CreateCompatibleBitmap" ascii fullword
		$b4 = "GDI32.dll" ascii fullword
		$b5 = "ReflectiveLoader"
		$b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword

	condition:
		2 of ($a*) or 
		5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_7bcd759c
{
	meta:
		author = "Elastic Security"
		id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
		fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies SSH Agent module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "sshagent.x64.dll" ascii fullword
		$a2 = "sshagent.dll" ascii fullword
		$b1 = "\\\\.\\pipe\\sshagent" ascii fullword
		$b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword

	condition:
		1 of ($a*) and 
		1 of ($b*)
}

rule Windows_Trojan_CobaltStrike_a56b820f
{
	meta:
		author = "Elastic Security"
		id = "a56b820f-0a20-4054-9c2d-008862646a78"
		fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Timestomp module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
		$b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
		$b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
		$b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
		$b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
		$b5 = "__imp_BeaconDataExtract" ascii fullword
		$b6 = "__imp_BeaconPrintf" ascii fullword
		$b7 = "__imp_BeaconDataParse" ascii fullword
		$b8 = "__imp_BeaconDataExtract" ascii fullword
		$c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
		$c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
		$c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
		$c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
		$c5 = "__imp__BeaconDataExtract" ascii fullword
		$c6 = "__imp__BeaconPrintf" ascii fullword
		$c7 = "__imp__BeaconDataParse" ascii fullword
		$c8 = "__imp__BeaconDataExtract" ascii fullword

	condition:
		1 of ($a*) or 
		5 of ($b*) or 
		5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_92f05172
{
	meta:
		author = "Elastic Security"
		id = "92f05172-f15c-4077-a958-b8490378bf08"
		fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC cmstp module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
		$b1 = "elevate_cmstp" ascii fullword
		$b2 = "$pdata$elevate_cmstp" ascii fullword
		$b3 = "$unwind$elevate_cmstp" ascii fullword
		$c1 = "_elevate_cmstp" ascii fullword
		$c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
		$c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
		$c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
		$c5 = "OLDNAMES"
		$c6 = "__imp__BeaconDataParse" ascii fullword
		$c7 = "_willAutoElevate" ascii fullword

	condition:
		1 of ($a*) or 
		3 of ($b*) or 
		4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_417239b5
{
	meta:
		author = "Elastic Security"
		id = "417239b5-cf2d-4c85-a022-7a8459c26793"
		fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC token module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
		$a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
		$a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
		$b1 = "$pdata$is_admin_already" ascii fullword
		$b2 = "$unwind$is_admin" ascii fullword
		$b3 = "$pdata$is_admin" ascii fullword
		$b4 = "$unwind$is_admin_already" ascii fullword
		$b5 = "$pdata$RunAsAdmin" ascii fullword
		$b6 = "$unwind$RunAsAdmin" ascii fullword
		$b7 = "is_admin_already" ascii fullword
		$b8 = "is_admin" ascii fullword
		$b9 = "process_walk" ascii fullword
		$b10 = "get_current_sess" ascii fullword
		$b11 = "elevate_try" ascii fullword
		$b12 = "RunAsAdmin" ascii fullword
		$b13 = "is_ctfmon" ascii fullword
		$c1 = "_is_admin_already" ascii fullword
		$c2 = "_is_admin" ascii fullword
		$c3 = "_process_walk" ascii fullword
		$c4 = "_get_current_sess" ascii fullword
		$c5 = "_elevate_try" ascii fullword
		$c6 = "_RunAsAdmin" ascii fullword
		$c7 = "_is_ctfmon" ascii fullword
		$c8 = "_reg_query_dword" ascii fullword
		$c9 = ".drectve" ascii fullword
		$c10 = "_is_candidate" ascii fullword
		$c11 = "_SpawnAsAdmin" ascii fullword
		$c12 = "_SpawnAsAdminX64" ascii fullword

	condition:
		1 of ($a*) or 
		9 of ($b*) or 
		7 of ($c*)
}

rule Windows_Trojan_CobaltStrike_29374056
{
	meta:
		author = "Elastic Security"
		id = "29374056-03ce-484b-8b2d-fbf75be86e27"
		fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Cobalt Strike MZ Reflective Loader."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
		$a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }

	condition:
		1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_949f10e3
{
	meta:
		author = "Elastic Security"
		id = "949f10e3-68c9-4600-a620-ed3119e09257"
		fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
		creation_date = "2021-03-25"
		last_modified = "2021-08-23"
		description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9
{
	meta:
		author = "Elastic Security"
		id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
		fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
		creation_date = "2021-03-25"
		last_modified = "2021-08-23"
		description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_8519072e
{
	meta:
		author = "Elastic Security"
		id = "8519072e-3e43-470b-a3cf-18f92b3f31a2"
		fingerprint = "9fc88b798083adbcf25f9f0b35fbb5035a98cdfe55377de96fa0353821de1cc8"
		creation_date = "2021-03-25"
		last_modified = "2021-10-04"
		description = "Identifies Cobalt Strike trial/default versions"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "User-Agent:"
		$a2 = "wini"
		$a3 = "5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_663fc95d
{
	meta:
		author = "Elastic Security"
		id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
		fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
		creation_date = "2021-04-01"
		last_modified = "2021-12-17"
		description = "Identifies CobaltStrike via unidentified function code"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac
{
	meta:
		author = "Elastic Security"
		id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
		fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon sleep obfuscation routine"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
		$a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
		$a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
		$a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
		$a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }

	condition:
		any of them
}

rule Windows_Trojan_CobaltStrike_f0b627fc
{
	meta:
		author = "Elastic Security"
		id = "f0b627fc-97cd-42cb-9eae-1efb0672762d"
		fingerprint = "fbc94bedd50b5b943553dd438a183a1e763c098a385ac3a4fc9ff24ee30f91e1"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon reflective loader"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
		$beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
		$beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
		$generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
		$generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }

	condition:
		any of them
}

rule Windows_Trojan_CobaltStrike_dcdcdd8c
{
	meta:
		author = "Elastic Security"
		id = "dcdcdd8c-7395-4453-a74a-60ab8e251a5a"
		fingerprint = "8aed1ae470d06a7aac37896df22b2f915c36845099839a85009212d9051f71e9"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon sleep PDB"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
		$a3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
		$a4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
		$a5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
		$a6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword

	condition:
		any of them
}

rule Windows_Trojan_CobaltStrike_a3fb2616
{
	meta:
		author = "Elastic Security"
		id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
		fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for browser pivot "
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "browserpivot.dll" ascii fullword
		$a2 = "browserpivot.x64.dll" ascii fullword
		$b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
		$b2 = "COBALTSTRIKE" ascii fullword

	condition:
		1 of ($a*) and 
		2 of ($b*)
}

rule Windows_Trojan_CobaltStrike_8ee55ee5
{
	meta:
		author = "Elastic Security"
		id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
		fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for wmi exec module"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
		$a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword

	condition:
		1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_8d5963a2
{
	meta:
		author = "Elastic Security"
		id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
		fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
		creation_date = "2022-08-10"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_1787eef5
{
	meta:
		author = "Elastic Security"
		id = "1787eef5-ff00-4e19-bd22-c5dfc9488c7b"
		fingerprint = "292f15bdc978fc29670126f1bdc72ade1e7faaf1948653f70b6789a82dbee67f"
		creation_date = "2022-08-29"
		last_modified = "2022-09-29"
		description = "CS shellcode variants"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
		$a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
		$a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
		$a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
		$a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }

	condition:
		1 of ($a*)
}

rule HKTL_CobaltStrike_SleepMask_Jul22
{
	meta:
		description = "Detects static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
		author = "CodeX"
		date = "2022-07-04"
		reference = "https://codex-7.gitbook.io/codexs-terminal-window/blue-team/detecting-cobalt-strike/sleep-mask-kit-iocs"
		score = 80
		id = "d396ab0e-b584-5a7c-8627-5f318a20f9dd"
		ruleset = "gen_cobaltstrike.yar"
		repository = "Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/007d9ddee386f68aca3a3aac5e1514782f02ed2d/yara/gen_cobaltstrike.yar"
		license = "Other"

	strings:
		$sleep_mask = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }

	condition:
		$sleep_mask
}

rule Windows_Trojan_CobaltStrike_4106070a
{
	meta:
		author = "Elastic Security"
		id = "4106070a-24e2-421b-ab83-67b817a9f019"
		fingerprint = "c12b919064a9cd2a603c134c5f73f6d05ffbf4cbed1e5b5246687378102e4338"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
		$a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_3dc22d14
{
	meta:
		author = "Elastic Security"
		id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
		fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$a2 = "%s as %s\\%s: %d" fullword

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_7f8da98a
{
	meta:
		author = "Elastic Security"
		id = "7f8da98a-3336-482b-91da-82c7cef34c62"
		fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }

	condition:
		all of them
}

rule CobaltStrikeStager
{
	meta:
		author = "@dan__mayer <daniel@stairwell.com>"
		description = "Cobalt Strike Stager Payload"
		cape_type = "CobaltStrikeStager Payload"
		ruleset = "CobaltStrikeStager.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/CobaltStrikeStager.yar"
		license = "Other"
		score = 75

	strings:
		$smb = { 68 00 B0 04 00 68 00 B0 04 00 6A 01 6A 06 6A 03 52 68 45 70 DF D4 }
		$http_x86 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$http_x64 = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 49 89 E6 4C 89 F1 41 BA 4C 77 26 07 }
		$dns = { 68 00 10 00 00 68 FF FF 07 00 6A 00 68 58 A4 53 E5 }

	condition:
		any of them
}

rule fsCobalt
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "cobalt"
		score = 75

	condition:
		Cobalt_functions or 
		cobalt_strike_indicator or 
		CobaltStrikeBeacon or 
		MALW_cobaltrike or 
		cobaltstrike_beacon_raw or 
		cobaltstrike_beacon_b64 or 
		CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6 or 
		CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6 or 
		MAL_CobaltStrike_Oct_2021_1 or 
		Windows_Trojan_CobaltStrike_c851687a or 
		Windows_Trojan_CobaltStrike_0b58325e or 
		Windows_Trojan_CobaltStrike_2b8cddf8 or 
		Windows_Trojan_CobaltStrike_59b44767 or 
		Windows_Trojan_CobaltStrike_7efd3c3f or 
		Windows_Trojan_CobaltStrike_6e971281 or 
		Windows_Trojan_CobaltStrike_09b79efa or 
		Windows_Trojan_CobaltStrike_6e77233e or 
		Windows_Trojan_CobaltStrike_de42495a or 
		Windows_Trojan_CobaltStrike_72f68375 or 
		Windows_Trojan_CobaltStrike_15f680fb or 
		Windows_Trojan_CobaltStrike_5b4383ec or 
		Windows_Trojan_CobaltStrike_91e08059 or 
		Windows_Trojan_CobaltStrike_ee756db7 or 
		Windows_Trojan_CobaltStrike_9c0d5561 or 
		Windows_Trojan_CobaltStrike_59ed9124 or 
		Windows_Trojan_CobaltStrike_8a791eb7 or 
		Windows_Trojan_CobaltStrike_d00573a3 or 
		Windows_Trojan_CobaltStrike_7bcd759c or 
		Windows_Trojan_CobaltStrike_a56b820f or 
		Windows_Trojan_CobaltStrike_92f05172 or 
		Windows_Trojan_CobaltStrike_417239b5 or 
		Windows_Trojan_CobaltStrike_29374056 or 
		Windows_Trojan_CobaltStrike_949f10e3 or 
		Windows_Trojan_CobaltStrike_8751cdf9 or 
		Windows_Trojan_CobaltStrike_8519072e or 
		Windows_Trojan_CobaltStrike_663fc95d or 
		Windows_Trojan_CobaltStrike_b54b94ac or 
		Windows_Trojan_CobaltStrike_f0b627fc or 
		Windows_Trojan_CobaltStrike_dcdcdd8c or 
		Windows_Trojan_CobaltStrike_a3fb2616 or 
		Windows_Trojan_CobaltStrike_8ee55ee5 or 
		Windows_Trojan_CobaltStrike_8d5963a2 or 
		Windows_Trojan_CobaltStrike_1787eef5 or 
		HKTL_CobaltStrike_SleepMask_Jul22 or 
		Windows_Trojan_CobaltStrike_4106070a or 
		Windows_Trojan_CobaltStrike_3dc22d14 or 
		Windows_Trojan_CobaltStrike_7f8da98a or 
		CobaltStrikeStager
}

