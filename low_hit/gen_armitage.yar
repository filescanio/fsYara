rule Armitage_msfconsole : hardened
{
	meta:
		description = "Detects Armitage component"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-12-24"
		modified = "2022-08-18"
		hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
		id = "9c610cd0-663e-54ea-a0f2-6c044fc45d23"

	strings:
		$s1 = {5c 75 6d 65 74 65 72 70 72 65 74 65 72 5c 75 20 3e}
		$s3 = {5e 6d 65 74 65 72 70 72 65 74 65 72 20 3e}
		$s11 = {5c 75 6d 73 66 5c 75 3e}

	condition:
		filesize < 1KB and 2 of them
}

rule Armitage_MeterpreterSession_Strings : hardened
{
	meta:
		description = "Detects Armitage component"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-12-24"
		hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
		hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"
		id = "c49fdb73-1c95-5c63-b039-2fddb77290dc"

	strings:
		$s1 = {73 65 73 73 69 6f 6e 2e 6d 65 74 65 72 70 72 65 74 65 72 5f 72 65 61 64}
		$s2 = {73 6e 69 66 66 65 72 5f 64 75 6d 70}
		$s3 = {6b 65 79 73 63 61 6e 5f 64 75 6d 70}
		$s4 = {4d 65 74 65 72 70 72 65 74 65 72 53 65 73 73 69 6f 6e 2e 6a 61 76 61}

	condition:
		filesize < 30KB and 1 of them
}

rule Armitage_OSX : hardened
{
	meta:
		description = "Detects Armitage component"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-12-24"
		hash1 = "2680d9900a057d553fcb28d84cdc41c3fc18fd224a88a32ee14c9c1b501a86af"
		hash2 = "b7b506f38d0553cd2beb4111c7ef383c821f04cee5169fed2ef5d869c9fbfab3"
		id = "e886e866-c163-56fb-9631-c586e9f23f9e"

	strings:
		$x1 = {72 65 73 6f 75 72 63 65 73 2f 63 6f 76 65 72 74 76 70 6e 2d 69 6e 6a 65 63 74 6f 72 2e 65 78 65}
		$s10 = {72 65 73 6f 75 72 63 65 73 2f 62 72 6f 77 73 65 72 70 69 76 6f 74 2e 78 36 34 2e 64 6c 6c}
		$s17 = {72 65 73 6f 75 72 63 65 73 2f 6d 73 66 72 70 63 64 5f 6e 65 77 2e 62 61 74}

	condition:
		filesize < 6000KB and 1 of them
}

