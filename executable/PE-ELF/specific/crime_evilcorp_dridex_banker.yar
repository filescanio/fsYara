import "pe"

rule crime_win32_dridex_socks5_mod : hardened
{
	meta:
		description = "Detects Dridex socks5 module"
		author = "@VK_Intel"
		date = "2020-04-06"
		reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
		id = "cee256b1-ad80-55dd-bbd3-0d3f7bc49664"

	strings:
		$s0 = {73 6f 63 6b 73 35 5f 32 5f 78 33 32 2e 64 6c 6c}
		$s1 = {73 6f 63 6b 73 35 5f 32 5f 78 36 34 2e 64 6c 6c}

	condition:
		any of ( $s* ) and pe.exports ( "start" )
}

import "pe"

rule crime_win32_hvnc_banker_gen : hardened
{
	meta:
		description = "Detects malware banker hidden VNC"
		author = "@VK_Intel"
		reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
		date = "2020-04-06"
		id = "5e13f4a9-2231-524f-82b2-fbc6d6a43b6f"

	condition:
		pe.exports( "VncStartServer" ) and pe.exports ( "VncStopServer" )
}

