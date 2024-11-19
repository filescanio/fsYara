rule wezrat { 
	meta:
		description = "Identifies wezrat strings"
        author = "OPSWAT"
        score = 80
        samples = "https://research.checkpoint.com/2024/wezrat-malware-deep-dive/"
	strings:
		// random phrases for exceptions
		$st0 = "He was wearing a vest." 
		$st1 = "Nothing ever really took off. " 
		$st2 = "How big you are!" 
		$st3 = "Tigers are gorgeous. " 
		$st4 = "The newspaper got wet in the rain." 
		$st5 = "Download Part 1"
		$st6 = "Step 1"
		$st7 = "The tree fell unexpectedly short."
		$st8 = "Step A"
		$st9 = "Nobody loves a pig wearing lipstick."
		$st10 = "She works two jobs to make ends meet; at least, that was her reason for not having time to join us."
		$st11 = "The best key lime pie is still up for debate."
		$st12 = "The teens wondered what was kept in the red shed on the far edge of the school grounds."
		$st13 = "If you spin around three times, you'll start to feel melancholy."
		$st14 = "Don't put peanut butter on the dog's nose."
		// encoded, groups of three + 10 (seen in PEEXEs)
		$lib1 = "065091104100091098041040036090098098" //Kernel32.dll wide
		$lib2 = "077095100095100091106036090098098" // Wininet.dll
		$lib3 = "055090108087102095041040036090098098" // Advapi32.dll
		$api1 = "057104091087106091067107106091110077" // CreateMutexW
		$api2 = "089101100100091089106" // connect
		$api3 = "089098101105091105101089097091106" // closesocket
		$api4 = "105101089097091106" // socket
		// encoded, groups of three + 14 (seen in PEDLLs)
		$command = "085097095095083096086" // command
		$command2 = "101094087087098" // sleep
		$command3 = "086091100100" // dirr
		$command4 = "086097105096094097083086" // download
		$command5 = "103098094097083086091096089" // uploading
		$command6 = "087106087085103102087" // execute
		$command7 = "085090083096089087086097095083091096" // changedomain
		$command8 = "094091084100083100107" // library
		$explicit = "/wez/api2.php"
		$explicit2 = "/wez/api.php"
		$explicit = "wez/insert.php" fullword
	condition:
		uint16(0) == 0x5A4D and (
			2 of ($st*) or
			any of ($lib*) or
			any of ($api*) or
			any of ($command*)
			)
}
