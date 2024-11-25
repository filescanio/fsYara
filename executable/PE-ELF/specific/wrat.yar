rule wezrat_strs { 
	meta:
		description = "Identifies wezrat strings"
	        author = "OPSWAT"
	        score = 80
	        samples = "https://research.checkpoint.com/2024/wezrat-malware-deep-dive/"
		vetted_family = "wezrat"
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
		$explicit3 = "wez/insert.php" fullword
	condition:
		uint16(0) == 0x5A4D and (
			2 of ($st*) or
			any of ($lib*) or
			any of ($api*) or
			any of ($command*)  or 
			any of ($explicit*)
			)
}

rule wezrat_decodefunc_64bit {
  meta:
	author = "OPSWAT"
    score = 80
    samples = "https://research.checkpoint.com/2024/wezrat-malware-deep-dive/"
    vetted_family = "wezrat"
    //PEEXE
    sample1 = "d1820d93322351f5684c4f75b68f738f"
    sample2 = "38fa7a0b850834269dee74e90d91497b"
    sample3 = "f6f7a2f76f6f011ad4907dee787e066e"
    //PEDLL
    sample4 = "3902dc396b9e59c7eb1405a95402275d" // Dll1.pdb
    sample5 = ""
  strings:
	$stoi = "stoi argument out of range"
	$functype1 = {
			E8 ?? ?? ?? ??
			4C 8B F0
			48 8D 5C 24 40
			48 ?? ?? ?? ?? ??
			48 0F ?? 5C 24 40
			44 89 20 
			41 B8 0A 00 00 00
			48 8D 54 24 30
			48 8B CB
			E8 ?? ?? ?? ??
			(44 8B C8 | 8B D0)
			48 3B 5C 24 30
			0F 84 ?? ?? ?? ??
			41 83 3E 22
			0F 84 ?? ?? ?? ??
			( 80 C2 | 41 80 C1) ??
			48 8B 4F 10
			(48 | 4C) 8B (57|47) 18
			(49|48) 3B ??
			73 ??
			48 8D 41 ??
			48 89 47 10
			48 8B C7
			(48|49) 83 ?? ??
			(76|72) 03
			48 8B 07
			[3-4]
			C6 44 08 01 00
			EB ??
			[0-16] E8
		} 

    // potentially contains junk code
    $functype2 = {
		48 83 ?? ??
		4C ?? ??
		31 D2
		41 ?? ?? ?? ?? ??
		E8 ?? ?? ?? ??
		48 ?? ?? ??
		8B ?? ?? ?? ?? ??
		8D ?? ??
		0F ?? ??
		F7 ??
		83 ?? ??
		83 ?? ??
		0F ?? ??
		83 3D ?? ?? ?? ?? ??
		0F ?? ??
		84 CA
		75 08
		30 CA
		0F 84 ?? ?? ?? ??
		04 ??
		48 83 EC 20
		48 8B 4D E0
		89 C2
		E8 ?? ?? ?? ??
		48 83 C4 20
    	}

        $functype3 = {
        	E8 ?? ?? ?? ??
        	48 89 C3
        	48 83 [2-3]
        	49 ?? ??
        	72 04
        	4C ?? ?? ??
		C7 ?? ?? ?? ?? ??
		4C ?? ??
		48 ?? ??
		41 ?? ?? ?? ?? ??
		E8 ?? ?? ?? ??
		4C ?? ?? ??
		0F ?? ?? ?? ?? ??
		83 ?? 22
		0F ?? ?? ?? ?? ??
		04 ??
		48 ?? ?? ??
		4C ?? ?? ??
		48 ?? ?? ??
		49 ?? ??
		73 29
		4D ?? ?? ??
		4C ?? ?? ??
		49 ?? ??
		48 ?? ?? ??
		72 03
    	} 
  condition:
    $stoi and any of ($functype*)
}

