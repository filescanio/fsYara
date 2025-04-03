import "pe"

rule IceID_Bank_trojan : hardened loosened limited
{
	meta:
		description = "Detects IcedID..adjusted several times"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-14"
		vetted_family = "IceID"

	strings:
		$header = { 4D 5A }
		$magic1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? }
		$st01 = {((43 43 6d 64 54 61 72 67 65 74) | (43 00 43 00 6d 00 64 00 54 00 61 00 72 00 67 00 65 00 74 00))}
		$st02 = {((43 55 73 65 72 45 78 63 65 70 74 69 6f 6e) | (43 00 55 00 73 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00))}
		$st03 = {((46 69 6c 65 54 79 70 65) | (46 00 69 00 6c 00 65 00 54 00 79 00 70 00 65 00))}
		$st04 = {((46 6c 73 47 65 74 56 61 6c 75 65) | (46 00 6c 00 73 00 47 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00))}
		$st05 = {((41 56 43 53 68 65 6c 6c 57 72 61 70 70 65 72 40 40) | (41 00 56 00 43 00 53 00 68 00 65 00 6c 00 6c 00 57 00 72 00 61 00 70 00 70 00 65 00 72 00 40 00 40 00))}
		$st06 = {((41 56 43 43 6d 64 54 61 72 67 65 74 40 40) | (41 00 56 00 43 00 43 00 6d 00 64 00 54 00 61 00 72 00 67 00 65 00 74 00 40 00 40 00))}
		$st07 = {((41 55 43 54 68 72 65 61 64 44 61 74 61 40 40) | (41 00 55 00 43 00 54 00 68 00 72 00 65 00 61 00 64 00 44 00 61 00 74 00 61 00 40 00 40 00))}
		$st08 = {((41 56 43 55 73 65 72 45 78 63 65 70 74 69 6f 6e 40 40) | (41 00 56 00 43 00 55 00 73 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 40 00 40 00))}

	condition:
		$header at 0 and all of ( $magic* ) and 6 of ( $st0* ) and pe.sections [ 0 ] . name contains ".text" and pe.sections [ 1 ] . name contains ".rdata" and pe.sections [ 2 ] . name contains ".data" and pe.sections [ 3 ] . name contains ".rsrc" and pe.characteristics & pe.EXECUTABLE_IMAGE and pe.characteristics & pe.RELOCS_STRIPPED
}

