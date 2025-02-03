rule Generic_ATMPot : Generic_ATMPot hardened
{
	meta:
		description = "Generic rule for Winpot aka ATMPot"
		author = "xylitol@temari.fr"
		date = "2019-02-24"
		reference = "https://securelist.com/atm-robber-winpot/89611/"

	strings:
		$api1 = {((43 53 43 43 4e 47) | (43 00 53 00 43 00 43 00 4e 00 47 00))}
		$api2 = {((43 73 63 43 6e 67 4f 70 65 6e) | (43 00 73 00 63 00 43 00 6e 00 67 00 4f 00 70 00 65 00 6e 00))}
		$api3 = {((43 73 63 43 6e 67 43 6c 6f 73 65) | (43 00 73 00 63 00 43 00 6e 00 67 00 43 00 6c 00 6f 00 73 00 65 00))}
		$string1 = {((25 64 2c 25 30 32 64 3b) | (25 00 64 00 2c 00 25 00 30 00 32 00 64 00 3b 00))}
		$hex1 = { FF 15 ?? ?? ?? ?? F6 C4 80 }
		$hex2 = { 25 31 5B ?? 2D ?? 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

