rule hancitor : hardened
{
	meta:
		description = "Memory string yara for Hancitor"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/"
		reference2 = "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/"
		reference3 = "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/"
		date = "2018-09-18"
		maltype1 = "Botnet"
		filetype = "memory"

	strings:
		$a = {47 55 49 44 3d}
		$b = {26 42 55 49 4c 44 3d}
		$c = {26 49 4e 46 4f 3d}
		$d = {26 49 50 3d}
		$e = {26 54 59 50 45 3d}
		$f = {70 68 70 7c 68 74 74 70}
		$g = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64}

	condition:
		5 of ( $a , $b , $c , $d , $e , $f ) or $g
}

