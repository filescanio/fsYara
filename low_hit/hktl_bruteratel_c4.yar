rule brc4_core : hardened
{
	meta:
		version = "first version"
		author = "@ninjaparanoid"
		reference = "https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/brc4.yara"
		date = "2022-11-19"
		description = "Hunts for known strings used in Badger till release v1.2.9 when not in an encrypted state"
		id = "3a702d21-392f-5b7d-90a7-eb053d259b32"

	strings:
		$coreStrings1 = {43 4c 4f 53 45 44}
		$coreStrings2 = {4c 49 53 54 45 4e 49 4e 47}
		$coreStrings3 = {53 59 4e 5f 53 45 4e 54}
		$coreStrings4 = {53 59 4e 5f 52 43 56 44}
		$coreStrings5 = {45 53 54 41 42 4c 49 53 48 45 44}
		$coreStrings6 = {46 49 4e 5f 57 41 49 54 31}
		$coreStrings7 = {46 49 4e 5f 57 41 49 54 32}
		$coreStrings8 = {43 4c 4f 53 45 5f 57 41 49 54}
		$coreStrings9 = {43 4c 4f 53 49 4e 47}
		$coreStrings10 = {4c 41 53 54 5f 41 43 4b}
		$coreStrings11 = {54 49 4d 45 5f 57 41 49 54}
		$coreStrings12 = {44 45 4c 45 54 45 5f 54 43 42}
		$coreStrings13 = {76 34 2e 30 2e 33 30 33 31 39}
		$coreStrings14 = {62 59 58 4a 6d 2f 33 23 4d 3f 3a 58 79 4d 42 46}
		$coreStrings15 = {53 65 72 76 69 63 65 73 41 63 74 69 76 65}
		$coreStrings16 = {63 6f 66 66 65 65}
		$coreStrings17 = {55 6e 74 69 6c 20 41 64 6d 69 6e 20 55 6e 6c 6f 63 6b}
		$coreStrings18 = {61 6c 65 72 74 61 62 6c 65}
		$coreStrings19 = {25 30 32 64 25 30 32 64 25 64 5f 25 30 32 64 25 30 32 64 25 32 64 25 30 32 64 5f 25 73}
		$coreStrings20 = {3c 4c 65 66 74 2d 4d 6f 75 73 65 3e 3b}
		$coreStrings21 = {3c 52 69 67 68 74 2d 4d 6f 75 73 65 3e 3b}
		$coreStrings22 = {3c 43 61 6e 63 65 6c 3e 3b}
		$coreStrings23 = {3c 4d 69 64 64 6c 65 2d 4d 6f 75 73 65 3e 3b}
		$coreStrings24 = {3c 58 31 2d 4d 6f 75 73 65 3e 3b}
		$coreStrings25 = {3c 58 32 2d 4d 6f 75 73 65 3e 3b}
		$coreStrings26 = {3c 42 61 63 6b 53 70 61 63 65 3e 3b}
		$coreStrings27 = {3c 45 6e 74 65 72 3e 3b}
		$coreStrings28 = {3c 53 68 69 66 74 3e 3b}
		$coreStrings29 = {3c 43 54 52 4c 3e 3b}
		$coreStrings30 = {3c 41 4c 54 3e 3b}
		$coreStrings31 = {3c 50 61 75 73 65 3e 3b}
		$coreStrings32 = {3c 43 61 70 73 2d 4c 6f 63 6b 3e 3b}
		$coreStrings33 = {3c 45 53 43 3e 3b}
		$coreStrings34 = {3c 50 61 67 65 2d 55 70 3e 3b}
		$coreStrings35 = {3c 50 61 67 65 2d 44 6f 77 6e 3e 3b}
		$coreStrings36 = {3c 45 6e 64 3e 3b}
		$coreStrings37 = {3c 48 6f 6d 65 2d 4b 65 79 3e 3b}
		$coreStrings38 = {3c 4c 65 66 74 2d 41 72 72 6f 77 3e 3b}
		$coreStrings39 = {3c 55 70 2d 41 72 72 6f 77 3e 3b}
		$coreStrings40 = {3c 52 69 67 68 74 2d 41 72 72 6f 77 3e 3b}
		$coreStrings41 = {3c 44 6f 77 6e 2d 41 72 72 6f 77 3e 3b}
		$coreStrings42 = {3c 53 65 6c 65 63 74 3e 3b}
		$coreStrings43 = {3c 50 72 69 6e 74 2d 4b 65 79 3e 3b}
		$coreStrings44 = {3c 50 72 69 6e 74 2d 53 63 72 65 65 6e 3e 3b}
		$coreStrings45 = {3c 49 4e 53 3e 3b}
		$coreStrings46 = {3c 44 65 6c 65 74 65 3e 3b}
		$coreStrings47 = {3c 48 65 6c 70 3e 3b}
		$coreStrings48 = {3c 4c 65 66 74 2d 57 69 6e 64 6f 77 73 2d 4b 65 79 3e 3b}
		$coreStrings49 = {3c 52 69 67 68 74 2d 57 69 6e 64 6f 77 73 2d 4b 65 79 3e 3b}
		$coreStrings50 = {3c 43 6f 6d 70 75 74 65 72 2d 53 6c 65 65 70 3e 3b}
		$coreStrings51 = {3c 46 31 3e 3b}
		$coreStrings52 = {3c 46 32 3e 3b}
		$coreStrings53 = {3c 46 33 3e 3b}
		$coreStrings54 = {3c 46 34 3e 3b}
		$coreStrings55 = {3c 46 35 3e 3b}
		$coreStrings56 = {3c 46 36 3e 3b}
		$coreStrings57 = {3c 46 37 3e 3b}
		$coreStrings58 = {3c 46 38 3e 3b}
		$coreStrings59 = {3c 46 39 3e 3b}
		$coreStrings60 = {3c 46 31 30 3e 3b}
		$coreStrings61 = {3c 46 31 31 3e 3b}
		$coreStrings62 = {3c 46 31 32 3e 3b}
		$coreStrings63 = {3c 46 31 33 3e 3b}
		$coreStrings64 = {3c 46 31 34 3e 3b}
		$coreStrings65 = {3c 46 31 35 3e 3b}
		$coreStrings66 = {3c 46 31 36 3e 3b}
		$coreStrings67 = {3c 46 31 37 3e 3b}
		$coreStrings68 = {3c 46 31 38 3e 3b}
		$coreStrings69 = {3c 46 31 39 3e 3b}
		$coreStrings70 = {3c 46 32 30 3e 3b}
		$coreStrings71 = {3c 46 32 31 3e 3b}
		$coreStrings72 = {3c 46 32 32 3e 3b}
		$coreStrings73 = {3c 46 32 33 3e 3b}
		$coreStrings74 = {3c 46 32 34 3e 3b}
		$coreStrings75 = {3c 4e 75 6d 2d 4c 6f 63 6b 3e 3b}
		$coreStrings76 = {3c 53 63 72 6f 6c 6c 2d 4c 6f 63 6b 3e 3b}
		$coreStrings77 = {3c 43 6f 6e 74 72 6f 6c 3e 3b}
		$coreStrings78 = {3c 4d 65 6e 75 3e 3b}
		$coreStrings79 = {3c 56 6f 6c 75 6d 65 20 4d 75 74 65 3e 3b}
		$coreStrings80 = {3c 56 6f 6c 75 6d 65 20 44 6f 77 6e 3e 3b}
		$coreStrings81 = {3c 56 6f 6c 75 6d 65 20 55 70 3e 3b}
		$coreStrings82 = {3c 4e 65 77 20 54 72 61 63 6b 3e 3b}
		$coreStrings83 = {3c 50 72 65 76 69 6f 75 73 20 54 72 61 63 6b 3e 3b}
		$coreStrings84 = {3c 50 6c 61 79 2f 50 61 75 73 65 3e 3b}
		$coreStrings85 = {3c 50 6c 61 79 3e 3b}
		$coreStrings86 = {3c 5a 6f 6f 6d 3e 3b}
		$coreStrings87 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58}
		$coreStrings88 = {25 30 32 64 25 30 32 64 25 64 5f 25 30 32 64 25 30 32 64 25 32 64 25 30 32 64 2e 70 6e 67}
		$coreStrings89 = {25 30 32 64 2d 25 30 32 64 2d 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 32 64}
		$coreStrings90 = {25 6c 73 25 73 25 6c 73 25 73 25 6c 73 25 73 25 6c 73 25 6c 75 25 6c 73 25 73 25 73}
		$coreStrings91 = {25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 6c 73 25 64 25 6c 73 25 6c 75 25 6c 73}
		$coreStrings92 = {62 68 74 74 70 5f 78 36 34 2e 64 6c 6c}
		$coreStrings93 = {20 20 2d 20 25 2d 34 35 6c 73 20 3a 20 25 64}
		$coreStrings94 = {20 20 2d 20 25 2d 34 35 6c 73 20 3a 20 25 6c 73}
		$coreStrings95 = {20 20 2d 20 25 2d 34 35 6c 73 20 3a 20 25 6c 6c 75}
		$coreStrings96 = {20 20 2d 20 25 2d 34 35 6c 73 20 3a 20 25 75}
		$coreStrings97 = {20 20 2d 20 25 2d 34 35 6c 73 20 3a 20 25 66}
		$coreStrings98 = {20 20 2d 20 25 2d 34 35 6c 73 20 3a 20 25 53}
		$coreStrings99 = {20 20 2d 20 50 61 74 68 3a 20 25 6c 73}
		$coreStrings100 = {20 20 2d 20 45 6e 61 62 6c 65 64 3a 20 25 6c 73}
		$coreStrings101 = {20 20 2d 20 4c 61 73 74 20 52 75 6e 3a 20 25 6c 73}
		$coreStrings102 = {20 20 2d 20 4e 65 78 74 20 52 75 6e 3a 20 25 6c 73}
		$coreStrings103 = {20 20 2d 20 43 75 72 72 65 6e 74 20 53 74 61 74 65 3a 20 25 6c 73}
		$coreStrings104 = {20 20 2d 20 58 4d 4c 20 4f 75 74 70 75 74 3a}
		$coreStrings105 = {20 20 2d 20 45 72 72 6f 72 20 66 65 74 63 68 69 6e 67 20 78 6d 6c}
		$coreStrings106 = {5b 2b 5d 20 4e 61 6d 65 3a 20 25 6c 73}
		$coreStrings107 = {5b 2b 5d 20 54 61 73 6b 3a 20 25 6c 64}
		$coreStrings108 = {20 20 2d 20 4e 61 6d 65 3a 20 25 6c 73}
		$coreStrings109 = {42 59 54 45 20 64 61 74 61 5b 5d 20 3d 20 7b}
		$coreStrings110 = {5b 2b 5d 20 25 73 20 50 61 73 73 77 6f 72 64 20 48 69 73 74 6f 72 79 3a}
		$coreStrings111 = {5b 2b 5d 20 4f 62 6a 65 63 74 20 52 44 4e 3a 20}
		$coreStrings112 = {5b 2b 5d 20 53 41 4d 20 55 73 65 72 6e 61 6d 65 3a 20}
		$coreStrings113 = {5b 2b 5d 20 55 73 65 72 20 50 72 69 6e 63 69 70 61 6c 20 4e 61 6d 65 3a 20}
		$coreStrings114 = {5b 2b 5d 20 55 41 43 3a 20 25 30 38 78 20 5b}
		$coreStrings115 = {5b 2b 5d 20 50 61 73 73 77 6f 72 64 20 6c 61 73 74 20 63 68 61 6e 67 65 3a 20}
		$coreStrings116 = {5b 2b 5d 20 53 49 44 20 68 69 73 74 6f 72 79 3a}
		$coreStrings117 = {5b 2b 5d 20 4f 62 6a 65 63 74 20 53 49 44 3a 20}
		$coreStrings118 = {5b 2b 5d 20 4f 62 6a 65 63 74 20 52 49 44 3a 20 25 75}
		$coreStrings119 = {5b 2d 5d 20 45 3a 20 30 78 25 30 38 78 20 28 25 75 29 20 2d 20 25 73}
		$coreStrings120 = {5b 2d 5d 20 45 3a 20 6e 6f 20 69 74 65 6d 21}
		$coreStrings121 = {5b 2d 5d 20 45 3a 20 62 61 64 20 76 65 72 73 69 6f 6e 20 28 25 75 29}
		$coreStrings122 = {5b 2d 5d 20 45 3a 20 30 78 25 30 38 78 20 28 25 75 29}
		$coreStrings123 = {5b 2d 5d 20 45 3a 20 28 25 30 38 78 29}
		$coreStrings124 = {5b 2d 5d 20 45 3a 20 44 52 53 20 45 78 74 65 6e 73 69 6f 6e 20 53 69 7a 65 20 28 25 75 29}
		$coreStrings125 = {5b 2d 5d 20 45 3a 20 4e 6f 20 44 52 53 20 45 78 74 65 6e 73 69 6f 6e}
		$coreStrings126 = {5b 2d 5d 20 45 3a 20 44 52 53 42 69 6e 64 20 28 25 75 29}
		$coreStrings127 = {5b 2d 5d 20 45 3a 20 44 43 20 27 25 73 27 20 6e 6f 74 20 66 6f 75 6e 64}
		$coreStrings128 = {5b 2d 5d 20 45 3a 20 56 65 72 73 69 6f 6e 20 28 25 75 29}
		$coreStrings129 = {5b 2d 5d 20 45 3a 20 30 78 25 30 38 78}
		$coreStrings130 = {5b 2d 5d 20 45 3a 20 44 43 20 6e 6f 74 20 66 6f 75 6e 64}
		$coreStrings131 = {5b 2d 5d 20 45 3a 20 42 69 6e 64 69 6e 67 20 44 43 21}
		$coreStrings132 = {5b 2d 5d 20 45 3a 20 25 75}
		$coreStrings133 = {5b 2d 5d 20 45 3a 20 44 6f 6d 61 69 6e 20 6e 6f 74 20 66 6f 75 6e 64}
		$coreStrings134 = {5b 2b 5d 20 53 79 6e 63 69 6e 67 20 44 43 3a 20 25 6c 73}
		$coreStrings135 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 7c}
		$coreStrings136 = {5b 2d 5d 20 45 3a 20 4e 43 43 68 61 6e 67 65 73 52 65 70 6c 79}
		$coreStrings137 = {5b 2d 5d 20 45 3a 20 47 65 74 4e 43 43 68 61 6e 67 65 73 20 28 25 75 29}
		$coreStrings138 = {5b 2d 5d 20 45 3a 20 47 65 74 4e 43 43 68 61 6e 67 65 73 3a 20 30 78 25 30 38 78}
		$coreStrings139 = {5b 2d 5d 20 45 3a 20 41 53 4e 31}
		$coreStrings140 = {5b 64 73 79 6e 5d}
		$coreStrings141 = {5b 2b 5d 20 73 69 7a 65 20 20 20 20 20 20 20 20 20 3a 20 25 6c 75}
		$coreStrings142 = {5b 2b 5d 20 6d 61 6c 6c 6f 63 20 28 52 58 29 20 20 3a 20 30 78 25 70}
		$coreStrings143 = {5b 2b 5d 20 6d 61 6c 6c 6f 63 20 28 52 57 29 20 20 3a 20 30 78 25 70}
		$coreStrings144 = {5b 2b 5d 20 73 69 7a 65 20 20 20 20 20 20 20 20 3a 20 25 6c 75}
		$coreStrings145 = {5b 2b 5d 20 6d 61 70 76 69 65 77 20 28 52 58 29 3a 20 30 78 25 70}
		$coreStrings146 = {5b 2b 5d 20 6d 61 70 76 69 65 77 20 28 52 57 29 3a 20 30 78 25 70}
		$coreStrings147 = {5b 2d 5d 20 49 6e 76 61 6c 69 64 20 74 68 72 65 61 64}
		$coreStrings148 = {5b 2b 5d 20 54 68 72 65 61 64 20 73 74 61 72 74 20 3a 20 30 78 25 70}
		$coreStrings149 = {5b 2b 5d 20 54 68 72 65 61 64 20 49 64 20 20 20 20 3a 20 25 6c 75}
		$coreStrings150 = {20 20 2d 20 65 78 70 69 72 65 73 20 61 74 3a 20 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64}
		$coreStrings151 = {25 2d 33 30 6c 73 25 2d 33 30 6c 73 25 6c 73}
		$coreStrings152 = {25 2d 33 30 53 2a 25 2d 32 39 6c 73 25 30 34 64 20 68 6f 75 72 73}
		$coreStrings153 = {25 2d 33 30 53 25 2d 33 30 6c 73 25 30 34 64 20 68 6f 75 72 73}
		$coreStrings154 = {5b 2b 5d 20 55 73 65 72 20 69 73 20 70 72 69 76 69 6c 65 67 65 64}
		$coreStrings155 = {5b 2b 5d 20 4d 65 6d 62 65 72 73 20 6f 66 20 5b 25 6c 73 5d 20 69 6e 20 25 6c 73}
		$coreStrings156 = {5b 2b 5d 20 4d 65 6d 62 65 72 73 20 6f 66 20 5b 25 6c 73 5d}
		$coreStrings157 = {70 5b 2b 5d 20 41 6c 65 72 74 61 62 6c 65 20 74 68 72 65 61 64 3a 20 25 6c 75}
		$coreStrings158 = {5b 2d 5d 20 45 3a 20 4e 6f 20 41 6c 65 72 74 61 62 6c 65 20 74 68 72 65 61 64 73}
		$coreStrings159 = {5b 21 5d 20 51 41 50 43 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64 20 6f 6e 20 65 78 69 73 74 69 6e 67 20 70 72 6f 63 65 73 73}
		$coreStrings160 = {5b 2b 5d 20 50 49 44 20 28 25 53 29 20 3d 3e 20 25 6c 75}
		$coreStrings161 = {5b 2b 5d 20 50 50 49 44 20 3d 3e 20 25 6c 75}
		$coreStrings162 = {5b 2b 5d 20 50 49 44 20 28 25 53 29 20 3d 3e 20 25 6c 75}
		$coreStrings163 = {5b 2b 5d 20 41 72 67 73 20 3d 3e 20 28 25 53 29}
		$coreStrings164 = {5b 2b 5d 20 50 50 49 44 20 3d 3e 20 25 6c 75}
		$coreStrings165 = {5b 2b 5d 20 25 53 20 3d 3e 20 50 49 44 3a 20 25 6c 75}
		$coreStrings166 = {5b 2b 5d 20 25 53 20 3d 3e 20 50 49 44 20 28 53 75 73 70 65 6e 64 65 64 29 3a 20 25 6c 75 3a 25 6c 75}
		$coreStrings167 = {5b 2b 5d 20 53 59 53 20 6b 65 79 3a 20}
		$coreStrings168 = {5b 2b 5d 20 53 41 4d 20 6b 65 79 3a 20}
		$coreStrings169 = {76 32 2e 30 2e 35 30 37 32 37}
		$coreStrings170 = {76 34 2e 30 2e 33 30 33 31 39}
		$coreStrings171 = {5b 2b 5d 20 44 6f 74 6e 65 74 3a 20 76}
		$coreStrings172 = {5b 2b 5d 20 53 6f 63 6b 73 20 73 74 61 72 74 65 64}
		$coreStrings173 = {5b 2d 5d 20 53 6f 63 6b 73 20 73 74 6f 70 70 65 64 20 61 6e 64 20 50 72 6f 66 69 6c 65 20 63 6c 65 61 72 65 64}
		$coreStrings174 = {5b 2b 5d 20 53 74 61 73 69 73 3a 20 25 64 3a 25 64}
		$coreStrings175 = {3c 44 49 52 3e 3f 25 6c 73 3f 25 30 32 64 2d 25 30 32 64 2d 25 64 20 25 30 32 64 3a 25 30 32 64}
		$coreStrings176 = {3c 44 49 52 3e 3f 25 6c 73}
		$coreStrings177 = {3c 46 49 4c 45 3e 3f 25 6c 73 3f 25 30 32 64 2d 25 30 32 64 2d 25 64 20 25 30 32 64 3a 25 30 32 64 3f 25 6c 6c 64 20 62 79 74 65 73}
		$coreStrings178 = {3c 46 49 4c 45 3e 3f 25 6c 73}
		$coreStrings179 = {5b 2b 5d 20 6c 69 73 74 69 6e 67 20 25 6c 73}
		$coreStrings180 = {25 30 32 64 2d 25 30 32 64 2d 25 64 20 25 30 32 64 3a 25 30 32 64 20 3c 44 49 52 3e 20 20 25 6c 73}
		$coreStrings181 = {25 30 32 64 2d 25 30 32 64 2d 25 64 20 25 30 32 64 3a 25 30 32 64 20 3c 46 49 4c 45 3e 20 25 6c 73 20 25 6c 6c 64 20 62 79 74 65 73}
		$coreStrings182 = {5b 2b 5d 20 50 49 44 3a 20 25 64}
		$coreStrings183 = {5b 2b 5d 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 3a 20 27 25 53 5c 25 53 27}
		$coreStrings184 = {5b 2b 5d 20 4b 69 6c 6c 65 64 3a 20 25 6c 75}
		$coreStrings185 = {25 6c 73 25 2d 38 6c 73 20 7c 20 25 2d 38 6c 73 20 7c 20 25 2d 36 6c 73 20 7c 20 25 2d 33 30 6c 73 20 09 7c 20 25 6c 73}
		$coreStrings186 = {5b 70 73 74 72 65 65 5d 20 25 53}
		$coreStrings187 = {36 25 64 3f 25 64 3f 25 53 3f 25 6c 73 3f 25 6c 73}
		$coreStrings188 = {25 2d 38 64 20 7c 20 25 2d 38 64 20 7c 20 25 2d 36 53 20 7c 20 25 2d 33 30 6c 73 20 09 7c 20 25 6c 73}
		$coreStrings189 = {25 64 3f 25 64 3f 4e 2f 41 3f 4e 2f 41 3f 25 6c 73}
		$coreStrings190 = {25 2d 38 64 20 7c 20 25 2d 38 64 20 7c 20 25 2d 36 6c 73 20 7c 20 25 2d 33 30 6c 73 20 09 7c 20 25 6c 73}
		$coreStrings191 = {5b 2d 5d 20 43 68 69 6c 64 20 50 72 6f 63 65 73 73 3f 3f 3f}
		$coreStrings192 = {5b 2b 5d 20 50 49 44 3a 20 25 6c 75}
		$coreStrings193 = {5b 2b 5d 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 20 27 25 6c 73 27}
		$coreStrings194 = {5b 2d 5d 20 44 75 70 6c 69 63 61 74 65 20 6c 69 73 74 65 6e 65 72 3a 20 25 53}
		$coreStrings195 = {5b 2b 5d 20 54 43 50 20 6c 69 73 74 65 6e 65 72 3a 20 25 53}
		$coreStrings196 = {5b 54 43 50 5d 20 5b 25 53 5d 2d 3c 3e 2d 5b 25 53 5d}
		$coreStrings197 = {5b 2b 5d 20 41 64 64 65 64 20 74 6f 20 54 6f 6b 65 6e 20 56 61 75 6c 74 3a 20 25 6c 73}
		$coreStrings198 = {5b 2d 5d 20 45 3a 20 49 6e 76 61 6c 69 64 20 41 72 63 68 3a 20 30 78 25 58}
		$coreStrings199 = {5b 2b 5d 20 53 65 61 72 63 68 69 6e 67 20 5b 30 78 25 30 32 58 5d 20 70 65 72 6d 69 73 73 69 6f 6e}
		$coreStrings200 = {5b 2d 5d 20 53 50 4e 20 6e 6f 74 20 66 6f 75 6e 64 3a 20 25 6c 73}
		$coreStrings201 = {5b 2d 5d 20 49 6e 76 61 6c 69 64 20 53 50 4e 3a 20 25 53}
		$coreStrings202 = {5b 2b 5d 20 53 50 4e 3a 20 25 6c 73}
		$coreStrings203 = {5b 2b 5d 20 53 74 61 72 74 20 41 64 64 72 65 73 73 3a 20 28 25 70 29}
		$coreStrings204 = {5b 21 5d 20 49 6e 76 61 6c 69 64 20 41 64 64 72 65 73 73}
		$coreStrings205 = {5b 21 5d 20 49 6e 76 61 6c 69 64 20 50 49 44 3a 20 25 53}
		$coreStrings206 = {5b 2b 5d 20 50 49 44 3a 20 25 6c 75}
		$coreStrings207 = {5b 2b 5d 20 54 49 44 3a 20 25 6c 75}
		$coreStrings208 = {5b 2b 5d 20 54 2d 48 61 6e 64 6c 65 3a 20 30 78 25 58}
		$coreStrings209 = {5b 2b 5d 20 53 75 73 70 65 6e 64 20 63 6f 75 6e 74 3a 20 25 6c 75}
		$coreStrings210 = {5b 2b 5d 20 25 2d 32 34 6c 73 25 2d 32 34 6c 73 25 2d 32 34 6c 73}
		$coreStrings211 = {25 2d 36 36 6c 73 25 2d 34 36 6c 73 25 6c 73}
		$coreStrings212 = {20 20 20 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$coreStrings213 = {5b 2b 5d 20 45 6c 65 76 61 74 65 64 20 50 72 69 76 69 6c 65 67 65}
		$coreStrings214 = {5b 2d 5d 20 52 65 73 74 72 69 63 74 65 64 20 50 72 69 76 69 6c 65 67 65}
		$coreStrings215 = {5b 2b 5d 20 54 61 73 6b 2d 25 64 20 3d 3e 20 25 53 20 28 25 53 20 25 25 29}
		$coreStrings216 = {5b 54 61 73 6b 73 5d 20 25 30 32 64 20 3d 3e 20 30 78 25 30 32 58 20 30 78 25 30 32 58}
		$coreStrings217 = {5b 2a 5d 20 4e 6f 20 61 63 74 69 76 65 20 74 61 73 6b 73}
		$coreStrings218 = {5b 2d 5d 20 43 68 69 6c 64 3a 20 4e 41}
		$coreStrings219 = {5b 2b 5d 20 43 68 69 6c 64 3a 20 25 53}
		$coreStrings220 = {5b 54 43 50 5d 20 54 61 73 6b 2d 25 64 20 3d 3e 20 25 53}
		$coreStrings221 = {5b 2b 5d 20 4d 61 6c 6c 6f 63 3a 20 25 6c 75}
		$coreStrings222 = {5b 2b 5d 20 54 68 72 65 61 64 45 78 3a 20 25 6c 75}
		$coreStrings223 = {5b 2b 5d 20 25 2d 33 30 6c 73 3a 20 25 53}
		$coreStrings224 = {5b 2b 5d 20 25 2d 33 30 6c 73 3a 20 25 53}
		$coreStrings225 = {5b 2b 5d 20 25 2d 33 30 6c 73 3a 20}
		$coreStrings226 = {5b 2b 5d 20 25 2d 33 30 6c 73 3a 20 25 6c 73}
		$coreStrings227 = {20 20 2d 20 25 2d 36 53 20 25 2d 32 32 53 20 25 2d 32 32 53 20 25 53}
		$coreStrings228 = {20 20 2d 20 25 2d 36 53 20 25 2d 32 32 53 20 25 2d 32 32 53}
		$coreStrings229 = {20 20 2d 20 30 78 25 6c 75 20 5b 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 5d 20 25 53}
		$coreStrings230 = {20 20 25 2d 32 31 53 25 2d 31 37 53 25 2d 31 37 53 25 2d 31 31 53 25 2d 31 30 53}
		$coreStrings231 = {20 20 2d 20 25 2d 31 39 53 25 2d 31 37 53 25 2d 31 37 53 25 2d 31 31 6c 64 25 2d 39 6c 64}
		$coreStrings232 = {20 20 2d 20 25 2d 33 30 6c 73 3a 20 25 49 36 34 64 4d 42 2f 25 49 36 34 64 4d 42}
		$coreStrings233 = {20 20 2d 20 25 2d 33 30 6c 73 3a 20 25 6c 75 20 4d 42}
		$coreStrings234 = {5b 2b 5d 20 43 4d 3a 20 41 6c 72 65 61 64 79 20 52 75 6e 6e 69 6e 67}
		$coreStrings235 = {5b 2b 5d 20 43 4d 3a 20 52 75 6e 6e 69 6e 67}
		$coreStrings236 = {5b 2b 5d 20 43 4d 3a 20 53 74 61 72 74 65 64}
		$coreStrings237 = {5b 2a 5d 20 54 61 73 6b 2d 25 30 32 64 20 5b 54 68 72 65 61 64 3a 20 25 6c 75 5d}
		$coreStrings238 = {2b 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2b}
		$coreStrings239 = {5b 2b 5d 20 53 65 73 73 69 6f 6e 20 49 44 20 25 6c 75 20 3d 3e 20 25 6c 73 3a 20 25 6c 73 5c 25 6c 73}
		$coreStrings240 = {5b 2b 5d 20 45 6e 75 6d 65 72 61 74 69 6e 67 20 50 49 44 3a 20 25 6c 75 20 5b 25 6c 73 5d}
		$coreStrings241 = {5b 2b 5d 20 43 61 70 74 75 72 65 64 20 48 61 6e 64 6c 65 20 28 50 49 44 3a 20 25 6c 75 29}
		$coreStrings242 = {5b 2b 5d 20 49 6e 69 74 69 61 74 65 64 20 4e 54 46 53 20 74 72 61 6e 73 61 63 74 69 6f 6e}
		$coreStrings243 = {5c 3f 3f 5c 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 63 68 65 2e 74 78 74}
		$coreStrings244 = {5b 2b 5d 20 44 75 6d 70 20 53 69 7a 65 3a 20 25 64 20 4d 62}
		$coreStrings245 = {62 68 74 74 70 5f 78 36 34 2e 64 6c 6c}
		$coreStrings246 = {62 59 58 4a 6d 2f 33 23 4d 3f 3a 58 79 4d 42 46}
		$coreStrings247 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65}

	condition:
		20 of them
}

import "pe"

rule brc4_shellcode : hardened
{
	meta:
		version = "last version"
		author = "@ninjaparanoid"
		description = "Hunts for shellcode opcode used in Badger x86/x64 till release v1.2.9"
		arch_context = "x64"
		reference = "https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/brc4.yara"
		date = "2022-11-19"
		id = "7e899d2f-332b-53f7-b9e6-cfde2bce6223"

	strings:
		$shellcode_x64_Start = { 55 50 53 51 52 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 }
		$shellcode_x64_End = { 5B 5E 5F 41 5C 41 5D 41 5E 41 5F 5D C3 }
		$shellcode_x64_StageEnd = { 5C 41 5F 41 5E 41 5D 41 5C 41 5B 41 5A 41 59 41 58 5F 5E 5A 59 5B 58 5D C3 }
		$funcHash1 = { 5B BC 4A 6A }
		$funcHash2 = { 5D 68 FA 3C }
		$funcHash3 = { AA FC 0D 7C }
		$funcHash4 = { 8E 4E 0E EC }
		$funcHash5 = { B8 12 DA 00 }
		$funcHash6 = { 07 C4 4C E5 }
		$funcHash7 = { BD CA 3B D3 }
		$funcHash8 = { 89 4D 39 8C }
		$hashFuncx64 = { EB 20 0F 1F 44 00 00 44 0F B6 C8 4C 89 DA 41 83 E9 20 4D 63 C1 4B 8D 04 10 49 39 CB 74 21 49 83 C3 01 41 89 C2 }
		$hashFuncx86 = { EB 07 8D 74 26 00 83 C2 01 0F B6 31 C1 C8 0D 89 F1 8D 5C 30 E0 01 F0 80 F9 61 89 D1 0F 43 C3 39 D7 75 E3 }

	condition:
		(pe.machine == pe.MACHINE_AMD64 and ( 2 of ( $shellcode* ) or all of ( $funcHash* ) and $hashFuncx64 ) ) or ( pe.machine == pe.MACHINE_I386 and ( all of ( $funcHash* ) and $hashFuncx86 ) )
}

