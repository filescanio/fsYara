// source: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/webshells/WShell_THOR_Webshells.yar
// This yara ruleset has been modified to remove the plaintext strings, converted to their hex format

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*

   THOR APT Scanner - Web Shells Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150122

*/
// rule Weevely_Webshell : webshell
// {
// 	meta:
// 		description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
// 		author = "Florian Roth"
// 		reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
// 		date = "2014/12/14"
// 		score = 60

// 	strings:
// 		$php = {3C 3F 70 68 70}
// 		$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
// 		$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
// 		$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
// 		$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii

// 	condition:
// 		$php at 0 and all of ($s*) and filesize >570 and filesize <800
// }

// rule webshell_h4ntu_shell_powered_by_tsoi_ : webshell
// {
// 	meta:
// 		description = "Web Shell - file h4ntu shell [powered by tsoi].php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "06ed0b2398f8096f1bebf092d0526137"

// 	strings:
// 		$s0 = {20 20 3C 54 44 3E 3C 44 49 56 20 53 54 59 4C 45 3D 5C 22 66 6F 6E 74 2D 66 61 6D 69 6C 79 3A 20 76 65 72 64 61 6E 61 3B 20 66 6F 6E 74 2D 73 69 7A 65 3A 20 31 30 70 78 3B 5C 22 3E 3C 62 3E 53 65 72 76 65 72 20 41 64 72 65 73 73 3A 3C 2F 62}
// 		$s3 = {20 20 3C 54 44 3E 3C 44 49 56 20 53 54 59 4C 45 3D 5C 22 66 6F 6E 74 2D 66 61 6D 69 6C 79 3A 20 76 65 72 64 61 6E 61 3B 20 66 6F 6E 74 2D 73 69 7A 65 3A 20 31 30 70 78 3B 5C 22 3E 3C 62 3E 55 73 65 72 20 49 6E 66 6F 3A 3C 2F 62 3E 20 75 69}
// 		$s4 = {20 20 20 20 3C 54 44 3E 3C 44 49 56 20 53 54 59 4C 45 3D 5C 22 66 6F 6E 74 2D 66 61 6D 69 6C 79 3A 20 76 65 72 64 61 6E 61 3B 20 66 6F 6E 74 2D 73 69 7A 65 3A 20 31 30 70 78 3B 5C 22 3E 3C 3F 3D 20 24 69 6E 66 6F 20 3F 3E 3A 20 3C 3F 3D 20}
// 		$s5 = {3C 49 4E 50 55 54 20 54 59 50 45 3D 5C 22 74 65 78 74 5C 22 20 4E 41 4D 45 3D 5C 22 63 6D 64 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 73 74 72 69 70 73 6C 61 73 68 65 73 28 68 74 6D 6C 65 6E 74 69 74 69 65 73 28 24}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_sql : webshell
// {
// 	meta:
// 		description = "Web Shell - file sql.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "2cf20a207695bbc2311a998d1d795c35"

// 	strings:
// 		$s0 = {24 72 65 73 75 6C 74 3D 6D 79 73 71 6C 5F 6C 69 73 74 5F 74 61 62 6C 65 73 28 24 64 62 29 20 6F 72 20 64 69 65 20 28 5C 22 24 68 5F 65 72 72 6F 72 3C 62 3E 5C 22 2E 6D 79 73 71 6C 5F 65 72 72 6F 72 28 29 2E 5C 22 3C 2F 62 3E 24 66 5F}
// 		$s4 = {70 72 69 6E 74 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 3F 73 3D 24 73 26 6C 6F 67 69 6E 3D 24 6C 6F 67 69 6E 26 70 61 73 73 77 64 3D 24 70 61 73 73 77 64 26}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_a : webshell
// {
// 	meta:
// 		description = "Web Shell - file a.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "e3b461f7464d81f5022419d87315a90d"

// 	strings:
// 		$s1 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 5C 22 2E 20 73 74 72 72 65 76 28 73 75 62 73 74 72 28 73 74 72 73 74 72 28 73 74 72 72 65 76 28 24 77 6F 72 6B 5F 64 69 72 29 2C 20 5C 22 2F 5C 22}
// 		$s2 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 77 6F 72 6B 5F 64 69 72 5C 5C 5C 22 20 73 65 6C 65 63 74 65 64 3E 43 75 72 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E}
// 		$s4 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 73 75 62 6D 69 74 5F 62 74 6E 5C 22 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 45 78 65 63 75 74 65 20 43 6F 6D 6D 61 6E 64 5C 22 3E 3C 2F 70 3E 20}

// 	condition:
// 		2 of them
// }

// rule webshell_iMHaPFtp_2 : webshell
// {
// 	meta:
// 		description = "Web Shell - file iMHaPFtp.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "12911b73bc6a5d313b494102abcf5c57"

// 	strings:
// 		$s8 = {69 66 20 28 24 6C 29 20 65 63 68 6F 20 27 3C 61 20 68 72 65 66 3D 5C 22 27 20 2E 20 24 73 65 6C 66 20 2E 20 27 3F 61 63 74 69 6F 6E 3D 70 65 72 6D 69 73 73 69 6F 6E 26 61 6D 70 3B 66 69 6C 65 3D 27 20 2E 20 75 72 6C 65 6E 63 6F 64 65 28 24}
// 		$s9 = {72 65 74 75 72 6E 20 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27 52 30 6C 47 4F 44 6C 68 45 51 41 4E 41 4A 45 44 41 4D 77 41 41 50 2F 2F 2F 35 6D 5A 6D 66 2F 2F 2F 79 48 35 42 41 48 6F 41 77 4D 41 4C 41 41 41 41 41 41 52 41 41 30 41 41 41}

// 	condition:
// 		1 of them
// }

// rule webshell_Jspspyweb : webshell
// {
// 	meta:
// 		description = "Web Shell - file Jspspyweb.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "4e9be07e95fff820a9299f3fb4ace059"

// 	strings:
// 		$s0 = {20 20 20 20 20 20 6F 75 74 2E 70 72 69 6E 74 28 5C 22 3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 27 36 30 25 27 3E 5C 22 2B 73 74 72 43 75 74 28 63 6F 6E 76 65 72 74 50 61 74 68 28 6C 69 73 74 5B 69 5D 2E 67 65 74 50 61 74 68 28 29 29 2C 37}
// 		$s3 = {20 20 5C 22 72 65 67 20 61 64 64 20 5C 5C 5C 22 48 4B 45 59 5F 4C 4F 43 41 4C 5F 4D 41 43 48 49 4E 45 5C 5C 5C 5C 53 59 53 54 45 4D 5C 5C 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 5C 5C 43 6F 6E 74 72 6F 6C}

// 	condition:
// 		all of them
// }

// rule webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 : webshell
// {
// 	meta:
// 		description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "49ad9117c96419c35987aaa7e2230f63"

// 	strings:
// 		$s0 = {64 69 65 28 5C 22 5C 5C 6E 57 65 6C 63 6F 6D 65 2E 2E 20 42 79 20 54 68 69 73 20 73 63 72 69 70 74 20 79 6F 75 20 63 61 6E 20 6A 75 6D 70 20 69 6E 20 74 68 65 20 28 53 61 66 65 20 4D 6F 64 65 3D 4F 4E 29 20 2E 2E 20 45 6E 6A 6F 79 5C 5C 6E}
// 		$s1 = {4D 6F 64 65 20 53 68 65 6C 6C 20 76 31 2E 30 3C 2F 66 6F 6E 74 3E 3C 2F 73 70 61 6E 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 57 65 62 64 69 6E 67 73 5C 22 20 73 69 7A 65 3D 5C 22 36 5C 22 20 63 6F 6C 6F 72}

// 	condition:
// 		1 of them
// }

// rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend : webshell
// {
// 	meta:
// 		description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "089ff24d978aeff2b4b2869f0c7d38a3"

// 	strings:
// 		$s2 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 3F 69 64 3D 66 6D 26 66 63 68 6D 6F 64 3D 24 64 69 72 24 66 69 6C 65 27 3E 3C 73 70 61 6E 20 73 74 79 6C 65 3D 27 74 65 78 74 2D 64 65 63 6F 72 61 74 69 6F 6E 3A 20 6E 6F 6E 65 27 3E 3C 66 6F}
// 		$s3 = {66 70 75 74 73 20 28 24 66 70 20 2C 5C 22 5C 5C 6E 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 5C 5C 6E 57 65 6C 63 6F 6D 65 20 54 30 20 53 69 6D}

// 	condition:
// 		1 of them
// }

// rule webshell_phpshell_2_1_pwhash : webshell
// {
// 	meta:
// 		description = "Web Shell - file pwhash.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "ba120abac165a5a30044428fac1970d8"

// 	strings:
// 		$s1 = {3C 74 74 3E 26 6E 62 73 70 3B 3C 2F 74 74 3E 5C 22 20 28 73 70 61 63 65 29 2C 20 5C 22 3C 74 74 3E 5B 3C 2F 74 74 3E 5C 22 20 28 6C 65 66 74 20 62 72 61 63 6B 65 74 29 2C 20 5C 22 3C 74 74 3E 7C 3C 2F 74 74 3E 5C 22 20 28 70 69}
// 		$s3 = {77 6F 72 64 3A 20 5C 22 3C 74 74 3E 6E 75 6C 6C 3C 2F 74 74 3E 5C 22 2C 20 5C 22 3C 74 74 3E 79 65 73 3C 2F 74 74 3E 5C 22 2C 20 5C 22 3C 74 74 3E 6E 6F 3C 2F 74 74 3E 5C 22 2C 20 5C 22 3C 74 74 3E 74 72 75 65 3C 2F 74 74 3E 5C 22 2C}

// 	condition:
// 		1 of them
// }

// rule webshell_PHPRemoteView : webshell
// {
// 	meta:
// 		description = "Web Shell - file PHPRemoteView.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "29420106d9a81553ef0d1ca72b9934d9"

// 	strings:
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 76 61 6C 75 65 3D 27 5C 22 2E 6D 6D 28 5C 22 44 65 6C 65 74 65 20 61 6C 6C 20 64 69 72 2F 66 69 6C 65 73 20 72 65 63 75 72 73 69 76 65 5C 22 29 2E 5C 22 20 28 72 6D 20 2D 66 72 29 27}
// 		$s4 = {3C 61 20 68 72 65 66 3D 27 24 73 65 6C 66 3F 63 3D 64 65 6C 65 74 65 26 63 32 3D 24 63 32 26 63 6F 6E 66 69 72 6D 3D 64 65 6C 65 74 65 26 64 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 64 29 2E 5C 22 26 66 3D 5C 22 2E 75}

// 	condition:
// 		1 of them
// }

// rule webshell_jsp_12302 : webshell
// {
// 	meta:
// 		description = "Web Shell - file 12302.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a3930518ea57d899457a62f372205f7f"

// 	strings:
// 		$s0 = {3C 2F 66 6F 6E 74 3E 3C 25 6F 75 74 2E 70 72 69 6E 74 28 72 65 71 75 65 73 74 2E 67 65 74 52 65 61 6C 50 61 74 68 28 72 65 71 75 65 73 74 2E 67 65 74 53 65 72 76 6C 65 74 50 61 74 68 28 29 29 29 3B 20 25 3E}
// 		$s1 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 2C 6A 61 76 61 2E 75 74 69 6C 2E 2A 2C 6A 61 76 61 2E 6E 65 74 2E 2A 5C 22 25 3E}
// 		$s4 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39 2D 31 5C 22}

// 	condition:
// 		all of them
// }

// rule webshell_caidao_shell_guo : webshell
// {
// 	meta:
// 		description = "Web Shell - file guo.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "9e69a8f499c660ee0b4796af14dc08f0"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 28 24 77 77 77 3D 20 24 5F 50 4F 53 54 5B 27 69 63 65 27 5D 29 21}
// 		$s1 = {40 70 72 65 67 5F 72 65 70 6C 61 63 65 28 27 2F 61 64 2F 65 27 2C 27 40 27 2E 73 74 72 5F 72 6F 74 31 33 28 27 72 69 6E 79 27 29 2E 27 28 24 77 77}

// 	condition:
// 		1 of them
// }

// rule webshell_PHP_redcod : webshell
// {
// 	meta:
// 		description = "Web Shell - file redcod.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5c1c8120d82f46ff9d813fbe3354bac5"

// 	strings:
// 		$s0 = {48 38 70 30 62 47 46 4F 45 79 37 65 41 6C 79 34 68 34 45 34 6F 38 38 4C 54 53 56 48 6F 41 67 6C 4A 32 4B 4C 51 68 55 77}
// 		$s1 = {48 4B 50 37 64 56 79 43 66 38 63 67 6E 57 46 79 38 6F 63 6A 72 50 35 66 66 7A 6B 6E 39 4F 44 72 6F 4D 30 2F 72 61 48 6D}

// 	condition:
// 		all of them
// }

// rule webshell_remview_fix : webshell
// {
// 	meta:
// 		description = "Web Shell - file remview_fix.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"

// 	strings:
// 		$s4 = {3C 61 20 68 72 65 66 3D 27 24 73 65 6C 66 3F 63 3D 64 65 6C 65 74 65 26 63 32 3D 24 63 32 26 63 6F 6E 66 69 72 6D 3D 64 65 6C 65 74 65 26 64 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 64 29 2E 5C 22 26 66 3D 5C 22 2E 75}
// 		$s5 = {65 63 68 6F 20 5C 22 3C 50 3E 3C 68 72 20 73 69 7A 65 3D 31 20 6E 6F 73 68 61 64 65 3E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E}

// 	condition:
// 		1 of them
// }

// rule webshell_asp_cmd : webshell
// {
// 	meta:
// 		description = "Web Shell - file cmd.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "895ca846858c315a3ff8daa7c55b3119"

// 	strings:
// 		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}
// 		$s1 = {53 65 74 20 6F 46 69 6C 65 53 79 73 20 3D 20 53 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 5C 22 29}
// 		$s3 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}

// 	condition:
// 		1 of them
// }

// rule webshell_php_sh_server : webshell
// {
// 	meta:
// 		description = "Web Shell - file server.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 50
// 		hash = "d87b019e74064aa90e2bb143e5e16cfa"

// 	strings:
// 		$s0 = {65 76 61 6C 28 67 65 74 65 6E 76 28 27 48 54 54 50 5F 43 4F 44 45 27 29 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_PH_Vayv_PH_Vayv : webshell
// {
// 	meta:
// 		description = "Web Shell - file PH Vayv.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "35fb37f3c806718545d97c6559abd262"

// 	strings:
// 		$s0 = {73 74 79 6C 65 3D 5C 22 42 41 43 4B 47 52 4F 55 4E 44 2D 43 4F 4C 4F 52 3A 20 23 65 61 65 39 65 39 3B 20 42 4F 52 44 45 52 2D 42 4F 54 54 4F 4D 3A 20 23 30 30 30 30 30 30 20 31 70 78 20 69 6E}
// 		$s4 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 38 35 38 35 38 35 5C 22 3E 53 48 4F 50 45 4E 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65}

// 	condition:
// 		1 of them
// }

// rule webshell_caidao_shell_ice : webshell
// {
// 	meta:
// 		description = "Web Shell - file ice.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "6560b436d3d3bb75e2ef3f032151d139"

// 	strings:
// 		$s0 = {3C 25 65 76 61 6C 20 72 65 71 75 65 73 74 28 5C 22 69 63 65 5C 22 29 25 3E}

// 	condition:
// 		all of them
// }

// rule webshell_cihshell_fix : webshell
// {
// 	meta:
// 		description = "Web Shell - file cihshell_fix.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "3823ac218032549b86ee7c26f10c4cb5"

// 	strings:
// 		$s7 = {3C 74 72 20 73 74 79 6C 65 3D 27 62 61 63 6B 67 72 6F 75 6E 64 3A 23 32 34 32 34 32 34 3B 27 20 3E 3C 74 64 20 73 74 79 6C 65 3D 27 70 61 64 64 69 6E 67 3A 31 30 70 78 3B 27 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 27 27 20 65 6E 63 74 79}
// 		$s8 = {69 66 20 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 77 5F 68 6F 73 74 27 5D 29 29 7B 24 64 62 68 6F 73 74 20 3D 20 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 77 5F 68 6F 73 74 27 5D 3B 7D 20 65 6C 73 65 20 7B 24 64 62 68 6F 73}

// 	condition:
// 		1 of them
// }

// rule webshell_asp_shell : webshell
// {
// 	meta:
// 		description = "Web Shell - file shell.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "e63f5a96570e1faf4c7b8ca6df750237"

// 	strings:
// 		$s7 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 53 65 6E 64 5C 22 20 76 61 6C 75 65 3D 5C 22 47 4F 21 5C 22 3E}
// 		$s8 = {3C 54 45 58 54 41 52 45 41 20 4E 41 4D 45 3D 5C 22 31 39 38 38 5C 22 20 52 4F 57 53 3D 5C 22 31 38 5C 22 20 43 4F 4C 53 3D 5C 22 37 38 5C 22 3E 3C 2F 54 45 58 54 41 52 45 41 3E}

// 	condition:
// 		all of them
// }

// rule webshell_Private_i3lue : webshell
// {
// 	meta:
// 		description = "Web Shell - file Private-i3lue.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "13f5c7a035ecce5f9f380967cf9d4e92"

// 	strings:
// 		$s8 = {63 61 73 65 20 31 35 3A 20 24 69 6D 61 67 65 20 2E 3D 20 5C 22 5C 5C 32 31 5C 5C 30 5C 5C}

// 	condition:
// 		all of them
// }

// rule webshell_php_up : webshell
// {
// 	meta:
// 		description = "Web Shell - file up.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "7edefb8bd0876c41906f4b39b52cd0ef"

// 	strings:
// 		$s0 = {63 6F 70 79 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 5F 50 4F 53 54 5B 27 72 65 6D 6F 74 65 66 69 6C 65 27 5D 29 3B}
// 		$s3 = {69 66 28 69 73 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 29 29 20 7B}
// 		$s8 = {65 63 68 6F 20 5C 22 55 70 6C 6F 61 64 65 64 20 66 69 6C 65 3A 20 5C 22 20 2E 20 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B}

// 	condition:
// 		2 of them
// }

// rule webshell_Mysql_interface_v1_0
// {
// 	meta:
// 		description = "Web Shell - file Mysql interface v1.0.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a12fc0a3d31e2f89727b9678148cd487"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 72 6F 70 44 42 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 27 20 6F 6E 43 6C 69 63 6B 3D 5C 5C 5C 22 72 65 74 75 72 6E}

// 	condition:
// 		all of them
// }

// rule webshell_php_s_u
// {
// 	meta:
// 		description = "Web Shell - file s-u.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"

// 	strings:
// 		$s6 = {3C 61 20 68 72 65 66 3D 5C 22 3F 61 63 74 3D 64 6F 5C 22 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 72 65 64 5C 22 3E 47 6F 20 45 78 65 63 75 74 65 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 62 3E 3C 62 72 20 2F 3E 3C 74 65 78 74 61 72 65 61}

// 	condition:
// 		all of them
// }

// rule webshell_phpshell_2_1_config
// {
// 	meta:
// 		description = "Web Shell - file config.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "bd83144a649c5cc21ac41b505a36a8f3"

// 	strings:
// 		$s1 = {3B 20 28 63 68 6F 6F 73 65 20 67 6F 6F 64 20 70 61 73 73 77 6F 72 64 73 21 29 2E 20 20 41 64 64 20 75 73 65 73 20 61 73 20 73 69 6D 70 6C 65 20 27 75 73 65 72 6E 61 6D 65 20 3D 20 5C 22 70 61 73 73 77 6F 72 64 5C 22 27 20 6C 69 6E 65 73 2E}

// 	condition:
// 		all of them
// }

// rule webshell_asp_EFSO_2
// {
// 	meta:
// 		description = "Web Shell - file EFSO_2.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a341270f9ebd01320a7490c12cb2e64c"

// 	strings:
// 		$s0 = {25 38 40 23 40 26 50 7E 2C 50 2C 50 50 2C 4D 56 7E 34 42 50 5E 7E 2C 4E 53 7E 6D 7E 50 58 63 33 2C 5F 50 57 62 53 50 55 20 57 7E 7E 5B 75 33 46 66 66 73 7E 2F 25 40 23 40 26 7E 7E 2C 50 50 7E 7E 2C 4D 21 50 6D 53 2C 34 53 2C 6D 42 50 4E 42}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_up
// {
// 	meta:
// 		description = "Web Shell - file up.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "515a5dd86fe48f673b72422cccf5a585"

// 	strings:
// 		$s9 = {2F 2F 20 42 55 47 3A 20 43 6F 72 74 61 20 65 6C 20 66 69 63 68 65 72 6F 20 73 69 20 65 73 20 6D 61 79 6F 72 20 64 65 20 36 34 30 4B 73}

// 	condition:
// 		all of them
// }

// rule webshell_NetworkFileManagerPHP
// {
// 	meta:
// 		description = "Web Shell - file NetworkFileManagerPHP.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"

// 	strings:
// 		$s9 = {20 20 65 63 68 6F 20 5C 22 3C 62 72 3E 3C 63 65 6E 74 65 72 3E 41 6C 6C 20 74 68 65 20 64 61 74 61 20 69 6E 20 74 68 65 73 65 20 74 61 62 6C 65 73 3A 3C 62 72 3E 20 5C 22 2E 24 74 62 6C 73 76 2E 5C 22 20 77 65 72 65 20 70 75 74 74 65 64 20}

// 	condition:
// 		all of them
// }

// rule webshell_Server_Variables
// {
// 	meta:
// 		description = "Web Shell - file Server Variables.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "47fb8a647e441488b30f92b4d39003d7"

// 	strings:
// 		$s7 = {3C 25 20 46 6F 72 20 45 61 63 68 20 56 61 72 73 20 49 6E 20 52 65 71 75 65 73 74 2E 53 65 72 76 65 72 56 61 72 69 61 62 6C 65 73 20 25 3E}
// 		$s9 = {56 61 72 69 61 62 6C 65 20 4E 61 6D 65 3C 2F 42 3E 3C 2F 66 6F 6E 74 3E 3C 2F 70 3E}

// 	condition:
// 		all of them
// }

// rule webshell_caidao_shell_ice_2
// {
// 	meta:
// 		description = "Web Shell - file ice.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "1d6335247f58e0a5b03e17977888f5f2"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 24 7B 24 7B 65 76 61 6C 28 24 5F 50 4F 53 54 5B 69 63 65 5D 29 7D 7D 3B 3F 3E}

// 	condition:
// 		all of them
// }

// rule webshell_caidao_shell_mdb
// {
// 	meta:
// 		description = "Web Shell - file mdb.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "fbf3847acef4844f3a0d04230f6b9ff9"

// 	strings:
// 		$s1 = {3C 25 20 65 78 65 63 75 74 65 20 72 65 71 75 65 73 74 28 5C 22 69 63 65 5C 22 29 25 3E 61 20}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_guige
// {
// 	meta:
// 		description = "Web Shell - file guige.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "2c9f2dafa06332957127e2c713aacdd2"

// 	strings:
// 		$s0 = {69 66 28 64 61 6D 61 70 61 74 68 21 3D 6E 75 6C 6C 20 26 26 21 64 61 6D 61 70 61 74 68 2E 65 71 75 61 6C 73 28 5C 22 5C 22 29 26 26 63 6F 6E 74 65 6E 74 21 3D 6E 75 6C 6C}

// 	condition:
// 		all of them
// }

// rule webshell_phpspy2010
// {
// 	meta:
// 		description = "Web Shell - file phpspy2010.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "14ae0e4f5349924a5047fed9f3b105c5"

// 	strings:
// 		$s3 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28}
// 		$s5 = {2F 2F 61 6E 67 65 6C}
// 		$s8 = {24 61 64 6D 69 6E 5B 27 63 6F 6F 6B 69 65 64 6F 6D 61 69 6E 27 5D 20 3D 20 27 27 3B}

// 	condition:
// 		all of them
// }

// rule webshell_asp_ice
// {
// 	meta:
// 		description = "Web Shell - file ice.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d141e011a92f48da72728c35f1934a2b"

// 	strings:
// 		$s0 = {44 2C 27 50 72 6A 6B 6E 44 2C 4A 7E 5B 2C 45 64 6E 4D 50 5B 2C 2D 34 3B 44 53 36 40 23 40 26 56 4B 6F 62 78 32 6C 64 64 2C 27 7E 4A 68 43}

// 	condition:
// 		all of them
// }

// rule webshell_drag_system
// {
// 	meta:
// 		description = "Web Shell - file system.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "15ae237cf395fb24cf12bff141fb3f7c"

// 	strings:
// 		$s9 = {53 74 72 69 6E 67 20 73 71 6C 20 3D 20 5C 22 53 45 4C 45 43 54 20 2A 20 46 52 4F 4D 20 44 42 41 5F 54 41 42 4C 45 53 20 57 48 45 52 45 20 54 41 42 4C 45 5F 4E 41 4D 45 20 6E 6F 74 20 6C 69 6B 65 20 27 25 24 25 27 20 61 6E 64 20 6E 75 6D 5F}

// 	condition:
// 		all of them
// }

// rule webshell_DarkBlade1_3_asp_indexx
// {
// 	meta:
// 		description = "Web Shell - file indexx.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b7f46693648f534c2ca78e3f21685707"

// 	strings:
// 		$s3 = {43 6F 6E 73 74 20 73 74 72 73 5F 74 6F 54 72 61 6E 73 66 6F 72 6D 3D 5C 22 63 6F 6D 6D 61 6E 64 7C 52 61 64 6D 69 6E 7C 4E 54 41 75 54 68 65 6E 61 62 6C 65 64 7C 46 69 6C 74 65 72 49 70 7C 49 49 53 53 61 6D 70 6C 65 7C 50 61 67 65 43 6F 75}

// 	condition:
// 		all of them
// }

// rule webshell_phpshell3
// {
// 	meta:
// 		description = "Web Shell - file phpshell3.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "76117b2ee4a7ac06832d50b2d04070b8"

// 	strings:
// 		$s2 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 6E 6F 75 6E 63 65 5C 22 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 24 5F 53 45 53 53 49 4F 4E 5B 27 6E 6F 75 6E 63 65 27 5D 3B}
// 		$s5 = {3C 70 3E 55 73 65 72 6E 61 6D 65 3A 20 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 75 73 65 72 6E 61 6D 65 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 24 75 73 65 72 6E 61}
// 		$s7 = {24 5F 53 45 53 53 49 4F 4E 5B 27 6F 75 74 70 75 74 27 5D 20 2E 3D 20 5C 22 63 64 3A 20 63 6F 75 6C 64 20 6E 6F 74 20 63 68 61 6E 67 65 20 74 6F 3A 20 24 6E 65 77 5F 64 69 72 5C 5C 6E 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule webshell_jsp_hsxa
// {
// 	meta:
// 		description = "Web Shell - file hsxa.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"

// 	strings:
// 		$s0 = {3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 5C 22 67 62 6B 5C 22 25 3E 3C 6A 73 70 3A 64 69 72 65 63 74 69 76 65 2E 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_utils
// {
// 	meta:
// 		description = "Web Shell - file utils.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "9827ba2e8329075358b8e8a53e20d545"

// 	strings:
// 		$s0 = {52 65 73 75 6C 74 53 65 74 20 72 20 3D 20 63 2E 67 65 74 4D 65 74 61 44 61 74 61 28 29 2E 67 65 74 54 61 62 6C 65 73 28 6E 75 6C 6C 2C 20 6E 75 6C 6C 2C 20 5C 22 25 5C 22 2C 20 74 29 3B}
// 		$s4 = {53 74 72 69 6E 67 20 63 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A 30 5C 22 29 3D 3D 6E 75 6C 6C 3F 5C 22 67 62 6B 5C 22 3A 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A}

// 	condition:
// 		all of them
// }

// rule webshell_asp_01
// {
// 	meta:
// 		description = "Web Shell - file 01.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 50
// 		hash = "61a687b0bea0ef97224c7bd2df118b87"

// 	strings:
// 		$s0 = {3C 25 65 76 61 6C 20 72 65 71 75 65 73 74 28 5C 22 70 61 73 73 5C 22 29 25 3E}

// 	condition:
// 		all of them
// }

// rule webshell_asp_404
// {
// 	meta:
// 		description = "Web Shell - file 404.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d9fa1e8513dbf59fa5d130f389032a2d"

// 	strings:
// 		$s0 = {6C 46 79 77 36 70 64 5E 44 4B 56 5E 34 43 44 52 57 6D 6D 6E 4F 31 47 56 4B 44 6C 3A 79 26 20 66 2B 32}

// 	condition:
// 		all of them
// }

// rule webshell_webshell_cnseay02_1
// {
// 	meta:
// 		description = "Web Shell - file webshell-cnseay02-1.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "95fc76081a42c4f26912826cb1bd24b1"

// 	strings:
// 		$s0 = {28 39 33 29 2E 24 5F 75 55 28 34 31 29 2E 24 5F 75 55 28 35 39 29 3B 24 5F 66 46 3D 24 5F 75 55 28 39 39 29 2E 24 5F 75 55 28 31 31 34 29 2E 24 5F 75 55 28 31 30 31 29 2E 24 5F 75 55 28 39 37 29 2E 24 5F 75 55 28 31 31 36 29 2E 24 5F 75 55}

// 	condition:
// 		all of them
// }

// rule webshell_php_fbi
// {
// 	meta:
// 		description = "Web Shell - file fbi.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "1fb32f8e58c8deb168c06297a04a21f1"

// 	strings:
// 		$s7 = {65 72 64 65 20 74 79 70 65 73 27 2C 27 47 65 74 61 6C 6C 65 6E 27 2C 27 44 61 74 75 6D 20 65 6E 20 74 69 6A 64 27 2C 27 54 65 6B 73 74 27 2C 27 42 69 6E 61 69 72 65 20 67 65 67 65 76 65 6E 73 27 2C 27 4E 65 74 77 65 72 6B 27 2C 27 47 65 6F}

// 	condition:
// 		all of them
// }

// rule webshell_B374kPHP_B374k
// {
// 	meta:
// 		description = "Web Shell - file B374k.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "bed7388976f8f1d90422e8795dff1ea6"

// 	strings:
// 		$s0 = {48 74 74 70 3A 2F 2F 63 6F 64 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D 2F 70 2F 62 33 37 34 6B 2D 73 68 65 6C 6C}
// 		$s1 = {24 5F 3D 73 74 72 5F 72 6F 74 31 33 28 27 74 6D 27 2E 27 76 61 73 27 2E 27 79 6E 67 72 27 29 3B 24 5F 3D 73 74 72 5F 72 6F 74 31 33 28 73 74 72 72 65 76 28 27 72 71 62 27 2E 27 70 72 71 27 2E 27 5F 27 2E 27 34 36 72 27 2E 27 66 6E 6F 27}
// 		$s3 = {4A 61 79 61 6C 61 68 20 49 6E 64 6F 6E 65 73 69 61 6B 75 20 26 20 4C 79 6B 65 20 40 20 32 30 31 33}
// 		$s4 = {42 33 37 34 6B 20 56 69 70 20 49 6E 20 42 65 61 75 74 69 66 79 20 4A 75 73 74 20 46 6F 72 20 53 65 6C 66}

// 	condition:
// 		1 of them
// }

// rule webshell_cmd_asp_5_1
// {
// 	meta:
// 		description = "Web Shell - file cmd-asp-5.1.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "8baa99666bf3734cbdfdd10088e0cd9f"

// 	strings:
// 		$s9 = {43 61 6C 6C 20 6F 53 2E 52 75 6E 28 5C 22 77 69 6E 2E 63 6F 6D 20 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 5C 22 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 46 20 26}

// 	condition:
// 		all of them
// }

// rule webshell_php_dodo_zip
// {
// 	meta:
// 		description = "Web Shell - file zip.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b7800364374077ce8864796240162ad5"

// 	strings:
// 		$s0 = {24 68 65 78 64 74 69 6D 65 20 3D 20 27 5C 5C 78 27 20 2E 20 24 64 74 69 6D 65 5B 36 5D 20 2E 20 24 64 74 69 6D 65 5B 37 5D 20 2E 20 27 5C 5C 78 27 20 2E 20 24 64 74 69 6D 65 5B 34 5D 20 2E 20 24 64 74 69 6D 65 5B 35 5D 20 2E 20 27 5C 5C 78}
// 		$s3 = {24 64 61 74 61 73 74 72 20 3D 20 5C 22 5C 5C 78 35 30 5C 5C 78 34 62 5C 5C 78 30 33 5C 5C 78 30 34 5C 5C 78 30 61 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30}

// 	condition:
// 		all of them
// }

// rule webshell_aZRaiLPhp_v1_0
// {
// 	meta:
// 		description = "Web Shell - file aZRaiLPhp v1.0.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "26b2d3943395682e36da06ed493a3715"

// 	strings:
// 		$s5 = {65 63 68 6F 20 5C 22 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 27 23 30 30 30 30 46 46 27 3E 43 48 4D 4F 44 55 20 5C 22 2E 73 75 62 73 74 72 28 62 61 73 65 5F 63 6F 6E 76 65 72 74 28 40 66 69 6C 65 70 65 72 6D 73 28 24}
// 		$s7 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 2E 2F 24 74 68 69 73 5F 66 69 6C 65 3F 6F 70 3D 65 66 70 26 66 6E 61 6D 65 3D 24 70 61 74 68 2F 24 66 69 6C 65 26 64 69 73 6D 69 3D 24 66 69 6C 65 26 79 6F 6C 3D 24 70 61 74 68 27 3E 3C 66 6F}

// 	condition:
// 		all of them
// }

// rule webshell_php_list
// {
// 	meta:
// 		description = "Web Shell - file list.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "922b128ddd90e1dc2f73088956c548ed"

// 	strings:
// 		$s1 = {2F 2F 20 6C 69 73 74 2E 70 68 70 20 3D 20 44 69 72 65 63 74 6F 72 79 20 26 20 46 69 6C 65 20 4C 69 73 74 69 6E 67}
// 		$s2 = {20 20 20 20 65 63 68 6F 20 5C 22 28 20 29 20 3C 61 20 68 72 65 66 3D 3F 66 69 6C 65 3D 5C 22 20 2E 20 24 66 69 63 68 65 72 6F 20 2E 20 5C 22 2F 5C 22 20 2E 20 24 66 69 6C 65 6E 61 6D 65 20 2E 20 5C 22 3E 5C 22 20 2E 20 24 66 69 6C 65 6E 61}
// 		$s9 = {2F 2F 20 62 79 3A 20 54 68 65 20 44 61 72 6B 20 52 61 76 65 72}

// 	condition:
// 		1 of them
// }

// rule webshell_ironshell
// {
// 	meta:
// 		description = "Web Shell - file ironshell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "8bfa2eeb8a3ff6afc619258e39fded56"

// 	strings:
// 		$s4 = {70 72 69 6E 74 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 6D 65 2E 5C 22 3F 70 3D 63 6D 64 26 64 69 72 3D 5C 22 2E 72 65 61 6C 70 61 74 68 28 27 2E 27 29 2E 5C 22}
// 		$s8 = {70 72 69 6E 74 20 5C 22 3C 74 64 20 69 64 3D 66 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 3F 70 3D 72 65 6E 61 6D 65 26 66 69 6C 65 3D 5C 22 2E 72 65 61 6C 70 61 74 68 28 24 66 69 6C 65 29 2E 5C 22 26 64 69}

// 	condition:
// 		all of them
// }

// rule webshell_caidao_shell_404
// {
// 	meta:
// 		description = "Web Shell - file 404.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "ee94952dc53d9a29bdf4ece54c7a7aa7"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 24 4B 3D 73 54 72 5F 52 65 70 4C 61 43 65 28 27 60 27 2C 27 27 2C 27 61 60 73 60 73 60 65 60 72 60 74 27 29 3B 24 4D 3D 24 5F 50 4F 53 54 5B 69 63 65 5D 3B 49 46 28 24 4D 3D 3D 4E 75 4C 6C 29 48 65 61 44 65 52 28 27 53 74}

// 	condition:
// 		all of them
// }

// rule webshell_ASP_aspydrv
// {
// 	meta:
// 		description = "Web Shell - file aspydrv.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "de0a58f7d1e200d0b2c801a94ebce330"

// 	strings:
// 		$s3 = {3C 25 3D 74 68 69 6E 67 79 2E 44 72 69 76 65 4C 65 74 74 65 72 25 3E 20 3C 2F 74 64 3E 3C 74 64 3E 3C 74 74 3E 20 3C 25 3D 74 68 69 6E 67 79 2E 44 72 69 76 65 54 79 70 65 25 3E 20 3C 2F 74 64 3E 3C 74 64 3E 3C 74 74 3E 20 3C 25 3D 74 68 69}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_web
// {
// 	meta:
// 		description = "Web Shell - file web.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"

// 	strings:
// 		$s0 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 5C 22 25 3E 3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 6E 65 74 2E 2A 5C 22 25 3E 3C 25 53 74 72 69 6E 67 20 74 3D 72 65 71 75 65 73 74 2E}

// 	condition:
// 		all of them
// }

// rule webshell_mysqlwebsh
// {
// 	meta:
// 		description = "Web Shell - file mysqlwebsh.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "babfa76d11943a22484b3837f105fada"

// 	strings:
// 		$s3 = {20 3C 54 52 3E 3C 54 44 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 3F 20 65 63 68 6F 20 28 21 24 43 4F 4E 4E 45 43 54 20 26 26 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 63 68 70 61 72 61 6D 5C 22 29 3F 5C 22 23 36 36 30 30 30 30 5C 22 3A 5C 22 23}

// 	condition:
// 		all of them
// }

// rule webshell_jspShell
// {
// 	meta:
// 		description = "Web Shell - file jspShell.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"

// 	strings:
// 		$s0 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 63 68 65 63 6B 62 6F 78 5C 22 20 6E 61 6D 65 3D 5C 22 61 75 74 6F 55 70 64 61 74 65 5C 22 20 76 61 6C 75 65 3D 5C 22 41 75 74 6F 55 70 64 61 74 65 5C 22 20 6F 6E}
// 		$s1 = {6F 6E 62 6C 75 72 3D 5C 22 64 6F 63 75 6D 65 6E 74 2E 73 68 65 6C 6C 2E 61 75 74 6F 55 70 64 61 74 65 2E 63 68 65 63 6B 65 64 3D 20 74 68 69 73 2E 6F 6C 64 56 61 6C 75 65 3B}

// 	condition:
// 		all of them
// }

// rule webshell_Dx_Dx
// {
// 	meta:
// 		description = "Web Shell - file Dx.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"

// 	strings:
// 		$s1 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 54 69 70 3A 20 74 6F 20 76 69 65 77 20 74 68 65 20 66 69 6C 65 20 5C 22 61 73 20 69 73 5C 22 20 2D 20 6F 70 65 6E 20 74 68 65 20 70 61 67 65 20 69 6E 20 3C 61 20 68 72 65 66 3D 5C 22 27 2E 44 78}
// 		$s9 = {63 6C 61 73 73 3D 6C 69 6E 65 6C 69 73 74 69 6E 67 3E 3C 6E 6F 62 72 3E 50 4F 53 54 20 28 70 68 70 20 65 76 61 6C 29 3C 2F 74 64 3E 3C}

// 	condition:
// 		1 of them
// }

// rule webshell_asp_ntdaddy
// {
// 	meta:
// 		description = "Web Shell - file ntdaddy.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "c5e6baa5d140f73b4e16a6cfde671c68"

// 	strings:
// 		$s9 = {69 66 20 20 46 50 20 20 3D 20 20 5C 22 52 65 66 72 65 73 68 46 6F 6C 64 65 72 5C 22 20 20 6F 72 20 20}
// 		$s10 = {72 65 71 75 65 73 74 2E 66 6F 72 6D 28 5C 22 63 6D 64 4F 70 74 69 6F 6E 5C 22 29 3D 5C 22 44 65 6C 65 74 65 46 6F 6C 64 65 72 5C 22 20 20}

// 	condition:
// 		1 of them
// }

// rule webshell_MySQL_Web_Interface_Version_0_8
// {
// 	meta:
// 		description = "Web Shell - file MySQL Web Interface Version 0.8.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "36d4f34d0a22080f47bb1cb94107c60f"

// 	strings:
// 		$s2 = {68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 75 6D 70 54 61 62 6C 65 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 26 74 61 62 6C 65 6E 61 6D 65 3D 24 74 61 62 6C 65 6E 61 6D 65 27 3E 44 75 6D 70 3C 2F 61 3E}

// 	condition:
// 		all of them
// }

// rule webshell_elmaliseker_2
// {
// 	meta:
// 		description = "Web Shell - file elmaliseker.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b32d1730d23a660fd6aa8e60c3dc549f"

// 	strings:
// 		$s1 = {3C 74 64 3C 25 69 66 20 28 46 53 4F 2E 47 65 74 45 78 74 65 6E 73 69 6F 6E 4E 61 6D 65 28 70 61 74 68 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 46 69 6C 65 2E 4E 61 6D 65 29 3D 5C 22 6C 6E 6B 5C 22 29 20 6F 72 20 28 46 53 4F 2E 47 65 74 45 78}
// 		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74 74 6F 6E 20 76 61 6C 75 65 3D 53 61 76 65 20 6F 6E 63 6C 69 63 6B 3D 5C 22 45 64 69 74 6F 72 43 6F 6D 6D 61 6E 64 28 27 53 61 76 65 27 29 5C 22 3E 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74}

// 	condition:
// 		all of them
// }

// rule webshell_ASP_RemExp
// {
// 	meta:
// 		description = "Web Shell - file RemExp.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "aa1d8491f4e2894dbdb91eec1abc2244"

// 	strings:
// 		$s0 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 53 75 62 46 6F 6C 64 65 72 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 3C 25 3D 52 65 71 75 65 73}
// 		$s1 = {50 72 69 76 61 74 65 20 46 75 6E 63 74 69 6F 6E 20 43 6F 6E 76 65 72 74 42 69 6E 61 72 79 28 42 79 56 61 6C 20 53 6F 75 72 63 65 4E 75 6D 62 65 72 2C 20 42 79 56 61 6C 20 4D 61 78 56 61 6C 75 65 50 65 72 49 6E 64 65 78 2C 20 42 79 56 61 6C}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_list1
// {
// 	meta:
// 		description = "Web Shell - file list1.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"

// 	strings:
// 		$s1 = {63 61 73 65 20 27 73 27 3A 43 6F 6E 6E 65 63 74 69 6F 6E 44 42 4D 28 6F 75 74 2C 65 6E 63 6F 64 65 43 68 61 6E 67 65 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 64 72 69 76 65}
// 		$s9 = {72 65 74 75 72 6E 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 64 65 6C 46 69 6C 65 28 27 5C 22 2B 66 6F 6C 64 65 72 52 65 70 6C 61 63 65 28 66 69 6C 65 29 2B 5C 22 27 29 5C 5C 5C 22}

// 	condition:
// 		all of them
// }

// rule webshell_phpkit_1_0_odd
// {
// 	meta:
// 		description = "Web Shell - file odd.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "594d1b1311bbef38a0eb3d6cbb1ab538"

// 	strings:
// 		$s0 = {69 6E 63 6C 75 64 65 28 27 70 68 70 3A 2F 2F 69 6E 70 75 74 27 29 3B}
// 		$s1 = {2F 2F 20 4E 6F 20 65 76 61 6C 28 29 20 63 61 6C 6C 73 2C 20 6E 6F 20 73 79 73 74 65 6D 28 29 20 63 61 6C 6C 73 2C 20 6E 6F 74 68 69 6E 67 20 6E 6F 72 6D 61 6C 6C 79 20 73 65 65 6E 20 61 73 20 6D 61 6C 69 63 69 6F 75 73 2E}
// 		$s2 = {69 6E 69 5F 73 65 74 28 27 61 6C 6C 6F 77 5F 75 72 6C 5F 69 6E 63 6C 75 64 65 2C 20 31 27 29 3B 20 2F 2F 20 41 6C 6C 6F 77 20 75 72 6C 20 69 6E 63 6C 75 73 69 6F 6E 20 69 6E 20 74 68 69 73 20 73 63 72 69 70 74}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_123
// {
// 	meta:
// 		description = "Web Shell - file 123.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "c691f53e849676cac68a38d692467641"

// 	strings:
// 		$s0 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 62 6C 75 65 5C 22 3E 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3A 3C 2F 66 6F 6E 74 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 73 69 7A 65 3D 5C 22 37}
// 		$s3 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39 2D 31 5C 22}
// 		$s9 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 62 74 6E 53 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 55 70 6C 6F 61 64 5C 22 3E 20 20 20 20}

// 	condition:
// 		all of them
// }

// rule webshell_asp_1
// {
// 	meta:
// 		description = "Web Shell - file 1.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "8991148adf5de3b8322ec5d78cb01bdb"

// 	strings:
// 		$s4 = {21 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32}
// 		$s8 = {3C 25 65 76 61 6C 20 72 65 71 75 65 73 74 28 5C 22 70 61 73 73 5C 22 29 25 3E}

// 	condition:
// 		all of them
// }

// rule webshell_ASP_tool
// {
// 	meta:
// 		description = "Web Shell - file tool.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "4ab68d38527d5834e9c1ff64407b34fb"

// 	strings:
// 		$s0 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 46 4F 52 4D 20 61 63 74 69 6F 6E 3D 5C 22 5C 22 5C 22 20 26 20 52 65 71 75 65 73 74 2E 53 65 72 76 65 72 56 61 72 69 61 62 6C 65 73 28 5C 22 55 52 4C 5C 22 29 20 26 20 5C 22 5C 22 5C 22}
// 		$s3 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 27 61 72 69 61 6C 27 20 73 69 7A 65 3D 27 32 27 3E 3C 62 3E 26 6C 74 3B 44 49 52 26 67 74 3B 20 3C 61 20 68 72 65 66 3D 27 5C 22 20}
// 		$s9 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 27 61 72 69 61 6C 27 20 73 69 7A 65 3D 27 31 27 3E 3C 61 20 68 72 65 66 3D 5C 22 5C 22 23 5C 22 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 5C 22 6A 61 76 61 73}

// 	condition:
// 		2 of them
// }

// rule webshell_cmd_win32
// {
// 	meta:
// 		description = "Web Shell - file cmd_win32.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "cc4d4d6cc9a25984aa9a7583c7def174"

// 	strings:
// 		$s0 = {50 72 6F 63 65 73 73 20 70 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 2B 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D}
// 		$s1 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 5C 22 50 4F 53 54 5C 22 20 4E 41 4D 45 3D 5C 22 6D 79 66 6F 72 6D 5C 22 20 41 43 54 49 4F 4E 3D 5C 22 5C 22 3E}

// 	condition:
// 		2 of them
// }

// rule webshell_jsp_jshell
// {
// 	meta:
// 		description = "Web Shell - file jshell.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "124b22f38aaaf064cef14711b2602c06"

// 	strings:
// 		$s0 = {6B 58 70 65 57 5B 5C 22}
// 		$s4 = {5B 37 62 3A 67 30 57 40 57 3C}
// 		$s5 = {62 3A 67 48 72 2C 67 3C}
// 		$s8 = {52 68 56 30 57 40 57 3C}
// 		$s9 = {53 5F 4D 52 28 75 37 62}

// 	condition:
// 		all of them
// }

// rule webshell_ASP_zehir4
// {
// 	meta:
// 		description = "Web Shell - file zehir4.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "7f4e12e159360743ec016273c3b9108c"

// 	strings:
// 		$s9 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 61 20 68 72 65 66 3D 27 5C 22 26 64 6F 73 79 61 50 61 74 68 26 5C 22 3F 73 74 61 74 75 73 3D 37 26 50 61 74 68 3D 5C 22 26 50 61 74 68 26 5C 22 2F}

// 	condition:
// 		all of them
// }

// rule webshell_wsb_idc
// {
// 	meta:
// 		description = "Web Shell - file idc.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "7c5b1b30196c51f1accbffb80296395f"

// 	strings:
// 		$s1 = {69 66 20 28 6D 64 35 28 24 5F 47 45 54 5B 27 75 73 72 27 5D 29 3D 3D 24 75 73 65 72 20 26 26 20 6D 64 35 28 24 5F 47 45 54 5B 27 70 61 73 73 27 5D 29 3D 3D 24 70 61 73 73 29}
// 		$s3 = {7B 65 76 61 6C 28 24 5F 47 45 54 5B 27 69 64 63 27 5D 29 3B 7D}

// 	condition:
// 		1 of them
// }

// rule webshell_cpg_143_incl_xpl
// {
// 	meta:
// 		description = "Web Shell - file cpg_143_incl_xpl.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5937b131b67d8e0afdbd589251a5e176"

// 	strings:
// 		$s3 = {24 64 61 74 61 3D 5C 22 75 73 65 72 6E 61 6D 65 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 55 53 45 52 29 2E 5C 22 26 70 61 73 73 77 6F 72 64 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 50 41}
// 		$s5 = {66 70 75 74 73 28 24 73 75 6E 5F 74 7A 75 2C 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 5C 5C 5C 22 48 69 20 4D 61 73 74 65 72 21 5C 5C 5C 22 3B 69 6E 69 5F 73 65 74 28 5C 5C 5C 22 6D 61 78 5F 65 78 65 63 75 74 69 6F 6E 5F 74 69 6D 65}

// 	condition:
// 		1 of them
// }

// rule webshell_mumaasp_com
// {
// 	meta:
// 		description = "Web Shell - file mumaasp.com.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "cce32b2e18f5357c85b6d20f564ebd5d"

// 	strings:
// 		$s0 = {26 39 4B 5F 29 50 38 32 61 69 2C 41 7D 49 39 32 5D 52 5C 22 71 21 43 3A 52 5A 7D 53 36 5D 3D 50 61 54 54 52}

// 	condition:
// 		all of them
// }

// rule webshell_php_404
// {
// 	meta:
// 		description = "Web Shell - file 404.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "ced050df5ca42064056a7ad610a191b3"

// 	strings:
// 		$s0 = {24 70 61 73 73 20 3D 20 6D 64 35 28 6D 64 35 28 6D 64 35 28 24 70 61 73 73 29 29 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_webshell_cnseay_x
// {
// 	meta:
// 		description = "Web Shell - file webshell-cnseay-x.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a0f9f7f5cd405a514a7f3be329f380e5"

// 	strings:
// 		$s9 = {24 5F 46 5F 46 2E 3D 27 5F 27 2E 24 5F 50 5F 50 5B 35 5D 2E 24 5F 50 5F 50 5B 32 30 5D 2E 24 5F 50 5F 50 5B 31 33 5D 2E 24 5F 50 5F 50 5B 32 5D 2E 24 5F 50 5F 50 5B 31 39 5D 2E 24 5F 50 5F 50 5B 38 5D 2E 24 5F 50 5F}

// 	condition:
// 		all of them
// }

// rule webshell_asp_up
// {
// 	meta:
// 		description = "Web Shell - file up.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "f775e721cfe85019fe41c34f47c0d67c"

// 	strings:
// 		$s0 = {50 6F 73 20 3D 20 49 6E 73 74 72 42 28 42 6F 75 6E 64 61 72 79 50 6F 73 2C 52 65 71 75 65 73 74 42 69 6E 2C 67 65 74 42 79 74 65 53 74 72 69 6E 67 28 5C 22 43 6F 6E 74 65 6E 74 2D 44 69 73 70 6F 73 69 74 69 6F}
// 		$s1 = {43 6F 6E 74 65 6E 74 54 79 70 65 20 3D 20 67 65 74 53 74 72 69 6E 67 28 4D 69 64 42 28 52 65 71 75 65 73 74 42 69 6E 2C 50 6F 73 42 65 67 2C 50 6F 73 45 6E 64 2D 50 6F 73 42 65 67 29 29}

// 	condition:
// 		1 of them
// }

// rule webshell_phpkit_0_1a_odd
// {
// 	meta:
// 		description = "Web Shell - file odd.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "3c30399e7480c09276f412271f60ed01"

// 	strings:
// 		$s1 = {69 6E 63 6C 75 64 65 28 27 70 68 70 3A 2F 2F 69 6E 70 75 74 27 29 3B}
// 		$s3 = {69 6E 69 5F 73 65 74 28 27 61 6C 6C 6F 77 5F 75 72 6C 5F 69 6E 63 6C 75 64 65 2C 20 31 27 29 3B 20 2F 2F 20 41 6C 6C 6F 77 20 75 72 6C 20 69 6E 63 6C 75 73 69 6F 6E 20 69 6E 20 74 68 69 73 20 73 63 72 69 70 74}
// 		$s4 = {2F 2F 20 75 73 65 73 20 69 6E 63 6C 75 64 65 28 27 70 68 70 3A 2F 2F 69 6E 70 75 74 27 29 20 74 6F 20 65 78 65 63 75 74 65 20 61 72 62 72 69 74 61 72 79 20 63 6F 64 65}
// 		$s5 = {2F 2F 20 70 68 70 3A 2F 2F 69 6E 70 75 74 20 62 61 73 65 64 20 62 61 63 6B 64 6F 6F 72}

// 	condition:
// 		2 of them
// }

// rule webshell_ASP_cmd
// {
// 	meta:
// 		description = "Web Shell - file cmd.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "97af88b478422067f23b001dd06d56a9"

// 	strings:
// 		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_Shell_x3
// {
// 	meta:
// 		description = "Web Shell - file PHP Shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"

// 	strings:
// 		$s4 = {26 6E 62 73 70 3B 26 6E 62 73 70 3B 3C 3F 70 68 70 20 65 63 68 6F 20 62 75 69 6C 64 55 72 6C 28 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 6E 61 76 79 5C 5C 5C 22 3E 5B}
// 		$s6 = {65 63 68 6F 20 5C 22 3C 2F 66 6F 72 6D 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 70 6F 73 74 5C 5C 5C 22 3E 3C 69 6E 70 75 74}
// 		$s9 = {69 66 20 20 28 20 28 20 28 69 73 73 65 74 28 24 68 74 74 70 5F 61 75 74 68 5F 75 73 65 72 29 20 29 20 26 26 20 28 69 73 73 65 74 28 24 68 74 74 70 5F 61 75 74 68 5F 70 61 73 73 29 29 20 29 20 26 26 20 28 20 21 69 73 73 65 74 28}

// 	condition:
// 		2 of them
// }

// rule webshell_PHP_g00nv13
// {
// 	meta:
// 		description = "Web Shell - file g00nv13.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "35ad2533192fe8a1a76c3276140db820"

// 	strings:
// 		$s1 = {63 61 73 65 20 5C 22 7A 69 70 5C 22 3A 20 63 61 73 65 20 5C 22 74 61 72 5C 22 3A 20 63 61 73 65 20 5C 22 72 61 72 5C 22 3A 20 63 61 73 65 20 5C 22 67 7A 5C 22 3A 20 63 61 73 65 20 5C 22 63 61 62 5C 22 3A 20 63 61 73}
// 		$s4 = {69 66 28 21 28 24 73 71 6C 63 6F 6E 20 3D 20 40 6D 79 73 71 6C 5F 63 6F 6E 6E 65 63 74 28 24 5F 53 45 53 53 49 4F 4E 5B 27 73 71 6C 5F 68 6F 73 74 27 5D 20 2E 20 27 3A 27 20 2E 20 24 5F 53 45 53 53 49 4F 4E 5B 27 73 71 6C 5F 70}

// 	condition:
// 		all of them
// }

// rule webshell_php_h6ss
// {
// 	meta:
// 		description = "Web Shell - file h6ss.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "272dde9a4a7265d6c139287560328cd5"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 65 76 61 6C 28 67 7A 75 6E 63 6F 6D 70 72 65 73 73 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 5C 22}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_zx
// {
// 	meta:
// 		description = "Web Shell - file zx.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "67627c264db1e54a4720bd6a64721674"

// 	strings:
// 		$s0 = {69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29 21 3D 6E 75 6C 6C 29 28 6E 65 77 20 6A 61 76 61 2E 69 6F 2E 46 69 6C 65 4F 75 74 70 75 74 53 74 72 65 61 6D 28 61 70 70 6C 69 63 61 74 69 6F 6E 2E 67}

// 	condition:
// 		all of them
// }

// rule webshell_Ani_Shell
// {
// 	meta:
// 		description = "Web Shell - file Ani-Shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "889bfc9fbb8ee7832044fc575324d01a"

// 	strings:
// 		$s0 = {24 50 79 74 68 6F 6E 5F 43 4F 44 45 20 3D 20 5C 22 49}
// 		$s6 = {24 70 61 73 73 77 6F 72 64 50 72 6F 6D 70 74 20 3D 20 5C 22 5C 5C 6E 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D}
// 		$s7 = {66 70 75 74 73 20 28 24 73 6F 63 6B 66 64 20 2C 5C 22 5C 5C 6E 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D}

// 	condition:
// 		1 of them
// }

// rule webshell_jsp_k8cmd
// {
// 	meta:
// 		description = "Web Shell - file k8cmd.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b39544415e692a567455ff033a97a682"

// 	strings:
// 		$s2 = {69 66 28 72 65 71 75 65 73 74 2E 67 65 74 53 65 73 73 69 6F 6E 28 29 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 68 65 68 65 5C 22 29 2E 74 6F 53 74 72 69 6E 67 28 29 2E 65 71 75 61 6C 73 28 5C 22 68 65 68 65 5C 22 29 29}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_cmd
// {
// 	meta:
// 		description = "Web Shell - file cmd.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5391c4a8af1ede757ba9d28865e75853"

// 	strings:
// 		$s6 = {6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 43 6F 6D 6D 61 6E 64 3A 20 5C 22 20 2B 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 63 6D 64 5C 22 29 20 2B 20 5C 22 3C 42 52 3E 5C 22 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_k81
// {
// 	meta:
// 		description = "Web Shell - file k81.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "41efc5c71b6885add9c1d516371bd6af"

// 	strings:
// 		$s1 = {62 79 74 65 5B 5D 20 62 69 6E 61 72 79 20 3D 20 42 41 53 45 36 34 44 65 63 6F 64 65 72 2E 63 6C 61 73 73 2E 6E 65 77 49 6E 73 74 61 6E 63 65 28 29 2E 64 65 63 6F 64 65 42 75 66 66 65 72 28 63 6D 64 29 3B}
// 		$s9 = {69 66 28 63 6D 64 2E 65 71 75 61 6C 73 28 5C 22 53 7A 68 30 5A 57 46 74 5C 22 29 29 7B 6F 75 74 2E 70 72 69 6E 74 28 5C 22 5B 53 5D 5C 22 2B 64 69 72 2B 5C 22 5B 45 5D 5C 22 29 3B 7D}

// 	condition:
// 		1 of them
// }

// rule webshell_ASP_zehir
// {
// 	meta:
// 		description = "Web Shell - file zehir.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "0061d800aee63ccaf41d2d62ec15985d"

// 	strings:
// 		$s9 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 77 69 6E 67 64 69 6E 67 73 20 73 69 7A 65 3D 33 3E 3C 61 20 68 72 65 66 3D 27 5C 22 26 64 6F 73 79 61 50 61 74 68 26 5C 22 3F 73 74 61 74 75 73 3D 31 38 26}

// 	condition:
// 		all of them
// }

// rule webshell_Worse_Linux_Shell
// {
// 	meta:
// 		description = "Web Shell - file Worse Linux Shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "8338c8d9eab10bd38a7116eb534b5fa2"

// 	strings:
// 		$s0 = {73 79 73 74 65 6D 28 5C 22 6D 76 20 5C 22 2E 24 5F 46 49 4C 45 53 5B 27 5F 75 70 6C 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2E 5C 22 20 5C 22 2E 24 63 75 72 72 65 6E 74 57 44}

// 	condition:
// 		all of them
// }

// rule webshell_zacosmall
// {
// 	meta:
// 		description = "Web Shell - file zacosmall.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5295ee8dc2f5fd416be442548d68f7a6"

// 	strings:
// 		$s0 = {69 66 28 24 63 6D 64 21 3D 3D 27 27 29 7B 20 65 63 68 6F 28 27 3C 73 74 72 6F 6E 67 3E 27 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 63 6D 64 29 2E 5C 22 3C 2F 73 74 72 6F 6E 67 3E 3C 68 72 3E}

// 	condition:
// 		all of them
// }

// rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
// {
// 	meta:
// 		description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"

// 	strings:
// 		$s1 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 61 74 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}

// 	condition:
// 		all of them
// }

// rule webshell_redirect
// {
// 	meta:
// 		description = "Web Shell - file redirect.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "97da83c6e3efbba98df270cc70beb8f8"

// 	strings:
// 		$s7 = {76 61 72 20 66 6C 61 67 20 3D 20 5C 22 3F 74 78 74 3D 5C 22 20 2B 20 28 64 6F 63 75 6D 65 6E 74 2E 67 65 74 45 6C 65 6D 65 6E 74 42 79 49 64 28 5C 22 64 6C 5C 22 29 2E 63 68 65 63 6B 65 64 20 3F 20 5C 22 32 5C 22 3A 5C 22 31 5C 22 20}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_cmdjsp
// {
// 	meta:
// 		description = "Web Shell - file cmdjsp.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b815611cc39f17f05a73444d699341d4"

// 	strings:
// 		$s5 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 47 45 54 20 41 43 54 49 4F 4E 3D 27 63 6D 64 6A 73 70 2E 6A 73 70 27 3E}

// 	condition:
// 		all of them
// }

// rule webshell_Java_Shell
// {
// 	meta:
// 		description = "Web Shell - file Java Shell.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "36403bc776eb12e8b7cc0eb47c8aac83"

// 	strings:
// 		$s4 = {70 75 62 6C 69 63 20 4A 79 74 68 6F 6E 53 68 65 6C 6C 28 69 6E 74 20 63 6F 6C 75 6D 6E 73 2C 20 69 6E 74 20 72 6F 77 73 2C 20 69 6E 74 20 73 63 72 6F 6C 6C 62 61 63 6B 29 20 7B}
// 		$s9 = {74 68 69 73 28 6E 75 6C 6C 2C 20 50 79 2E 67 65 74 53 79 73 74 65 6D 53 74 61 74 65 28 29 2C 20 63 6F 6C 75 6D 6E 73 2C 20 72 6F 77 73 2C 20 73 63 72 6F 6C 6C 62 61 63 6B 29 3B}

// 	condition:
// 		1 of them
// }

// rule webshell_asp_1d
// {
// 	meta:
// 		description = "Web Shell - file 1d.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "fad7504ca8a55d4453e552621f81563c"

// 	strings:
// 		$s0 = {2B 39 4A 6B 73 6B 4F 66 4B 68 55 78 5A 4A 50 4C 7E 5C 5C 28 6D 44 5E 57 7E 5B 2C 7B 40 23 40 26 45 4F}

// 	condition:
// 		all of them
// }

// // duplicated
// /* rule webshell_jsp_IXRbE
// {
// 	meta:
// 		description = "Web Shell - file IXRbE.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "e26e7e0ebc6e7662e1123452a939e2cd"

// 	strings:
// 		$s0 = {3C 25 69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29 21 3D 6E 75 6C 6C 29 28 6E 65 77 20 6A 61 76 61 2E 69 6F 2E 46 69 6C 65 4F 75 74 70 75 74 53 74 72 65 61 6D 28 61 70 70 6C 69 63 61 74 69 6F 6E}

// 	condition:
// 		all of them
// }*/

// rule webshell_PHP_G5
// {
// 	meta:
// 		description = "Web Shell - file G5.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "95b4a56140a650c74ed2ec36f08d757f"

// 	strings:
// 		$s3 = {65 63 68 6F 20 5C 22 48 61 63 6B 69 6E 67 20 4D 6F 64 65 3F 3C 62 72 3E 3C 73 65 6C 65 63 74 20 6E 61 6D 65 3D 27 68 74 79 70 65 27 3E 3C 6F 70 74 69 6F 6E 20 3E 2D 2D 2D 2D 2D 2D 2D 2D 53 45 4C 45 43 54 2D 2D 2D 2D 2D 2D 2D 2D 3C 2F 6F 70}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_r57142
// {
// 	meta:
// 		description = "Web Shell - file r57142.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"

// 	strings:
// 		$s0 = {24 64 6F 77 6E 6C 6F 61 64 65 72 73 20 3D 20 61 72 72 61 79 28 27 77 67 65 74 27 2C 27 66 65 74 63 68 27 2C 27 6C 79 6E 78 27 2C 27 6C 69 6E 6B 73 27 2C 27 63 75 72 6C 27 2C 27 67 65 74 27 2C 27 6C 77 70 2D 6D 69 72 72 6F 72 27 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_tree
// {
// 	meta:
// 		description = "Web Shell - file tree.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"

// 	strings:
// 		$s5 = {24 28 27 23 74 74 32 27 29 2E 74 72 65 65 28 27 6F 70 74 69 6F 6E 73 27 29 2E 75 72 6C 20 3D 20 5C 22 73 65 6C 65 63 74 43 68 69 6C 64 2E 61 63 74 69 6F 6E 3F 63 68 65 63 6B 69}
// 		$s6 = {53 74 72 69 6E 67 20 62 61 73 65 50 61 74 68 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 53 63 68 65 6D 65 28 29 2B 5C 22 3A 2F 2F 5C 22 2B 72 65 71 75 65 73 74 2E 67 65 74 53 65 72 76 65 72 4E 61 6D 65 28 29 2B 5C 22 3A 5C 22 2B 72 65 71 75}

// 	condition:
// 		all of them
// }

// rule webshell_C99madShell_v_3_0_smowu
// {
// 	meta:
// 		description = "Web Shell - file smowu.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "74e1e7c7a6798f1663efb42882b85bee"

// 	strings:
// 		$s2 = {3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 5C 22 35 30 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 31 5C 22 20 76 61 6C 69 67 6E 3D 5C 22 74 6F 70 5C 22 3E 3C 63 65 6E 74 65 72 3E 3C 62 3E 3A 3A 20 45 6E 74 65 72 20 3A 3A 3C 2F 62 3E 3C 66 6F 72}
// 		$s8 = {3C 70 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 57 6F 72 64 70 72 65 73 73 20 4E 6F 74 20 46 6F 75 6E 64 21 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 69 64 3D 5C 22 77 70 5F 70 61 74 5C 22 3E 3C 69 6E 70 75 74 20 74 79}

// 	condition:
// 		1 of them
// }

// rule webshell_simple_backdoor
// {
// 	meta:
// 		description = "Web Shell - file simple-backdoor.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "f091d1b9274c881f8e41b2f96e6b9936"

// 	strings:
// 		$s0 = {24 63 6D 64 20 3D 20 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 3B}
// 		$s1 = {69 66 28 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
// 		$s4 = {73 79 73 74 65 6D 28 24 63 6D 64 29 3B}

// 	condition:
// 		2 of them
// }

// rule webshell_PHP_404
// {
// 	meta:
// 		description = "Web Shell - file 404.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "078c55ac475ab9e028f94f879f548bca"

// 	strings:
// 		$s4 = {3C 73 70 61 6E 3E 50 6F 73 69 78 5F 67 65 74 70 77 75 69 64 20 28 5C 22 52 65 61 64 5C 22 20 2F 65 74 63 2F 70 61 73 73 77 64 29}

// 	condition:
// 		all of them
// }

// rule webshell_Macker_s_Private_PHPShell
// {
// 	meta:
// 		description = "Web Shell - file Macker's Private PHPShell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "e24cbf0e294da9ac2117dc660d890bb9"

// 	strings:
// 		$s3 = {65 63 68 6F 20 5C 22 3C 74 72 3E 3C 74 64 20 63 6C 61 73 73 3D 5C 5C 5C 22 73 69 6C 76 65 72 20 62 6F 72 64 65 72 5C 5C 5C 22 3E 26 6E 62 73 70 3B 3C 73 74 72 6F 6E 67 3E 53 65 72 76 65 72 27 73 20 50 48 50 20 56 65 72 73 69 6F 6E 3A 26 6E}
// 		$s4 = {26 6E 62 73 70 3B 26 6E 62 73 70 3B 3C 3F 70 68 70 20 65 63 68 6F 20 62 75 69 6C 64 55 72 6C 28 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 6E 61 76 79 5C 5C 5C 22 3E 5B}
// 		$s7 = {65 63 68 6F 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D}

// 	condition:
// 		all of them
// }

// rule webshell_Antichat_Shell_v1_3_2
// {
// 	meta:
// 		description = "Web Shell - file Antichat Shell v1.3.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "40d0abceba125868be7f3f990f031521"

// 	strings:
// 		$s3 = {24 68 65 61 64 65 72 3D 27 3C 68 74 6D 6C 3E 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 27 2E 67 65 74 65 6E 76 28 5C 22 48 54 54 50 5F 48 4F 53 54 5C 22 29 2E 27 20 2D 20 41 6E 74 69 63 68 61 74 20 53 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E 3C 6D}

// 	condition:
// 		all of them
// }

// rule webshell_Safe_mode_breaker
// {
// 	meta:
// 		description = "Web Shell - file Safe mode breaker.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5bd07ccb1111950a5b47327946bfa194"

// 	strings:
// 		$s5 = {70 72 65 67 5F 6D 61 74 63 68 28 5C 22 2F 53 41 46 45 5C 5C 20 4D 4F 44 45 5C 5C 20 52 65 73 74 72 69 63 74 69 6F 6E 5C 5C 20 69 6E 5C 5C 20 65 66 66 65 63 74 5C 5C 2E 2E 2A 77 68 6F 73 65 5C 5C 20 75 69 64 5C 5C 20 69 73 28}
// 		$s6 = {24 70 61 74 68 20 3D 5C 22 7B 24 72 6F 6F 74 7D 5C 22 2E 28 28 73 75 62 73 74 72 28 24 72 6F 6F 74 2C 2D 31 29 21 3D 5C 22 2F 5C 22 29 20 3F 20 5C 22 2F 5C 22 20 3A 20 4E 55 4C 4C 29 2E}

// 	condition:
// 		1 of them
// }

// rule webshell_Sst_Sheller
// {
// 	meta:
// 		description = "Web Shell - file Sst-Sheller.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d93c62a0a042252f7531d8632511ca56"

// 	strings:
// 		$s2 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 3F 70 61 67 65 3D 66 69 6C 65 6D 61 6E 61 67 65 72 26 69 64 3D 66 6D 26 66 63 68 6D 6F 64 3D 24 64 69 72 24 66 69 6C 65 27 3E}
// 		$s3 = {3C 3F 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 29 3B 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 31 29 3B 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 32 29 3B 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 33 29}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_list
// {
// 	meta:
// 		description = "Web Shell - file list.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "1ea290ff4259dcaeb680cec992738eda"

// 	strings:
// 		$s0 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 5C 22 50 4F 53 54 5C 22 20 4E 41 4D 45 3D 5C 22 6D 79 66 6F 72 6D 5C 22 20 41 43 54 49 4F 4E 3D 5C 22 5C 22 3E}
// 		$s2 = {6F 75 74 2E 70 72 69 6E 74 28 5C 22 29 20 3C 41 20 53 74 79 6C 65 3D 27 43 6F 6C 6F 72 3A 20 5C 22 20 2B 20 66 63 6F 6C 6F 72 2E 74 6F 53 74 72 69 6E 67 28 29 20 2B 20 5C 22 3B 27 20 48 52 65 66 3D 27 3F 66 69 6C 65 3D 5C 22 20 2B 20 66 6E}
// 		$s7 = {69 66 28 66 6C 69 73 74 5B 69 5D 2E 63 61 6E 52 65 61 64 28 29 20 3D 3D 20 74 72 75 65 29 20 6F 75 74 2E 70 72 69 6E 74 28 5C 22 72 5C 22 20 29 3B 20 65 6C 73 65 20 6F 75 74 2E 70 72 69 6E 74 28 5C 22 2D 5C 22 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_PHPJackal_v1_5
// {
// 	meta:
// 		description = "Web Shell - file PHPJackal v1.5.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d76dc20a4017191216a0315b7286056f"

// 	strings:
// 		$s7 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 24 7B 74 7D 4D 79 53 51 4C 20 63 69 6C 65 6E 74 3A 3C 2F 74 64 3E 3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 33 33 33 33 33 33 5C 5C 5C 22 3E 3C 2F 74 64 3E 3C 2F 74 72 3E 3C 66 6F 72 6D}
// 		$s8 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 24 7B 74 7D 57 6F 72 64 6C 69 73 74 20 67 65 6E 65 72 61 74 6F 72 3A 3C 2F 74 64 3E 3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 33 33 33 33 33 33 5C 5C 5C 22 3E 3C 2F 74 64 3E 3C 2F 74 72}

// 	condition:
// 		all of them
// }

// // duplicated
// /* rule webshell_customize
// {
// 	meta:
// 		description = "Web Shell - file customize.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d55578eccad090f30f5d735b8ec530b1"

// 	strings:
// 		$s4 = {53 74 72 69 6E 67 20 63 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A 30 5C 22 29 3D 3D 6E 75 6C 6C 3F 5C 22 67 62 6B 5C 22 3A 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A}

// 	condition:
// 		all of them
// }*/

// rule webshell_s72_Shell_v1_1_Coding
// {
// 	meta:
// 		description = "Web Shell - file s72 Shell v1.1 Coding.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "c2e8346a5515c81797af36e7e4a3828e"

// 	strings:
// 		$s5 = {3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 5C 22 20 63 6F 6C 6F 72 3D 5C 22 23 38 30 30 30 38 30 5C 22 3E 42 75 72 61 64 61 6E 20 44 6F 73 79 61 20}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_sys3
// {
// 	meta:
// 		description = "Web Shell - file sys3.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b3028a854d07674f4d8a9cf2fb6137ec"

// 	strings:
// 		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 62 74 6E 53 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 55 70 6C 6F 61 64 5C 22 3E}
// 		$s4 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39 2D 31 5C 22}
// 		$s9 = {3C 25 40 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 63 68 61 72 73 65 74 3D 67 62 32 33 31 32 5C 22 25 3E}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_guige02
// {
// 	meta:
// 		description = "Web Shell - file guige02.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a3b8b2280c56eaab777d633535baf21d"

// 	strings:
// 		$s0 = {3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 25 3E 3C 68 74 6D 6C 3E 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 68 61 68 61 68 61 68 61 3C 2F 74 69 74 6C 65 3E 3C 2F 68 65 61 64 3E 3C 62 6F 64 79 20 62 67 63 6F 6C 6F 72 3D 5C 22 23 66 66 66}
// 		$s1 = {3C 25 40 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 47 42 4B 5C 22 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 3B 5C 22 25 3E 3C 25 21 70 72 69 76 61 74 65}

// 	condition:
// 		all of them
// }

// rule webshell_php_ghost
// {
// 	meta:
// 		description = "Web Shell - file ghost.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "38dc8383da0859dca82cf0c943dbf16d"

// 	strings:
// 		$s1 = {3C 3F 70 68 70 20 24 4F 4F 4F 30 30 30 30 30 30 3D 75 72 6C 64 65 63 6F 64 65 28 27 25 36 31 25 36 38 25 33 36 25 37 33 25 36 32 25 36 35 25 36 38 25 37 31 25 36 63 25 36 31 25 33 34 25 36 33 25 36 66 25 35 66 25 37 33 25 36 31 25 36 34 27}
// 		$s6 = {2F 2F 3C 69 6D 67 20 77 69 64 74 68 3D 31 20 68 65 69 67 68 74 3D 31 20 73 72 63 3D 5C 22 68 74 74 70 3A 2F 2F 77 65 62 73 61 66 65 2E 66 61 63 61 69 6F 6B 2E 63 6F 6D 2F 6A 75 73 74 37 7A 2F 73 78 2E 61 73 70 3F 75 3D 2A 2A 2A 2E 2A 2A 2A}
// 		$s7 = {70 72 65 67 5F 72 65 70 6C 61 63 65 28 27 5C 5C 27 61 5C 5C 27 65 69 73 27 2C 27 65 27 2E 27 76 27 2E 27 61 27 2E 27 6C 27 2E 27 28 4B 6D 55 28 5C 22}

// 	condition:
// 		all of them
// }

// rule webshell_WinX_Shell
// {
// 	meta:
// 		description = "Web Shell - file WinX Shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "17ab5086aef89d4951fe9b7c7a561dda"

// 	strings:
// 		$s5 = {70 72 69 6E 74 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 5C 5C 22 56 65 72 64 61 6E 61 5C 5C 5C 22 20 73 69 7A 65 3D 5C 5C 5C 22 31 5C 5C 5C 22 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 39 39 30 30 30 30 5C 5C 5C 22 3E 46 69 6C 65 6E 61 6D}
// 		$s8 = {70 72 69 6E 74 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 5C 5C 22 56 65 72 64 61 6E 61 5C 5C 5C 22 20 73 69 7A 65 3D 5C 5C 5C 22 31 5C 5C 5C 22 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 39 39 30 30 30 30 5C 5C 5C 22 3E 46 69 6C 65 3A 20 3C 2F}

// 	condition:
// 		all of them
// }

// rule webshell_Crystal_Crystal
// {
// 	meta:
// 		description = "Web Shell - file Crystal.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "fdbf54d5bf3264eb1c4bff1fac548879"

// 	strings:
// 		$s1 = {73 68 6F 77 20 6F 70 65 6E 65 64 20 70 6F 72 74 73 3C 2F 6F 70 74 69 6F 6E 3E 3C 2F 73 65 6C 65 63 74 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 63 6D 64 5F 74 78 74 5C 22 20 76 61 6C 75 65}
// 		$s6 = {5C 22 20 68 72 65 66 3D 5C 22 3F 61 63 74 3D 74 6F 6F 6C 73 5C 22 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 43 43 30 30 30 30 20 73 69 7A 65 3D 5C 22 33 5C 22 3E 54 6F 6F 6C 73 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 73 70 61 6E 3E 3C 2F 66}

// 	condition:
// 		all of them
// }

// rule webshell_r57_1_4_0
// {
// 	meta:
// 		description = "Web Shell - file r57.1.4.0.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "574f3303e131242568b0caf3de42f325"

// 	strings:
// 		$s4 = {40 69 6E 69 5F 73 65 74 28 27 65 72 72 6F 72 5F 6C 6F 67 27 2C 4E 55 4C 4C 29 3B}
// 		$s6 = {24 70 61 73 73 3D 27 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 27 3B}
// 		$s7 = {40 69 6E 69 5F 72 65 73 74 6F 72 65 28 5C 22 64 69 73 61 62 6C 65 5F 66 75 6E 63 74 69 6F 6E 73 5C 22 29 3B}
// 		$s9 = {40 69 6E 69 5F 72 65 73 74 6F 72 65 28 5C 22 73 61 66 65 5F 6D 6F 64 65 5F 65 78 65 63 5F 64 69 72 5C 22 29 3B}

// 	condition:
// 		all of them
// }


// // duplicated
// /* rule webshell_jsp_hsxa1
// {
// 	meta:
// 		description = "Web Shell - file hsxa1.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5686d5a38c6f5b8c55095af95c2b0244"

// 	strings:
// 		$s0 = {3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 5C 22 67 62 6B 5C 22 25 3E 3C 6A 73 70 3A 64 69 72 65 63 74 69 76 65 2E 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61}

// 	condition:
// 		all of them
// } */


// rule webshell_asp_ajn
// {
// 	meta:
// 		description = "Web Shell - file ajn.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "aaafafc5d286f0bff827a931f6378d04"

// 	strings:
// 		$s1 = {73 65 61 6C 2E 77 72 69 74 65 20 5C 22 53 65 74 20 57 73 68 53 68 65 6C 6C 20 3D 20 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 5C 22 57 53 63 72 69 70 74 2E 53 68 65 6C 6C 5C 22 5C 22 29 5C 22 20 26 20 76 62 63 72 6C 66}
// 		$s6 = {73 65 61 6C 2E 77 72 69 74 65 20 5C 22 42 69 6E 61 72 79 53 74 72 65 61 6D 2E 53 61 76 65 54 6F 46 69 6C 65 20 5C 22 5C 22 63 3A 5C 5C 64 6F 77 6E 6C 6F 61 64 65 64 2E 7A 69 70 5C 22 5C 22 2C 20 61 64 53 61 76 65 43 72 65 61 74 65 4F 76 65}

// 	condition:
// 		all of them
// }

// rule webshell_php_cmd
// {
// 	meta:
// 		description = "Web Shell - file cmd.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"

// 	strings:
// 		$s0 = {69 66 28 24 5F 47 45 54 5B 27 63 6D 64 27 5D 29 20 7B}
// 		$s1 = {2F 2F 20 63 6D 64 2E 70 68 70 20 3D 20 43 6F 6D 6D 61 6E 64 20 45 78 65 63 75 74 69 6F 6E}
// 		$s7 = {20 20 73 79 73 74 65 6D 28 24 5F 47 45 54 5B 27 63 6D 64 27 5D 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_asp_list
// {
// 	meta:
// 		description = "Web Shell - file list.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"

// 	strings:
// 		$s0 = {3C 49 4E 50 55 54 20 54 59 50 45 3D 5C 22 68 69 64 64 65 6E 5C 22 20 4E 41 4D 45 3D 5C 22 74 79 70 65 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 74 69 70 6F 25 3E 5C 22 3E}
// 		$s4 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 28 5C 22 3C 68 33 3E 46 49 4C 45 3A 20 5C 22 20 26 20 66 69 6C 65 20 26 20 5C 22 3C 2F 68 33 3E 5C 22 29}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_co
// {
// 	meta:
// 		description = "Web Shell - file co.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "62199f5ac721a0cb9b28f465a513874c"

// 	strings:
// 		$s0 = {63 47 58 36 52 39 71 37 33 33 57 76 52 52 6A 49 53 4B 48 4F 70 39 6E 65 54 37 77 61 36 5A 41 44 38 75 74 68 6D 56 4A 56}
// 		$s11 = {36 4D 6B 33 36 6C 7A 2F 48 4F 6B 46 66 6F 58 58 38 37 4D 70 50 68 5A 7A 42 51 48 36 4F 61 59 75 6B 4E 67 31 4F 45 31 6A}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_150
// {
// 	meta:
// 		description = "Web Shell - file 150.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "400c4b0bed5c90f048398e1d268ce4dc"

// 	strings:
// 		$s0 = {48 4A 33 48 6A 71 78 63 6C 6B 5A 66 70}
// 		$s1 = {3C 3F 20 65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_cmdjsp_2
// {
// 	meta:
// 		description = "Web Shell - file cmdjsp.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "1b5ae3649f03784e2a5073fa4d160c8b"

// 	strings:
// 		$s0 = {50 72 6F 63 65 73 73 20 70 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 5C 22 63 6D 64 2E 65 78 65 20 2F 43 20 5C 22 20 2B 20 63 6D 64 29 3B}
// 		$s4 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 47 45 54 20 41 43 54 49 4F 4E 3D 27 63 6D 64 6A 73 70 2E 6A 73 70 27 3E}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_c37
// {
// 	meta:
// 		description = "Web Shell - file c37.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d01144c04e7a46870a8dd823eb2fe5c8"

// 	strings:
// 		$s3 = {61 72 72 61 79 28 27 63 70 70 27 2C 27 63 78 78 27 2C 27 68 78 78 27 2C 27 68 70 70 27 2C 27 63 63 27 2C 27 6A 78 78 27 2C 27 63 2B 2B 27 2C 27 76 63 70 72 6F 6A 27 29 2C}
// 		$s9 = {2B 2B 24 46 3B 20 24 46 69 6C 65 20 3D 20 75 72 6C 65 6E 63 6F 64 65 28 24 64 69 72 5B 24 64 69 72 46 49 4C 45 5D 29 3B 20 24 65 58 54 20 3D 20 27 2E 3A 27 3B 20 69 66 20 28 73 74 72 70 6F 73 28 24 64 69 72 5B 24 64 69 72 46 49 4C 45 5D 2C}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_b37
// {
// 	meta:
// 		description = "Web Shell - file b37.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "0421445303cfd0ec6bc20b3846e30ff0"

// 	strings:
// 		$s0 = {78 6D 67 32 2F 47 34 4D 5A 37 4B 70 4E 76 65 52 61 4C 67 4F 4A 76 42 63 71 61 32 41 38 2F 73 4B 57 70 39 57 39 33 4E 4C 58 70 54 54 55 67 52 63}

// 	condition:
// 		all of them
// }

// rule webshell_php_backdoor
// {
// 	meta:
// 		description = "Web Shell - file php-backdoor.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"

// 	strings:
// 		$s1 = {69 66 28 21 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 66 69 6C 65 5F 6E 61 6D 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 64 69 72 2E 24 66 6E 61 6D 65 29 29}
// 		$s2 = {3C 70 72 65 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 20 65 63 68 6F 20 24 50 48 50 5F 53 45 4C 46 3B 20 3F 3E 5C 22 20 4D 45 54 48 4F 44 3D 47 45 54 20 3E 65 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 3A 20 3C 69 6E 70 75 74 20}

// 	condition:
// 		all of them
// }

// rule webshell_asp_dabao
// {
// 	meta:
// 		description = "Web Shell - file dabao.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "3919b959e3fa7e86d52c2b0a91588d5d"

// 	strings:
// 		$s2 = {20 45 63 68 6F 20 5C 22 3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74 74 6F 6E 20 6E 61 6D 65 3D 53 75 62 6D 69 74 20 6F 6E 63 6C 69 63 6B 3D 5C 22 5C 22 64 6F 63 75 6D 65 6E 74 2E 6C 6F 63 61 74 69 6F 6E 20 3D 26 23 30 33 39 3B 5C 22 20 26}
// 		$s8 = {20 45 63 68 6F 20 5C 22 64 6F 63 75 6D 65 6E 74 2E 46 72 6D 5F 50 61 63 6B 2E 46 69 6C 65 4E 61 6D 65 2E 76 61 6C 75 65 3D 5C 22 5C 22 5C 22 5C 22 2B 79 65 61 72 2B 5C 22 5C 22 2D 5C 22 5C 22 2B 28 6D 6F 6E 74 68 2B 31 29 2B 5C 22 5C 22 2D}

// 	condition:
// 		all of them
// }

// rule webshell_php_2
// {
// 	meta:
// 		description = "Web Shell - file 2.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "267c37c3a285a84f541066fc5b3c1747"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 61 73 73 65 72 74 28 24 5F 52 45 51 55 45 53 54 5B 5C 22 63 5C 22 5D 29 3B 3F 3E 20}

// 	condition:
// 		all of them
// }

// rule webshell_asp_cmdasp
// {
// 	meta:
// 		description = "Web Shell - file cmdasp.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "57b51418a799d2d016be546f399c2e9b"

// 	strings:
// 		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}
// 		$s7 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}

// 	condition:
// 		all of them
// }

// rule webshell_spjspshell
// {
// 	meta:
// 		description = "Web Shell - file spjspshell.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "d39d51154aaad4ba89947c459a729971"

// 	strings:
// 		$s7 = {55 6E 69 78 3A 2F 62 69 6E 2F 73 68 20 2D 63 20 74 61 72 20 76 78 66 20 78 78 78 2E 74 61 72 20 57 69 6E 64 6F 77 73 3A 63 3A 5C 5C 77 69 6E 6E 74 5C 5C 73 79 73 74 65 6D 33 32 5C 5C 63 6D 64 2E 65 78 65 20 2F 63 20 74 79 70 65 20 63 3A}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_action
// {
// 	meta:
// 		description = "Web Shell - file action.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"

// 	strings:
// 		$s1 = {53 74 72 69 6E 67 20 75 72 6C 3D 5C 22 6A 64 62 63 3A 6F 72 61 63 6C 65 3A 74 68 69 6E 3A 40 6C 6F 63 61 6C 68 6F 73 74 3A 31 35 32 31 3A 6F 72 63 6C 5C 22 3B}
// 		$s6 = {3C 25 40 20 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 63 68 61 72 73 65 74 3D 67 62 32 33 31 32 5C 22 25 3E}

// 	condition:
// 		all of them
// }

// rule webshell_Inderxer
// {
// 	meta:
// 		description = "Web Shell - file Inderxer.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "9ea82afb8c7070817d4cdf686abe0300"

// 	strings:
// 		$s4 = {3C 74 64 3E 4E 65 72 65 79 65 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 65 79 65 5C 22 20 73 69 7A 65 3D 32 35 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70}

// 	condition:
// 		all of them
// }

// rule webshell_asp_Rader
// {
// 	meta:
// 		description = "Web Shell - file Rader.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "ad1a362e0a24c4475335e3e891a01731"

// 	strings:
// 		$s1 = {46 4F 4E 54 2D 57 45 49 47 48 54 3A 20 62 6F 6C 64 3B 20 46 4F 4E 54 2D 53 49 5A 45 3A 20 31 30 70 78 3B 20 42 41 43 4B 47 52 4F 55 4E 44 3A 20 6E 6F 6E 65 20 74 72 61 6E 73 70 61 72 65 6E 74 20 73 63 72 6F 6C 6C 20 72 65 70 65 61 74 20 30}
// 		$s3 = {6D 5C 22 20 74 61 72 67 65 74 3D 69 6E 66 20 6F 6E 43 6C 69 63 6B 3D 5C 22 77 69 6E 64 6F 77 2E 6F 70 65 6E 28 27 3F 61 63 74 69 6F 6E 3D 68 65 6C 70 27 2C 27 69 6E 66 27 2C 27 77 69 64 74 68 3D 34 35 30 2C 68 65 69 67 68 74 3D 34 30 30 20}

// 	condition:
// 		all of them
// }

// rule webshell_c99_madnet_smowu
// {
// 	meta:
// 		description = "Web Shell - file smowu.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "3aaa8cad47055ba53190020311b0fb83"

// 	strings:
// 		$s0 = {2F 2F 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E}
// 		$s1 = {24 6C 6F 67 69 6E 20 3D 20 5C 22}
// 		$s2 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}
// 		$s4 = {2F 2F 50 61 73 73}
// 		$s5 = {24 6D 64 35 5F 70 61 73 73 20 3D 20 5C 22}
// 		$s6 = {2F 2F 49 66 20 6E 6F 20 70 61 73 73 20 74 68 65 6E 20 68 61 73 68}

// 	condition:
// 		all of them
// }

// rule webshell_php_moon
// {
// 	meta:
// 		description = "Web Shell - file moon.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"

// 	strings:
// 		$s2 = {65 63 68 6F 20 27 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 72 65 61 74 65 20 66 75 6E 63 74 69 6F 6E 20 62 61 63 6B 73 68 65 6C 6C 20 72 65 74 75 72 6E 73 20 73 74 72 69 6E 67 20 73 6F 6E 61 6D 65}
// 		$s3 = {65 63 68 6F 20 20 20 20 20 20 5C 22 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 27 70 27 20 74 79 70 65 3D 27 74 65 78 74 27 20 73 69 7A 65 3D 27 32 37 27 20 76 61 6C 75 65 3D 27 5C 22 2E 64 69 72 6E 61 6D 65 28 5F 46 49 4C 45 5F 29 2E 5C 22}
// 		$s8 = {65 63 68 6F 20 27 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 73 65 6C 65 63 74 20 63 6D 64 73 68 65 6C 6C 28 5C 5C 27 6E 65 74 20 75 73 65 72 20}

// 	condition:
// 		2 of them
// }

// rule webshell_jsp_jdbc
// {
// 	meta:
// 		description = "Web Shell - file jdbc.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "23b0e6f91a8f0d93b9c51a2a442119ce"

// 	strings:
// 		$s4 = {53 74 72 69 6E 67 20 63 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A 30 5C 22 29 3D 3D 6E 75 6C 6C 3F 5C 22 67 62 6B 5C 22 3A 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A}

// 	condition:
// 		all of them
// }

// rule webshell_minupload
// {
// 	meta:
// 		description = "Web Shell - file minupload.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "ec905a1395d176c27f388d202375bdf9"

// 	strings:
// 		$s0 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 62 74 6E 53 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 55 70 6C 6F 61 64 5C 22 3E 20 20 20}
// 		$s9 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39}

// 	condition:
// 		all of them
// }

// rule webshell_ELMALISEKER_Backd00r
// {
// 	meta:
// 		description = "Web Shell - file ELMALISEKER Backd00r.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"

// 	strings:
// 		$s0 = {72 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 28 5C 22 3C 74 72 3E 3C 74 64 20 62 67 63 6F 6C 6F 72 3D 23 46 38 46 38 46 46 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 6E 61 6D 65 3D 63 6D 64 74 78 74 46 69 6C 65 4F 70 74 69 6F}
// 		$s2 = {69 66 20 46 50 20 3D 20 5C 22 52 65 66 72 65 73 68 46 6F 6C 64 65 72 5C 22 20 6F 72 20 72 65 71 75 65 73 74 2E 66 6F 72 6D 28 5C 22 63 6D 64 4F 70 74 69 6F 6E 5C 22 29 3D 5C 22 44 65 6C 65 74 65 46 6F 6C 64 65 72 5C 22 20 6F 72 20 72 65 71}

// 	condition:
// 		all of them
// }

// rule webshell_PHP_bug_1_
// {
// 	meta:
// 		description = "Web Shell - file bug (1).php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "91c5fae02ab16d51fc5af9354ac2f015"

// 	strings:
// 		$s0 = {40 69 6E 63 6C 75 64 65 28 24 5F 47 45 54 5B 27 62 75 67 27 5D 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_caidao_shell_hkmjj
// {
// 	meta:
// 		description = "Web Shell - file hkmjj.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "e7b994fe9f878154ca18b7cde91ad2d0"

// 	strings:
// 		$s6 = {63 6F 64 65 64 73 3D 5C 22 4C 69 23 75 68 74 78 68 76 77 2B 25 7B 7B 25 2C 23 40 25 7B 25 23 77 6B 68 71 23 68 79 64 6F 23 75 68 74 78 68 76 77 2B 25 6B 6E 70 6D 6D 25 2C 23 68 71 67 23 6C 69 5C 22 20 20}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_asd
// {
// 	meta:
// 		description = "Web Shell - file asd.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "a042c2ca64176410236fcc97484ec599"

// 	strings:
// 		$s3 = {3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 5C 22 67 62 6B 5C 22 25 3E}
// 		$s6 = {3C 69 6E 70 75 74 20 73 69 7A 65 3D 5C 22 31 30 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 61 70 70 6C 69 63 61 74 69 6F 6E 2E 67 65 74 52 65 61 6C 50 61 74 68 28 5C 22 2F 5C 22 29 20 25 3E 5C 22 20 6E 61 6D 65 3D 5C 22 75 72 6C}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_inback3
// {
// 	meta:
// 		description = "Web Shell - file inback3.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "ea5612492780a26b8aa7e5cedd9b8f4e"

// 	strings:
// 		$s0 = {3C 25 69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29 21 3D 6E 75 6C 6C 29 28 6E 65 77 20 6A 61 76 61 2E 69 6F 2E 46 69 6C 65 4F 75 74 70 75 74 53 74 72 65 61 6D 28 61 70 70 6C 69 63 61 74 69 6F 6E}

// 	condition:
// 		all of them
// }

// rule webshell_metaslsoft
// {
// 	meta:
// 		description = "Web Shell - file metaslsoft.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "aa328ed1476f4a10c0bcc2dde4461789"

// 	strings:
// 		$s7 = {24 62 75 66 66 20 2E 3D 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 3F 64 3D 5C 22 2E 24 70 77 64 2E 5C 22 5C 5C 5C 22 3E 5B 20 24 66 6F 6C 64 65 72 20 5D 3C 2F 61 3E 3C 2F 74 64 3E 3C 74 64 3E 4C 49 4E 4B 3C 2F 74}

// 	condition:
// 		all of them
// }

// rule webshell_asp_Ajan
// {
// 	meta:
// 		description = "Web Shell - file Ajan.asp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		hash = "b6f468252407efc2318639da22b08af0"

// 	strings:
// 		$s3 = {65 6E 74 72 69 6B 61 2E 77 72 69 74 65 20 5C 22 42 69 6E 61 72 79 53 74 72 65 61 6D 2E 53 61 76 65 54 6F 46 69 6C 65 20 5C 22 5C 22 63 3A 5C 5C 64 6F 77 6E 6C 6F 61 64 65 64 2E 7A 69 70 5C 22 5C 22 2C 20 61 64 53 61 76 65 43 72 65 61 74 65}

// 	condition:
// 		all of them
// }

// rule webshell_config_myxx_zend
// {
// 	meta:
// 		description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
// 		hash1 = "e0354099bee243702eb11df8d0e046df"
// 		hash2 = "591ca89a25f06cf01e4345f98a22845c"

// 	strings:
// 		$s3 = {2E 70 72 69 6E 74 6C 6E 28 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 61 6C 65 72 74 28 27 59 6F 75 20 41 72 65 20 49 6E 20 46 69 6C 65 20 4E 6F 77 20 21 20 43 61 6E 20 4E 6F 74 20 50 61 63 6B 20 21 27 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_browser_201_3_ma_download
// {
// 	meta:
// 		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
// 		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
// 		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
// 		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
// 		hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"

// 	strings:
// 		$s2 = {3C 73 6D 61 6C 6C 3E 6A 73 70 20 46 69 6C 65 20 42 72 6F 77 73 65 72 20 76 65 72 73 69 6F 6E 20 3C 25 3D 20 56 45 52 53 49 4F 4E 5F 4E 52 25 3E 20 62 79 20 3C 61}
// 		$s3 = {65 6C 73 65 20 69 66 20 28 66 4E 61 6D 65 2E 65 6E 64 73 57 69 74 68 28 5C 22 2E 6D 70 67 5C 22 29 20 7C 7C 20 66 4E 61 6D 65 2E 65 6E 64 73 57 69 74 68 28 5C 22 2E 6D 70 65 67 5C 22 29 20 7C 7C 20 66 4E 61 6D 65 2E 65 6E 64 73 57 69 74 68}

// 	condition:
// 		all of them
// }

// rule webshell_itsec_itsecteam_shell_jHn
// {
// 	meta:
// 		description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
// 		hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
// 		hash2 = "40c6ecf77253e805ace85f119fe1cebb"

// 	strings:
// 		$s4 = {65 63 68 6F 20 24 68 65 61 64 2E 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 27 54 61 68 6F 6D 61 27 20 73 69 7A 65 3D 27 32 27 3E 4F 70 65 72 61 74 69 6E 67 20 53 79 73 74 65 6D 20 3A 20 5C 22 2E 70 68 70 5F 75 6E 61 6D 65 28 29 2E 5C 22 3C 62}
// 		$s5 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 66 6F 72 6D 20 6E 61 6D 65 3D 63 6C 69 65 6E 74 20 6D 65 74 68 6F 64 3D 27 50 4F 53 54 27 20 61 63 74 69 6F 6E 3D 27 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 3F 64 6F 3D 64 62 27}

// 	condition:
// 		all of them
// }

// rule webshell_ghost_source_icesword_silic
// {
// 	meta:
// 		description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
// 		hash1 = "6e20b41c040efb453d57780025a292ae"
// 		hash2 = "437d30c94f8eef92dc2f064de4998695"

// 	strings:
// 		$s3 = {69 66 28 65 72 65 67 69 28 27 57 48 45 52 45 7C 4C 49 4D 49 54 27 2C 24 5F 50 4F 53 54 5B 27 6E 73 71 6C 27 5D 29 20 26 26 20 65 72 65 67 69 28 27 53 45 4C 45 43 54 7C 46 52 4F 4D 27 2C 24 5F 50 4F 53 54 5B 27 6E 73 71 6C 27 5D 29 29 20 24}
// 		$s6 = {69 66 28 21 65 6D 70 74 79 28 24 5F 46 49 4C 45 53 5B 27 75 66 70 27 5D 5B 27 6E 61 6D 65 27 5D 29 29 7B 69 66 28 24 5F 50 4F 53 54 5B 27 75 66 6E 27 5D 20 21 3D 20 27 27 29 20 24 75 70 66 69 6C 65 6E 61 6D 65 20 3D 20 24 5F 50 4F 53 54 5B}

// 	condition:
// 		all of them
// }

// rule webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx
// {
// 	meta:
// 		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
// 		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
// 		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
// 		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
// 		hash4 = "8b457934da3821ba58b06a113e0d53d9"
// 		hash5 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
// 		hash6 = "14e9688c86b454ed48171a9d4f48ace8"
// 		hash7 = "b330a6c2d49124ef0729539761d6ef0b"
// 		hash8 = "d71716df5042880ef84427acee8b121e"
// 		hash9 = "341298482cf90febebb8616426080d1d"
// 		hash10 = "29aebe333d6332f0ebc2258def94d57e"
// 		hash11 = "42654af68e5d4ea217e6ece5389eb302"
// 		hash12 = "88fc87e7c58249a398efd5ceae636073"
// 		hash13 = "4a812678308475c64132a9b56254edbc"
// 		hash14 = "9626eef1a8b9b8d773a3b2af09306a10"
// 		hash15 = "344f9073576a066142b2023629539ebd"
// 		hash16 = "32dea47d9c13f9000c4c807561341bee"
// 		hash17 = "90a5ba0c94199269ba33a58bc6a4ad99"
// 		hash18 = "655722eaa6c646437c8ae93daac46ae0"
// 		hash19 = "b9744f6876919c46a29ea05b1d95b1c3"
// 		hash20 = "9c94637f76e68487fa33f7b0030dd932"
// 		hash21 = "6acc82544be056580c3a1caaa4999956"
// 		hash22 = "6aa32a6392840e161a018f3907a86968"
// 		hash23 = "349ec229e3f8eda0f9eb918c74a8bf4c"
// 		hash24 = "3ea688e3439a1f56b16694667938316d"
// 		hash25 = "ab77e4d1006259d7cbc15884416ca88c"
// 		hash26 = "71097537a91fac6b01f46f66ee2d7749"
// 		hash27 = "2434a7a07cb47ce25b41d30bc291cacc"
// 		hash28 = "7a4b090619ecce6f7bd838fe5c58554b"

// 	strings:
// 		$s8 = {5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2B 53 48 45 4C 4C 5F 4E 41 4D 45 2B 5C 22 3F 6F 3D 75 70 6C 6F 61 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 20 65 6E 63 74 79 70 65 3D}
// 		$s9 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 27 72 65 67 20 71 75 65 72 79 20 5C 5C 5C 22 48 4B 4C 4D 5C 5C 5C 5C 53 79 73 74 65 6D 5C 5C 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 5C 5C 54}

// 	condition:
// 		all of them
// }

// rule webshell_2_520_job_ma1_ma4_2
// {
// 	meta:
// 		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "64a3bf9142b045b9062b204db39d4d57"
// 		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
// 		hash2 = "56c005690da2558690c4aa305a31ad37"
// 		hash3 = "532b93e02cddfbb548ce5938fe2f5559"
// 		hash4 = "6e0fa491d620d4af4b67bae9162844ae"
// 		hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

// 	strings:
// 		$s4 = {5F 75 72 6C 20 3D 20 5C 22 6A 64 62 63 3A 6D 69 63 72 6F 73 6F 66 74 3A 73 71 6C 73 65 72 76 65 72 3A 2F 2F 5C 22 20 2B 20 64 62 53 65 72 76 65 72 20 2B 20 5C 22 3A 5C 22 20 2B 20 64 62 50 6F 72 74 20 2B 20 5C 22 3B 55 73 65 72 3D 5C 22 20}
// 		$s9 = {72 65 73 75 6C 74 20 2B 3D 20 5C 22 3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 5C 5C 5C 22 72 65 66 72 65 73 68 5C 5C 5C 22 20 63 6F 6E 74 65 6E 74 3D 5C 5C 5C 22 32 3B 75 72 6C 3D 5C 22 20 2B 20 72 65 71 75 65 73 74 2E 67 65 74 52}

// 	condition:
// 		all of them
// }

// rule webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx
// {
// 	meta:
// 		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
// 		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
// 		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
// 		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
// 		hash4 = "8b457934da3821ba58b06a113e0d53d9"
// 		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
// 		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
// 		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
// 		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
// 		hash9 = "d71716df5042880ef84427acee8b121e"
// 		hash10 = "341298482cf90febebb8616426080d1d"
// 		hash11 = "29aebe333d6332f0ebc2258def94d57e"
// 		hash12 = "42654af68e5d4ea217e6ece5389eb302"
// 		hash13 = "88fc87e7c58249a398efd5ceae636073"
// 		hash14 = "4a812678308475c64132a9b56254edbc"
// 		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
// 		hash16 = "e0354099bee243702eb11df8d0e046df"
// 		hash17 = "344f9073576a066142b2023629539ebd"
// 		hash18 = "32dea47d9c13f9000c4c807561341bee"
// 		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
// 		hash20 = "655722eaa6c646437c8ae93daac46ae0"
// 		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
// 		hash22 = "9c94637f76e68487fa33f7b0030dd932"
// 		hash23 = "6acc82544be056580c3a1caaa4999956"
// 		hash24 = "6aa32a6392840e161a018f3907a86968"
// 		hash25 = "591ca89a25f06cf01e4345f98a22845c"
// 		hash26 = "349ec229e3f8eda0f9eb918c74a8bf4c"
// 		hash27 = "3ea688e3439a1f56b16694667938316d"
// 		hash28 = "ab77e4d1006259d7cbc15884416ca88c"
// 		hash29 = "71097537a91fac6b01f46f66ee2d7749"
// 		hash30 = "2434a7a07cb47ce25b41d30bc291cacc"
// 		hash31 = "7a4b090619ecce6f7bd838fe5c58554b"

// 	strings:
// 		$s0 = {70 6F 72 74 73 20 3D 20 5C 22 32 31 2C 32 35 2C 38 30 2C 31 31 30 2C 31 34 33 33 2C 31 37 32 33 2C 33 33 30 36 2C 33 33 38 39 2C 34 38 39 39 2C 35 36 33 31 2C 34 33 39 35 38 2C 36 35 35 30 30 5C 22 3B}
// 		$s1 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 63 6C 61 73 73 20 56 45 64 69 74 50 72 6F 70 65 72 74 79 49 6E 76 6F 6B 65 72 20 65 78 74 65 6E 64 73 20 44 65 66 61 75 6C 74 49 6E 76 6F 6B 65 72 20 7B}

// 	condition:
// 		all of them
// }

// rule webshell_wso2_5_1_wso2_5_wso2
// {
// 	meta:
// 		description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "dbeecd555a2ef80615f0894027ad75dc"
// 		hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
// 		hash2 = "cbc44fb78220958f81b739b493024688"

// 	strings:
// 		$s7 = {24 6F 70 74 5F 63 68 61 72 73 65 74 73 20 2E 3D 20 27 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 27 2E 24 69 74 65 6D 2E 27 5C 22 20 27 2E 28 24 5F 50 4F 53 54 5B 27 63 68 61 72 73 65 74 27 5D 3D 3D 24 69 74 65 6D 3F 27 73 65 6C 65 63}
// 		$s8 = {2E 27 3C 2F 74 64 3E 3C 74 64 3E 3C 61 20 68 72 65 66 3D 5C 22 23 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 67 28 5C 5C 27 46 69 6C 65 73 54 6F 6F 6C 73 5C 5C 27 2C 6E 75 6C 6C 2C 5C 5C 27 27 2E 75 72 6C 65 6E 63 6F 64 65 28 24 66 5B 27 6E 61}

// 	condition:
// 		all of them
// }

// rule webshell_000_403_c5_queryDong_spyjsp2010_t00ls
// {
// 	meta:
// 		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
// 		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
// 		hash2 = "8b457934da3821ba58b06a113e0d53d9"
// 		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
// 		hash4 = "655722eaa6c646437c8ae93daac46ae0"
// 		hash5 = "9c94637f76e68487fa33f7b0030dd932"

// 	strings:
// 		$s8 = {74 61 62 6C 65 2E 61 70 70 65 6E 64 28 5C 22 3C 74 64 20 6E 6F 77 72 61 70 3E 20 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 23 5C 5C 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 5C 5C 22 76 69 65 77 28 27 5C 22 2B 74 62 4E 61 6D 65 2B 5C 22 27 29}
// 		$s9 = {5C 22 3C 70 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 5C 5C 22 68 69 64 64 65 6E 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 73 65 6C 65 63 74 44 62 5C 5C 5C 22 20 76 61 6C 75 65 3D 5C 5C 5C 22 5C 22 2B 73 65 6C 65 63 74 44 62 2B 5C 22}

// 	condition:
// 		all of them
// }

// rule webshell_404_data_suiyue
// {
// 	meta:
// 		description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "7066f4469c3ec20f4890535b5f299122"
// 		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
// 		hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"

// 	strings:
// 		$s3 = {20 73 62 43 6F 70 79 2E 61 70 70 65 6E 64 28 5C 22 3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74 74 6F 6E 20 6E 61 6D 65 3D 67 6F 62 61 63 6B 20 76 61 6C 75 65 3D 27 20 5C 22 2B 73 74 72 42 61 63 6B 5B 6C 61 6E 67 75 61 67 65 4E 6F 5D 2B}

// 	condition:
// 		all of them
// }

// rule webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx
// {
// 	meta:
// 		description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "ef43fef943e9df90ddb6257950b3538f"
// 		hash1 = "ae025c886fbe7f9ed159f49593674832"
// 		hash2 = "911195a9b7c010f61b66439d9048f400"
// 		hash3 = "697dae78c040150daff7db751fc0c03c"
// 		hash4 = "513b7be8bd0595c377283a7c87b44b2e"
// 		hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
// 		hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
// 		hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
// 		hash8 = "41af6fd253648885c7ad2ed524e0692d"
// 		hash9 = "6fcc283470465eed4870bcc3e2d7f14d"

// 	strings:
// 		$s2 = {65 63 68 6F 20 73 72 28 31 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 35 38 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 69 6E 28 27 74 65 78 74 27 2C 27 6D 6B 5F 6E 61 6D 65}
// 		$s3 = {65 63 68 6F 20 73 72 28 31 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 32 31 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 69 6E 28 27 63 68 65 63 6B 62 6F 78 27 2C 27 6E 66 31}
// 		$s9 = {65 63 68 6F 20 73 72 28 34 30 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 32 36 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 5C 22 3C 73 65 6C 65 63 74 20 73 69 7A 65 3D}

// 	condition:
// 		all of them
// }

// rule webshell_807_a_css_dm_he1p_JspSpy_xxx
// {
// 	meta:
// 		description = "Web Shell - from files 807.jsp, a.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, style.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
// 		hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
// 		hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
// 		hash3 = "14e9688c86b454ed48171a9d4f48ace8"
// 		hash4 = "b330a6c2d49124ef0729539761d6ef0b"
// 		hash5 = "d71716df5042880ef84427acee8b121e"
// 		hash6 = "341298482cf90febebb8616426080d1d"
// 		hash7 = "29aebe333d6332f0ebc2258def94d57e"
// 		hash8 = "42654af68e5d4ea217e6ece5389eb302"
// 		hash9 = "88fc87e7c58249a398efd5ceae636073"
// 		hash10 = "4a812678308475c64132a9b56254edbc"
// 		hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
// 		hash12 = "344f9073576a066142b2023629539ebd"
// 		hash13 = "32dea47d9c13f9000c4c807561341bee"
// 		hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
// 		hash15 = "6acc82544be056580c3a1caaa4999956"
// 		hash16 = "6aa32a6392840e161a018f3907a86968"
// 		hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
// 		hash18 = "3ea688e3439a1f56b16694667938316d"
// 		hash19 = "ab77e4d1006259d7cbc15884416ca88c"
// 		hash20 = "71097537a91fac6b01f46f66ee2d7749"
// 		hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
// 		hash22 = "7a4b090619ecce6f7bd838fe5c58554b"

// 	strings:
// 		$s1 = {5C 22 3C 68 32 3E 52 65 6D 6F 74 65 20 43 6F 6E 74 72 6F 6C 20 26 72 61 71 75 6F 3B 3C 2F 68 32 3E 3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 5C 5C 5C 22 62 74 5C 5C 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 5C 5C 22 76 61 72}
// 		$s2 = {5C 22 3C 70 3E 43 75 72 72 65 6E 74 20 46 69 6C 65 20 28 69 6D 70 6F 72 74 20 6E 65 77 20 66 69 6C 65 20 6E 61 6D 65 20 61 6E 64 20 6E 65 77 20 66 69 6C 65 29 3C 62 72 20 2F 3E 3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 5C 5C 5C 22 69 6E 70 75}
// 		$s3 = {5C 22 3C 70 3E 43 75 72 72 65 6E 74 20 66 69 6C 65 20 28 66 75 6C 6C 70 61 74 68 29 3C 62 72 20 2F 3E 3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 5C 5C 5C 22 69 6E 70 75 74 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 66 69 6C 65 5C 5C 5C 22 20 69}

// 	condition:
// 		all of them
// }

// rule webshell_201_3_ma_download
// {
// 	meta:
// 		description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "a7e25b8ac605753ed0c438db93f6c498"
// 		hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
// 		hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
// 		hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"

// 	strings:
// 		$s0 = {3C 69 6E 70 75 74 20 74 69 74 6C 65 3D 5C 22 55 70 6C 6F 61 64 20 73 65 6C 65 63 74 65 64 20 66 69 6C 65 20 74 6F 20 74 68 65 20 63 75 72 72 65 6E 74 20 77 6F 72 6B 69 6E 67 20 64 69 72 65 63 74 6F 72 79 5C 22 20 74 79 70 65 3D 5C 22 53 75}
// 		$s5 = {3C 69 6E 70 75 74 20 74 69 74 6C 65 3D 5C 22 4C 61 75 6E 63 68 20 63 6F 6D 6D 61 6E 64 20 69 6E 20 63 75 72 72 65 6E 74 20 64 69 72 65 63 74 6F 72 79 5C 22 20 74 79 70 65 3D 5C 22 53 75 62 6D 69 74 5C 22 20 63 6C 61 73 73 3D 5C 22 62 75 74}
// 		$s6 = {3C 69 6E 70 75 74 20 74 69 74 6C 65 3D 5C 22 44 65 6C 65 74 65 20 61 6C 6C 20 73 65 6C 65 63 74 65 64 20 66 69 6C 65 73 20 61 6E 64 20 64 69 72 65 63 74 6F 72 69 65 73 20 69 6E 63 6C 2E 20 73 75 62 64 69 72 73 5C 22 20 63 6C 61 73 73 3D}

// 	condition:
// 		all of them
// }

// rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download
// {
// 	meta:
// 		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, ma.jsp, warn.jsp, webshell-nc.jsp, download.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
// 		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
// 		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
// 		hash3 = "36331f2c81bad763528d0ae00edf55be"
// 		hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
// 		hash5 = "8979594423b68489024447474d113894"
// 		hash6 = "ec482fc969d182e5440521c913bab9bd"
// 		hash7 = "f98d2b33cd777e160d1489afed96de39"
// 		hash8 = "4b4c12b3002fad88ca6346a873855209"
// 		hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
// 		hash10 = "e9a5280f77537e23da2545306f6a19ad"
// 		hash11 = "598eef7544935cf2139d1eada4375bb5"
// 		hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"

// 	strings:
// 		$s4 = {55 70 6C 49 6E 66 6F 20 69 6E 66 6F 20 3D 20 55 70 6C 6F 61 64 4D 6F 6E 69 74 6F 72 2E 67 65 74 49 6E 66 6F 28 66 69 2E 63 6C 69 65 6E 74 46 69 6C 65 4E 61 6D 65 29 3B}
// 		$s5 = {6C 6F 6E 67 20 74 69 6D 65 20 3D 20 28 53 79 73 74 65 6D 2E 63 75 72 72 65 6E 74 54 69 6D 65 4D 69 6C 6C 69 73 28 29 20 2D 20 73 74 61 72 74 74 69 6D 65 29 20 2F 20 31 30 30 30 6C 3B}

// 	condition:
// 		all of them
// }

// rule webshell_shell_phpspy_2006_arabicspy
// {
// 	meta:
// 		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "791708057d8b429d91357d38edf43cc0"
// 		hash1 = "40a1f840111996ff7200d18968e42cfe"
// 		hash2 = "e0202adff532b28ef1ba206cf95962f2"

// 	strings:
// 		$s0 = {65 6C 73 65 69 66 28 28 24 72 65 67 77 72 69 74 65 29 20 41 4E 44 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 77 72 69 74 65 72 65 67 6E 61 6D 65 27 5D 29 20 41 4E 44 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 72 65 67 74 79 70 65}
// 		$s8 = {65 63 68 6F 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 3F 61 63 74 69 6F 6E 3D 73 68 65 6C 6C 26 64 69 72 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 64 69 72 29 2E 5C 22 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50}

// 	condition:
// 		all of them
// }

// rule webshell_in_JFolder_jfolder01_jsp_leo_warn
// {
// 	meta:
// 		description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "793b3d0a740dbf355df3e6f68b8217a4"
// 		hash1 = "8979594423b68489024447474d113894"
// 		hash2 = "ec482fc969d182e5440521c913bab9bd"
// 		hash3 = "f98d2b33cd777e160d1489afed96de39"
// 		hash4 = "4b4c12b3002fad88ca6346a873855209"
// 		hash5 = "e9a5280f77537e23da2545306f6a19ad"

// 	strings:
// 		$s4 = {73 62 46 69 6C 65 2E 61 70 70 65 6E 64 28 5C 22 20 20 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 64 6F 46 6F 72 6D 28 27 64 6F 77 6E 27 2C 27 5C 22 2B 66 6F 72 6D 61 74 50 61 74 68 28 73 74 72 44}
// 		$s9 = {73 62 46 69 6C 65 2E 61 70 70 65 6E 64 28 5C 22 20 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 64 6F 46 6F 72 6D 28 27 65 64 69 74 27 2C 27 5C 22 2B 66 6F 72 6D 61 74 50 61 74 68 28 73 74 72 44 69}

// 	condition:
// 		all of them
// }

// rule webshell_2_520_icesword_job_ma1_ma4_2
// {
// 	meta:
// 		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "64a3bf9142b045b9062b204db39d4d57"
// 		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
// 		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
// 		hash3 = "56c005690da2558690c4aa305a31ad37"
// 		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
// 		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
// 		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

// 	strings:
// 		$s2 = {70 72 69 76 61 74 65 20 53 74 72 69 6E 67 5B 5D 20 5F 74 65 78 74 46 69 6C 65 54 79 70 65 73 20 3D 20 7B 5C 22 74 78 74 5C 22 2C 20 5C 22 68 74 6D 5C 22 2C 20 5C 22 68 74 6D 6C 5C 22 2C 20 5C 22 61 73 70 5C 22 2C 20 5C 22 6A 73 70 5C 22 2C}
// 		$s3 = {5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 75 70 46 69 6C 65 5C 5C 5C 22 20 73 69 7A 65 3D 5C 5C 5C 22 38 5C 5C 5C 22 20 63 6C 61 73 73 3D 5C 5C 5C 22 74 65 78 74 62 6F 78 5C 5C 5C 22 20 2F 3E 26 6E 62 73 70 3B 3C 69 6E 70 75 74 20 74 79 70}
// 		$s9 = {69 66 20 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 20 3D 3D 20 6E 75 6C 6C 20 26 26 20 73 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 70 61 73 73 77 6F 72}

// 	condition:
// 		all of them
// }

// rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY
// {
// 	meta:
// 		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
// 		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
// 		hash2 = "0712e3dc262b4e1f98ed25760b206836"

// 	strings:
// 		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 63 6F 6D 6D 61 6E 64 5C 22 20 73 69 7A 65 3D 5C 22 36 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61}
// 		$s7 = {65 63 68 6F 20 24 6D 73 67 3D 40 63 6F 70 79 28 24 5F 46 49 4C 45 53 5B 27 75 70 6C 6F 61 64 6D 79 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 5C 22 5C 22 2E 24 75 70 6C 6F 61 64 64 69 72 2E 5C 22 2F 5C 22 2E 24 5F 46 49 4C 45}
// 		$s8 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 70 61 73 73 74 68 72 75 5C 22 20 3C 3F 20 69 66 20 28 24 65 78 65 63 66 75 6E 63 3D 3D 5C 22 70 61 73 73 74 68 72 75 5C 22 29 20 7B 20 65 63 68 6F 20 5C 22 73 65 6C 65 63 74 65 64 5C 22 3B 20}

// 	condition:
// 		2 of them
// }

// rule webshell_shell_phpspy_2006_arabicspy_hkrkoz
// {
// 	meta:
// 		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "791708057d8b429d91357d38edf43cc0"
// 		hash1 = "40a1f840111996ff7200d18968e42cfe"
// 		hash2 = "e0202adff532b28ef1ba206cf95962f2"
// 		hash3 = "802f5cae46d394b297482fd0c27cb2fc"

// 	strings:
// 		$s5 = {24 70 72 6F 67 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 20 3A 20 5C 22 2F 63 20 6E 65 74 20 73 74 61 72 74 20 3E 20 5C 22 2E 24 70 61 74 68 6E 61 6D 65 2E}

// 	condition:
// 		all of them
// }

// rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx
// {
// 	meta:
// 		description = "Web Shell - from files c99.php, Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
// 		hash1 = "f2fa878de03732fbf5c86d656467ff50"
// 		hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
// 		hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
// 		hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
// 		hash5 = "048ccc01b873b40d57ce25a4c56ea717"

// 	strings:
// 		$s8 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 52 75 6E 6E 69 6E 67 20 64 61 74 61 70 69 70 65 2E 2E 2E 20 6F 6B 21 20 43 6F 6E 6E 65 63 74 20 74 6F 20 3C 62 3E 5C 22 2E 67 65 74 65 6E 76 28 5C 22 53 45 52 56 45 52 5F 41 44 44 52 5C 22}

// 	condition:
// 		all of them
// }

// rule webshell_2008_2009lite_2009mssql
// {
// 	meta:
// 		description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
// 		hash1 = "3f4d454d27ecc0013e783ed921eeecde"
// 		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"

// 	strings:
// 		$s0 = {3C 61 20 68 72 65 66 3D 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 67 6F 64 69 72 28 5C 5C 27 27 2E 24 64 72 69 76 65 2D 3E 50 61 74 68 2E 27 2F 5C 5C 27 29 3B}
// 		$s7 = {70 28 27 3C 68 32 3E 46 69 6C 65 20 4D 61 6E 61 67 65 72 20 2D 20 43 75 72 72 65 6E 74 20 64 69 73 6B 20 66 72 65 65 20 27 2E 73 69 7A 65 63 6F 75 6E 74 28 24 66 72 65 65 29 2E 27 20 6F 66 20 27 2E 73 69 7A 65 63 6F 75 6E 74 28 24 61 6C 6C}

// 	condition:
// 		all of them
// }

// rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz
// {
// 	meta:
// 		description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "791708057d8b429d91357d38edf43cc0"
// 		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
// 		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
// 		hash3 = "40a1f840111996ff7200d18968e42cfe"
// 		hash4 = "e0202adff532b28ef1ba206cf95962f2"
// 		hash5 = "0712e3dc262b4e1f98ed25760b206836"
// 		hash6 = "802f5cae46d394b297482fd0c27cb2fc"

// 	strings:
// 		$s0 = {24 6D 61 69 6E 70 61 74 68 5F 69 6E 66 6F 20 20 20 20 20 20 20 20 20 20 20 3D 20 65 78 70 6C 6F 64 65 28 27 2F 27 2C 20 24 6D 61 69 6E 70 61 74 68 29 3B}
// 		$s6 = {69 66 20 28 21 69 73 73 65 74 28 24 5F 47 45 54 5B 27 61 63 74 69 6F 6E 27 5D 29 20 4F 52 20 65 6D 70 74 79 28 24 5F 47 45 54 5B 27 61 63 74 69 6F 6E 27 5D 29 20 4F 52 20 28 24 5F 47 45 54 5B 27 61 63 74 69 6F 6E 27 5D 20 3D 3D 20 5C 22 64}

// 	condition:
// 		all of them
// }

// rule webshell_807_dm_JspSpyJDK5_m_cofigrue
// {
// 	meta:
// 		description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
// 		hash1 = "14e9688c86b454ed48171a9d4f48ace8"
// 		hash2 = "341298482cf90febebb8616426080d1d"
// 		hash3 = "88fc87e7c58249a398efd5ceae636073"
// 		hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"

// 	strings:
// 		$s1 = {75 72 6C 5F 63 6F 6E 2E 73 65 74 52 65 71 75 65 73 74 50 72 6F 70 65 72 74 79 28 5C 22 52 45 46 45 52 45 52 5C 22 2C 20 5C 22 5C 22 2B 66 63 6B 61 6C 2B 5C 22 5C 22 29 3B}
// 		$s9 = {46 69 6C 65 4C 6F 63 61 6C 55 70 6C 6F 61 64 28 75 63 28 64 78 28 29 29 2B 73 78 6D 2C 72 65 71 75 65 73 74 2E 67 65 74 52 65 71 75 65 73 74 55 52 4C 28 29 2E 74 6F 53 74 72 69 6E 67 28 29 2C 20 20 5C 22 47 42 4B 5C 22 29 3B}

// 	condition:
// 		1 of them
// }

// rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx
// {
// 	meta:
// 		description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
// 		hash1 = "f8a6d5306fb37414c5c772315a27832f"
// 		hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"

// 	strings:
// 		$s1 = {69 66 20 28 28 24 69 20 3D 20 61 72 72 61 79 5F 73 65 61 72 63 68 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20 24 5F 53 45 53 53 49 4F 4E 5B 27 68 69 73 74 6F 72 79 27 5D 29 29 20 21 3D 3D 20 66 61 6C 73}
// 		$s9 = {69 66 20 28 65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 24 27 2C 20 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 29 29 20 7B}

// 	condition:
// 		all of them
// }

// rule webshell_404_data_in_JFolder_jfolder01_xxx
// {
// 	meta:
// 		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "7066f4469c3ec20f4890535b5f299122"
// 		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
// 		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
// 		hash3 = "8979594423b68489024447474d113894"
// 		hash4 = "ec482fc969d182e5440521c913bab9bd"
// 		hash5 = "f98d2b33cd777e160d1489afed96de39"
// 		hash6 = "4b4c12b3002fad88ca6346a873855209"
// 		hash7 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
// 		hash8 = "e9a5280f77537e23da2545306f6a19ad"

// 	strings:
// 		$s4 = {26 6E 62 73 70 3B 3C 54 45 58 54 41 52 45 41 20 4E 41 4D 45 3D 5C 22 63 71 71 5C 22 20 52 4F 57 53 3D 5C 22 32 30 5C 22 20 43 4F 4C 53 3D 5C 22 31 30 30 25 5C 22 3E 3C 25 3D 73 62 43 6D 64 2E 74 6F 53 74 72 69 6E 67 28 29 25 3E 3C 2F 54 45}

// 	condition:
// 		all of them
// }

// rule webshell_jsp_reverse_jsp_reverse_jspbd
// {
// 	meta:
// 		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		super_rule = 1
// 		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
// 		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
// 		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
// 		score = 50

// 	strings:
// 		$s0 = {6F 73 77 20 3D 20 6E 65 77 20 42 75 66 66 65 72 65 64 57 72 69 74 65 72 28 6E 65 77 20 4F 75 74 70 75 74 53 74 72 65 61 6D 57 72 69 74 65 72 28 6F 73 29 29 3B}
// 		$s7 = {73 6F 63 6B 20 3D 20 6E 65 77 20 53 6F 63 6B 65 74 28 69 70 41 64 64 72 65 73 73 2C 20 28 6E 65 77 20 49 6E 74 65 67 65 72 28 69 70 50 6F 72 74 29 29 2E 69 6E 74 56 61 6C 75 65 28 29 29 3B}
// 		$s9 = {69 73 72 20 3D 20 6E 65 77 20 42 75 66 66 65 72 65 64 52 65 61 64 65 72 28 6E 65 77 20 49 6E 70 75 74 53 74 72 65 61 6D 52 65 61 64 65 72 28 69 73 29 29 3B}

// 	condition:
// 		all of them
// }

// rule webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc
// {
// 	meta:
// 		description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "36331f2c81bad763528d0ae00edf55be"
// 		hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
// 		hash2 = "8979594423b68489024447474d113894"
// 		hash3 = "ec482fc969d182e5440521c913bab9bd"
// 		hash4 = "f98d2b33cd777e160d1489afed96de39"
// 		hash5 = "4b4c12b3002fad88ca6346a873855209"
// 		hash6 = "e9a5280f77537e23da2545306f6a19ad"
// 		hash7 = "598eef7544935cf2139d1eada4375bb5"

// 	strings:
// 		$s0 = {73 62 46 6F 6C 64 65 72 2E 61 70 70 65 6E 64 28 5C 22 3C 74 72 3E 3C 74 64 20 3E 26 6E 62 73 70 3B 3C 2F 74 64 3E 3C 74 64 3E 5C 22 29 3B}
// 		$s1 = {72 65 74 75 72 6E 20 66 69 6C 65 73 69 7A 65 20 2F 20 69 6E 74 44 69 76 69 73 6F 72 20 2B 20 5C 22 2E 5C 22 20 2B 20 73 74 72 41 66 74 65 72 43 6F 6D 6D 61 20 2B 20 5C 22 20 5C 22 20 2B 20 73 74 72 55 6E 69 74 3B}
// 		$s5 = {46 69 6C 65 49 6E 66 6F 20 66 69 20 3D 20 28 46 69 6C 65 49 6E 66 6F 29 20 68 74 2E 67 65 74 28 5C 22 63 71 71 55 70 6C 6F 61 64 46 69 6C 65 5C 22 29 3B}
// 		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 63 6D 64 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 73 74 72 43 6D 64 25 3E 5C 22 3E}

// 	condition:
// 		2 of them
// }

// rule webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2
// {
// 	meta:
// 		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "64a3bf9142b045b9062b204db39d4d57"
// 		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
// 		hash2 = "56c005690da2558690c4aa305a31ad37"
// 		hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
// 		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
// 		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
// 		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

// 	strings:
// 		$s1 = {77 68 69 6C 65 20 28 28 6E 52 65 74 20 3D 20 69 6E 73 52 65 61 64 65 72 2E 72 65 61 64 28 74 6D 70 42 75 66 66 65 72 2C 20 30 2C 20 31 30 32 34 29 29 20 21 3D 20 2D 31 29 20 7B}
// 		$s6 = {70 61 73 73 77 6F 72 64 20 3D 20 28 53 74 72 69 6E 67 29 73 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 3B}
// 		$s7 = {69 6E 73 52 65 61 64 65 72 20 3D 20 6E 65 77 20 49 6E 70 75 74 53 74 72 65 61 6D 52 65 61 64 65 72 28 70 72 6F 63 2E 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D 28 29 2C 20 43 68 61 72 73 65 74 2E 66 6F 72 4E 61 6D 65 28 5C 22 47 42 32 33 31}

// 	condition:
// 		2 of them
// }

// rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz
// {
// 	meta:
// 		description = "Web Shell - from files shell.php, 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 60
// 		super_rule = 1
// 		hash0 = "791708057d8b429d91357d38edf43cc0"
// 		hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
// 		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
// 		hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
// 		hash4 = "40a1f840111996ff7200d18968e42cfe"
// 		hash5 = "e0202adff532b28ef1ba206cf95962f2"
// 		hash6 = "802f5cae46d394b297482fd0c27cb2fc"

// 	strings:
// 		$s0 = {24 74 61 62 6C 65 64 75 6D 70 20 2E 3D 20 5C 22 27 5C 22 2E 6D 79 73 71 6C 5F 65 73 63 61 70 65 5F 73 74 72 69 6E 67 28 24 72 6F 77 5B 24 66 69 65 6C 64 63 6F 75 6E 74 65 72 5D 29 2E 5C 22 27 5C 22 3B}
// 		$s5 = {77 68 69 6C 65 28 6C 69 73 74 28 24 6B 6E 61 6D 65 2C 20 24 63 6F 6C 75 6D 6E 73 29 20 3D 20 40 65 61 63 68 28 24 69 6E 64 65 78 29 29 20 7B}
// 		$s6 = {24 74 61 62 6C 65 64 75 6D 70 20 3D 20 5C 22 44 52 4F 50 20 54 41 42 4C 45 20 49 46 20 45 58 49 53 54 53 20 24 74 61 62 6C 65 3B 5C 5C 6E 5C 22 3B}
// 		$s9 = {24 74 61 62 6C 65 64 75 6D 70 20 2E 3D 20 5C 22 20 20 20 50 52 49 4D 41 52 59 20 4B 45 59 20 28 24 63 6F 6C 6E 61 6D 65 73 29 5C 22 3B}
// 		$fn = {66 69 6C 65 6E 61 6D 65 3A 20 62 61 63 6B 75 70}

// 	condition:
// 		2 of ($s*) and not $fn
// }

// rule webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx
// {
// 	meta:
// 		description = "Web Shell - from files gfs_sh.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
// 		hash1 = "ef43fef943e9df90ddb6257950b3538f"
// 		hash2 = "ae025c886fbe7f9ed159f49593674832"
// 		hash3 = "911195a9b7c010f61b66439d9048f400"
// 		hash4 = "697dae78c040150daff7db751fc0c03c"
// 		hash5 = "513b7be8bd0595c377283a7c87b44b2e"
// 		hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
// 		hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
// 		hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
// 		hash9 = "41af6fd253648885c7ad2ed524e0692d"
// 		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"

// 	strings:
// 		$s0 = {6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49 69 6B 37 44 51 70 6A 62 32 35 75 5A 57 4E 30 4B 46 4E 50 51 30 74 46 56 43 77 67 4A 48 42 68 5A 47 52 79 4B 53 42 38 66 43 42 6B 61 57 55 6F 49 6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49}
// 		$s11 = {41 6F 63 33 52 79 64 57 4E 30 49 48 4E 76 59 32 74 68 5A 47 52 79 49 43 6F 70 49 43 5A 7A 61 57 34 73 49 48 4E 70 65 6D 56 76 5A 69 68 7A 64 48 4A 31 59 33 51 67 63 32 39 6A 61 32 46 6B 5A 48 49 70 4B 53 6B 38 4D 43 6B 67 65 77 30 4B 49 43}

// 	condition:
// 		all of them
// }

// rule webshell_itsec_PHPJackal_itsecteam_shell_jHn
// {
// 	meta:
// 		description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
// 		hash1 = "e2830d3286001d1455479849aacbbb38"
// 		hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
// 		hash3 = "40c6ecf77253e805ace85f119fe1cebb"

// 	strings:
// 		$s0 = {24 6C 69 6E 6B 3D 70 67 5F 63 6F 6E 6E 65 63 74 28 5C 22 68 6F 73 74 3D 24 68 6F 73 74 20 64 62 6E 61 6D 65 3D 24 64 62 20 75 73 65 72 3D 24 75 73 65 72 20 70 61 73 73 77 6F 72 64 3D 24 70 61 73 73 5C 22 29 3B}
// 		$s6 = {77 68 69 6C 65 28 24 64 61 74 61 3D 6F 63 69 66 65 74 63 68 69 6E 74 6F 28 24 73 74 6D 2C 24 64 61 74 61 2C 4F 43 49 5F 41 53 53 4F 43 2B 4F 43 49 5F 52 45 54 55 52 4E 5F 4E 55 4C 4C 53 29 29 24 72 65 73 2E 3D 69 6D 70 6C 6F 64 65 28 27 7C}
// 		$s9 = {77 68 69 6C 65 28 24 64 61 74 61 3D 70 67 5F 66 65 74 63 68 5F 72 6F 77 28 24 72 65 73 75 6C 74 29 29 24 72 65 73 2E 3D 69 6D 70 6C 6F 64 65 28 27 7C 2D 7C 2D 7C 2D 7C 2D 7C 2D 7C 27 2C 24 64 61 74 61 29 2E 27 7C 2B 7C 2B 7C 2B 7C 2B 7C 2B}

// 	condition:
// 		2 of them
// }

// rule webshell_Shell_ci_Biz_was_here_c100_v_xxx
// {
// 	meta:
// 		description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "f2fa878de03732fbf5c86d656467ff50"
// 		hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
// 		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"

// 	strings:
// 		$s2 = {69 66 20 28 24 64 61 74 61 7B 30 7D 20 3D 3D 20 5C 22 5C 5C 78 39 39 5C 22 20 61 6E 64 20 24 64 61 74 61 7B 31 7D 20 3D 3D 20 5C 22 5C 5C 78 30 31 5C 22 29 20 7B 72 65 74 75 72 6E 20 5C 22 45 72 72 6F 72 3A 20 5C 22 2E 24 73 74 72 69}
// 		$s3 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 66 69 6E 64 20 2F 65 74 63 2F 20 2D 74 79 70 65 20 66 20 2D 70 65 72 6D 20 2D 6F 2B 77 20 32 3E 20 2F 64 65 76 2F 6E 75 6C 6C 5C 22}
// 		$s4 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 63 61 74 20 2F 70 72 6F 63 2F 76 65 72 73 69 6F 6E 20 2F 70 72 6F 63 2F 63 70 75 69 6E 66 6F 5C 22 3E 43 50 55 49 4E 46 4F}
// 		$s7 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 77 67 65 74 20 68 74 74 70 3A 2F 2F 66 74 70 2E 70 6F 77 65 72 6E 65 74 2E 63 6F 6D 2E 74 72 2F 73 75 70 65 72 6D 61 69 6C 2F 64 65}
// 		$s9 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 63 75 74 20 2D 64 3A 20 2D 66 31 2C 32 2C 33 20 2F 65 74 63 2F 70 61 73 73 77 64 20 7C 20 67 72 65 70 20 3A 3A 5C 22 3E 55 53 45 52}

// 	condition:
// 		2 of them
// }

// rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1
// {
// 	meta:
// 		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
// 		hash1 = "f3ca29b7999643507081caab926e2e74"
// 		hash2 = "527cf81f9272919bf872007e21c4bdda"

// 	strings:
// 		$s1 = {3C 74 64 3E 3C 69 6E 70 75 74 20 73 69 7A 65 3D 5C 22 34 38 5C 22 20 76 61 6C 75 65 3D 5C 22 24 64 6F 63 72 2F 5C 22 20 6E 61 6D 65 3D 5C 22 70 61 74 68 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D}
// 		$s2 = {24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 5F 50 4F 53 54 5B 27 70 61 74 68 27 5D 2E 24 5F 46 49 4C 45 53 5B 27 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B}
// 		$s6 = {65 6C 73 65 69 66 20 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 61 63 27 5D 29 29 20 7B 24 61 63 20 3D 20 24 5F 50 4F 53 54 5B 27 61 63 27 5D 3B 7D}
// 		$s7 = {69 66 20 28 24 5F 50 4F 53 54 5B 27 70 61 74 68 27 5D 3D 3D 5C 22 5C 22 29 7B 24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 5F 46 49 4C 45 53 5B 27 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B 7D}

// 	condition:
// 		2 of them
// }

// rule webshell_c99_c99shell_c99_w4cking_Shell_xxx
// {
// 	meta:
// 		description = "Web Shell - from files c99.php, c99shell.php, c99_w4cking.php, Shell [ci] .Biz was here.php, acid.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99.php, c99shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
// 		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
// 		hash2 = "9c34adbc8fd8d908cbb341734830f971"
// 		hash3 = "f2fa878de03732fbf5c86d656467ff50"
// 		hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
// 		hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
// 		hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
// 		hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
// 		hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
// 		hash9 = "048ccc01b873b40d57ce25a4c56ea717"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 3C 62 3E 48 45 58 44 55 4D 50 3A 3C 2F 62 3E 3C 6E 6F 62 72 3E}
// 		$s4 = {69 66 20 28 24 66 69 6C 65 73 74 65 61 6C 74 68 29 20 7B 24 73 74 61 74 20 3D 20 73 74 61 74 28 24 64 2E 24 66 29 3B 7D}
// 		$s5 = {77 68 69 6C 65 20 28 24 72 6F 77 20 3D 20 6D 79 73 71 6C 5F 66 65 74 63 68 5F 61 72 72 61 79 28 24 72 65 73 75 6C 74 2C 20 4D 59 53 51 4C 5F 4E 55 4D 29 29 20 7B 20 65 63 68 6F 20 5C 22 3C 74 72 3E 3C 74 64 3E 5C 22 2E 24 72}
// 		$s6 = {69 66 20 28 28 6D 79 73 71 6C 5F 63 72 65 61 74 65 5F 64 62 20 28 24 73 71 6C 5F 6E 65 77 64 62 29 29 20 61 6E 64 20 28 21 65 6D 70 74 79 28 24 73 71 6C 5F 6E 65 77 64 62 29 29 29 20 7B 65 63 68 6F 20 5C 22 44 42 20}
// 		$s8 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 53 65 72 76 65 72 2D 73 74 61 74 75 73 20 76 61 72 69 61 62 6C 65 73 3A 3C 2F 62 3E 3C 62 72 3E 3C 62 72 3E 5C 22 3B}
// 		$s9 = {65 63 68 6F 20 5C 22 3C 74 65 78 74 61 72 65 61 20 63 6F 6C 73 3D 38 30 20 72 6F 77 73 3D 31 30 3E 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 65 6E 63 6F 64 65 64 29 2E 5C 22 3C 2F 74 65 78 74 61 72 65 61 3E}

// 	condition:
// 		2 of them
// }

// rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz
// {
// 	meta:
// 		description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
// 		hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
// 		hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
// 		hash3 = "40a1f840111996ff7200d18968e42cfe"
// 		hash4 = "e0202adff532b28ef1ba206cf95962f2"
// 		hash5 = "802f5cae46d394b297482fd0c27cb2fc"

// 	strings:
// 		$s0 = {24 74 68 69 73 20 2D 3E 20 61 64 64 46 69 6C 65 28 24 63 6F 6E 74 65 6E 74 2C 20 24 66 69 6C 65 6E 61 6D 65 29 3B}
// 		$s3 = {66 75 6E 63 74 69 6F 6E 20 61 64 64 46 69 6C 65 28 24 64 61 74 61 2C 20 24 6E 61 6D 65 2C 20 24 74 69 6D 65 20 3D 20 30 29 20 7B}
// 		$s8 = {66 75 6E 63 74 69 6F 6E 20 75 6E 69 78 32 44 6F 73 54 69 6D 65 28 24 75 6E 69 78 74 69 6D 65 20 3D 20 30 29 20 7B}
// 		$s9 = {66 6F 72 65 61 63 68 28 24 66 69 6C 65 6C 69 73 74 20 61 73 20 24 66 69 6C 65 6E 61 6D 65 29 7B}

// 	condition:
// 		all of them
// }

// rule webshell_c99_c66_c99_shadows_mod_c99shell
// {
// 	meta:
// 		description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
// 		hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
// 		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
// 		hash3 = "048ccc01b873b40d57ce25a4c56ea717"

// 	strings:
// 		$s2 = {20 20 69 66 20 28 75 6E 6C 69 6E 6B 28 5F 46 49 4C 45 5F 29 29 20 7B 40 6F 62 5F 63 6C 65 61 6E 28 29 3B 20 65 63 68 6F 20 5C 22 54 68 61 6E 6B 73 20 66 6F 72 20 75 73 69 6E 67 20 63 39 39 73 68 65 6C 6C 20 76 2E 5C 22 2E 24 73 68 76}
// 		$s3 = {20 20 5C 22 63 39 39 73 68 5F 62 61 63 6B 63 6F 6E 6E 2E 70 6C 5C 22 3D 3E 61 72 72 61 79 28 5C 22 55 73 69 6E 67 20 50 45 52 4C 5C 22 2C 5C 22 70 65 72 6C 20 25 70 61 74 68 20 25 68 6F 73 74 20 25 70 6F 72 74 5C 22 29 2C}
// 		$s4 = {3C 62 72 3E 3C 54 41 42 4C 45 20 73 74 79 6C 65 3D 5C 22 42 4F 52 44 45 52 2D 43 4F 4C 4C 41 50 53 45 3A 20 63 6F 6C 6C 61 70 73 65 5C 22 20 63 65 6C 6C 53 70 61 63 69 6E 67 3D 30 20 62 6F 72 64 65 72 43 6F 6C 6F 72 44 61 72 6B 3D 23 36 36}
// 		$s7 = {20 20 20 65 6C 73 65 69 66 20 28 21 24 64 61 74 61 20 3D 20 63 39 39 67 65 74 73 6F 75 72 63 65 28 24 62 69 6E 64 5B 5C 22 73 72 63 5C 22 5D 29 29 20 7B 65 63 68 6F 20 5C 22 43 61 6E 27 74 20 64 6F 77 6E 6C 6F 61 64 20 73 6F 75 72 63 65 73}
// 		$s8 = {20 20 5C 22 63 39 39 73 68 5F 64 61 74 61 70 69 70 65 2E 70 6C 5C 22 3D 3E 61 72 72 61 79 28 5C 22 55 73 69 6E 67 20 50 45 52 4C 5C 22 2C 5C 22 70 65 72 6C 20 25 70 61 74 68 20 25 6C 6F 63 61 6C 70 6F 72 74 20 25 72 65 6D 6F 74 65 68 6F 73}
// 		$s9 = {20 20 20 65 6C 73 65 69 66 20 28 21 24 64 61 74 61 20 3D 20 63 39 39 67 65 74 73 6F 75 72 63 65 28 24 62 63 5B 5C 22 73 72 63 5C 22 5D 29 29 20 7B 65 63 68 6F 20 5C 22 43 61 6E 27 74 20 64 6F 77 6E 6C 6F 61 64 20 73 6F 75 72 63 65 73 21}

// 	condition:
// 		2 of them
// }

// rule webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1
// {
// 	meta:
// 		description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "b330a6c2d49124ef0729539761d6ef0b"
// 		hash1 = "d71716df5042880ef84427acee8b121e"
// 		hash2 = "344f9073576a066142b2023629539ebd"
// 		hash3 = "32dea47d9c13f9000c4c807561341bee"
// 		hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
// 		hash5 = "3ea688e3439a1f56b16694667938316d"
// 		hash6 = "2434a7a07cb47ce25b41d30bc291cacc"

// 	strings:
// 		$s0 = {5C 22 5C 22 2B 66 2E 63 61 6E 52 65 61 64 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 57 72 69 74 65 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 45 78 65 63 75 74 65 28 29 2B 5C 22 3C 2F 74 64 3E 5C 22 2B}
// 		$s4 = {6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 3C 68 32 3E 46 69 6C 65 20 4D 61 6E 61 67 65 72 20 2D 20 43 75 72 72 65 6E 74 20 64 69 73 6B 20 26 71 75 6F 74 3B 5C 22 2B 28 63 72 2E 69 6E 64 65 78 4F 66 28 5C 22 2F 5C 22 29 20 3D 3D 20 30 3F}
// 		$s7 = {53 74 72 69 6E 67 20 65 78 65 63 75 74 65 20 3D 20 66 2E 63 61 6E 45 78 65 63 75 74 65 28 29 20 3F 20 5C 22 63 68 65 63 6B 65 64 3D 5C 5C 5C 22 63 68 65 63 6B 65 64 5C 5C 5C 22 5C 22 20 3A 20 5C 22 5C 22 3B}
// 		$s8 = {5C 22 3C 74 64 20 6E 6F 77 72 61 70 3E 5C 22 2B 66 2E 63 61 6E 52 65 61 64 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 57 72 69 74 65 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 45 78 65 63 75 74 65 28 29 2B 5C 22 3C 2F 74 64 3E}

// 	condition:
// 		2 of them
// }

// rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend
// {
// 	meta:
// 		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
// 		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
// 		hash2 = "8b457934da3821ba58b06a113e0d53d9"
// 		hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
// 		hash4 = "e0354099bee243702eb11df8d0e046df"
// 		hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
// 		hash6 = "655722eaa6c646437c8ae93daac46ae0"
// 		hash7 = "591ca89a25f06cf01e4345f98a22845c"

// 	strings:
// 		$s0 = {72 65 74 75 72 6E 20 6E 65 77 20 44 6F 75 62 6C 65 28 66 6F 72 6D 61 74 2E 66 6F 72 6D 61 74 28 76 61 6C 75 65 29 29 2E 64 6F 75 62 6C 65 56 61 6C 75 65 28 29 3B}
// 		$s5 = {46 69 6C 65 20 74 65 6D 70 46 20 3D 20 6E 65 77 20 46 69 6C 65 28 73 61 76 65 50 61 74 68 29 3B}
// 		$s9 = {69 66 20 28 74 65 6D 70 46 2E 69 73 44 69 72 65 63 74 6F 72 79 28 29 29 20 7B}

// 	condition:
// 		2 of them
// }

// rule webshell_c99_c99shell_c99_c99shell
// {
// 	meta:
// 		description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
// 		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
// 		hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
// 		hash3 = "048ccc01b873b40d57ce25a4c56ea717"

// 	strings:
// 		$s2 = {24 62 69 6E 64 70 6F 72 74 5F 70 61 73 73 20 3D 20 5C 22 63 39 39 5C 22 3B}
// 		$s5 = {20 65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 45 78 65 63 75 74 69 6F 6E 20 50 48 50 2D 63 6F 64 65 3C 2F 62 3E 5C 22 3B 20 69 66 20 28 65 6D 70 74 79 28 24 65 76 61 6C 5F 74 78 74 29 29 20 7B 24 65 76 61 6C 5F 74 78 74 20 3D 20 74 72}

// 	condition:
// 		1 of them
// }

// rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat
// {
// 	meta:
// 		description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "ae025c886fbe7f9ed159f49593674832"
// 		hash1 = "513b7be8bd0595c377283a7c87b44b2e"
// 		hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
// 		hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
// 		hash4 = "3f71175985848ee46cc13282fbed2269"

// 	strings:
// 		$s6 = {24 72 65 73 20 20 20 3D 20 40 6D 79 73 71 6C 5F 71 75 65 72 79 28 5C 22 53 48 4F 57 20 43 52 45 41 54 45 20 54 41 42 4C 45 20 60 5C 22 2E 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 5F 74 62 6C 27 5D 2E 5C 22 60 5C 22 2C 20 24 64}
// 		$s7 = {24 73 71 6C 31 20 2E 3D 20 24 72 6F 77 5B 31 5D 2E 5C 22 5C 5C 72 5C 5C 6E 5C 5C 72 5C 5C 6E 5C 22 3B}
// 		$s8 = {69 66 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 64 69 66 27 5D 29 26 26 24 66 70 29 20 7B 20 40 66 70 75 74 73 28 24 66 70 2C 24 73 71 6C 31 2E 24 73 71 6C 32 29 3B 20 7D}
// 		$s9 = {66 6F 72 65 61 63 68 28 24 76 61 6C 75 65 73 20 61 73 20 24 6B 3D 3E 24 76 29 20 7B 24 76 61 6C 75 65 73 5B 24 6B 5D 20 3D 20 61 64 64 73 6C 61 73 68 65 73 28 24 76 29 3B 7D}

// 	condition:
// 		2 of them
// }

// rule webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx
// {
// 	meta:
// 		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
// 		hash1 = "4745d510fed4378e4b1730f56f25e569"
// 		hash2 = "f3ca29b7999643507081caab926e2e74"
// 		hash3 = "46a18979750fa458a04343cf58faa9bd"

// 	strings:
// 		$s3 = {42 4F 44 59 2C 20 54 44 2C 20 54 52 20 7B}
// 		$s5 = {24 64 3D 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 5C 22 2F 5C 22 2C 24 64 29 3B}
// 		$s6 = {69 66 20 28 24 66 69 6C 65 3D 3D 5C 22 2E 5C 22 20 7C 7C 20 24 66 69 6C 65 3D 3D 5C 22 2E 2E 5C 22 29 20 63 6F 6E 74 69 6E 75 65 3B}

// 	condition:
// 		2 of them
// }

// rule webshell_000_403_807_a_c5_config_css_dm_he1p_xxx
// {
// 	meta:
// 		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
// 		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
// 		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
// 		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
// 		hash4 = "8b457934da3821ba58b06a113e0d53d9"
// 		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
// 		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
// 		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
// 		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
// 		hash9 = "d71716df5042880ef84427acee8b121e"
// 		hash10 = "341298482cf90febebb8616426080d1d"
// 		hash11 = "29aebe333d6332f0ebc2258def94d57e"
// 		hash12 = "42654af68e5d4ea217e6ece5389eb302"
// 		hash13 = "88fc87e7c58249a398efd5ceae636073"
// 		hash14 = "4a812678308475c64132a9b56254edbc"
// 		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
// 		hash16 = "e0354099bee243702eb11df8d0e046df"
// 		hash17 = "344f9073576a066142b2023629539ebd"
// 		hash18 = "32dea47d9c13f9000c4c807561341bee"
// 		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
// 		hash20 = "655722eaa6c646437c8ae93daac46ae0"
// 		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
// 		hash22 = "6acc82544be056580c3a1caaa4999956"
// 		hash23 = "6aa32a6392840e161a018f3907a86968"
// 		hash24 = "591ca89a25f06cf01e4345f98a22845c"
// 		hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
// 		hash26 = "3ea688e3439a1f56b16694667938316d"
// 		hash27 = "ab77e4d1006259d7cbc15884416ca88c"
// 		hash28 = "71097537a91fac6b01f46f66ee2d7749"
// 		hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
// 		hash30 = "7a4b090619ecce6f7bd838fe5c58554b"

// 	strings:
// 		$s3 = {53 74 72 69 6E 67 20 73 61 76 65 50 61 74 68 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 73 61 76 65 70 61 74 68 5C 22 29 3B}
// 		$s4 = {55 52 4C 20 64 6F 77 6E 55 72 6C 20 3D 20 6E 65 77 20 55 52 4C 28 64 6F 77 6E 46 69 6C 65 55 72 6C 29 3B}
// 		$s5 = {69 66 20 28 55 74 69 6C 2E 69 73 45 6D 70 74 79 28 64 6F 77 6E 46 69 6C 65 55 72 6C 29 20 7C 7C 20 55 74 69 6C 2E 69 73 45 6D 70 74 79 28 73 61 76 65 50 61 74 68 29 29}
// 		$s6 = {53 74 72 69 6E 67 20 64 6F 77 6E 46 69 6C 65 55 72 6C 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 75 72 6C 5C 22 29 3B}
// 		$s7 = {46 69 6C 65 49 6E 70 75 74 53 74 72 65 61 6D 20 66 49 6E 70 75 74 20 3D 20 6E 65 77 20 46 69 6C 65 49 6E 70 75 74 53 74 72 65 61 6D 28 66 29 3B}
// 		$s8 = {55 52 4C 43 6F 6E 6E 65 63 74 69 6F 6E 20 63 6F 6E 6E 20 3D 20 64 6F 77 6E 55 72 6C 2E 6F 70 65 6E 43 6F 6E 6E 65 63 74 69 6F 6E 28 29 3B}
// 		$s9 = {73 69 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D 28 29 3B}

// 	condition:
// 		4 of them
// }

// rule webshell_2_520_icesword_job_ma1
// {
// 	meta:
// 		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "64a3bf9142b045b9062b204db39d4d57"
// 		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
// 		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
// 		hash3 = "56c005690da2558690c4aa305a31ad37"
// 		hash4 = "532b93e02cddfbb548ce5938fe2f5559"

// 	strings:
// 		$s1 = {3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 5C 22 20 63 6F 6E 74 65 6E 74 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 67 62 32 33 31 32 5C 22 3E 3C 2F 68 65 61 64 3E}
// 		$s3 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 5F 45 56 45 4E 54 54 41 52 47 45 54 5C 22 20 76 61 6C 75 65 3D 5C 22 5C 22 20 2F 3E}
// 		$s8 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 5F 45 56 45 4E 54 41 52 47 55 4D 45 4E 54 5C 22 20 76 61 6C 75 65 3D 5C 22 5C 22 20 2F 3E}

// 	condition:
// 		2 of them
// }

// rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn
// {
// 	meta:
// 		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "7066f4469c3ec20f4890535b5f299122"
// 		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
// 		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
// 		hash3 = "8979594423b68489024447474d113894"
// 		hash4 = "ec482fc969d182e5440521c913bab9bd"
// 		hash5 = "f98d2b33cd777e160d1489afed96de39"
// 		hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
// 		hash7 = "e9a5280f77537e23da2545306f6a19ad"

// 	strings:
// 		$s0 = {3C 74 61 62 6C 65 20 77 69 64 74 68 3D 5C 22 31 30 30 25 5C 22 20 62 6F 72 64 65 72 3D 5C 22 31 5C 22 20 63 65 6C 6C 73 70 61 63 69 6E 67 3D 5C 22 30 5C 22 20 63 65 6C 6C 70 61 64 64 69 6E 67 3D 5C 22 35 5C 22 20 62 6F 72 64 65 72 63 6F 6C}
// 		$s2 = {20 4B 42 20 3C 2F 74 64 3E}
// 		$s3 = {3C 74 61 62 6C 65 20 77 69 64 74 68 3D 5C 22 39 38 25 5C 22 20 62 6F 72 64 65 72 3D 5C 22 30 5C 22 20 63 65 6C 6C 73 70 61 63 69 6E 67 3D 5C 22 30 5C 22 20 63 65 6C 6C 70 61 64 64 69 6E 67 3D 5C 22}
// 		$s4 = {3C 21 2D 2D 20 3C 74 72 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 20}

// 	condition:
// 		all of them
// }

// rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY
// {
// 	meta:
// 		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
// 		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
// 		hash2 = "40a1f840111996ff7200d18968e42cfe"
// 		hash3 = "0712e3dc262b4e1f98ed25760b206836"

// 	strings:
// 		$s4 = {68 74 74 70 3A 2F 2F 77 77 77 2E 34 6E 67 65 6C 2E 6E 65 74}
// 		$s5 = {3C 2F 61 3E 20 7C 20 3C 61 20 68 72 65 66 3D 5C 22 3F 61 63 74 69 6F 6E 3D 70 68 70 65 6E 76 5C 22 3E 50 48 50}
// 		$s8 = {65 63 68 6F 20 24 6D 73 67 3D 40 66 77 72 69 74 65 28 24 66 70 2C 24 5F 50 4F 53 54 5B 27 66 69 6C 65 63 6F 6E 74 65 6E 74 27 5D 29 20 3F 20 5C 22}
// 		$s9 = {43 6F 64 7A 20 62 79 20 41 6E 67 65 6C}

// 	condition:
// 		2 of them
// }

// rule webshell_c99_locus7s_c99_w4cking_xxx
// {
// 	meta:
// 		description = "Web Shell - from files c99_locus7s.php, c99_w4cking.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, acid.php, newsh.php, r57.php, Backdoor.PHP.Agent.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
// 		hash1 = "9c34adbc8fd8d908cbb341734830f971"
// 		hash2 = "ef43fef943e9df90ddb6257950b3538f"
// 		hash3 = "ae025c886fbe7f9ed159f49593674832"
// 		hash4 = "911195a9b7c010f61b66439d9048f400"
// 		hash5 = "697dae78c040150daff7db751fc0c03c"
// 		hash6 = "513b7be8bd0595c377283a7c87b44b2e"
// 		hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
// 		hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
// 		hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
// 		hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
// 		hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
// 		hash12 = "41af6fd253648885c7ad2ed524e0692d"
// 		hash13 = "6fcc283470465eed4870bcc3e2d7f14d"

// 	strings:
// 		$s1 = {24 72 65 73 20 3D 20 40 73 68 65 6C 6C 5F 65 78 65 63 28 24 63 66 65 29 3B}
// 		$s8 = {24 72 65 73 20 3D 20 40 6F 62 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 29 3B}
// 		$s9 = {40 65 78 65 63 28 24 63 66 65 2C 24 72 65 73 29 3B}

// 	condition:
// 		2 of them
// }

// rule webshell_browser_201_3_ma_ma2_download
// {
// 	meta:
// 		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
// 		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
// 		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
// 		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
// 		hash4 = "4b45715fa3fa5473640e17f49ef5513d"
// 		hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"

// 	strings:
// 		$s1 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 66 69 6E 61 6C 20 69 6E 74 20 45 44 49 54 46 49 45 4C 44 5F 52 4F 57 53 20 3D 20 33 30 3B}
// 		$s2 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 53 74 72 69 6E 67 20 74 65 6D 70 64 69 72 20 3D 20 5C 22 2E 5C 22 3B}
// 		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 64 69 72 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 72 65 71 75 65 73 74 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 64 69 72 5C 22 29 25 3E 5C 22}

// 	condition:
// 		2 of them
// }

// rule webshell_000_403_c5_queryDong_spyjsp2010
// {
// 	meta:
// 		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
// 		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
// 		hash2 = "8b457934da3821ba58b06a113e0d53d9"
// 		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
// 		hash4 = "655722eaa6c646437c8ae93daac46ae0"

// 	strings:
// 		$s2 = {5C 22 20 3C 73 65 6C 65 63 74 20 6E 61 6D 65 3D 27 65 6E 63 6F 64 65 27 20 63 6C 61 73 73 3D 27 69 6E 70 75 74 27 3E 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 27 27 3E 41 4E 53 49 3C 2F 6F 70 74 69 6F 6E 3E 3C 6F 70 74 69 6F 6E 20 76 61 6C}
// 		$s7 = {4A 53 65 73 73 69 6F 6E 2E 73 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 4D 53 47 5C 22 2C 5C 22 3C 73 70 61 6E 20 73 74 79 6C 65 3D 27 63 6F 6C 6F 72 3A 72 65 64 27 3E 55 70 6C 6F 61 64 20 46 69 6C 65 20 46 61 69 6C 65 64 21 3C 2F 73 70 61}
// 		$s8 = {46 69 6C 65 20 66 20 3D 20 6E 65 77 20 46 69 6C 65 28 4A 53 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 43 55 52 52 45 4E 54 5F 44 49 52 29 2B 5C 22 2F 5C 22 2B 66 69 6C 65 42 65 61 6E 2E 67 65 74 46 69 6C 65 4E 61 6D 65 28}
// 		$s9 = {28 28 49 6E 76 6F 6B 65 72 29 69 6E 73 2E 67 65 74 28 5C 22 76 64 5C 22 29 29 2E 69 6E 76 6F 6B 65 28 72 65 71 75 65 73 74 2C 72 65 73 70 6F 6E 73 65 2C 4A 53 65 73 73 69 6F 6E 29 3B}

// 	condition:
// 		2 of them
// }

// rule webshell_r57shell127_r57_kartal_r57
// {
// 	meta:
// 		description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
// 		author = "Florian Roth"
// 		date = "2014/01/28"
// 		score = 70
// 		super_rule = 1
// 		hash0 = "ae025c886fbe7f9ed159f49593674832"
// 		hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
// 		hash2 = "4108f28a9792b50d95f95b9e5314fa1e"

// 	strings:
// 		$s2 = {24 68 61 6E 64 6C 65 20 3D 20 40 6F 70 65 6E 64 69 72 28 24 64 69 72 29 20 6F 72 20 64 69 65 28 5C 22 43 61 6E 27 74 20 6F 70 65 6E 20 64 69 72 65 63 74 6F 72 79 20 24 64 69 72 5C 22 29 3B}
// 		$s3 = {69 66 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 5F 64 62 27 5D 29 29 20 7B 20 40 6D 73 73 71 6C 5F 73 65 6C 65 63 74 5F 64 62 28 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 5F 64 62 27 5D 2C 24 64 62 29 3B 20 7D}
// 		$s5 = {69 66 20 28 21 69 73 73 65 74 28 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 55 53 45 52 27 5D 29 20 7C 7C 20 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 55 53 45 52 27 5D 21 3D 3D 24 6E 61 6D 65 20 7C 7C 20 24 5F}

// 	condition:
// 		2 of them
// }

// rule webshell_webshells_new_con2
// {
// 	meta:
// 		description = "Web shells - generated from file con2.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "d3584159ab299d546bd77c9654932ae3"

// 	strings:
// 		$s7 = {2C 68 74 61 50 72 65 77 6F 50 28 65 63 61 6C 70 65 72 3D 68 74 61 50 72 65 77 6F 50 3A 66 49 20 64 6E 45 3A 30 3D 4B 4F 74 69 64 45 3A 31 20 2D 20 65 75 6C 61 56 74 6E 69 20 3D 20 65 75 6C 61 56 74 6E 69 3A 6E 65 68 54 20 31 20 3D 3E 20 65}
// 		$s10 = {6A 20 5C 22 3C 46 6F 72 6D 20 61 63 74 69 6F 6E 3D 27 5C 22 26 55 52 4C 26 5C 22 3F 41 63 74 69 6F 6E 32 3D 50 6F 73 74 27 20 6D 65 74 68 6F 64 3D 27 70 6F 73 74 27 20 6E 61 6D 65 3D 27 45 64 69 74 46 6F 72 6D 27 3E 3C 69 6E 70 75 74 20 6E}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_make2
// {
// 	meta:
// 		description = "Web shells - generated from file make2.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		hash = "9af195491101e0816a263c106e4c145e"
// 		score = 50

// 	strings:
// 		$s1 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 30 29 3B 73 65 73 73 69 6F 6E 5F 73 74 61 72 74 28 29 3B 68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 74 79 70 65 3A 74 65 78 74 2F 68 74 6D 6C 3B 63 68 61 72 73 65 74 3D 75 74 66 2D 38}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_aaa
// {
// 	meta:
// 		description = "Web shells - generated from file aaa.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "68483788ab171a155db5266310c852b2"

// 	strings:
// 		$s0 = {46 75 6E 63 74 69 6F 6E 20 66 76 6D 28 6A 77 76 29 3A 49 66 20 6A 77 76 3D 5C 22 5C 22 54 68 65 6E 3A 66 76 6D 3D 6A 77 76 3A 45 78 69 74 20 46 75 6E 63 74 69 6F 6E 3A 45 6E 64 20 49 66 3A 44 69 6D 20 74 74 2C 73 72 75 3A 74 74 3D 5C 22}
// 		$s5 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 5C 22 44 52 4F 50 20 54 41 42 4C 45 20 5B 6A 6E 63 5D 3B 65 78 65 63 20 6D 61 73 74 5C 22 26 6B 76 70 26 5C 22 65 72 2E 2E 78 70 5F 72 65 67 77 72 69 74 65 20 27 48 4B 45 59 5F 4C 4F 43 41 4C}
// 		$s17 = {69 66 20 71 70 76 3D 5C 22 5C 22 20 74 68 65 6E 20 71 70 76 3D 5C 22 78 3A 5C 5C 50 72 6F 67 72 61 6D 20 46 69 6C 65 73 5C 5C 4D 79 53 51 4C 5C 5C 4D 79 53 51 4C 20 53 65 72 76 65 72 20 35 2E 30 5C 5C 6D 79 2E 69 6E 69 5C 22 26 62 72 26}

// 	condition:
// 		1 of them
// }

// rule webshell_Expdoor_com_ASP
// {
// 	meta:
// 		description = "Web shells - generated from file Expdoor.com ASP.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "caef01bb8906d909f24d1fa109ea18a7"

// 	strings:
// 		$s4 = {5C 22 3E 77 77 77 2E 45 78 70 64 6F 6F 72 2E 63 6F 6D 3C 2F 61 3E}
// 		$s5 = {20 20 20 20 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 46 69 6C 65 4E 61 6D 65 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 76 61 6C 75 65 3D 5C 22 41 73 70 5F 76 65 72 2E 41 73 70 5C 22 20 73 69 7A 65 3D 5C 22 32 30 5C 22 20 6D 61 78}
// 		$s10 = {73 65 74 20 66 69 6C 65 3D 66 73 2E 4F 70 65 6E 54 65 78 74 46 69 6C 65 28 73 65 72 76 65 72 2E 4D 61 70 50 61 74 68 28 46 69 6C 65 4E 61 6D 65 29 2C 38 2C 54 72 75 65 29 20 20 27}
// 		$s14 = {73 65 74 20 66 73 3D 73 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 5C 22 29 20 20 20 27}
// 		$s16 = {3C 54 49 54 4C 45 3E 45 78 70 64 6F 6F 72 2E 63 6F 6D 20 41 53 50}

// 	condition:
// 		2 of them
// }

// rule webshell_webshells_new_php2
// {
// 	meta:
// 		description = "Web shells - generated from file php2.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "fbf2e76e6f897f6f42b896c855069276"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 24 73 3D 40 24 5F 47 45 54 5B 32 5D 3B 69 66 28 6D 64 35 28 24 73 2E 24 73 29 3D 3D}

// 	condition:
// 		all of them
// }

// rule webshell_bypass_iisuser_p
// {
// 	meta:
// 		description = "Web shells - generated from file bypass-iisuser-p.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "924d294400a64fa888a79316fb3ccd90"

// 	strings:
// 		$s0 = {3C 25 45 76 61 6C 28 52 65 71 75 65 73 74 28 63 68 72 28 31 31 32 29 29 29 3A 53 65 74 20 66 73 6F 3D 43 72 65 61 74 65 4F 62 6A 65 63 74}

// 	condition:
// 		all of them
// }

// rule webshell_sig_404super
// {
// 	meta:
// 		description = "Web shells - generated from file 404super.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "7ed63176226f83d36dce47ce82507b28"

// 	strings:
// 		$s4 = {24 69 20 3D 20 70 61 63 6B 28 27 63 2A 27 2C 20 30 78 37 30 2C 20 30 78 36 31 2C 20 39 39 2C 20 31 30 37 29 3B}
// 		$s6 = {20 20 20 20 27 68 27 20 3D 3E 20 24 69 28 27 48 2A 27 2C 20 27 36 38 37 34 37 34 37 30 33 61 32 66 32 66 36 32 36 63 36 31 36 62 36 39 36 65 32 65 36 34 37 35 36 31 37 30 37 30 32 65 36 33 36 66 36 64 32 66 37 36 33 31 27 29 2C}
// 		$s7 = {2F 2F 68 74 74 70 3A 2F 2F 72 65 71 75 69 72 65 2E 64 75 61 70 70 2E 63 6F 6D 2F 73 65 73 73 69 6F 6E 2E 70 68 70}
// 		$s8 = {69 66 28 21 69 73 73 65 74 28 24 5F 53 45 53 53 49 4F 4E 5B 27 74 27 5D 29 29 7B 24 5F 53 45 53 53 49 4F 4E 5B 27 74 27 5D 20 3D 20 24 47 4C 4F 42 41 4C 53 5B 27 66 27 5D 28 24 47 4C 4F 42 41 4C 53 5B 27 68 27 5D 29 3B 7D}
// 		$s12 = {2F 2F 64 65 66 69 6E 65 28 27 70 61 73 73 27 2C 27 31 32 33 34 35 36 27 29 3B}
// 		$s13 = {24 47 4C 4F 42 41 4C 53 5B 27 63 27 5D 28 24 47 4C 4F 42 41 4C 53 5B 27 65 27 5D 28 6E 75 6C 6C 2C 20 24 47 4C 4F 42 41 4C 53 5B 27 73 27 5D 28 27 25 73 27 2C 24 47 4C 4F 42 41 4C 53 5B 27 70 27 5D 28 27 48 2A 27 2C 24 5F 53 45 53 53 49 4F}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_JSP
// {
// 	meta:
// 		description = "Web shells - generated from file JSP.jsp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "495f1a0a4c82f986f4bdf51ae1898ee7"

// 	strings:
// 		$s1 = {76 6F 69 64 20 41 41 28 53 74 72 69 6E 67 42 75 66 66 65 72 20 73 62 29 74 68 72 6F 77 73 20 45 78 63 65 70 74 69 6F 6E 7B 46 69 6C 65 20 72 5B 5D 3D 46 69 6C 65 2E 6C 69 73 74 52 6F 6F 74 73 28 29 3B 66 6F 72 28 69 6E 74 20 69 3D 30 3B 69}
// 		$s5 = {62 77 2E 77 72 69 74 65 28 7A 32 29 3B 62 77 2E 63 6C 6F 73 65 28 29 3B 73 62 2E 61 70 70 65 6E 64 28 5C 22 31 5C 22 29 3B 7D 65 6C 73 65 20 69 66 28 5A 2E 65 71 75 61 6C 73 28 5C 22 45 5C 22 29 29 7B 45 45 28 7A 31 29 3B 73 62 2E 61 70 70}
// 		$s11 = {69 66 28 5A 2E 65 71 75 61 6C 73 28 5C 22 41 5C 22 29 29 7B 53 74 72 69 6E 67 20 73 3D 6E 65 77 20 46 69 6C 65 28 61 70 70 6C 69 63 61 74 69 6F 6E 2E 67 65 74 52 65 61 6C 50 61 74 68 28 72 65 71 75 65 73 74 2E 67 65 74 52 65 71 75 65 73 74}

// 	condition:
// 		1 of them
// }

// rule webshell_webshell_123
// {
// 	meta:
// 		description = "Web shells - generated from file webshell-123.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "2782bb170acaed3829ea9a04f0ac7218"

// 	strings:
// 		$s0 = {2F 2F 20 57 65 62 20 53 68 65 6C 6C 21 21}
// 		$s1 = {40 70 72 65 67 5F 72 65 70 6C 61 63 65 28 5C 22 2F 2E 2A 2F 65 5C 22 2C 5C 22 5C 5C 78 36 35 5C 5C 78 37 36 5C 5C 78 36 31 5C 5C 78 36 43 5C 5C 78 32 38 5C 5C 78 36 37 5C 5C 78 37 41 5C 5C 78 36 39 5C 5C 78 36 45 5C 5C 78 36 36 5C 5C 78 36}
// 		$s3 = {24 64 65 66 61 75 6C 74 5F 63 68 61 72 73 65 74 20 3D 20 5C 22 55 54 46 2D 38 5C 22 3B}
// 		$s4 = {2F 2F 20 75 72 6C 3A 68 74 74 70 3A 2F 2F 77 77 77 2E 77 65 69 67 6F 6E 67 6B 61 69 2E 63 6F 6D 2F 73 68 65 6C 6C 2F}

// 	condition:
// 		2 of them
// }

// rule webshell_dev_core
// {
// 	meta:
// 		description = "Web shells - generated from file dev_core.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "55ad9309b006884f660c41e53150fc2e"

// 	strings:
// 		$s1 = {69 66 20 28 73 74 72 70 6F 73 28 24 5F 53 45 52 56 45 52 5B 27 48 54 54 50 5F 55 53 45 52 5F 41 47 45 4E 54 27 5D 2C 20 27 45 42 53 44 27 29 20 3D 3D 20 66 61 6C 73 65 29 20 7B}
// 		$s9 = {73 65 74 63 6F 6F 6B 69 65 28 27 6B 65 79 27 2C 20 24 5F 50 4F 53 54 5B 27 70 77 64 27 5D 2C 20 74 69 6D 65 28 29 20 2B 20 33 36 30 30 20 2A 20 32 34 20 2A 20 33 30 29 3B}
// 		$s10 = {24 5F 53 45 53 53 49 4F 4E 5B 27 63 6F 64 65 27 5D 20 3D 20 5F 52 45 51 55 45 53 54 28 73 70 72 69 6E 74 66 28 5C 22 25 73 3F 25 73 5C 22 2C 70 61 63 6B 28 5C 22 48 2A 5C 22 2C 27 36 38 37 34}
// 		$s11 = {69 66 20 28 70 72 65 67 5F 6D 61 74 63 68 28 5C 22 2F 5E 48 54 54 50 5C 5C 2F 5C 5C 64 5C 5C 2E 5C 5C 64 5C 5C 73 28 5B 5C 5C 64 5D 2B 29 5C 5C 73 2E 2A 24 2F 5C 22 2C 20 24 73 74 61 74 75 73 2C 20 24 6D 61 74 63 68 65 73 29 29}
// 		$s12 = {65 76 61 6C 28 67 7A 75 6E 63 6F 6D 70 72 65 73 73 28 67 7A 75 6E 63 6F 6D 70 72 65 73 73 28 43 72 79 70 74 3A 3A 64 65 63 72 79 70 74 28 24 5F 53 45 53 53 49 4F 4E 5B 27 63 6F 64 65 27 5D 2C 20 24 5F 43}
// 		$s15 = {69 66 20 28 28 24 66 73 6F 63 6B 20 3D 20 66 73 6F 63 6B 6F 70 65 6E 28 24 75 72 6C 32 5B 27 68 6F 73 74 27 5D 2C 20 38 30 2C 20 24 65 72 72 6E 6F 2C 20 24 65 72 72 73 74 72 2C 20 24 66 73 6F 63 6B 5F 74 69 6D 65 6F 75 74 29 29}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_pHp
// {
// 	meta:
// 		description = "Web shells - generated from file pHp.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "b0e842bdf83396c3ef8c71ff94e64167"

// 	strings:
// 		$s0 = {69 66 28 69 73 5F 72 65 61 64 61 62 6C 65 28 24 70 61 74 68 29 29 20 61 6E 74 69 76 69 72 75 73 28 24 70 61 74 68 2E 27 2F 27 2C 24 65 78 73 2C 24 6D 61 74 63 68 65 73 29 3B}
// 		$s1 = {27 2F 28 65 76 61 6C 7C 61 73 73 65 72 74 7C 69 6E 63 6C 75 64 65 7C 72 65 71 75 69 72 65 7C 69 6E 63 6C 75 64 65 5C 5C 5F 6F 6E 63 65 7C 72 65 71 75 69 72 65 5C 5C 5F 6F 6E 63 65 7C 61 72 72 61 79 5C 5C 5F 6D 61 70 7C 61 72 72}
// 		$s13 = {27 2F 28 65 78 65 63 7C 73 68 65 6C 6C 5C 5C 5F 65 78 65 63 7C 73 79 73 74 65 6D 7C 70 61 73 73 74 68 72 75 29 2B 5C 5C 73 2A 5C 5C 28 5C 5C 73 2A 5C 5C 24 5C 5C 5F 28 5C 5C 77 2B 29 5C 5C 5B 28 2E 2A 29 5C 5C 5D 5C 5C 73 2A}
// 		$s14 = {27 2F 28 69 6E 63 6C 75 64 65 7C 72 65 71 75 69 72 65 7C 69 6E 63 6C 75 64 65 5C 5C 5F 6F 6E 63 65 7C 72 65 71 75 69 72 65 5C 5C 5F 6F 6E 63 65 29 2B 5C 5C 73 2A 5C 5C 28 5C 5C 73 2A 5B 5C 5C 27 7C 5C 5C 5C 22 5D 28 5C 5C 77 2B}
// 		$s19 = {27 2F 5C 5C 24 5C 5C 5F 28 5C 5C 77 2B 29 28 2E 2A 29 28 65 76 61 6C 7C 61 73 73 65 72 74 7C 69 6E 63 6C 75 64 65 7C 72 65 71 75 69 72 65 7C 69 6E 63 6C 75 64 65 5C 5C 5F 6F 6E 63 65 7C 72 65 71 75 69 72 65 5C 5C 5F 6F 6E 63 65}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_pppp
// {
// 	meta:
// 		description = "Web shells - generated from file pppp.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "cf01cb6e09ee594545693c5d327bdd50"

// 	strings:
// 		$s0 = {4D 61 69 6C 3A 20 63 68 69 6E 65 73 65 40 68 61 63 6B 65 72 6D 61 69 6C 2E 63 6F 6D}
// 		$s3 = {69 66 28 24 5F 47 45 54 5B 5C 22 68 61 63 6B 65 72 73 5C 22 5D 3D 3D 5C 22 32 62 5C 22 29 7B 69 66 20 28 24 5F 53 45 52 56 45 52 5B 27 52 45 51 55 45 53 54 5F 4D 45 54 48 4F 44 27 5D 20 3D 3D 20 27 50 4F 53 54 27 29 20 7B 20 65 63 68 6F 20}
// 		$s6 = {53 69 74 65 3A 20 68 74 74 70 3A 2F 2F 62 6C 6F 67 2E 77 65 69 6C 69 2E 6D 65}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_code
// {
// 	meta:
// 		description = "Web shells - generated from file code.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "a444014c134ff24c0be5a05c02b81a79"

// 	strings:
// 		$s1 = {3C 61 20 63 6C 61 73 73 3D 5C 22 68 69 67 68 32 5C 22 20 68 72 65 66 3D 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 3B 3B 3B 5C 22 20 6E 61 6D 65 3D 5C 22 61 63 74 69 6F 6E 3D 73 68 6F 77 26 64 69 72 3D 24 5F 69 70 61 67 65 5F 66 69}
// 		$s7 = {24 66 69 6C 65 20 3D 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 5C 22 64 69 72 5C 22 5D 29 20 3F 20 75 72 6C 64 65 63 6F 64 65 28 73 65 6C 66 3A 3A 63 6F 6E 76 65 72 74 5F 74 6F 5F 75 74 66 38 28 72 74 72 69 6D 28 24 5F 50 4F}
// 		$s10 = {69 66 20 28 74 72 75 65 3D 3D 40 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 73 65 6C 66 3A 3A 63 6F 6E 76 65 72 74 5F}
// 		$s14 = {50 72 6F 63 65 73 73 65 64 20 69 6E 20 3C 73 70 61 6E 20 69 64 3D 5C 22 72 75 6E 74 69 6D 65 5C 22 3E 3C 2F 73 70 61 6E 3E 20 73 65 63 6F 6E 64 28 73 29 20 7B 67 7A 69 70 7D 20 75 73 61 67 65 3A}
// 		$s17 = {3C 61 20 68 72 65 66 3D 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 3B 3B 3B 5C 22 20 6E 61 6D 65 3D 5C 22 7B 72 65 74 75 72 6E 5F 6C 69 6E 6B 7D 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 66 69 6C 65 70 65 72 6D}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_jspyyy
// {
// 	meta:
// 		description = "Web shells - generated from file jspyyy.jsp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"

// 	strings:
// 		$s0 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 5C 22 25 3E 3C 25 69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_xxxx
// {
// 	meta:
// 		description = "Web shells - generated from file xxxx.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "5bcba70b2137375225d8eedcde2c0ebb"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 65 76 61 6C 28 24 5F 50 4F 53 54 5B 31 5D 29 3B 3F 3E 20 20}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_JJjsp3
// {
// 	meta:
// 		description = "Web shells - generated from file JJjsp3.jsp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "949ffee1e07a1269df7c69b9722d293e"

// 	strings:
// 		$s0 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 2C 6A 61 76 61 2E 75 74 69 6C 2E 2A 2C 6A 61 76 61 2E 6E 65 74 2E 2A 2C 6A 61 76 61 2E 73 71 6C 2E 2A 2C 6A 61 76 61 2E 74 65 78 74 2E 2A 5C 22 25 3E 3C 25 21 53}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_PHP1
// {
// 	meta:
// 		description = "Web shells - generated from file PHP1.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"

// 	strings:
// 		$s0 = {3C 5B 75 72 6C 3D 6D 61 69 6C 74 6F 3A 3F 40 61 72 72 61 79 5F 6D 61 70 28 24 5F 47 45 54 5B 5D 3F 40 61 72 72 61 79 5F 6D 61 70 28 24 5F 47 45 54 5B 27 66 27 5D 2C 24 5F 47 45 54 5B 2F 75 72 6C 5D 29 3B 3F 3E}
// 		$s2 = {3A 68 74 74 70 73 3A 2F 2F 66 6F 72 75 6D 2E 39 30 73 65 63 2E 6F 72 67 2F 66 6F 72 75 6D 2E 70 68 70 3F 6D 6F 64 3D 76 69 65 77 74 68 72 65 61 64 26 74 69 64 3D 37 33 31 36}
// 		$s3 = {40 70 72 65 67 5F 72 65 70 6C 61 63 65 28 5C 22 2F 66 2F 65 5C 22 2C 24 5F 47 45 54 5B 27 75 27 5D 2C 5C 22 66 65 6E 67 6A 69 61 6F 5C 22 29 3B 20}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_JJJsp2
// {
// 	meta:
// 		description = "Web shells - generated from file JJJsp2.jsp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "5a9fec45236768069c99f0bfd566d754"

// 	strings:
// 		$s2 = {51 51 28 63 73 2C 20 7A 31 2C 20 7A 32 2C 20 73 62 2C 7A 32 2E 69 6E 64 65 78 4F 66 28 5C 22 2D 74 6F 3A 5C 22 29 21 3D 2D 31 3F 7A 32 2E 73 75 62 73 74 72 69 6E 67 28 7A 32 2E 69 6E 64 65 78 4F 66 28 5C 22 2D 74 6F 3A 5C 22 29 2B 34 2C 7A}
// 		$s8 = {73 62 2E 61 70 70 65 6E 64 28 6C 5B 69 5D 2E 67 65 74 4E 61 6D 65 28 29 20 2B 20 5C 22 2F 5C 5C 74 5C 22 20 2B 20 73 54 20 2B 20 5C 22 5C 5C 74 5C 22 20 2B 20 6C 5B 69 5D 2E 6C 65 6E 67 74 68 28 29 2B 20 5C 22 5C 5C 74 5C 22 20 2B 20 73 51}
// 		$s10 = {52 65 73 75 6C 74 53 65 74 20 72 20 3D 20 73 2E 69 6E 64 65 78 4F 66 28 5C 22 6A 64 62 63 3A 6F 72 61 63 6C 65 5C 22 29 21 3D 2D 31 3F 63 2E 67 65 74 4D 65 74 61 44 61 74 61 28 29}
// 		$s11 = {72 65 74 75 72 6E 20 44 72 69 76 65 72 4D 61 6E 61 67 65 72 2E 67 65 74 43 6F 6E 6E 65 63 74 69 6F 6E 28 78 5B 31 5D 2E 74 72 69 6D 28 29 2B 5C 22 3A 5C 22 2B 78 5B 34 5D 2C 78 5B 32 5D 2E 65 71 75 61 6C 73 49 67 6E 6F 72 65 43 61 73 65 28}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_radhat
// {
// 	meta:
// 		description = "Web shells - generated from file radhat.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "72cb5ef226834ed791144abaa0acdfd4"

// 	strings:
// 		$s1 = {73 6F 64 3D 41 72 72 61 79 28 5C 22 44 5C 22 2C 5C 22 37 5C 22 2C 5C 22 53}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_asp1
// {
// 	meta:
// 		description = "Web shells - generated from file asp1.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "b63e708cd58ae1ec85cf784060b69cad"

// 	strings:
// 		$s0 = {20 68 74 74 70 3A 2F 2F 77 77 77 2E 62 61 69 64 75 2E 63 6F 6D 2F 66 75 63 6B 2E 61 73 70 3F 61 3D 29 30 28 74 73 65 75 71 65 72 25 32 30 6C 61 76 65 20}
// 		$s2 = {20 3C 25 20 61 3D 72 65 71 75 65 73 74 28 63 68 72 28 39 37 29 29 20 45 78 65 63 75 74 65 47 6C 6F 62 61 6C 28 53 74 72 52 65 76 65 72 73 65 28 61 29 29 20 25 3E}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_php6
// {
// 	meta:
// 		description = "Web shells - generated from file php6.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "ea75280224a735f1e445d244acdfeb7b"

// 	strings:
// 		$s1 = {61 72 72 61 79 5F 6D 61 70 28 5C 22 61 73 78 37 33 65 72 74 5C 22 2C 28 61 72}
// 		$s3 = {70 72 65 67 5F 72 65 70 6C 61 63 65 28 5C 22 2F 5B 65 72 72 6F 72 70 61 67 65 5D 2F 65 5C 22 2C 24 70 61 67 65 2C 5C 22 73 61 66 74 5C 22 29 3B}
// 		$s4 = {73 68 65 6C 6C 2E 70 68 70 3F 71 69 64 3D 7A 78 65 78 70 20 20}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_xxx
// {
// 	meta:
// 		description = "Web shells - generated from file xxx.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "0e71428fe68b39b70adb6aeedf260ca0"

// 	strings:
// 		$s3 = {3C 3F 70 68 70 20 61 72 72 61 79 5F 6D 61 70 28 5C 22 61 73 73 5C 5C 78 36 35 72 74 5C 22 2C 28 61 72 72 61 79 29 24 5F 52 45 51 55 45 53 54 5B 27 65 78 70 64 6F 6F 72 27 5D 29 3B 3F 3E}

// 	condition:
// 		all of them
// }

// rule webshell_GetPostpHp
// {
// 	meta:
// 		description = "Web shells - generated from file GetPostpHp.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "20ede5b8182d952728d594e6f2bb5c76"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 65 76 61 6C 28 73 74 72 5F 72 6F 74 31 33 28 27 72 69 6E 79 28 24 5F 43 42 46 47 5B 63 6E 74 72 5D 29 3B 27 29 29 3B 3F 3E}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_php5
// {
// 	meta:
// 		description = "Web shells - generated from file php5.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "cf2ab009cbd2576a806bfefb74906fdf"

// 	strings:
// 		$s0 = {3C 3F 24 5F 75 55 3D 63 68 72 28 39 39 29 2E 63 68 72 28 31 30 34 29 2E 63 68 72 28 31 31 34 29 3B 24 5F 63 43 3D 24 5F 75 55 28 31 30 31 29 2E 24 5F 75 55 28 31 31 38 29 2E 24 5F 75 55 28 39 37 29 2E 24 5F 75 55 28 31 30 38 29 2E 24 5F 75}

// 	condition:
// 		all of them
// }

// rule webshell_webshells_new_PHP
// {
// 	meta:
// 		description = "Web shells - generated from file PHP.php"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"

// 	strings:
// 		$s1 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 3E 45 72 72 6F 72 21 3C 2F 66 6F 6E 74 3E 5C 22 3B}
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 73 69 7A 65 3D 36 31 20 6E 61 6D 65 3D 5C 22 66 5C 22 20 76 61 6C 75 65 3D 27 3C 3F 70 68 70 20 65 63 68 6F 20 24 5F 53 45 52 56 45 52 5B 5C 22 53 43 52 49 50 54 5F 46 49 4C 45}
// 		$s5 = {20 2D 20 45 78 70 44 6F 6F 72 2E 63 6F 6D 3C 2F 74 69 74 6C 65 3E}
// 		$s10 = {24 66 3D 66 6F 70 65 6E 28 24 5F 50 4F 53 54 5B 5C 22 66 5C 22 5D 2C 5C 22 77 5C 22 29 3B}
// 		$s12 = {3C 74 65 78 74 61 72 65 61 20 6E 61 6D 65 3D 5C 22 63 5C 22 20 63 6F 6C 73 3D 36 30 20 72 6F 77 73 3D 31 35 3E 3C 2F 74 65 78 74 61 72 65 61 3E 3C 62 72 3E}

// 	condition:
// 		1 of them
// }

// rule webshell_webshells_new_Asp
// {
// 	meta:
// 		description = "Web shells - generated from file Asp.asp"
// 		author = "Florian Roth"
// 		date = "2014/03/28"
// 		score = 70
// 		hash = "32c87744ea404d0ea0debd55915010b7"

// 	strings:
// 		$s1 = {45 78 65 63 75 74 65 20 4D 6F 72 66 69 43 6F 64 65 72 28 5C 22 29 2F 2A 2F 7A 2F 2A 2F 28 74 73 65 75 71 65 72 20 6C 61 76 65 5C 22 29}
// 		$s2 = {46 75 6E 63 74 69 6F 6E 20 4D 6F 72 66 69 43 6F 64 65 72 28 43 6F 64 65 29}
// 		$s3 = {4D 6F 72 66 69 43 6F 64 65 72 3D 52 65 70 6C 61 63 65 28 52 65 70 6C 61 63 65 28 53 74 72 52 65 76 65 72 73 65 28 43 6F 64 65 29 2C 5C 22 2F 2A 2F 5C 22 2C 5C 22 5C 22 5C 22 5C 22 29 2C 5C 22 5C 5C 2A 5C 5C 5C 22 2C 76 62 43 72 6C 66 29}

// 	condition:
// 		1 of them
// }

// rule perlbot_pl
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file perlbot.pl.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "7e4deb9884ffffa5d82c22f8dc533a45"

// 	strings:
// 		$s0 = {6D 79 20 40 61 64 6D 73 3D 28 5C 22 4B 65 6C 73 65 72 69 66 69 63 5C 22 2C 5C 22 50 75 6E 61 5C 22 2C 5C 22 6E 6F 64 33 32 5C 22 29}
// 		$s1 = {23 41 63 65 73 73 6F 20 61 20 53 68 65 6C 20 2D 20 31 20 4F 4E 20 30 20 4F 46 46}

// 	condition:
// 		1 of them
// }

// rule php_backdoor_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"

// 	strings:
// 		$s0 = {68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 20 20 20 32 30 30 36}
// 		$s1 = {6F 72 20 68 74 74 70 3A 2F 2F 3C 3F 20 65 63 68 6F 20 24 53 45 52 56 45 52 5F 4E 41 4D 45 2E 24 52 45 51 55 45 53 54 5F 55 52 49 3B 20 3F 3E 3F 64 3D 63 3A 2F 77 69 6E 64 6F 77 73 20 6F 6E 20 77 69 6E}
// 		$s3 = {63 6F 64 65 64 20 62 79 20 7A 30 6D 62 69 65}

// 	condition:
// 		1 of them
// }

// rule Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"

// 	strings:
// 		$s0 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 61 74 20 2F 76 61 72 2F 63 70 61 6E 65 6C 2F 61 63 63 6F 75 6E 74 69 6E 67 2E 6C 6F 67 5C 22 3E 2F 76 61 72 2F 63 70 61 6E 65 6C 2F 61 63 63 6F 75 6E 74 69 6E 67 2E 6C 6F 67 3C 2F 6F 70 74}
// 		$s1 = {4C 69 7A 30 7A 69 4D 20 50 72 69 76 61 74 65 20 53 61 66 65 20 4D 6F 64 65 20 43 6F 6D 6D 61 6E 64 20 45 78 65 63 75 72 69 74 6F 6E 20 42 79 70 61 73 73}
// 		$s2 = {65 63 68 6F 20 5C 22 3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 4B 69 6D 69 6D 20 42 65 6E 20 3A 3D 29 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E 3A 24 75 69 64 3C 62 72 3E 5C 22 3B}

// 	condition:
// 		1 of them
// }

// rule Nshell__1__php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "973fc89694097a41e684b43a21b1b099"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 43 6F 6D 6D 61 6E 64 20 3A 20 3C 49 4E 50 55 54 20 54 59 50 45 3D 74 65 78 74 20 4E 41 4D 45 3D 63 6D 64 20 76 61 6C 75 65 3D 5C 22 2E 40 73 74 72 69 70 73 6C 61 73 68 65 73 28 68 74 6D 6C 65 6E 74 69 74 69 65 73 28 24}
// 		$s1 = {69 66 28 21 24 77 68 6F 61 6D 69 29 24 77 68 6F 61 6D 69 3D 65 78 65 63 28 5C 22 77 68 6F 61 6D 69 5C 22 29 3B 20 65 63 68 6F 20 5C 22 77 68 6F 61 6D 69 20 3A 5C 22 2E 24 77 68 6F 61 6D 69 2E 5C 22 3C 62 72 3E 5C 22 3B}

// 	condition:
// 		1 of them
// }

// rule shankar_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file shankar.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "6eb9db6a3974e511b7951b8f7e7136bb"

// 	strings:
// 		$sAuthor = {53 68 41 6E 4B 61 52}
// 		$s0 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 63 68 65 63 6B 62 6F 78 20 6E 61 6D 65 3D 27 64 64 27 20 5C 22 2E 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 64 64 27 5D 29 3F 27 63 68 65 63 6B 65 64 27 3A 27 27 29 2E 5C 22 3E 44 42 3C 69 6E 70 75 74}
// 		$s3 = {53 68 6F 77 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 73 69 7A 65 3D 35 20 76 61 6C 75 65 3D 5C 22 2E 28 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 62 72 5F 73 74 27 5D 29 20 26 26 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 62}

// 	condition:
// 		1 of ($s*) and $sAuthor
// }

// rule Casus15_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"

// 	strings:
// 		$s0 = {63 6F 70 79 20 28 20 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72 32 2C 20 5C 22 24 64 69 72 2F 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72 32 5F 6E 61 6D 65 5C 22 29 20 3F 20 70 72 69 6E 74 28 5C 22 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72 32 5F 6E 61}
// 		$s2 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 27 24 73 61 79 69 27 20 63 6F 6C 6F 72 3D 27 23 46 46 46 46 46 46 27 3E 48 41 43 4B 4C 45 52 49 4E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 27 23 30 30 38 30 30 30 27}
// 		$s3 = {76 61 6C 75 65 3D 27 43 61 6C 69 73 74 69 72 6D 61 6B 20 69 73 74 65 64 69 67 69 6E 69 7A 20}

// 	condition:
// 		1 of them
// }

// rule small_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file small.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "fcee6226d09d150bfa5f103bee61fbde"

// 	strings:
// 		$s1 = {24 70 61 73 73 3D 27 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 27 3B}
// 		$s2 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27 46 4A 7A 48 6B 71 50 61 74 6B 55 2F 35 35 30 49 47 6E 6A 58 78 48 76 76 36 62 7A 41 65 30 69 45 35 2B 73 76 46 56 47 74 4B 71 58 4D 5A 71 30 35 78 31}
// 		$s4 = {40 69 6E 69 5F 73 65 74 28 27 65 72 72 6F 72 5F 6C 6F 67 27 2C 4E 55 4C 4C 29 3B}

// 	condition:
// 		2 of them
// }

// rule shellbot_pl
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file shellbot.pl.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"

// 	strings:
// 		$s0 = {53 68 65 6C 6C 42 4F 54}
// 		$s1 = {50 61 63 6B 74 73 47 72 30 75 70}
// 		$s2 = {43 6F 52 70 4F 72 41 74 49 6F 4E}
// 		$s3 = {23 20 53 65 72 76 69 64 6F 72 20 64 65 20 69 72 63 20 71 75 65 20 76 61 69 20 73 65 72 20 75 73 61 64 6F 20}
// 		$s4 = {2F 5E 63 74 63 70 66 6C 6F 6F 64 5C 5C 73 2B 28 5C 5C 64 2B 29 5C 5C 73 2B 28 5C 5C 53 2B 29}

// 	condition:
// 		2 of them
// }

// rule fuckphpshell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "554e50c1265bb0934fcc8247ec3b9052"

// 	strings:
// 		$s0 = {24 73 75 63 63 20 3D 20 5C 22 57 61 72 6E 69 6E 67 21 20}
// 		$s1 = {44 6F 6E 60 74 20 62 65 20 73 74 75 70 69 64 20 2E 2E 20 74 68 69 73 20 69 73 20 61 20 70 72 69 76 33 20 73 65 72 76 65 72 2C 20 73 6F 20 74 61 6B 65 20 65 78 74 72 61 20 63 61 72 65 21}
// 		$s2 = {5C 5C 2A 3D 2D 2D 20 4D 45 4D 42 45 52 53 20 41 52 45 41 20 2D 2D 3D 2A 2F}
// 		$s3 = {70 72 65 67 5F 6D 61 74 63 68 28 27 2F 28 5C 5C 6E 5B 5E 5C 5C 6E 5D 2A 29 7B 27 20 2E 20 24 63 61 63 68 65 5F 6C 69 6E 65 73 20 2E 20 27 7D 24 2F 27 2C 20 24 5F 53 45 53 53 49 4F 4E 5B 27 6F}

// 	condition:
// 		2 of them
// }

// rule ngh_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file ngh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "c372b725419cdfd3f8a6371cfeebc2fd"

// 	strings:
// 		$s0 = {43 72 34 73 68 5F 61 6B 61 5F 52 4B 4C}
// 		$s1 = {4E 47 48 20 65 64 69 74 69 6F 6E}
// 		$s2 = {2F 2A 20 63 6F 6E 6E 65 63 74 62 61 63 6B 2D 62 61 63 6B 64 6F 6F 72 20 6F 6E 20 70 65 72 6C}
// 		$s3 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 62 69 6E 64 73 68 65 6C 6C 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
// 		$s4 = {24 6C 6F 67 6F 20 3D 20 5C 22 52 30 6C 47 4F 44 6C 68 4D 41 41 77 41 4F 59 41 41 41 41 41 41 50 2F 2F 2F 2F 72}

// 	condition:
// 		1 of them
// }

// rule jsp_reverse_jsp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8b0e6779f25a17f0ffb3df14122ba594"

// 	strings:
// 		$s0 = {2F 2F 20 62 61 63 6B 64 6F 6F 72 2E 6A 73 70}
// 		$s1 = {4A 53 50 20 42 61 63 6B 64 6F 6F 72 20 52 65 76 65 72 73 65 20 53 68 65 6C 6C}
// 		$s2 = {68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67}

// 	condition:
// 		2 of them
// }

// rule Tool_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Tool.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"

// 	strings:
// 		$s0 = {6D 61 69 6C 74 6F 3A 72 68 66 61 63 74 6F 72 40 61 6E 74 69 73 6F 63 69 61 6C 2E 63 6F 6D}
// 		$s2 = {3F 72 61 69 7A 3D 72 6F 6F 74}
// 		$s3 = {44 49 47 4F 20 43 4F 52 52 4F 4D 50 49 44 4F 3C 42 52 3E 43 4F 52 52 55 50 54 20 43 4F 44 45}
// 		$s4 = {6B 65 79 20 3D 20 5C 22 35 44 43 41 44 41 43 31 39 30 32 45 35 39 46 37 32 37 33 45 31 39 30 32 45 35 41 44 38 34 31 34 42 31 39 30 32 45 35 41 42 46 33 45 36 36 31 39 30 32 45 35 42 35 35 34 46 43 34 31 39 30 32 45 35 33 32 30 35 43 41 30}

// 	condition:
// 		2 of them
// }

// rule NT_Addy_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "2e0d1bae844c9a8e6e351297d77a1fec"

// 	strings:
// 		$s0 = {4E 54 44 61 64 64 79 20 76 31 2E 39 20 62 79 20 6F 62 7A 65 72 76 65 20 6F 66 20 66 75 78 30 72 20 69 6E 63}
// 		$s2 = {3C 45 52 52 4F 52 3A 20 54 48 49 53 20 49 53 20 4E 4F 54 20 41 20 54 45 58 54 20 46 49 4C 45 3E}
// 		$s4 = {52 41 57 20 44 2E 4F 2E 53 2E 20 43 4F 4D 4D 41 4E 44 20 49 4E 54 45 52 46 41 43 45}

// 	condition:
// 		1 of them
// }

// rule SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "089ff24d978aeff2b4b2869f0c7d38a3"

// 	strings:
// 		$s0 = {53 69 6D 41 74 74 61 63 6B 65 72 20 2D 20 56 72 73 69 6F 6E 20 3A 20 31 2E 30 2E 30 20 2D 20 70 72 69 76 38 20 34 20 4D 79 20 66 72 69 65 6E 64}
// 		$s3 = {20 66 70 75 74 73 20 28 24 66 70 20 2C 5C 22 5C 5C 6E 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 5C 5C 6E 57 65 6C 63 6F 6D 65 20 54 30 20 53 69 6D}
// 		$s4 = {65 63 68 6F 20 5C 22 3C 61 20 74 61 72 67 65 74 3D 27 5F 62 6C 61 6E 6B 27 20 68 72 65 66 3D 27 3F 69 64 3D 66 6D 26 66 65 64 69 74 3D 24 64 69 72 24 66 69 6C 65 27 3E 3C 73 70 61 6E 20 73 74 79 6C 65 3D 27 74 65 78 74 2D 64 65 63 6F 72 61}

// 	condition:
// 		1 of them
// }

// rule RemExp_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file RemExp.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "aa1d8491f4e2894dbdb91eec1abc2244"

// 	strings:
// 		$s0 = {3C 74 69 74 6C 65 3E 52 65 6D 6F 74 65 20 45 78 70 6C 6F 72 65 72 3C 2F 74 69 74 6C 65 3E}
// 		$s3 = {20 46 53 4F 2E 43 6F 70 79 46 69 6C 65 20 52 65 71 75 65 73 74 2E 51 75 65 72 79 53 74 72 69 6E 67 28 5C 22 46 6F 6C 64 65 72 50 61 74 68 5C 22 29 20 26 20 52 65 71 75 65 73 74 2E 51 75 65 72 79 53 74 72 69 6E 67 28 5C 22 43 6F 70 79 46 69}
// 		$s4 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 46 69 6C 65 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 73 68 6F 77 63 6F 64 65 2E 61 73 70 3F 66}

// 	condition:
// 		2 of them
// }

// rule phvayvv_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "35fb37f3c806718545d97c6559abd262"

// 	strings:
// 		$s0 = {7B 6D 6B 64 69 72 28 5C 22 24 64 69 7A 69 6E 2F 24 64 75 7A 65 6E 78 32 5C 22 2C 37 37 37 29}
// 		$s1 = {24 62 61 67 6C 61 6E 3D 66 6F 70 65 6E 28 24 64 75 7A 6B 61 79 64 65 74 2C 27 77 27 29 3B}
// 		$s2 = {50 48 56 61 79 76 20 31 2E 30}

// 	condition:
// 		1 of them
// }

// rule klasvayv_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "2b3e64bf8462fc3d008a3d1012da64ef"

// 	strings:
// 		$s1 = {73 65 74 20 61 6B 74 69 66 6B 6C 61 73 3D 72 65 71 75 65 73 74 2E 71 75 65 72 79 73 74 72 69 6E 67 28 5C 22 61 6B 74 69 66 6B 6C 61 73 5C 22 29}
// 		$s2 = {61 63 74 69 6F 6E 3D 5C 22 6B 6C 61 73 76 61 79 76 2E 61 73 70 3F 6B 6C 61 73 6F 72 61 63 3D 31 26 61 6B 74 69 66 6B 6C 61 73 3D 3C 25 3D 61 6B 74 69 66 6B 6C 61 73 25 3E 26 6B 6C 61 73 3D 3C 25 3D 61 6B 74 69 66 6B 6C 61 73 25 3E}
// 		$s3 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 38 35 38 35 38 35 5C 22 3E 77 77 77 2E 61 76 65 6E 74 67 72 75 70 2E 6E 65 74}
// 		$s4 = {73 74 79 6C 65 3D 5C 22 42 41 43 4B 47 52 4F 55 4E 44 2D 43 4F 4C 4F 52 3A 20 23 39 35 42 34 43 43 3B 20 42 4F 52 44 45 52 2D 42 4F 54 54 4F 4D 3A 20 23 30 30 30 30 30 30 20 31 70 78 20 69 6E 73 65 74 3B 20 42 4F 52 44 45 52 2D 4C 45 46 54}

// 	condition:
// 		1 of them
// }

// rule r57shell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file r57shell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "d28445de424594a5f14d0fe2a7c4e94f"

// 	strings:
// 		$s0 = {72 35 37 73 68 65 6C 6C}
// 		$s1 = {20 65 6C 73 65 20 69 66 20 28 24 48 54 54 50 5F 50 4F 53 54 5F 56 41 52 53 5B 27 77 69 74 68 27 5D 20 3D 3D 20 5C 22 6C 79 6E 78 5C 22 29 20 7B 20 24 48 54 54 50 5F 50 4F 53 54 5F 56 41 52 53 5B 27 63 6D 64 27 5D 3D 20 5C 22 6C 79 6E 78 20}
// 		$s2 = {52 75 73 48 20 73 65 63 75 72 69 74 79 20 74 65 61 6D}
// 		$s3 = {27 72 75 5F 74 65 78 74 31 32 27 20 3D 3E 20 27 62 61 63 6B 2D 63 6F 6E 6E 65 63 74}

// 	condition:
// 		1 of them
// }

// rule rst_sql_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "0961641a4ab2b8cb4d2beca593a92010"

// 	strings:
// 		$s0 = {43 3A 5C 5C 74 6D 70 5C 5C 64 75 6D 70 5F}
// 		$s1 = {52 53 54 20 4D 79 53 51 4C}
// 		$s2 = {68 74 74 70 3A 2F 2F 72 73 74 2E 76 6F 69 64 2E 72 75}
// 		$s3 = {24 73 74 5F 66 6F 72 6D 5F 62 67 3D 27 52 30 6C 47 4F 44 6C 68 43 51 41 4A 41 49 41 41 41 4F 66 6F 36 75 37 77 38 79 48 35 42 41 41 41 41 41 41 41 4C 41 41 41 41 41 41 4A 41 41 6B 41 41 41 49 50 6A 41 4F 6E 75 4A 66 4E 48 4A 68 30 71 74 66 77 30 6C 63 56 41 44 73 3D 27 3B}

// 	condition:
// 		2 of them
// }

// rule wh_bindshell_py
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "fab20902862736e24aaae275af5e049c"

// 	strings:
// 		$s0 = {23 55 73 65 3A 20 70 79 74 68 6F 6E 20 77 68 5F 62 69 6E 64 73 68 65 6C 6C 2E 70 79 20 5B 70 6F 72 74 5D 20 5B 70 61 73 73 77 6F 72 64 5D}
// 		$s2 = {70 79 74 68 6F 6E 20 2D 63 5C 22 69 6D 70 6F 72 74 20 6D 64 35 3B 78 3D 6D 64 35 2E 6E 65 77 28 27 79 6F 75 5F 70 61 73 73 77 6F 72 64 27 29 3B 70 72 69 6E 74 20 78 2E 68 65 78 64 69 67 65 73 74 28 29 5C 22}
// 		$s3 = {23 62 75 67 7A 3A 20 63 74 72 6C 2B 63 20 65 74 63 20 3D 73 63 72 69 70 74 20 73 74 6F 70 65 64 3D}

// 	condition:
// 		1 of them
// }

// rule lurm_safemod_on_cgi
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "5ea4f901ce1abdf20870c214b3231db3"

// 	strings:
// 		$s0 = {4E 65 74 77 6F 72 6B 20 73 65 63 75 72 69 74 79 20 74 65 61 6D 20 3A 3A 20 43 47 49 20 53 68 65 6C 6C}
// 		$s1 = {23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 3C 3C 4B 4F 4E 45 43 3E 3E 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23}
// 		$s2 = {23 23 69 66 20 28 21 64 65 66 69 6E 65 64 24 70 61 72 61 6D 7B 70 77 64 7D 29 7B 24 70 61 72 61 6D 7B 70 77 64 7D 3D 27 45 6E 74 65 72 5F 50 61 73 73 77 6F 72 64 27 7D 3B 23 23}

// 	condition:
// 		1 of them
// }

// rule c99madshell_v2_0_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "d27292895da9afa5b60b9d3014f39294"

// 	strings:
// 		$s2 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27 48 4A 33 48 6B 71 4E 51 45 6B 55 2F 5A 7A 71 43 42 64 34 74 38 56 34 59 41 51 49 32 45 33 6A 76 50 56 38 2F 31 47 77 36 6F 72 73 56 46 4C 79 58 65 66}

// 	condition:
// 		all of them
// }

// rule backupsql_php_often_with_c99shell
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file backupsql.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"

// 	strings:
// 		$s2 = {2F 2F 24 6D 65 73 73 61 67 65 2E 3D 20 5C 22 2D 2D 7B 24 6D 69 6D 65 5F 62 6F 75 6E 64 61 72 79 7D 5C 5C 6E 5C 22 20 2E 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 7B 24 66 69 6C 65 61 74 74 5F 74 79 70 65 7D 3B 5C 5C 6E 5C 22 20 2E}
// 		$s4 = {24 66 74 70 63 6F 6E 6E 65 63 74 20 3D 20 5C 22 6E 63 66 74 70 70 75 74 20 2D 75 20 24 66 74 70 5F 75 73 65 72 5F 6E 61 6D 65 20 2D 70 20 24 66 74 70 5F 75 73 65 72 5F 70 61 73 73 20 2D 64 20 64 65 62 73 65 6E 64 65 72 5F 66 74 70 6C 6F 67}

// 	condition:
// 		all of them
// }

// rule uploader_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file uploader.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "0b53b67bb3b004a8681e1458dd1895d0"

// 	strings:
// 		$s2 = {6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 2C 20 5C 22 65 6E 74 72 69 6B 61 2E 70 68 70 5C 22 29 3B 20}
// 		$s3 = {53 65 6E 64 20 74 68 69 73 20 66 69 6C 65 3A 20 3C 49 4E 50 55 54 20 4E 41 4D 45 3D 5C 22 75 73 65 72 66 69 6C 65 5C 22 20 54 59 50 45 3D 5C 22 66 69 6C 65 5C 22 3E}
// 		$s4 = {3C 49 4E 50 55 54 20 54 59 50 45 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 4D 41 58 5F 46 49 4C 45 5F 53 49 5A 45 5C 22 20 76 61 6C 75 65 3D 5C 22 31 30 30 30 30 30 5C 22 3E}

// 	condition:
// 		2 of them
// }

// rule telnet_pl
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file telnet.pl.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "dd9dba14383064e219e29396e242c1ec"

// 	strings:
// 		$s0 = {57 20 41 20 52 20 4E 20 49 20 4E 20 47 3A 20 50 72 69 76 61 74 65 20 53 65 72 76 65 72}
// 		$s2 = {24 4D 65 73 73 61 67 65 20 3D 20 71 24 3C 70 72 65 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 36 36 39 39 39 39 5C 22 3E 20 5F 5F 5F 5F 5F 20 20 5F 5F 5F 5F 5F 20 20 5F 5F 5F 5F 5F 20 20 20 20 20 20 20 20 20 20 5F 5F 5F 5F 5F 20 20 20}

// 	condition:
// 		all of them
// }

// rule w3d_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file w3d.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "987f66b29bfb209a0b4f097f84f57c3b"

// 	strings:
// 		$s0 = {57 33 44 20 53 68 65 6C 6C}
// 		$s1 = {42 79 3A 20 57 61 72 70 62 6F 79}
// 		$s2 = {4E 6F 20 51 75 65 72 79 20 45 78 65 63 75 74 65 64}

// 	condition:
// 		2 of them
// }

// rule WebShell_cgi
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file WebShell.cgi.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "bc486c2e00b5fc3e4e783557a2441e6f"

// 	strings:
// 		$s0 = {57 65 62 53 68 65 6C 6C 2E 63 67 69}
// 		$s2 = {3C 74 64 3E 3C 63 6F 64 65 20 63 6C 61 73 73 3D 5C 22 65 6E 74 72 79 2D 5B 25 20 69 66 20 65 6E 74 72 79 2E 61 6C 6C 5F 72 69 67 68 74 73 20 25 5D 6D 69 6E 65 5B 25 20 65 6C 73 65}

// 	condition:
// 		all of them
// }

// rule WinX_Shell_html
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file WinX Shell.html.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "17ab5086aef89d4951fe9b7c7a561dda"

// 	strings:
// 		$s0 = {57 69 6E 58 20 53 68 65 6C 6C}
// 		$s1 = {43 72 65 61 74 65 64 20 62 79 20 67 72 65 65 6E 77 6F 6F 64 20 66 72 6F 6D 20 6E 35 37}
// 		$s2 = {3C 74 64 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 39 39 30 30 30 30 5C 5C 5C 22 3E 57 69 6E 20 44 69 72 3A 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E}

// 	condition:
// 		2 of them
// }

// rule Dx_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Dx.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"

// 	strings:
// 		$s0 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 54 69 70 3A 20 74 6F 20 76 69 65 77 20 74 68 65 20 66 69 6C 65 20 5C 22 61 73 20 69 73 5C 22 20 2D 20 6F 70 65 6E 20 74 68 65 20 70 61 67 65 20 69 6E 20 3C 61 20 68 72 65 66 3D 5C 22 27 2E 44 78}
// 		$s2 = {24 44 45 46 5F 50 4F 52 54 53 3D 61 72 72 61 79 20 28 31 3D 3E 27 74 63 70 6D 75 78 20 28 54 43 50 20 50 6F 72 74 20 53 65 72 76 69 63 65 20 4D 75 6C 74 69 70 6C 65 78 65 72 29 27 2C 32 3D 3E 27 4D 61 6E 61 67 65 6D 65 6E 74 20 55 74 69 6C}
// 		$s3 = {24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20 24 5F 53 45 52 56 45 52 5B 27 48 54 54 50}

// 	condition:
// 		1 of them
// }

// rule csh_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file csh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "194a9d3f3eac8bc56d9a7c55c016af96"

// 	strings:
// 		$s0 = {2E 3A 3A 5B 63 30 64 65 72 7A 5D 3A 3A 2E 20 77 65 62 2D 73 68 65 6C 6C}
// 		$s1 = {68 74 74 70 3A 2F 2F 63 30 64 65 72 7A 2E 6F 72 67 2E 75 61}
// 		$s2 = {76 69 6E 74 32 31 68 40 63 30 64 65 72 7A 2E 6F 72 67 2E 75 61}
// 		$s3 = {24 6E 61 6D 65 3D 27 36 33 61 39 66 30 65 61 37 62 62 39 38 30 35 30 37 39 36 62 36 34 39 65 38 35 34 38 31 38 34 35 27 3B 2F 2F 72 6F 6F 74}

// 	condition:
// 		1 of them
// }

// rule pHpINJ_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "d7a4b0df45d34888d5a09f745e85733f"

// 	strings:
// 		$s1 = {4E 65 77 73 20 52 65 6D 6F 74 65 20 50 48 50 20 53 68 65 6C 6C 20 49 6E 6A 65 63 74 69 6F 6E}
// 		$s3 = {50 68 70 20 53 68 65 6C 6C 20 3C 62 72 20 2F 3E}
// 		$s4 = {3C 69 6E 70 75 74 20 74 79 70 65 20 3D 20 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 20 3D 20 5C 22 75 72 6C 5C 22 20 76 61 6C 75 65 20 3D 20 5C 22}

// 	condition:
// 		2 of them
// }

// rule sig_2008_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file 2008.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "3e4ba470d4c38765e4b16ed930facf2c"

// 	strings:
// 		$s0 = {43 6F 64 7A 20 62 79 20 61 6E 67 65 6C 28 34 6E 67 65 6C 29}
// 		$s1 = {57 65 62 3A 20 68 74 74 70 3A 2F 2F 77 77 77 2E 34 6E 67 65 6C 2E 6E 65 74}
// 		$s2 = {24 61 64 6D 69 6E 5B 27 63 6F 6F 6B 69 65 6C 69 66 65 27 5D 20 3D 20 38 36 34 30 30 3B}
// 		$s3 = {24 65 72 72 6D 73 67 20 3D 20 27 54 68 65 20 66 69 6C 65 20 79 6F 75 20 77 61 6E 74 20 44 6F 77 6E 6C 6F 61 64 61 62 6C 65 20 77 61 73 20 6E 6F 6E 65 78 69 73 74 65 6E 74 27 3B}

// 	condition:
// 		1 of them
// }

// rule ak74shell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file ak74shell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "7f83adcb4c1111653d30c6427a94f66f"

// 	strings:
// 		$s1 = {24 72 65 73 20 2E 3D 20 27 3C 74 64 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 3C 61 20 68 72 65 66 3D 5C 22 27 2E 24 78 73 68 65 6C 6C 2E 27 3F 61 63 74 3D 63 68 6D 6F 64 26 66 69 6C 65 3D 27 2E 24 5F 53 45 53 53 49 4F 4E 5B}
// 		$s2 = {41 4B 2D 37 34 20 53 65 63 75 72 69 74 79 20 54 65 61 6D 20 57 65 62 20 53 69 74 65 3A 20 77 77 77 2E 61 6B 37 34 2D 74 65 61 6D 2E 6E 65 74}
// 		$s3 = {24 78 73 68 65 6C 6C}

// 	condition:
// 		2 of them
// }

// rule Rem_View_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Rem View.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "29420106d9a81553ef0d1ca72b9934d9"

// 	strings:
// 		$s0 = {24 70 68 70 3D 5C 22 2F 2A 20 6C 69 6E 65 20 31 20 2A 2F 5C 5C 6E 5C 5C 6E 2F 2F 20 5C 22 2E 6D 6D 28 5C 22 66 6F 72 20 65 78 61 6D 70 6C 65 2C 20 75 6E 63 6F 6D 6D 65 6E 74 20 6E 65 78 74 20 6C 69 6E 65 5C 22 29 2E 5C 22}
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 76 61 6C 75 65 3D 27 5C 22 2E 6D 6D 28 5C 22 44 65 6C 65 74 65 20 61 6C 6C 20 64 69 72 2F 66 69 6C 65 73 20 72 65 63 75 72 73 69 76 65 5C 22 29 2E 5C 22 20 28 72 6D 20 2D 66 72 29 27}
// 		$s4 = {57 65 6C 63 6F 6D 65 20 74 6F 20 70 68 70 52 65 6D 6F 74 65 56 69 65 77 20 28 52 65 6D 56 69 65 77 29}

// 	condition:
// 		1 of them
// }

// rule Java_Shell_js
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Java Shell.js.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "36403bc776eb12e8b7cc0eb47c8aac83"

// 	strings:
// 		$s2 = {50 79 53 79 73 74 65 6D 53 74 61 74 65 2E 69 6E 69 74 69 61 6C 69 7A 65 28 53 79 73 74 65 6D 2E 67 65 74 50 72 6F 70 65 72 74 69 65 73 28 29 2C 20 6E 75 6C 6C 2C 20 61 72 67 76 29 3B}
// 		$s3 = {70 75 62 6C 69 63 20 63 6C 61 73 73 20 4A 79 74 68 6F 6E 53 68 65 6C 6C 20 65 78 74 65 6E 64 73 20 4A 50 61 6E 65 6C 20 69 6D 70 6C 65 6D 65 6E 74 73 20 52 75 6E 6E 61 62 6C 65 20 7B}
// 		$s4 = {70 75 62 6C 69 63 20 73 74 61 74 69 63 20 69 6E 74 20 44 45 46 41 55 4C 54 5F 53 43 52 4F 4C 4C 42 41 43 4B 20 3D 20 31 30 30}

// 	condition:
// 		2 of them
// }

// rule STNC_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file STNC.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "2e56cfd5b5014cbbf1c1e3f082531815"

// 	strings:
// 		$s0 = {64 72 6D 69 73 74 2E 72 75}
// 		$s1 = {68 69 64 64 65 6E 28 5C 22 61 63 74 69 6F 6E 5C 22 2C 5C 22 64 6F 77 6E 6C 6F 61 64 5C 22 29 2E 68 69 64 64 65 6E 5F 70 77 64 28 29 2E 5C 22 3C 63 65 6E 74 65 72 3E 3C 74 61 62 6C 65 3E 3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 38 30}
// 		$s2 = {53 54 4E 43 20 57 65 62 53 68 65 6C 6C}
// 		$s3 = {68 74 74 70 3A 2F 2F 77 77 77 2E 73 65 63 75 72 69 74 79 2D 74 65 61 6D 73 2E 6E 65 74 2F 69 6E 64 65 78 2E 70 68 70 3F 73 68 6F 77 74 6F 70 69 63 3D}

// 	condition:
// 		1 of them
// }

// rule aZRaiLPhp_v1_0_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "26b2d3943395682e36da06ed493a3715"

// 	strings:
// 		$s0 = {61 7A 72 61 69 6C 70 68 70}
// 		$s1 = {3C 62 72 3E 3C 63 65 6E 74 65 72 3E 3C 49 4E 50 55 54 20 54 59 50 45 3D 27 53 55 42 4D 49 54 27 20 4E 41 4D 45 3D 27 64 79 27 20 56 41 4C 55 45 3D 27 44 6F 73 79 61 20 59 6F 6C 6C 61 21 27 3E 3C 2F 63 65 6E 74 65 72 3E}
// 		$s3 = {3C 63 65 6E 74 65 72 3E 3C 49 4E 50 55 54 20 54 59 50 45 3D 27 73 75 62 6D 69 74 27 20 6E 61 6D 65 3D 27 6F 6B 6D 66 27 20 76 61 6C 75 65 3D 27 54 41 4D 41 4D 27 3E 3C 2F 63 65 6E 74 65 72 3E}

// 	condition:
// 		2 of them
// }

// rule Moroccan_Spamers_Ma_EditioN_By_GhOsT_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "d1b7b311a7ffffebf51437d7cd97dc65"

// 	strings:
// 		$s0 = {3B 24 73 64 39 38 3D 5C 22 6A 6F 68 6E 2E 62 61 72 6B 65 72 34 34 36 40 67 6D 61 69 6C 2E 63 6F 6D 5C 22}
// 		$s1 = {70 72 69 6E 74 20 5C 22 53 65 6E 64 69 6E 67 20 6D 61 69 6C 20 74 6F 20 24 74 6F 2E 2E 2E 2E 2E 2E 2E 20 5C 22 3B}
// 		$s2 = {3C 74 64 20 63 6F 6C 73 70 61 6E 3D 5C 22 32 5C 22 20 77 69 64 74 68 3D 5C 22 37 31 35 5C 22 20 62 61 63 6B 67 72 6F 75 6E 64 3D 5C 22 2F 73 69 6D 70 61 72 74 73 2F 69 6D 61 67 65 73 2F 63 65 6C 6C 70 69 63 31 2E 67 69 66 5C 22 20 68 65 69}

// 	condition:
// 		1 of them
// }

// rule zacosmall_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file zacosmall.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "5295ee8dc2f5fd416be442548d68f7a6"

// 	strings:
// 		$s0 = {72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38}
// 		$s1 = {24 64 75 6D 70 5F 66 69 6C 65 2E 3D 27 60 27 2E 24 72 6F 77 73 32 5B 30 5D 2E 27 60}
// 		$s3 = {66 69 6C 65 6E 61 6D 65 3D 5C 5C 5C 22 64 75 6D 70 5F 7B 24 64 62 5F 64 75 6D 70 7D 5F 24 7B 74 61 62 6C 65 5F 64}

// 	condition:
// 		2 of them
// }

// rule CmdAsp_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "64f24f09ec6efaa904e2492dffc518b9"

// 	strings:
// 		$s0 = {43 6D 64 41 73 70 2E 61 73 70}
// 		$s1 = {53 65 74 20 6F 46 69 6C 65 53 79 73 20 3D 20 53 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 5C 22 29}
// 		$s2 = {2D 2D 20 55 73 65 20 61 20 70 6F 6F 72 20 6D 61 6E 27 73 20 70 69 70 65 20 2E 2E 2E 20 61 20 74 65 6D 70 20 66 69 6C 65 20 2D 2D}
// 		$s3 = {6D 61 63 65 6F 20 40 20 64 6F 67 6D 69 6C 65 2E 63 6F 6D}

// 	condition:
// 		2 of them
// }

// rule simple_backdoor_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "f091d1b9274c881f8e41b2f96e6b9936"

// 	strings:
// 		$s0 = {24 63 6D 64 20 3D 20 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 3B}
// 		$s1 = {3C 21 2D 2D 20 53 69 6D 70 6C 65 20 50 48 50 20 62 61 63 6B 64 6F 6F 72 20 62 79 20 44 4B 20 28 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 29 20 2D 2D 3E}
// 		$s2 = {55 73 61 67 65 3A 20 68 74 74 70 3A 2F 2F 74 61 72 67 65 74 2E 63 6F 6D 2F 73 69 6D 70 6C 65 2D 62 61 63 6B 64 6F 6F 72 2E 70 68 70 3F 63 6D 64 3D 63 61 74 2B 2F 65 74 63 2F 70 61 73 73 77 64}

// 	condition:
// 		2 of them
// }

// rule mysql_shell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file mysql_shell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "d42aec2891214cace99b3eb9f3e21a63"

// 	strings:
// 		$s0 = {53 6F 6F 4D 69 6E 20 4B 69 6D}
// 		$s1 = {73 6D 6B 69 6D 40 70 6F 70 65 79 65 2E 73 6E 75 2E 61 63 2E 6B 72}
// 		$s2 = {65 63 68 6F 20 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 65 6C 65 74 65 44 61 74 61 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 26 74 61 62 6C 65 6E 61 6D 65 3D 24 74 61 62 6C 65 6E}

// 	condition:
// 		1 of them
// }

// rule Dive_Shell_1_0___Emperor_Hacking_Team_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "1b5102bdc41a7bc439eea8f0010310a5"

// 	strings:
// 		$s0 = {45 6D 70 65 72 6F 72 20 48 61 63 6B 69 6E 67 20 54 45 41 4D}
// 		$s1 = {53 69 6D 73 68 65 6C 6C}
// 		$s2 = {65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D}
// 		$s3 = {3C 66 6F 72 6D 20 6E 61 6D 65 3D 5C 22 73 68 65 6C 6C 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 20 3F 3E 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54}

// 	condition:
// 		2 of them
// }

// rule Asmodeus_v0_1_pl
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "0978b672db0657103c79505df69cb4bb"

// 	strings:
// 		$s0 = {5B 75 72 6C 3D 68 74 74 70 3A 2F 2F 77 77 77 2E 67 6F 76 65 72 6E 6D 65 6E 74 73 65 63 75 72 69 74 79 2E 6F 72 67}
// 		$s1 = {70 65 72 6C 20 61 73 6D 6F 64 65 75 73 2E 70 6C 20 63 6C 69 65 6E 74 20 36 36 36 36 20 31 32 37 2E 30 2E 30 2E 31}
// 		$s2 = {70 72 69 6E 74 20 5C 22 41 73 6D 6F 64 65 75 73 20 50 65 72 6C 20 52 65 6D 6F 74 65 20 53 68 65 6C 6C}
// 		$s4 = {24 69 6E 74 65 72 6E 65 74 5F 61 64 64 72 20 3D 20 69 6E 65 74 5F 61 74 6F 6E 28 5C 22 24 68 6F 73 74 5C 22 29 20 6F 72 20 64 69 65 20 5C 22 41 4C 4F 41 3A 24 21 5C 5C 6E 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule backup_php_often_with_c99shell
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file backup.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "aeee3bae226ad57baf4be8745c3f6094"

// 	strings:
// 		$s0 = {23 70 68 70 4D 79 41 64 6D 69 6E 20 4D 79 53 51 4C 2D 44 75 6D 70}
// 		$s2 = {3B 64 62 5F 63 6F 6E 6E 65 63 74 28 29 3B 68 65 61 64 65 72 28 27 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 73 74 72}
// 		$s4 = {24 64 61 74 61 20 2E 3D 20 5C 22 23 44 61 74 61 62 61 73 65 3A 20 24 64 61 74 61 62 61 73 65}

// 	condition:
// 		all of them
// }

// rule Reader_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Reader.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "ad1a362e0a24c4475335e3e891a01731"

// 	strings:
// 		$s1 = {4D 65 68 64 69 20 26 20 48 6F 6C 79 44 65 6D 6F 6E}
// 		$s2 = {77 77 77 2E 69 6E 66 69 6C 61 6B 2E}
// 		$s3 = {27 2A 54 40 2A 72 40 23 40 26 6D 6D 73 5E 50 64 62 59 62 56 75 42 63 41 41 41 3D 3D 5E 23 7E 40 25 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 20 6E 61 6D 65 3D 69 6E 66 3E 3C 74 61 62 6C 65 20 77 69 64 74 68 3D 5C 22 37 35 25}

// 	condition:
// 		2 of them
// }

// rule phpshell17_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file phpshell17.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "9a928d741d12ea08a624ee9ed5a8c39d"

// 	strings:
// 		$s0 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 73 75 62 6D 69 74 5F 62 74 6E 5C 22 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 45 78 65 63 75 74 65 20 43 6F 6D 6D 61 6E 64 5C 22 3E 3C 2F 70 3E}
// 		$s1 = {3C 74 69 74 6C 65 3E 5B 41 44 44 49 54 49 4E 41 4C 20 54 49 54 54 4C 45 5D 2D 70 68 70 53 68 65 6C 6C 20 62 79 3A 5B 59 4F 55 52 4E 41 4D 45 5D 3C 3F 70 68 70 20 65 63 68 6F 20 50 48 50 53 48 45 4C 4C 5F 56 45 52 53 49 4F 4E 20 3F 3E 3C 2F}
// 		$s2 = {68 72 65 66 3D 5C 22 6D 61 69 6C 74 6F 3A 20 5B 59 4F 55 20 43 41 4E 20 45 4E 54 45 52 20 59 4F 55 52 20 4D 41 49 4C 20 48 45 52 45 5D 2D 20 5B 41 44 44 49 54 49 4F 4E 41 4C 20 54 45 58 54 5D 3C 2F 61 3E 3C 2F 69 3E}

// 	condition:
// 		1 of them
// }

// rule myshell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file myshell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "62783d1db52d05b1b6ae2403a7044490"

// 	strings:
// 		$s0 = {40 63 68 64 69 72 28 24 77 6F 72 6B 5F 64 69 72 29 20 6F 72 20 28 24 73 68 65 6C 6C 4F 75 74 70 75 74 20 3D 20 5C 22 4D 79 53 68 65 6C 6C 3A 20 63 61 6E 27 74 20 63 68 61 6E 67 65 20 64 69 72 65 63 74 6F 72 79 2E}
// 		$s1 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 24 6C 69 6E 6B 43 6F 6C 6F 72 3E 3C 62 3E 4D 79 53 68 65 6C 6C 20 66 69 6C 65 20 65 64 69 74 6F 72 3C 2F 66 6F 6E 74 3E 20 46 69 6C 65 3A 3C 66 6F 6E 74 20 63 6F 6C 6F 72}
// 		$s2 = {20 24 66 69 6C 65 45 64 69 74 49 6E 66 6F 20 3D 20 5C 22 26 6E 62 73 70 3B 26 6E 62 73 70 3B 3A 3A 3A 3A 3A 3A 3A 26 6E 62 73 70 3B 26 6E 62 73 70 3B 4F 77 6E 65 72 3A 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 24}

// 	condition:
// 		2 of them
// }

// rule SimShell_1_0___Simorgh_Security_MGZ_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "37cb1db26b1b0161a4bf678a6b4565bd"

// 	strings:
// 		$s0 = {53 69 6D 6F 72 67 68 20 53 65 63 75 72 69 74 79 20 4D 61 67 61 7A 69 6E 65 20}
// 		$s1 = {53 69 6D 73 68 65 6C 6C 2E 63 73 73}
// 		$s2 = {7D 20 65 6C 73 65 69 66 20 28 65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2B 28 5B 5E 3B 5D 2B 29 24 27 2C 20 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20}
// 		$s3 = {77 77 77 2E 73 69 6D 6F 72 67 68 2D 65 76 2E 63 6F 6D}

// 	condition:
// 		2 of them
// }

// rule jspshall_jsp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file jspshall.jsp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"

// 	strings:
// 		$s0 = {6B 6A 30 32 31 33 32 30}
// 		$s1 = {63 61 73 65 20 27 54 27 3A 73 79 73 74 65 6D 54 6F 6F 6C 73 28 6F 75 74 29 3B 62 72 65 61 6B 3B}
// 		$s2 = {6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 3C 74 72 3E 3C 74 64 3E 5C 22 2B 69 63 6F 28 35 30 29 2B 66 5B 69 5D 2E 67 65 74 4E 61 6D 65 28 29 2B 5C 22 3C 2F 74 64 3E 3C 74 64 3E 20 66 69 6C 65}

// 	condition:
// 		2 of them
// }

// rule webshell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file webshell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "e425241b928e992bde43dd65180a4894"

// 	strings:
// 		$s2 = {3C 64 69 65 28 5C 22 43 6F 75 6C 64 6E 27 74 20 52 65 61 64 20 64 69 72 65 63 74 6F 72 79 2C 20 42 6C 6F 63 6B 65 64 21 21 21 5C 22 29 3B}
// 		$s3 = {50 48 50 20 57 65 62 20 53 68 65 6C 6C}

// 	condition:
// 		all of them
// }

// rule rootshell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file rootshell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "265f3319075536030e59ba2f9ef3eac6"

// 	strings:
// 		$s0 = {73 68 65 6C 6C 73 2E 64 6C 2E 61 6D}
// 		$s1 = {54 68 69 73 20 73 65 72 76 65 72 20 68 61 73 20 62 65 65 6E 20 69 6E 66 65 63 74 65 64 20 62 79 20 24 6F 77 6E 65 72}
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 49 6E 63 6C 75 64 65 21 5C 22 20 6E 61 6D 65 3D 5C 22 69 6E 63 5C 22 3E 3C 2F 70 3E}
// 		$s4 = {43 6F 75 6C 64 20 6E 6F 74 20 77 72 69 74 65 20 74 6F 20 66 69 6C 65 21 20 28 4D 61 79 62 65 20 79 6F 75 20 64 69 64 6E 27 74 20 65 6E 74 65 72 20 61 6E 79 20 74 65 78 74 3F 29}

// 	condition:
// 		2 of them
// }

// rule connectback2_pl
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file connectback2.pl.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "473b7d226ea6ebaacc24504bd740822e"

// 	strings:
// 		$s0 = {23 57 65 20 41 72 65 3A 20 4D 61 73 74 65 72 4B 69 64 2C 20 41 6C 65 58 75 74 7A 2C 20 46 61 74 4D 61 6E 20 26 20 4D 69 4B 75 54 75 4C 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}
// 		$s1 = {65 63 68 6F 20 2D 2D 3D 3D 55 73 65 72 69 6E 66 6F 3D 3D 2D 2D 20 3B 20 69 64 3B 65 63 68 6F 3B 65 63 68 6F 20 2D 2D 3D 3D 44 69 72 65 63 74 6F 72 79 3D 3D 2D 2D 20 3B 20 70 77 64 3B 65 63 68 6F 3B 20 65 63 68 6F 20 2D 2D 3D 3D 53 68 65 6C}
// 		$s2 = {43 6F 6E 6E 65 63 74 42 61 63 6B 20 42 61 63 6B 64 6F 6F 72}

// 	condition:
// 		1 of them
// }

// rule DefaceKeeper_0_2_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "713c54c3da3031bc614a8a55dccd7e7f"

// 	strings:
// 		$s0 = {74 61 72 67 65 74 20 66 69 31 65 3A 3C 62 72 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 74 61 72 67 65 74 5C 22 20 76 61 6C 75 65 3D 5C 22 69 6E 64 65 78 2E 70 68 70 5C 22 3E 3C 2F 62 72 3E}
// 		$s1 = {65 76 61 6C 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 5C 22 5A 58 5A 68 62 43 68 69 59 58 4E 6C 4E 6A 52 66 5A 47 56 6A 62 32 52 6C 4B 43 4A 68 56 32 52 31 59 6A 4E 4B 62 46 67 7A 56 6E 70 61 57 45 70 6D 57 56 64 4B 64 6D 4E 75 55 57 39}
// 		$s2 = {3C 69 6D 67 20 73 72 63 3D 5C 22 68 74 74 70 3A 2F 2F 73 34 33 2E 72 61 64 69 6B 61 6C 2E 72 75 2F 69 31 30 31 2F 31 30 30 34 2F 64 38 2F 63 65 64 31 66 36 62 32 66 35 61 39 2E 70 6E 67 5C 22 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72}

// 	condition:
// 		1 of them
// }

// rule shells_PHP_wso
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file wso.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "33e2891c13b78328da9062fbfcf898b6"

// 	strings:
// 		$s0 = {24 62 61 63 6B 5F 63 6F 6E 6E 65 63 74 5F 70 3D 5C 22 49 79 45 76 64 58 4E 79 4C 32 4A 70 62 69 39 77 5A 58 4A 73 44 51 70 31 63 32 55 67 55 32 39 6A 61 32 56 30 4F 77 30 4B 4A 47 6C 68 5A 47 52 79 50 57 6C 75 5A 58 52 66 59 58 52 76 62 69}
// 		$s3 = {65 63 68 6F 20 27 3C 68 31 3E 45 78 65 63 75 74 69 6F 6E 20 50 48 50 2D 63 6F 64 65 3C 2F 68 31 3E 3C 64 69 76 20 63 6C 61 73 73 3D 63 6F 6E 74 65 6E 74 3E 3C 66 6F 72 6D 20 6E 61 6D 65 3D 70 66 20 6D 65 74 68 6F 64 3D 70 6F 73}

// 	condition:
// 		1 of them
// }

// rule backdoor1_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file backdoor1.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "e1adda1f866367f52de001257b4d6c98"

// 	strings:
// 		$s1 = {65 63 68 6F 20 5C 22 5B 44 49 52 5D 20 3C 41 20 48 52 45 46 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 72 65 70 3D 5C 22 2E 72 65 61 6C 70 61 74 68 28 24 72 65 70 2E 5C 22 2E 2E}
// 		$s2 = {63 6C 61 73 73 20 62 61 63 6B 64 6F 6F 72 20 7B}
// 		$s4 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 63 6F 70 79 3D 31 5C 5C 5C 22 3E 43 6F 70 69 65 72 20 75 6E 20 66 69 63 68 69 65 72 3C 2F 61 3E 20 3C}

// 	condition:
// 		1 of them
// }

// rule elmaliseker_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "b32d1730d23a660fd6aa8e60c3dc549f"

// 	strings:
// 		$s0 = {69 66 20 49 6E 74 28 28 31 2D 30 2B 31 29 2A 52 6E 64 2B 30 29 3D 30 20 74 68 65 6E 20 6D 61 6B 65 45 6D 61 69 6C 3D 6D 61 6B 65 54 65 78 74 28 38 29 20 26 20 5C 22 40 5C 22 20 26 20 6D 61 6B 65 54 65 78 74 28 38 29 20 26 20 5C 22 2E 5C 22}
// 		$s1 = {3C 66 6F 72 6D 20 6E 61 6D 65 3D 66 72 6D 43 4D 44 20 6D 65 74 68 6F 64 3D 70 6F 73 74 20 61 63 74 69 6F 6E 3D 5C 22 3C 25 3D 67 55 52 4C 25 3E 5C 22 3E}
// 		$s2 = {64 69 6D 20 7A 6F 6D 62 69 65 5F 61 72 72 61 79 2C 73 70 65 63 69 61 6C 5F 61 72 72 61 79}
// 		$s3 = {68 74 74 70 3A 2F 2F 76 6E 68 61 63 6B 65 72 2E 6F 72 67}

// 	condition:
// 		1 of them
// }

// rule indexer_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file indexer.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "9ea82afb8c7070817d4cdf686abe0300"

// 	strings:
// 		$s0 = {3C 74 64 3E 4E 65 72 65 79 65 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 65 79 65 5C 22 20 73 69 7A 65 3D 32 35 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70}
// 		$s2 = {44 37 6E 44 37 6C 2E 6B 6D 34 73 6E 6B 60 4A 7A 4B 6E 64 7B 6E 5F 65 6A 71 3B 62 64 7B 4B 62 50 75 72 23 6B 51 38 41 41 41 3D 3D 5E 23 7E 40 25 3E 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74}

// 	condition:
// 		1 of them
// }

// rule DxShell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file DxShell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "33a2b31810178f4c2e71fbdeb4899244"

// 	strings:
// 		$s0 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 54 69 70 3A 20 74 6F 20 76 69 65 77 20 74 68 65 20 66 69 6C 65 20 5C 22 61 73 20 69 73 5C 22 20 2D 20 6F 70 65 6E 20 74 68 65 20 70 61 67 65 20 69 6E 20 3C 61 20 68 72 65 66 3D 5C 22 27 2E 44 78}
// 		$s2 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 31 30 30 70 74 20 63 6C 61 73 73 3D 6C 69 6E 65 6C 69 73 74 69 6E 67 3E 3C 6E 6F 62 72 3E 50 4F 53 54 20 28 70 68 70 20 65 76 61 6C 29 3C 2F 74 64 3E 3C}

// 	condition:
// 		1 of them
// }

// rule s72_Shell_v1_1_Coding_html
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "c2e8346a5515c81797af36e7e4a3828e"

// 	strings:
// 		$s0 = {44 69 7A 69 6E 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 5C 22 3E 3C}
// 		$s1 = {73 37 32 20 53 68 65 6C 6C 20 76 31 2E 30 20 43 6F 64 69 6E 66 20 62 79 20 43 72 40 7A 79 5F 4B 69 6E 67}
// 		$s3 = {65 63 68 6F 20 5C 22 3C 70 20 61 6C 69 67 6E 3D 63 65 6E 74 65 72 3E 44 6F 73 79 61 20 5A 61 74 65 6E 20 42 75 6C 75 6E 75 79 6F 72 3C 2F 70 3E 5C 22}

// 	condition:
// 		1 of them
// }

// // duplicated
// /* rule hidshell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file hidshell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "c2f3327d60884561970c63ffa09439a4"

// 	strings:
// 		$s0 = {3C 3F 24 64 3D 27 47 37 6D 48 57 51 39 76 76 58 69 4C 2F 51 58 32 6F 5A 32 56 54 44 70 6F 36 67 33 46 59 41 61 36 58 2B 38 44 4D 49 7A 63 44 30 65 48 5A 61 42 5A 48 37 6A 46 70 5A 7A 55 7A 37 58 4E 65 6E 78 53 59 76 42 50 32 57 79 33 36 55}

// 	condition:
// 		all of them
// }*/

// rule kacak_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file kacak.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "907d95d46785db21331a0324972dda8c"

// 	strings:
// 		$s0 = {4B 61 63 61 6B 20 46 53 4F 20 31 2E 30}
// 		$s1 = {69 66 20 72 65 71 75 65 73 74 2E 71 75 65 72 79 73 74 72 69 6E 67 28 5C 22 54 47 48 5C 22 29 20 3D 20 5C 22 31 5C 22 20 74 68 65 6E}
// 		$s3 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 38 35 38 35 38 35 5C 22 3E 42 75 71 58 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65 3D}
// 		$s4 = {6D 61 69 6C 74 6F 3A 42 75 71 58 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D}

// 	condition:
// 		1 of them
// }

// rule PHP_Backdoor_Connect_pl_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "57fcd9560dac244aeaf95fd606621900"

// 	strings:
// 		$s0 = {4C 6F 72 44 20 6F 66 20 49 52 41 4E 20 48 41 43 4B 45 52 53 20 53 41 42 4F 54 41 47 45}
// 		$s1 = {4C 6F 72 44 2D 43 30 64 33 72 2D 4E 54}
// 		$s2 = {65 63 68 6F 20 2D 2D 3D 3D 55 73 65 72 69 6E 66 6F 3D 3D 2D 2D 20 3B}

// 	condition:
// 		1 of them
// }

// rule Antichat_Socks5_Server_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "cbe9eafbc4d86842a61a54d98e5b61f1"

// 	strings:
// 		$s0 = {24 70 6F 72 74 20 3D 20 62 61 73 65 5F 63 6F 6E 76 65 72 74 28 62 69 6E 32 68 65 78 28 73 75 62 73 74 72 28 24 72 65 71 6D 65 73 73 61 67 65 5B 24 69 64 5D 2C 20 33 2B 24 72 65 71 6C 65 6E 2B 31 2C 20 32 29 29 2C 20 31 36 2C 20 31 30 29 3B}
// 		$s3 = {23 20 20 20 5B 2B 5D 20 44 6F 6D 61 69 6E 20 6E 61 6D 65 20 61 64 64 72 65 73 73 20 74 79 70 65}
// 		$s4 = {77 77 77 2E 61 6E 74 69 63 68 61 74 2E 72 75}

// 	condition:
// 		1 of them
// }

// rule Antichat_Shell_v1_3_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "40d0abceba125868be7f3f990f031521"

// 	strings:
// 		$s0 = {41 6E 74 69 63 68 61 74}
// 		$s1 = {43 61 6E 27 74 20 6F 70 65 6E 20 66 69 6C 65 2C 20 70 65 72 6D 69 73 73 69 6F 6E 20 64 65 6E 69 64 65}
// 		$s2 = {24 72 61 34 34}

// 	condition:
// 		2 of them
// }

// rule Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "49ad9117c96419c35987aaa7e2230f63"

// 	strings:
// 		$s0 = {57 65 6C 63 6F 6D 65 2E 2E 20 42 79 20 54 68 69 73 20 73 63 72 69 70 74 20 79 6F 75 20 63 61 6E 20 6A 75 6D 70 20 69 6E 20 74 68 65 20 28 53 61 66 65 20 4D 6F 64 65 3D 4F 4E 29 20 2E 2E 20 45 6E 6A 6F 79}
// 		$s1 = {4D 6F 64 65 20 53 68 65 6C 6C 20 76 31 2E 30 3C 2F 66 6F 6E 74 3E 3C 2F 73 70 61 6E 3E}
// 		$s2 = {68 61 73 20 62 65 65 6E 20 61 6C 72 65 61 64 79 20 6C 6F 61 64 65 64 2E 20 50 48 50 20 45 6D 70 65 72 6F 72 20 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E}

// 	condition:
// 		1 of them
// }

// rule mysql_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file mysql.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "12bbdf6ef403720442a47a3cc730d034"

// 	strings:
// 		$s0 = {61 63 74 69 6F 6E 3D 6D 79 73 71 6C 72 65 61 64 26 6D 61 73 73 3D 6C 6F 61 64 6D 61 73 73 5C 22 3E 6C 6F 61 64 20 61 6C 6C 20 64 65 66 61 75 6C 74 73}
// 		$s2 = {69 66 20 28 40 70 61 73 73 74 68 72 75 28 24 63 6D 64 29 29 20 7B 20 65 63 68 6F 20 5C 22 20 2D 2D 3E 5C 22 3B 20 24 74 68 69 73 2D 3E 6F 75 74 70 75 74 5F 73 74 61 74 65 28 31 2C 20 5C 22 70 61 73 73 74 68 72 75}
// 		$s3 = {24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20}

// 	condition:
// 		1 of them
// }

// rule Worse_Linux_Shell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8338c8d9eab10bd38a7116eb534b5fa2"

// 	strings:
// 		$s1 = {70 72 69 6E 74 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 62 3E 53 65 72 76 65 72 20 69 73 3A 3C 2F 62 3E 3C 2F 74 64 3E 3C 74 64 3E 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 53 45 52 56 45 52 5F 53 49 47 4E 41 54 55 52 45 27 5D 2E 5C 22 3C 2F 74 64}
// 		$s2 = {70 72 69 6E 74 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 62 3E 45 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 3A 3C 2F 62 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 73 69 7A 65 3D 31 30 30 20 6E 61 6D 65 3D 5C 5C 5C 22 5F 63 6D 64}

// 	condition:
// 		1 of them
// }

// rule cyberlords_sql_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file cyberlords_sql.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "03b06b4183cb9947ccda2c3d636406d4"

// 	strings:
// 		$s0 = {43 6F 64 65 64 20 62 79 20 6E 30 20 5B 6E 5A 65 72 30 5D}
// 		$s1 = {20 77 77 77 2E 63 79 62 65 72 6C 6F 72 64 73 2E 6E 65 74}
// 		$s2 = {55 32 39 6D 64 48 64 68 63 6D 55 41 51 57 52 76 59 6D 55 67 53 57 31 68 5A 32 56 53 5A 57 46 6B 65 58 48 4A 5A 54 77 41 41 41 41 4D 55 45 78 55 52 66 2F 2F 2F 77 41 41 41 4A 6D 5A 7A 41 41 41 41 43 4A 6F 55 52 6B 41 41 41 41 45}
// 		$s3 = {72 65 74 75 72 6E 20 5C 22 3C 42 52 3E 44 75 6D 70 20 65 72 72 6F 72 21 20 43 61 6E 27 74 20 77 72 69 74 65 20 74 6F 20 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 66 69 6C 65 29 3B}

// 	condition:
// 		1 of them
// }

// rule cmd_asp_5_1_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8baa99666bf3734cbdfdd10088e0cd9f"

// 	strings:
// 		$s0 = {43 61 6C 6C 20 6F 53 2E 52 75 6E 28 5C 22 77 69 6E 2E 63 6F 6D 20 63 6D 64 2E 65 78 65 20 2F 63 20 64 65 6C 20 5C 22 26 20 73 7A 54 46 2C 30 2C 54 72 75 65 29}
// 		$s3 = {43 61 6C 6C 20 6F 53 2E 52 75 6E 28 5C 22 77 69 6E 2E 63 6F 6D 20 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 5C 22 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 46 20 26}

// 	condition:
// 		1 of them
// }

// rule pws_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file pws.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"

// 	strings:
// 		$s0 = {3C 64 69 76 20 61 6C 69 67 6E 3D 5C 22 6C 65 66 74 5C 22 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 5C 22 31 5C 22 3E 49 6E 70 75 74 20 63 6F 6D 6D 61 6E 64 20 3A 3C 2F 66 6F 6E 74 3E 3C 2F 64 69 76 3E}
// 		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 63 6D 64 5C 22 20 73 69 7A 65 3D 5C 22 33 30 5C 22 20 63 6C 61 73 73 3D 5C 22 69 6E 70 75 74 5C 22 3E 3C 62 72 3E}
// 		$s4 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 64 69 72 5C 22 20 73 69 7A 65 3D 5C 22 33 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 20 70 61 73 73 74 68 72 75 28 5C 22 70 77 64 5C 22 29 3B 20 3F 3E}

// 	condition:
// 		2 of them
// }

// rule PHP_Shell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file PHP Shell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 3C 2F 66 6F 72 6D 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 70 6F 73 74 5C 5C 5C 22 3E 3C 69 6E 70 75 74}
// 		$s1 = {65 63 68 6F 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D}

// 	condition:
// 		all of them
// }

// rule Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8a8c8bb153bd1ee097559041f2e5cf0a"

// 	strings:
// 		$s0 = {41 79 79 69 6C 64 69 7A}
// 		$s1 = {54 6F 75 43 68 20 42 79 20 69 4A 4F 6F}
// 		$s2 = {46 69 72 73 74 20 77 65 20 63 68 65 63 6B 20 69 66 20 74 68 65 72 65 20 68 61 73 20 62 65 65 6E 20 61 73 6B 65 64 20 66 6F 72 20 61 20 77 6F 72 6B 69 6E 67 20 64 69 72 65 63 74 6F 72 79}
// 		$s3 = {68 74 74 70 3A 2F 2F 61 79 79 69 6C 64 69 7A 2E 6F 72 67 2F 69 6D 61 67 65 73 2F 77 68 6F 73 6F 6E 6C 69 6E 65 32 2E 67 69 66}

// 	condition:
// 		2 of them
// }

// rule EFSO_2_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "b5fde9682fd63415ae211d53c6bfaa4d"

// 	strings:
// 		$s0 = {45 6A 64 65 72 20 77 61 73 20 48 45 52 45}
// 		$s1 = {2A 7E 50 55 2A 26 42 50 5B 5F 29 66 21 38 63 32 46 2A 40 23 40 26 7E 2C 50 7E 50 2C 7E 50 26 71 7E 38 42 50 6D 53 7E 39 7E 7E 6C 42 7E 58 60 56 2C 5F 2C 46 26 2A 7E 2C 6A 63 57 7E 7E 5B 5F 63 33 54 52 46 46 7A 71 40 23 40 26 50 50 2C 7E 7E}

// 	condition:
// 		2 of them
// }

// rule lamashell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file lamashell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "de9abc2e38420cad729648e93dfc6687"

// 	strings:
// 		$s0 = {6C 61 6D 61 27 73 27 68 65 6C 6C}
// 		$s1 = {69 66 28 24 5F 50 4F 53 54 5B 27 6B 69 6E 67 27 5D 20 3D 3D 20 5C 22 5C 22 29 20 7B}
// 		$s2 = {69 66 20 28 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 5F 46 49 4C 45 53 5B 27 66 69 6C 61 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 63 75 72 64 69 72 2E 5C 22 2F 5C 22 2E 24 5F 46 49 4C 45 53 5B 27 66}

// 	condition:
// 		1 of them
// }

// rule Ajax_PHP_Command_Shell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Ajax_PHP Command Shell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "93d1a2e13a3368a2472043bd6331afe9"

// 	strings:
// 		$s1 = {6E 65 77 68 74 6D 6C 20 3D 20 27 3C 62 3E 46 69 6C 65 20 62 72 6F 77 73 65 72 20 69 73 20 75 6E 64 65 72 20 63 6F 6E 73 74 72 75 63 74 69 6F 6E 21 20 55 73 65 20 61 74 20 79 6F 75 72 20 6F 77 6E 20 72 69 73 6B 21 3C 2F 62 3E 20 3C 62 72 3E}
// 		$s2 = {45 6D 70 74 79 20 43 6F 6D 6D 61 6E 64 2E 2E 74 79 70 65 20 5C 5C 5C 22 73 68 65 6C 6C 68 65 6C 70 5C 5C 5C 22 20 66 6F 72 20 73 6F 6D 65 20 65 68 68 2E 2E 2E 68 65 6C 70}
// 		$s3 = {6E 65 77 68 74 6D 6C 20 3D 20 27 3C 66 6F 6E 74 20 73 69 7A 65 3D 30 3E 3C 62 3E 54 68 69 73 20 77 69 6C 6C 20 72 65 6C 6F 61 64 20 74 68 65 20 70 61 67 65 2E 2E 2E 20 3A 28 3C 2F 62 3E 3C 62 72 3E 3C 62 72 3E 3C 66 6F 72 6D 20 65 6E 63 74}

// 	condition:
// 		1 of them
// }

// rule JspWebshell_1_2_jsp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "70a0ee2624e5bbe5525ccadc467519f6"

// 	strings:
// 		$s0 = {4A 73 70 57 65 62 73 68 65 6C 6C}
// 		$s1 = {43 72 65 61 74 65 41 6E 64 44 65 6C 65 74 65 46 6F 6C 64 65 72 20 69 73 20 65 72 72 6F 72 3A}
// 		$s2 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 37 30 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 32 32 5C 22 3E 26 6E 62 73 70 3B 3C 25 3D 65 6E 76 2E 71 75 65 72 79 48 61 73 68 74 61 62 6C 65 28 5C 22 6A 61 76 61 2E 63}
// 		$s3 = {53 74 72 69 6E 67 20 5F 70 61 73 73 77 6F 72 64 20 3D 5C 22 31 31 31 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule Sincap_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Sincap.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "b68b90ff6012a103e57d141ed38a7ee9"

// 	strings:
// 		$s0 = {24 62 61 67 6C 61 6E 3D 66 6F 70 65 6E 28 5C 22 2F 74 6D 70 2F 24 65 6B 69 6E 63 69 5C 22 2C 27 72 27 29 3B}
// 		$s2 = {24 74 61 6D 70 6F 6E 34 3D 24 74 61 6D 70 6F 6E 33 2D 31}
// 		$s3 = {40 61 76 65 6E 74 67 72 75 70 2E 6E 65 74}

// 	condition:
// 		2 of them
// }

// rule Test_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Test.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "77e331abd03b6915c6c6c7fe999fcb50"

// 	strings:
// 		$s0 = {24 79 61 7A 69 20 3D 20 5C 22 74 65 73 74 5C 22 20 2E 20 5C 22 5C 5C 72 5C 5C 6E 5C 22 3B}
// 		$s2 = {66 77 72 69 74 65 20 28 24 66 70 2C 20 5C 22 24 79 61 7A 69 5C 22 29 3B}
// 		$s3 = {24 65 6E 74 72 79 5F 6C 69 6E 65 3D 5C 22 48 41 43 4B 65 64 20 62 79 20 45 6E 74 72 69 4B 61 5C 22 3B}

// 	condition:
// 		1 of them
// }

// rule Phyton_Shell_py
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Phyton Shell.py.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "92b3c897090867c65cc169ab037a0f55"

// 	strings:
// 		$s1 = {73 68 5F 6F 75 74 3D 6F 73 2E 70 6F 70 65 6E 28 53 48 45 4C 4C 2B 5C 22 20 5C 22 2B 63 6D 64 29 2E 72 65 61 64 6C 69 6E 65 73 28 29}
// 		$s2 = {23 20 20 20 64 30 30 72 2E 70 79 20 30 2E 33 61 20 28 72 65 76 65 72 73 65 7C 62 69 6E 64 29 2D 73 68 65 6C 6C 20 69 6E 20 70 79 74 68 6F 6E 20 62 79 20 66 51}
// 		$s3 = {70 72 69 6E 74 20 5C 22 65 72 72 6F 72 3B 20 68 65 6C 70 3A 20 68 65 61 64 20 2D 6E 20 31 36 20 64 30 30 72 2E 70 79 5C 22}
// 		$s4 = {70 72 69 6E 74 20 5C 22 50 57 3A 5C 22 2C 50 57 2C 5C 22 50 4F 52 54 3A 5C 22 2C 50 4F 52 54 2C 5C 22 48 4F 53 54 3A 5C 22 2C 48 4F 53 54}

// 	condition:
// 		1 of them
// }

// rule mysql_tool_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "5fbe4d8edeb2769eda5f4add9bab901e"

// 	strings:
// 		$s0 = {24 65 72 72 6F 72 5F 74 65 78 74 20 3D 20 27 3C 73 74 72 6F 6E 67 3E 46 61 69 6C 65 64 20 73 65 6C 65 63 74 69 6E 67 20 64 61 74 61 62 61 73 65 20 5C 22 27 2E 24 74 68 69 73 2D 3E 64 62 5B 27}
// 		$s1 = {24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20 24 5F 53 45 52 56}
// 		$s4 = {3C 64 69 76 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 54 68 65 20 62 61 63 6B 75 70 20 70 72 6F 63 65 73 73 20 68 61 73 20 6E 6F 77 20 73 74 61 72 74 65 64 3C 62 72 20}

// 	condition:
// 		1 of them
// }

// rule Zehir_4_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "7f4e12e159360743ec016273c3b9108c"

// 	strings:
// 		$s2 = {3C 2F 61 3E 3C 61 20 68 72 65 66 3D 27 5C 22 26 64 6F 73 79 61 70 61 74 68 26 5C 22 3F 73 74 61 74 75 73 3D 31 30 26 64 50 61 74 68 3D 5C 22 26 66 31 2E 70 61 74 68 26 5C 22 26 70 61 74 68 3D 5C 22 26 70 61 74 68 26 5C 22 26 54 69 6D 65 3D}
// 		$s4 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 76 61 6C 75 65 3D 5C 22 54 65 73 74 20 45 74 21 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22}

// 	condition:
// 		1 of them
// }

// rule sh_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file sh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "330af9337ae51d0bac175ba7076d6299"

// 	strings:
// 		$s1 = {24 61 72 5F 66 69 6C 65 3D 61 72 72 61 79 28 27 2F 65 74 63 2F 70 61 73 73 77 64 27 2C 27 2F 65 74 63 2F 73 68 61 64 6F 77 27 2C 27 2F 65 74 63 2F 6D 61 73 74 65 72 2E 70 61 73 73 77 64 27 2C 27 2F 65 74 63 2F 66 73 74 61 62 27 2C 27 2F 65}
// 		$s2 = {53 68 6F 77 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 73 69 7A 65 3D 35 20 76 61 6C 75 65 3D 5C 22 2E 28 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 62 72 5F 73 74 27 5D 29 29 3F 24 5F 50 4F 53 54 5B 27 62 72 5F 73 74 27 5D 3A}

// 	condition:
// 		1 of them
// }

// rule phpbackdoor15_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "0fdb401a49fc2e481e3dfd697078334b"

// 	strings:
// 		$s1 = {65 63 68 6F 20 5C 22 66 69 63 68 69 65 72 20 74 65 6C 65 63 68 61 72 67 65 20 64 61 6E 73 20 5C 22 2E 67 6F 6F 64 5F 6C 69 6E 6B 28 5C 22 2E 2F 5C 22 2E 24 5F 46 49 4C 45 53 5B 5C 22 66 69 63 5C 22 5D 5B 5C 22 6E 61}
// 		$s2 = {69 66 28 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 5F 46 49 4C 45 53 5B 5C 22 66 69 63 5C 22 5D 5B 5C 22 74 6D 70 5F 6E 61 6D 65 5C 22 5D 2C 67 6F 6F 64 5F 6C 69 6E 6B 28 5C 22 2E 2F 5C 22 2E 24 5F 46 49}
// 		$s3 = {65 63 68 6F 20 5C 22 43 6C 69 71 75 65 7A 20 73 75 72 20 75 6E 20 6E 6F 6D 20 64 65 20 66 69 63 68 69 65 72 20 70 6F 75 72 20 6C 61 6E 63 65 72 20 73 6F 6E 20 74 65 6C 65 63 68 61 72 67 65 6D 65 6E 74 2E 20 43 6C 69 71 75 65 7A 20 73}

// 	condition:
// 		1 of them
// }

// rule phpjackal_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file phpjackal.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "ab230817bcc99acb9bdc0ec6d264d76f"

// 	strings:
// 		$s3 = {24 64 6C 3D 24 5F 52 45 51 55 45 53 54 5B 27 64 6F 77 6E 6C 6F 61 44 27 5D 3B}
// 		$s4 = {65 6C 73 65 20 73 68 65 6C 4C 28 5C 22 70 65 72 6C 2E 65 78 65 20 24 6E 61 6D 65 20 24 70 6F 72 74 5C 22 29 3B}

// 	condition:
// 		1 of them
// }

// rule sql_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file sql.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8334249cbb969f2d33d678fec2b680c5"

// 	strings:
// 		$s1 = {66 70 75 74 73 20 28 24 66 70 2C 20 5C 22 23 20 52 53 54 20 4D 79 53 51 4C 20 74 6F 6F 6C 73 5C 5C 72 5C 5C 6E 23 20 48 6F 6D 65 20 70 61 67 65 3A 20 68 74 74 70 3A 2F 2F 72 73 74 2E 76 6F 69 64 2E 72 75 5C 5C 72 5C 5C 6E 23}
// 		$s2 = {68 74 74 70 3A 2F 2F 72 73 74 2E 76 6F 69 64 2E 72 75}
// 		$s3 = {70 72 69 6E 74 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 3F 73 3D 24 73 26 6C 6F 67 69 6E 3D 24 6C 6F 67 69 6E 26 70 61 73 73 77 64 3D 24 70 61 73 73 77 64 26}

// 	condition:
// 		1 of them
// }

// rule cgi_python_py
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file cgi-python.py.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "0a15f473e2232b89dae1075e1afdac97"

// 	strings:
// 		$s0 = {61 20 43 47 49 20 62 79 20 46 75 7A 7A 79 6D 61 6E}
// 		$s1 = {5C 22 5C 22 5C 22 2B 66 6F 6E 74 6C 69 6E 65 20 2B 5C 22 56 65 72 73 69 6F 6E 20 3A 20 5C 22 20 2B 20 76 65 72 73 69 6F 6E 73 74 72 69 6E 67 20 2B 20 5C 22 5C 22 5C 22 2C 20 52 75 6E 6E 69 6E 67 20 6F 6E 20 3A 20 5C 22 5C 22 5C 22 20 2B 20}
// 		$s2 = {76 61 6C 75 65 73 20 3D 20 6D 61 70 28 6C 61 6D 62 64 61 20 78 3A 20 78 2E 76 61 6C 75 65 2C 20 74 68 65 66 6F 72 6D 5B 66 69 65 6C 64 5D 29 20 20 20 20 20 23 20 61 6C 6C 6F 77 73 20 66 6F 72}

// 	condition:
// 		1 of them
// }

// rule ru24_post_sh_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "5b334d494564393f419af745dc1eeec7"

// 	strings:
// 		$s1 = {3C 74 69 74 6C 65 3E 52 75 32 34 50 6F 73 74 57 65 62 53 68 65 6C 6C 20 2D 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 2E 5C 22 3C 2F 74 69 74 6C 65 3E}
// 		$s3 = {69 66 20 28 28 21 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 20 7C 7C 20 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 3D 5C 22 5C 22 29 29 20 7B 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 5C 22 69 64 3B 70 77 64 3B 75 6E 61 6D 65 20 2D 61}
// 		$s4 = {57 72 69 74 65 64 20 62 79 20 44 72 65 41 6D 65 52 7A}

// 	condition:
// 		1 of them
// }

// rule DTool_Pro_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file DTool Pro.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "366ad973a3f327dfbfb915b0faaea5a6"

// 	strings:
// 		$s0 = {72 33 76 33 6E 67 34 6E 73 5C 5C 6E 44 69 67 69 74 65}
// 		$s1 = {69 66 28 21 40 6F 70 65 6E 64 69 72 28 24 63 68 64 69 72 29 29 20 24 63 68 5F 6D 73 67 3D 5C 22 64 74 6F 6F 6C 3A 20 6C 69 6E 65 20 31 3A 20 63 68 64 69 72 3A 20 49 74 20 73 65 65 6D 73 20 74 68 61 74 20 74 68 65 20 70 65 72 6D 69 73 73 69}
// 		$s3 = {69 66 20 28 65 6D 70 74 79 28 24 63 6D 64 29 20 61 6E 64 20 24 63 68 5F 6D 73 67 3D 3D 5C 22 5C 22 29 20 65 63 68 6F 20 28 5C 22 43 6F 6D 61 6E 64 6F 73 20 45 78 63 6C 75 73 69 76 6F 73 20 64 6F 20 44 54 6F 6F 6C 20 50 72 6F 5C 5C 6E}

// 	condition:
// 		1 of them
// }

// rule telnetd_pl
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file telnetd.pl.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "5f61136afd17eb025109304bd8d6d414"

// 	strings:
// 		$s0 = {30 6C 64 57 30 6C 66}
// 		$s1 = {48 6F 77 65 76 65 72 20 79 6F 75 20 61 72 65 20 6C 75 63 6B 79 20 3A 50}
// 		$s2 = {49 27 6D 20 46 75 43 4B 65 44}
// 		$s3 = {69 6F 63 74 6C 28 24 43 4C 49 45 4E 54 7B 24 63 6C 69 65 6E 74 7D 2D 3E 7B 73 68 65 6C 6C 7D 2C 20 26 54 49 4F 43 53 57 49 4E 53 5A 2C 20 24 77 69 6E 73 69 7A 65 29 3B 23}
// 		$s4 = {61 74 72 69 78 40 69 72 63 2E 62 72 61 73 6E 65 74 2E 6F 72 67}

// 	condition:
// 		1 of them
// }

// rule php_include_w_shell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "4e913f159e33867be729631a7ca46850"

// 	strings:
// 		$s0 = {24 64 61 74 61 6F 75 74 20 2E 3D 20 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 24 4D 79 4C 6F 63 3F 24 53 52 45 51 26 69 6E 63 64 62 68 6F 73 74 3D 24 6D 79 68 6F 73 74 26 69 6E 63 64 62 75 73 65 72 3D 24 6D 79 75 73 65 72 26 69 6E 63 64}
// 		$s1 = {69 66 28 24 72 75 6E 20 3D 3D 20 31 20 26 26 20 24 70 68 70 73 68 65 6C 6C 61 70 70 20 26 26 20 24 70 68 70 73 68 65 6C 6C 68 6F 73 74 20 26 26 20 24 70 68 70 73 68 65 6C 6C 70 6F 72 74 29 20 24 73 74 72 4F 75 74 70 75 74 20 2E 3D 20 44 42}

// 	condition:
// 		1 of them
// }

// rule Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "6163b30600f1e80d2bb5afaa753490b6"

// 	strings:
// 		$s0 = {53 61 66 65 30 76 65 72}
// 		$s1 = {53 63 72 69 70 74 20 47 65 63 69 73 69 20 54 61 6D 61 6D 6C 61 79 61 6D 61 64 69 21}
// 		$s2 = {64 6F 63 75 6D 65 6E 74 2E 77 72 69 74 65 28 75 6E 65 73 63 61 70 65 28 27 25 33 43 25 36 38 25 37 34 25 36 44 25 36 43 25 33 45 25 33 43 25 36 32 25 36 46 25 36 34 25 37 39 25 33 45 25 33 43 25 35 33 25 34 33 25 35 32 25 34 39 25 35 30 25}

// 	condition:
// 		1 of them
// }

// rule shell_php_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file shell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "1a95f0163b6dea771da1694de13a3d8d"

// 	strings:
// 		$s1 = {2F 2A 20 57 65 20 68 61 76 65 20 66 6F 75 6E 64 20 74 68 65 20 70 61 72 65 6E 74 20 64 69 72 2E 20 57 65 20 6D 75 73 74 20 62 65 20 63 61 72 65 66 75 6C 6C 20 69 66 20 74 68 65 20 70 61 72 65 6E 74 20}
// 		$s2 = {24 74 6D 70 66 69 6C 65 20 3D 20 74 65 6D 70 6E 61 6D 28 27 2F 74 6D 70 27 2C 20 27 70 68 70 73 68 65 6C 6C 27 29 3B}
// 		$s3 = {69 66 20 28 65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2B 28 5B 5E 3B 5D 2B 29 24 27 2C 20 24 63 6F 6D 6D 61 6E 64 2C 20 24 72 65 67 73 29 29 20 7B}

// 	condition:
// 		1 of them
// }

// rule telnet_cgi
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file telnet.cgi.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "dee697481383052980c20c48de1598d1"

// 	strings:
// 		$s0 = {77 77 77 2E 72 6F 68 69 74 61 62 2E 63 6F 6D}
// 		$s1 = {57 20 41 20 52 20 4E 20 49 20 4E 20 47 3A 20 50 72 69 76 61 74 65 20 53 65 72 76 65 72}
// 		$s2 = {70 72 69 6E 74 20 5C 22 53 65 74 2D 43 6F 6F 6B 69 65 3A 20 53 41 56 45 44 50 57 44 3D 3B 5C 5C 6E 5C 22 3B 20 23 20 72 65 6D 6F 76 65 20 70 61 73 73 77 6F 72 64 20 63 6F 6F 6B 69 65}
// 		$s3 = {24 50 72 6F 6D 70 74 20 3D 20 24 57 69 6E 4E 54 20 3F 20 5C 22 24 43 75 72 72 65 6E 74 44 69 72 3E 20 5C 22 20 3A 20 5C 22 5B 61 64 6D 69 6E 5C 5C 40 24 53 65 72 76 65 72 4E 61 6D 65 20 24 43}

// 	condition:
// 		2 of them
// }

// rule ironshell_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file ironshell.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "8bfa2eeb8a3ff6afc619258e39fded56"

// 	strings:
// 		$s0 = {77 77 77 2E 69 72 6F 6E 77 61 72 65 7A 2E 69 6E 66 6F}
// 		$s1 = {24 63 6F 6F 6B 69 65 6E 61 6D 65 20 3D 20 5C 22 77 69 65 65 65 65 65 5C 22 3B}
// 		$s2 = {7E 20 53 68 65 6C 6C 20 49}
// 		$s3 = {77 77 77 2E 72 6F 6F 74 73 68 65 6C 6C 2D 74 65 61 6D 2E 69 6E 66 6F}
// 		$s4 = {73 65 74 63 6F 6F 6B 69 65 28 24 63 6F 6F 6B 69 65 6E 61 6D 65 2C 20 24 5F 50 4F 53 54 5B 27 70 61 73 73 27 5D 2C 20 74 69 6D 65 28 29 2B 33 36 30 30 29 3B}

// 	condition:
// 		1 of them
// }

// rule backdoorfr_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "91e4afc7444ed258640e85bcaf0fecfc"

// 	strings:
// 		$s1 = {77 77 77 2E 76 69 63 74 69 6D 65 2E 63 6F 6D 2F 69 6E 64 65 78 2E 70 68 70 3F 70 61 67 65 3D 68 74 74 70 3A 2F 2F 65 6D 70 6C 61 63 65 6D 65 6E 74 5F 64 65 5F 6C 61 5F 62 61 63 6B 64 6F 6F 72 2E 70 68 70 20 2C 20 6F 75 20 65 6E 20 74 61 6E}
// 		$s2 = {70 72 69 6E 74 28 5C 22 3C 62 72 3E 50 72 6F 76 65 6E 61 6E 63 65 20 64 75 20 6D 61 69 6C 20 3A 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 70 72 6F 76 65 6E 61 6E 63}

// 	condition:
// 		1 of them
// }

// rule aspydrv_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "1c01f8a88baee39aa1cebec644bbcb99"
// 		score = 60

// 	strings:
// 		$s0 = {49 66 20 6D 63 6F 6C 46 6F 72 6D 45 6C 65 6D 2E 45 78 69 73 74 73 28 4C 43 61 73 65 28 73 49 6E 64 65 78 29 29 20 54 68 65 6E 20 46 6F 72 6D 20 3D 20 6D 63 6F 6C 46 6F 72 6D 45 6C 65 6D 2E 49 74 65 6D 28 4C 43 61 73 65 28 73 49 6E 64 65 78 29 29}
// 		$s1 = {70 61 73 73 77 6F 72 64}
// 		$s2 = {73 65 73 73 69 6F 6E 28 5C 22 73 68 61 67 6D 61 6E 5C 22 29 3D}

// 	condition:
// 		2 of them
// }

// rule cmdjsp_jsp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "b815611cc39f17f05a73444d699341d4"

// 	strings:
// 		$s0 = {2F 2F 20 6E 6F 74 65 20 74 68 61 74 20 6C 69 6E 75 78 20 3D 20 63 6D 64 20 61 6E 64 20 77 69 6E 64 6F 77 73 20 3D 20 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 2B 20 63 6D 64 5C 22 20}
// 		$s1 = {50 72 6F 63 65 73 73 20 70 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 5C 22 63 6D 64 2E 65 78 65 20 2F 43 20 5C 22 20 2B 20 63 6D 64 29 3B}
// 		$s2 = {63 6D 64 6A 73 70 2E 6A 73 70}
// 		$s3 = {6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67}

// 	condition:
// 		2 of them
// }

// rule h4ntu_shell__powered_by_tsoi_
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "06ed0b2398f8096f1bebf092d0526137"

// 	strings:
// 		$s0 = {68 34 6E 74 75 20 73 68 65 6C 6C}
// 		$s1 = {73 79 73 74 65 6D 28 5C 22 24 63 6D 64 20 31 3E 20 2F 74 6D 70 2F 63 6D 64 74 65 6D 70 20 32 3E 26 31 3B 20 63 61 74 20 2F 74 6D 70 2F 63 6D 64 74 65 6D 70 3B 20 72 6D 20 2F 74 6D 70 2F 63 6D 64 74 65 6D 70 5C 22 29 3B}

// 	condition:
// 		1 of them
// }

// rule Ajan_asp
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file Ajan.asp.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "b6f468252407efc2318639da22b08af0"

// 	strings:
// 		$s1 = {63 3A 5C 5C 64 6F 77 6E 6C 6F 61 64 65 64 2E 7A 69 70}
// 		$s2 = {53 65 74 20 65 6E 74 72 69 6B 61 20 3D 20 65 6E 74 72 69 6B 61 2E 43 72 65 61 74 65 54 65 78 74 46 69 6C 65 28 5C 22 63 3A 5C 5C 6E 65 74 2E 76 62 73 5C 22 2C 20 54 72 75 65 29}
// 		$s3 = {68 74 74 70 3A 2F 2F 77 77 77 33 35 2E 77 65 62 73 61 6D 62 61 2E 63 6F 6D 2F 63 79 62 65 72 76 75 72 67 75 6E 2F}

// 	condition:
// 		1 of them
// }

// rule PHANTASMA_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file PHANTASMA.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "52779a27fa377ae404761a7ce76a5da7"

// 	strings:
// 		$s0 = {3E 5B 2A 5D 20 53 61 66 65 6D 6F 64 65 20 4D 6F 64 65 20 52 75 6E 3C 2F 44 49 56 3E}
// 		$s1 = {24 66 69 6C 65 31 20 2D 20 24 66 69 6C 65 32 20 2D 20 3C 61 20 68 72 65 66 3D 24 53 43 52 49 50 54 5F 4E 41 4D 45 3F 24 51 55 45 52 59 5F 53 54 52 49 4E 47 26 73 65 65 3D 24 66 69 6C 65 3E 24 66 69 6C 65 3C 2F 61 3E 3C 62 72 3E}
// 		$s2 = {5B 2A 5D 20 53 70 61 77 6E 69 6E 67 20 53 68 65 6C 6C}
// 		$s3 = {43 68 61 30 73}

// 	condition:
// 		2 of them
// }

// rule MySQL_Web_Interface_Version_0_8_php
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "36d4f34d0a22080f47bb1cb94107c60f"

// 	strings:
// 		$s0 = {53 6F 6F 4D 69 6E 20 4B 69 6D}
// 		$s1 = {68 74 74 70 3A 2F 2F 70 6F 70 65 79 65 2E 73 6E 75 2E 61 63 2E 6B 72 2F 7E 73 6D 6B 69 6D 2F 6D 79 73 71 6C}
// 		$s2 = {68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 72 6F 70 46 69 65 6C 64 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 26 74 61 62 6C 65 6E 61 6D 65 3D 24 74 61 62 6C 65 6E 61 6D 65}
// 		$s3 = {3C 74 68 3E 54 79 70 65 3C 2F 74 68 3E 3C 74 68 3E 26 6E 62 73 70 4D 26 6E 62 73 70 3C 2F 74 68 3E 3C 74 68 3E 26 6E 62 73 70 44 26 6E 62 73 70 3C 2F 74 68 3E 3C 74 68 3E 75 6E 73 69 67 6E 65 64 3C 2F 74 68 3E 3C 74 68 3E 7A 65 72 6F 66 69}

// 	condition:
// 		2 of them
// }

// rule simple_cmd_html
// {
// 	meta:
// 		description = "Semi-Auto-generated  - file simple_cmd.html.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		hash = "c6381412df74dbf3bcd5a2b31522b544"

// 	strings:
// 		$s1 = {3C 74 69 74 6C 65 3E 47 2D 53 65 63 75 72 69 74 79 20 57 65 62 73 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E}
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 54 45 58 54 20 6E 61 6D 65 3D 5C 22 2D 63 6D 64 5C 22 20 73 69 7A 65 3D 36 34 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 63 6D 64 3F 3E 5C 22 20}
// 		$s3 = {3C 3F 20 69 66 28 24 63 6D 64 20 21 3D 20 5C 22 5C 22 29 20 70 72 69 6E 74 20 53 68 65 6C 6C 5F 45 78 65 63 28 24 63 6D 64 29 3B 3F 3E}
// 		$s4 = {3C 3F 20 24 63 6D 64 20 3D 20 24 5F 52 45 51 55 45 53 54 5B 5C 22 2D 63 6D 64 5C 22 5D 3B 3F 3E}

// 	condition:
// 		all of them
// }

// rule multiple_webshells_0001
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_1_c2007_php_php_c100_php"
// 		hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
// 		hash1 = "d089e7168373a0634e1ac18c0ee00085"
// 		hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 3C 62 3E 43 68 61 6E 67 69 6E 67 20 66 69 6C 65 2D 6D 6F 64 65 20 28 5C 22 2E 24 64 2E 24 66 2E 5C 22 29 2C 20 5C 22 2E 76 69 65 77 5F 70 65 72 6D 73 5F 63 6F 6C 6F 72 28 24 64 2E 24 66 29 2E 5C 22 20 28 5C 22}
// 		$s3 = {65 63 68 6F 20 5C 22 3C 74 64 3E 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 73 71 6C 5F 73 75 72 6C 2E 5C 22 73 71 6C 5F 61 63 74 3D 71 75 65 72 79 26 73 71 6C 5F 71 75 65 72 79 3D 5C 22 2E 75 72}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0002
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_nst_php_php_img_php_php_nstview_php_php"
// 		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
// 		hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
// 		hash2 = "4745d510fed4378e4b1730f56f25e569"

// 	strings:
// 		$s0 = {3C 74 72 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E 3C 74 64 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 3C 62 3E 42 61 63 6B 20 63 6F 6E 6E 65 63 74 3A 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69}
// 		$s1 = {24 70 65 72 6C 5F 70 72 6F 78 79 5F 73 63 70 20 3D 20 5C 22 49 79 45 76 64 58 4E 79 4C 32 4A 70 62 69 39 77 5A 58 4A 73 49 43 41 4E 43 69 4D 68 4C 33 56 7A 63 69 39 31 63 32 4D 76 63 47 56 79 62 43 38 31 4C 6A 41 77 4E 43 39 69 61 57 34 76}
// 		$s2 = {3C 74 72 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E 3C 74 64 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 3C 62 3E 42 61 63 6B 64 6F 6F 72 3A 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0003
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_network_php_php_xinfo_php_php_nfm_php_php"
// 		hash0 = "acdbba993a5a4186fd864c5e4ea0ba4f"
// 		hash1 = "2601b6fc1579f263d2f3960ce775df70"
// 		hash2 = "401fbae5f10283051c39e640b77e4c26"

// 	strings:
// 		$s0 = {2E 74 65 78 74 62 6F 78 20 7B 20 62 61 63 6B 67 72 6F 75 6E 64 3A 20 57 68 69 74 65 3B 20 62 6F 72 64 65 72 3A 20 31 70 78 20 23 30 30 30 30 30 30 20 73 6F 6C 69 64 3B 20 63 6F 6C 6F 72 3A 20 23 30 30 30 30 39 39 3B 20 66 6F 6E 74 2D 66 61}
// 		$s2 = {3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 27 69 6E 70 75 74 62 6F 78 27 20 74 79 70 65 3D 27 74 65 78 74 27 20 6E 61 6D 65 3D 27 70 61 73 73 5F 64 65 27 20 73 69 7A 65 3D 35 30 20 6F 6E 63 6C 69 63 6B 3D 74 68 69 73 2E 76 61 6C 75 65 3D 27 27}

// 	condition:
// 		all of them
// }

// rule multiple_webshells_0004
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s2 = {65 63 68 6F 20 5C 22 3C 68 72 20 73 69 7A 65 3D 5C 5C 5C 22 31 5C 5C 5C 22 20 6E 6F 73 68 61 64 65 3E 3C 62 3E 44 6F 6E 65 21 3C 2F 62 3E 3C 62 72 3E 54 6F 74 61 6C 20 74 69 6D 65 20 28 73 65 63 73 2E 29 3A 20 5C 22 2E 24 66 74}
// 		$s3 = {24 66 71 62 5F 6C 6F 67 20 2E 3D 20 5C 22 5C 5C 72 5C 5C 6E 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 5C 5C 72 5C 5C 6E 44 6F 6E 65 21 5C 5C 72}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0005
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "911195a9b7c010f61b66439d9048f400"
// 		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
// 		hash3 = "8023394542cddf8aee5dec6072ed02b5"
// 		hash4 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash5 = "817671e1bdc85e04cc3440bbd9288800"

// 	strings:
// 		$s2 = {27 65 6E 67 5F 74 65 78 74 37 31 27 3D 3E 5C 22 53 65 63 6F 6E 64 20 63 6F 6D 6D 61 6E 64 73 20 70 61 72 61 6D 20 69 73 3A 5C 5C 72 5C 5C 6E 2D 20 66 6F 72 20 43 48 4F 57 4E 20 2D 20 6E 61 6D 65 20 6F 66 20 6E 65 77 20 6F 77 6E 65 72 20 6F}
// 		$s4 = {69 66 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 73 5F 6D 61 73 6B 27 5D 29 20 26 26 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 6D 27 5D 29 29 20 7B 20 24 73 72 20 3D 20 6E 65 77 20 53 65 61 72 63 68 52 65 73 75 6C 74}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0006
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php"
// 		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
// 		hash3 = "671cad517edd254352fe7e0c7c981c39"

// 	strings:
// 		$s0 = {5C 22 41 41 41 41 41 43 48 35 42 41 45 41 41 41 6B 41 4C 41 41 41 41 41 41 55 41 42 51 41 41 41 52 30 4D 4D 6C 4A 71 79 7A 46 61 6C 71 45 51 4A 75 47 45 51 53 43 6E 57 67 36 46 6F 67 70 6B 48 41 4D 46 34 48 41 4A 73 57 68 37 2F 7A 65 5C 22}
// 		$s2 = {5C 22 6D 54 50 2F 7A 44 50 2F 2F 32 59 41 41 47 59 41 4D 32 59 41 5A 6D 59 41 6D 57 59 41 7A 47 59 41 2F 32 59 7A 41 47 59 7A 4D 32 59 7A 5A 6D 59 7A 6D 57 59 7A 7A 47 59 7A 2F 32 5A 6D 41 47 5A 6D 4D 32 5A 6D 5A 6D 5A 6D 6D 57 5A 6D 5C 22}
// 		$s4 = {5C 22 52 30 6C 47 4F 44 6C 68 46 41 41 55 41 4B 4C 2F 41 50 2F 34 2F 38 44 41 77 48 39 2F 41 50 2F 34 41 4C 2B 2F 76 77 41 41 41 41 41 41 41 41 41 41 41 43 48 35 42 41 45 41 41 41 45 41 4C 41 41 41 41 41 41 55 41 42 51 41 51 41 4D 6F 5C 22}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0007
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_spy_php_php_s_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash2 = "817671e1bdc85e04cc3440bbd9288800"

// 	strings:
// 		$s2 = {65 63 68 6F 20 24 74 65 2E 5C 22 3C 64 69 76 20 61 6C 69 67 6E 3D 63 65 6E 74 65 72 3E 3C 74 65 78 74 61 72 65 61 20 63 6F 6C 73 3D 33 35 20 6E 61 6D 65 3D 64 62 5F 71 75 65 72 79 3E 5C 22 2E 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27}
// 		$s3 = {65 63 68 6F 20 73 72 28 34 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 38 30 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 5C 22 3C 73 65 6C 65 63 74 20 6E 61 6D 65 3D 64 62 3E}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0008
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php_ctt_sh_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash5 = "09609851caa129e40b0d56e90dfc476c"
// 		hash6 = "671cad517edd254352fe7e0c7c981c39"

// 	strings:
// 		$s0 = {20 20 69 66 20 28 24 63 6F 70 79 5F 75 6E 73 65 74 29 20 7B 66 6F 72 65 61 63 68 28 24 73 65 73 73 5F 64 61 74 61 5B 5C 22 63 6F 70 79 5C 22 5D 20 61 73 20 24 6B 3D 3E 24 76 29 20 7B 75 6E 73 65 74 28 24 73 65 73 73 5F 64 61 74 61 5B 5C 22}
// 		$s1 = {20 20 69 66 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 24 6D 6B 66 69 6C 65 29 29 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 4D 61 6B 65 20 46 69 6C 65 20 5C 5C 5C 22 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 6D 6B 66 69 6C 65}
// 		$s2 = {20 20 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 4D 79 53 51 4C 20 5C 22 2E 6D 79 73 71 6C 5F 67 65 74 5F 73 65 72 76 65 72 5F 69 6E 66 6F 28 29 2E 5C 22 20 28 70 72 6F 74 6F 20 76 2E 5C 22 2E 6D 79 73 71 6C 5F 67 65 74 5F 70 72}
// 		$s3 = {20 20 65 6C 73 65 69 66 20 28 21 66 6F 70 65 6E 28 24 6D 6B 66 69 6C 65 2C 5C 22 77 5C 22 29 29 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 4D 61 6B 65 20 46 69 6C 65 20 5C 5C 5C 22 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 6D}

// 	condition:
// 		all of them
// }

// rule multiple_webshells_0009
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash5 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {24 73 65 73 73 5F 64 61 74 61 5B 5C 22 63 75 74 5C 22 5D 20 3D 20 61 72 72 61 79 28 29 3B 20 63 39 39 5F 73}
// 		$s3 = {69 66 20 28 28 21 65 72 65 67 69 28 5C 22 68 74 74 70 3A 2F 2F 5C 22 2C 24 75 70 6C 6F 61 64 75 72 6C 29 29 20 61 6E 64 20 28 21 65 72 65 67 69 28 5C 22 68 74 74 70 73 3A 2F 2F 5C 22 2C 24 75 70 6C 6F 61 64 75 72 6C 29 29}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0010
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_wacking_php_php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash2 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {5C 22 3C 74 64 3E 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 73 71 6C 5F 73 75 72 6C 2E 5C 22 73 71 6C 5F 61 63 74 3D 71 75 65 72 79 26 73 71 6C 5F 71 75 65 72 79 3D 5C 22 2E 75 72}
// 		$s2 = {63 39 39 73 68 5F 73 71 6C 71 75 65 72 79}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0011
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
// 		hash4 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {65 6C 73 65 20 7B 24 61 63 74 20 3D 20 5C 22 66 5C 22 3B 20 24 64 20 3D 20 64 69 72 6E 61 6D 65 28 24 6D 6B 66 69 6C 65 29 3B 20 69 66 20 28 73 75 62 73 74 72 28 24 64 2C 2D 31 29 20 21 3D 20 44 49 52 45 43 54 4F 52 59 5F 53 45 50 41}
// 		$s3 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 46 69 6C 65 20 5C 5C 5C 22 5C 22 2E 24 73 71 6C 5F 67 65 74 66 69 6C 65 2E 5C 22 5C 5C 5C 22 3A 3C 2F 62 3E 3C 62 72 3E 5C 22 2E 6E 6C 32 62 72 28 68 74 6D 6C 73 70 65 63}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0012
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_spy_php_php_s_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "911195a9b7c010f61b66439d9048f400"
// 		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
// 		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash4 = "817671e1bdc85e04cc3440bbd9288800"

// 	strings:
// 		$s0 = {65 63 68 6F 20 73 72 28 31 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74}
// 		$s1 = {2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 69 6E 28 27 74 65 78 74 27 2C 27}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0013
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "911195a9b7c010f61b66439d9048f400"
// 		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"

// 	strings:
// 		$s0 = {27 72 75 5F 74 65 78 74 39 27 20 3D 3E 27 3F 3F 3F 3F 3F 3F 3F 3F 20 3F 3F 3F 3F 3F 20 3F 20 3F 3F 3F 3F 3F 3F 3F 3F 20 3F 3F 3F 20 3F 20 2F 62 69 6E 2F 62 61 73 68 27 2C}
// 		$s1 = {24 6E 61 6D 65 3D 27 65 63 33 37 31 37 34 38 64 63 32 64 61 36 32 34 62 33 35 61 34 66 38 66 36 38 35 64 64 31 32 32 27}
// 		$s2 = {72 73 74 2E 76 6F 69 64 2E 72 75}

// 	condition:
// 		3 of them
// }

// rule multiple_webshells_0014
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "8023394542cddf8aee5dec6072ed02b5"
// 		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash3 = "817671e1bdc85e04cc3440bbd9288800"

// 	strings:
// 		$s0 = {65 63 68 6F 20 77 73 28 32 29 2E 24 6C 62 2E 5C 22 20 3C 61}
// 		$s1 = {24 73 71 6C 20 3D 20 5C 22 4C 4F 41 44 20 44 41 54 41 20 49 4E 46 49 4C 45 20 5C 5C 5C 22 5C 22 2E 24 5F 50 4F 53 54 5B 27 74 65 73 74 33 5F 66 69 6C 65 27 5D}
// 		$s3 = {69 66 20 28 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 26 26 21 24 73 61 66 65 5F 6D 6F 64 65 29 20 7B 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 28 24 77 69 6E 64 6F 77 73 29 3F 28 5C 22 64 69 72 5C 22 29 3A 28 5C 22 6C}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0015
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_wacking_php_php_1_SpecialShell_99_php_php_c100_php"
// 		hash0 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
// 		hash2 = "09609851caa129e40b0d56e90dfc476c"
// 		hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"

// 	strings:
// 		$s0 = {69 66 28 65 72 65 67 69 28 5C 22 2E 2F 73 68 62 64 20 24 70 6F 72 5C 22 2C 24 73 63 61 6E 29 29}
// 		$s1 = {24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 6F 6E 6E 65 63 74 69 70 27 5D}
// 		$s2 = {24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 63 6F 6E 6E 6D 73 67 27 5D}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0016
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
// 		hash2 = "8023394542cddf8aee5dec6072ed02b5"
// 		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash4 = "817671e1bdc85e04cc3440bbd9288800"

// 	strings:
// 		$s1 = {69 66 28 72 6D 64 69 72 28 24 5F 50 4F 53 54 5B 27 6D 6B 5F 6E 61 6D 65 27 5D 29 29}
// 		$s2 = {24 72 20 2E 3D 20 27 3C 74 72 3E 3C 74 64 3E 27 2E 77 73 28 33 29 2E 27 3C 66 6F 6E 74 20 66 61 63 65 3D 56 65 72 64 61 6E 61 20 73 69 7A 65 3D 2D 32 3E 3C 62 3E 27 2E 24 6B 65 79 2E 27 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E}
// 		$s3 = {69 66 28 75 6E 6C 69 6E 6B 28 24 5F 50 4F 53 54 5B 27 6D 6B 5F 6E 61 6D 65 27 5D 29 29 20 65 63 68 6F 20 5C 22 3C 74 61 62 6C 65 20 77 69 64 74 68 3D 31 30 30 25 20 63 65 6C 6C 70 61 64 64 69 6E 67 3D 30 20 63 65 6C 6C}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0017
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
// 		hash3 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {5C 22 65 78 74 5F 61 76 69 5C 22 3D 3E 61 72 72 61 79 28 5C 22 65 78 74 5F 61 76 69 5C 22 2C 5C 22 65 78 74 5F 6D 6F 76 5C 22 2C 5C 22 65 78 74 5F 6D 76 69}
// 		$s1 = {65 63 68 6F 20 5C 22 3C 62 3E 45 78 65 63 75 74 65 20 66 69 6C 65 3A 3C 2F 62 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 73 75 72 6C 2E 5C 22 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E 3C 69 6E 70 75}
// 		$s2 = {5C 22 65 78 74 5F 68 74 61 63 63 65 73 73 5C 22 3D 3E 61 72 72 61 79 28 5C 22 65 78 74 5F 68 74 61 63 63 65 73 73 5C 22 2C 5C 22 65 78 74 5F 68 74 70 61 73 73 77 64}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0018
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files webadmin.php.php.txt, iMHaPFtp.php.php.txt, Private-i3lue.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_webadmin_php_php_iMHaPFtp_php_php_Private_i3lue_php"
// 		hash0 = "b268e6fa3bf3fe496cffb4ea574ec4c7"
// 		hash1 = "12911b73bc6a5d313b494102abcf5c57"
// 		hash2 = "13f5c7a035ecce5f9f380967cf9d4e92"

// 	strings:
// 		$s0 = {72 65 74 75 72 6E 20 24 74 79 70 65 20 2E 20 24 6F 77 6E 65 72 20 2E 20 24 67 72 6F 75 70 20 2E 20 24 6F 74 68 65 72 3B}
// 		$s1 = {24 6F 77 6E 65 72 20 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 34 30 30 29 20 3F 20 27 72 27 20 3A 20 27 2D 27 3B}

// 	condition:
// 		all of them
// }

// rule multiple_php_webshells
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files multiple_php_webshells"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "911195a9b7c010f61b66439d9048f400"
// 		hash2 = "be0f67f3e995517d18859ed57b4b4389"
// 		hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
// 		hash4 = "8023394542cddf8aee5dec6072ed02b5"
// 		hash5 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash6 = "817671e1bdc85e04cc3440bbd9288800"
// 		hash7 = "7101fe72421402029e2629f3aaed6de7"
// 		hash8 = "f618f41f7ebeb5e5076986a66593afd1"
// 		score = 75

// 	strings:
// 		$s0 = {6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49 69 6B 37 44 51 70 6A 62 32 35 75 5A 57 4E 30 4B 46 4E 50 51 30 74 46 56 43 77 67 4A 48 42 68 5A 47 52 79 4B 53 42 38 66 43 42 6B 61 57 55 6F 49 6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49}
// 		$s2 = {73 4E 43 69 52 77 63 6D 39 30 62 7A 31 6E 5A 58 52 77 63 6D 39 30 62 32 4A 35 62 6D 46 74 5A 53 67 6E 64 47 4E 77 4A 79 6B 37 44 51 70 7A 62 32 4E 72 5A 58 51 6F 55 30 39 44 53 30 56 55 4C 43 42 51 52 6C 39 4A 54 6B 56 55 4C 43 42 54 54 30}
// 		$s4 = {41 38 63 33 6C 7A 4C 33 4E 76 59 32 74 6C 64 43 35 6F 50 67 30 4B 49 32 6C 75 59 32 78 31 5A 47 55 67 50 47 35 6C 64 47 6C 75 5A 58 51 76 61 57 34 75 61 44 34 4E 43 69 4E 70 62 6D 4E 73 64 57 52 6C 49 44 78 6C 63 6E 4A 75 62 79 35 6F 50 67}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0019
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"

// 	strings:
// 		$s0 = {3C 62 3E 44 75 6D 70 65 64 21 20 44 75 6D 70 20 68 61 73 20 62 65 65 6E 20 77 72 69 74 65 64 20 74 6F 20}
// 		$s1 = {69 66 20 28 28 21 65 6D 70 74 79 28 24 64 6F 6E 61 74 65 64 5F 68 74 6D 6C 29 29 20 61 6E 64 20 28 69 6E 5F 61 72 72 61 79 28 24 61 63 74 2C 24 64 6F 6E 61 74 65 64 5F 61 63 74 29 29 29 20 7B 65 63 68 6F 20 5C 22 3C 54 41 42 4C 45 20 73 74}
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 6E 61 6D 65 3D 61 63 74 61 72 63 62 75 66 66 20 76 61 6C 75 65 3D 5C 5C 5C 22 50 61 63 6B 20 62 75 66 66 65 72 20 74 6F 20 61 72 63 68 69 76 65}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0020
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"

// 	strings:
// 		$s0 = {40 69 6E 69 5F 73 65 74 28 5C 22 68 69 67 68 6C 69 67 68 74}
// 		$s1 = {65 63 68 6F 20 5C 22 3C 62 3E 52 65 73 75 6C 74 20 6F 66 20 65 78 65 63 75 74 69 6F 6E 20 74 68 69 73 20 50 48 50 2D 63 6F 64 65 3C 2F 62 3E 3A 3C 62 72 3E 5C 22 3B}
// 		$s2 = {7B 24 72 6F 77 5B 5D 20 3D 20 5C 22 3C 62 3E 4F 77 6E 65 72 2F 47 72 6F 75 70 3C 2F 62 3E 5C 22 3B 7D}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0021
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_GFS_web_shell_ver_3_1_7___PRiV8_php_nshell_php_php_gfs_sh_php_php"
// 		hash0 = "be0f67f3e995517d18859ed57b4b4389"
// 		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
// 		hash2 = "f618f41f7ebeb5e5076986a66593afd1"

// 	strings:
// 		$s2 = {65 63 68 6F 20 24 75 6E 61 6D 65 2E 5C 22 3C 2F 66 6F 6E 74 3E 3C 62 72 3E 3C 62 3E 5C 22 3B}
// 		$s3 = {77 68 69 6C 65 28 21 66 65 6F 66 28 24 66 29 29 20 7B 20 24 72 65 73 2E 3D 66 72 65 61 64 28 24 66 2C 31 30 32 34 29 3B 20 7D}
// 		$s4 = {65 63 68 6F 20 5C 22 75 73 65 72 3D 5C 22 2E 40 67 65 74 5F 63 75 72 72 65 6E 74 5F 75 73 65 72 28 29 2E 5C 22 20 75 69 64 3D 5C 22 2E 40 67 65 74 6D 79 75 69 64 28 29 2E 5C 22 20 67 69 64 3D 5C 22 2E 40 67 65 74 6D 79 67 69 64 28 29}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0022
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash4 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {63 39 39 66 74 70 62 72 75 74 65 63 68 65 63 6B}
// 		$s1 = {24 66 74 70 71 75 69 63 6B 5F 74 20 3D 20 72 6F 75 6E 64 28 67 65 74 6D 69 63 72 6F 74 69 6D 65 28 29 2D 24 66 74 70 71 75 69 63 6B 5F 73 74 2C 34 29 3B}
// 		$s2 = {24 66 71 62 5F 6C 65 6E 67 68 74 20 3D 20 24 6E 69 78 70 77 64 70 65 72 70 61 67 65 3B}
// 		$s3 = {24 73 6F 63 6B 20 3D 20 40 66 74 70 5F 63 6F 6E 6E 65 63 74 28 24 68 6F 73 74 2C 24 70 6F 72 74 2C 24 74 69 6D 65 6F 75 74 29 3B}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0023
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash4 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {24 73 71 6C 71 75 69 63 6B 6C 61 75 6E 63 68 5B 5D 20 3D 20 61 72 72 61 79 28 5C 22}
// 		$s1 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 46 69 6C 65 20 64 6F 65 73 20 6E 6F 74 20 65 78 69 73 74 73 20 28 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 64 2E 24 66 29 2E 5C 22 29 21 3C}

// 	condition:
// 		all of them
// }

// rule multiple_webshells_0024
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_antichat_php_php_Fatalshell_php_php_a_gedit_php_php"
// 		hash0 = "128e90b5e2df97e21e96d8e268cde7e3"
// 		hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
// 		hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"

// 	strings:
// 		$s0 = {69 66 28 40 24 5F 50 4F 53 54 5B 27 73 61 76 65 27 5D 29 77 72 69 74 65 66 28 24 66 69 6C 65 2C 24 5F 50 4F 53 54 5B 27 64 61 74 61 27 5D 29 3B}
// 		$s1 = {69 66 28 24 61 63 74 69 6F 6E 3D 3D 5C 22 70 68 70 65 76 61 6C 5C 22 29 7B}
// 		$s2 = {24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 64 69 72 75 70 6C 6F 61 64 2E 5C 22 2F 5C 22 2E 24 5F 50 4F 53 54 5B 27 66 69 6C 65 6E 61 6D 65 27 5D 3B}
// 		$s3 = {24 64 69 72 3D 67 65 74 63 77 64 28 29 2E 5C 22 2F 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0025
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php"
// 		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"

// 	strings:
// 		$s3 = {69 66 20 28 21 65 6D 70 74 79 28 24 64 65 6C 65 72 72 29 29 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 44 65 6C 65 74 69 6E 67 20 77 69 74 68 20 65 72 72 6F 72 73 3A 3C 2F 62 3E 3C 62 72 3E 5C 22 2E 24 64 65 6C 65 72 72 3B 7D}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0026
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_Crystal_php_nshell_php_php_load_shell_php_php"
// 		hash0 = "fdbf54d5bf3264eb1c4bff1fac548879"
// 		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
// 		hash2 = "0c5d227f4aa76785e4760cdcff78a661"

// 	strings:
// 		$s0 = {69 66 20 28 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 5C 22 20 61 6E 64 20 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 2E 5C 22 29 7B}
// 		$s1 = {24 64 69 72 65 73 20 3D 20 24 64 69 72 65 73 20 2E 20 24 64 69 72 65 63 74 6F 72 79 3B}
// 		$s4 = {24 61 72 72 20 3D 20 61 72 72 61 79 5F 6D 65 72 67 65 28 24 61 72 72 2C 20 67 6C 6F 62 28 5C 22 2A 5C 22 29 29 3B}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0027
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_nst_php_php_cybershell_php_php_img_php_php_nstview_php_php"
// 		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
// 		hash1 = "ef8828e0bc0641a655de3932199c0527"
// 		hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
// 		hash3 = "4745d510fed4378e4b1730f56f25e569"

// 	strings:
// 		$s0 = {40 24 72 74 6F 3D 24 5F 50 4F 53 54 5B 27 72 74 6F 27 5D 3B}
// 		$s2 = {53 43 52 4F 4C 4C 42 41 52 2D 54 52 41 43 4B 2D 43 4F 4C 4F 52 3A 20 23 39 31 41 41 46 46}
// 		$s3 = {24 74 6F 31 3D 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 2F 2F 5C 22 2C 5C 22 2F 5C 22 2C 24 74 6F 31 29 3B}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0028
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, dC3 Security Crew Shell PRiV.php.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_dC3_Security_Crew_Shell_PRiV_php_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "433706fdc539238803fd47c4394b5109"
// 		hash4 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {20 69 66 20 28 24 6D 6F 64 65 20 26 20 30 78 32 30 30 29 20 7B 24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 3D 20 5C 22 78 5C 22 29 3F 5C 22 74 5C 22 3A}
// 		$s1 = {20 24 67 72 6F 75 70 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 31 30 29 3F 5C 22 78 5C 22 3A 5C 22 2D 5C 22 3B}

// 	condition:
// 		all of them
// }

// rule multiple_webshells_0029
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php"
// 		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
// 		hash3 = "d089e7168373a0634e1ac18c0ee00085"
// 		hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"

// 	strings:
// 		$s0 = {24 72 65 73 75 6C 74 20 3D 20 6D 79 73 71 6C 5F 71 75 65 72 79 28 5C 22 53 48 4F 57 20 50 52 4F 43 45 53 53 4C 49 53 54 5C 22 2C 20 24 73 71 6C 5F 73 6F 63 6B 29 3B 20}

// 	condition:
// 		all of them
// }

// rule multiple_php_webshells_2
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
// 		hash6 = "09609851caa129e40b0d56e90dfc476c"
// 		hash7 = "671cad517edd254352fe7e0c7c981c39"

// 	strings:
// 		$s0 = {65 6C 73 65 69 66 20 28 21 65 6D 70 74 79 28 24 66 74 29 29 20 7B 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 4D 61 6E 75 61 6C 6C 79 20 73 65 6C 65 63 74 65 64 20 74 79 70 65 20 69 73 20 69 6E 63 6F 72 72 65 63 74 2E 20 49}
// 		$s1 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 55 6E 6B 6E 6F 77 6E 20 65 78 74 65 6E 73 69 6F 6E 20 28 5C 22 2E 24 65 78 74 2E 5C 22 29 2C 20 70 6C 65 61 73 65 2C 20 73 65 6C 65 63 74 20 74 79 70 65 20 6D 61}
// 		$s3 = {24 73 20 3D 20 5C 22 21 5E 28 5C 22 2E 69 6D 70 6C 6F 64 65 28 5C 22 7C 5C 22 2C 24 74 6D 70 29 2E 5C 22 29 24 21 69 5C 22 3B}

// 	condition:
// 		all of them
// }

// rule multiple_webshells_0030
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php"
// 		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
// 		hash1 = "3ca5886cd54d495dc95793579611f59a"
// 		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
// 		hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
// 		hash4 = "09609851caa129e40b0d56e90dfc476c"

// 	strings:
// 		$s0 = {69 66 20 28 24 74 6F 74 61 6C 20 3D 3D 3D 20 46 41 4C 53 45 29 20 7B 24 74 6F 74 61 6C 20 3D 20 30 3B 7D}
// 		$s1 = {24 66 72 65 65 5F 70 65 72 63 65 6E 74 20 3D 20 72 6F 75 6E 64 28 31 30 30 2F 28 24 74 6F 74 61 6C 2F 24 66 72 65 65 29 2C 32 29 3B}
// 		$s2 = {69 66 20 28 21 24 62 6F 6F 6C 29 20 7B 24 62 6F 6F 6C 20 3D 20 69 73 5F 64 69 72 28 24 6C 65 74 74 65 72 2E 5C 22 3A 5C 5C 5C 5C 5C 22 29 3B 7D}
// 		$s3 = {24 62 6F 6F 6C 20 3D 20 24 69 73 64 69 73 6B 65 74 74 65 20 3D 20 69 6E 5F 61 72 72 61 79 28 24 6C 65 74 74 65 72 2C 24 73 61 66 65 6D 6F 64 65 5F 64 69 73 6B 65 74 74 65 73 29 3B}

// 	condition:
// 		2 of them
// }

// rule multiple_webshells_0031
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_r577_php_php_r57_php_php_spy_php_php_s_php_php"
// 		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
// 		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
// 		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
// 		hash3 = "817671e1bdc85e04cc3440bbd9288800"

// 	strings:
// 		$s0 = {24 72 65 73 20 3D 20 6D 73 73 71 6C 5F 71 75 65 72 79 28 5C 22 73 65 6C 65 63 74 20 2A 20 66 72 6F 6D 20 72 35 37 5F 74 65 6D 70 5F 74 61 62 6C 65 5C 22 2C 24 64 62 29 3B}
// 		$s2 = {27 65 6E 67 5F 74 65 78 74 33 30 27 3D 3E 27 43 61 74 20 66 69 6C 65 27 2C}
// 		$s3 = {40 6D 73 73 71 6C 5F 71 75 65 72 79 28 5C 22 64 72 6F 70 20 74 61 62 6C 65 20 72 35 37 5F 74 65 6D 70 5F 74 61 62 6C 65 5C 22 2C 24 64 62 29 3B}

// 	condition:
// 		1 of them
// }

// rule multiple_webshells_0032
// {
// 	meta:
// 		description = "Semi-Auto-generated  - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
// 		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
// 		super_rule = 1
// 		was = "_nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php"
// 		hash0 = "40a3e86a63d3d7f063a86aab5b5f92c6"
// 		hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
// 		hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
// 		hash3 = "f3ca29b7999643507081caab926e2e74"

// 	strings:
// 		$s0 = {24 6E 75 6D 20 3D 20 24 6E 69 78 70 61 73 73 77 64 20 2B 20 24 6E 69 78 70 77 64 70 65 72 70 61 67 65 3B}
// 		$s1 = {24 72 65 74 20 3D 20 70 6F 73 69 78 5F 6B 69 6C 6C 28 24 70 69 64 2C 24 73 69 67 29 3B}
// 		$s2 = {69 66 20 28 24 75 69 64 29 20 7B 65 63 68 6F 20 6A 6F 69 6E 28 5C 22 3A 5C 22 2C 24 75 69 64 29 2E 5C 22 3C 62 72 3E 5C 22 3B 7D}
// 		$s3 = {24 69 20 3D 20 24 6E 69 78 70 61 73 73 77 64 3B}

// 	condition:
// 		2 of them
// }

// rule DarkSecurityTeam_Webshell
// {
// 	meta:
// 		description = "Dark Security Team Webshell"
// 		author = "Florian Roth"
// 		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
// 		score = 50

// 	strings:
// 		$s0 = {66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 68 69 64 64 65 6E 20 6E 61 6D 65 3D 5C 22 5C 22 23 5C 22 5C 22 20 76 61 6C 75 65 3D 45 78 65 63 75 74 65 28 53 65 73 73 69 6F 6E 28 5C 22 5C 22 23 5C 22 5C 22 29 29 3E 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 74 68 65 50 61 74 68 20 76 61 6C 75 65 3D 5C 22 5C 22 5C 22 26 48 74 6D 6C 45 6E 63 6F 64 65 28 53 65 72 76 65 72 2E 4D 61 70 50 61 74 68 28 5C 22 2E 5C 22 29 29 26}

// 	condition:
// 		1 of them
// }

// rule PHP_Cloaked_Webshell_SuperFetchExec
// {
// 	meta:
// 		description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
// 		reference = "http://goo.gl/xFvioC"
// 		author = "Florian Roth"
// 		score = 50

// 	strings:
// 		$s0 = {65 6C 73 65 7B 24 64 2E 3D 40 63 68 72 28 28 24 68 5B 24 65 5B 24 6F 5D 5D 3C 3C 34 29 2B 28 24 68 5B 24 65 5B 2B 2B 24 6F 5D 5D 29 29 3B 7D 7D 65 76 61 6C 28 24 64 29 3B}

// 	condition:
// 		$s0
// }

// rule WebShell_RemExp_asp_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
// 		author = "Florian Roth"
// 		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"

// 	strings:
// 		$s0 = {6C 73 45 78 74 20 3D 20 52 69 67 68 74 28 46 69 6C 65 4E 61 6D 65 2C 20 4C 65 6E 28 46 69 6C 65 4E 61 6D 65 29 20 2D 20 6C 69 43 6F 75 6E 74 29}
// 		$s7 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 46 69 6C 65 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 73 68 6F 77 63 6F 64 65 2E 61 73 70 3F 66}
// 		$s13 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 44 72 69 76 65 2E 53 68 61 72 65 4E 61 6D 65 20 26 20 5C 22 20 5B 73 68 61 72 65 5D 5C 22}
// 		$s19 = {49 66 20 52 65 71 75 65 73 74 2E 51 75 65 72 79 53 74 72 69 6E 67 28 5C 22 43 6F 70 79 46 69 6C 65 5C 22 29 20 3C 3E 20 5C 22 5C 22 20 54 68 65 6E}
// 		$s20 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 34 30 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 32 30 5C 22 20 62 67 63 6F 6C 6F 72 3D 5C 22 73 69 6C 76 65 72 5C 22 3E 20 20 4E 61 6D 65 3C 2F 74 64 3E}

// 	condition:
// 		all of them
// }

// rule WebShell_dC3_Security_Crew_Shell_PRiV
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
// 		author = "Florian Roth"
// 		hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"

// 	strings:
// 		$s0 = {40 72 6D 64 69 72 28 24 5F 47 45 54 5B 27 66 69 6C 65 27 5D 29 20 6F 72 20 64 69 65 20 28 5C 22 5B 2D 5D 45 72 72 6F 72 20 64 65 6C 65 74 69 6E 67 20 64 69 72 21 5C 22 29 3B}
// 		$s4 = {24 70 73 3D 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 5C 22 2F 5C 22 2C 67 65 74 65 6E 76 28 27 44 4F 43 55 4D 45 4E 54 5F 52 4F 4F 54 27 29 29 3B}
// 		$s5 = {68 65 61 64 65 72 28 5C 22 45 78 70 69 72 65 73 3A 20 5C 22 2E 64 61 74 65 28 5C 22 72 5C 22 2C 6D 6B 74 69 6D 65 28 30 2C 30 2C 30 2C 31 2C 31 2C 32 30 33 30 29 29 29 3B}
// 		$s15 = {73 65 61 72 63 68 5F 66 69 6C 65 28 24 5F 50 4F 53 54 5B 27 73 65 61 72 63 68 27 5D 2C 75 72 6C 64 65 63 6F 64 65 28 24 5F 50 4F 53 54 5B 27 64 69 72 27 5D 29 29 3B}
// 		$s16 = {65 63 68 6F 20 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 69 6D 61 67 65 73 5B 24 5F 47 45 54 5B 27 70 69 63 27 5D 5D 29 3B}
// 		$s20 = {69 66 20 28 69 73 73 65 74 28 24 5F 47 45 54 5B 27 72 65 6E 61 6D 65 5F 61 6C 6C 27 5D 29 29 20 7B}

// 	condition:
// 		3 of them
// }

// rule WebShell_simattacker
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file simattacker.php"
// 		author = "Florian Roth"
// 		hash = "258297b62aeaf4650ce04642ad5f19be25ec29c9"

// 	strings:
// 		$s1 = {24 66 72 6F 6D 20 3D 20 72 61 6E 64 20 28 37 31 2C 31 30 32 30 30 30 30 30 30 30 29 2E 5C 22 40 5C 22 2E 5C 22 41 74 74 61 63 6B 65 72 2E 63 6F 6D 5C 22 3B}
// 		$s4 = {26 6E 62 73 70 3B 54 75 72 6B 69 73 68 20 48 61 63 6B 65 72 73 20 3A 20 57 57 57 2E 41 4C 54 55 52 4B 53 2E 43 4F 4D 20 3C 62 72 3E}
// 		$s5 = {26 6E 62 73 70 3B 50 72 6F 67 72 61 6D 65 72 20 3A 20 53 69 6D 41 74 74 61 63 6B 65 72 20 2D 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 3C 62 72 3E}
// 		$s6 = {2F 2F 66 61 6B 65 20 6D 61 69 6C 20 3D 20 55 73 65 20 76 69 63 74 69 6D 20 73 65 72 76 65 72 20 34 20 44 4F 53 20 2D 20 66 61 6B 65 20 6D 61 69 6C 20}
// 		$s10 = {26 6E 62 73 70 3B 65 2D 6D 61 69 6C 20 3A 20 6B 69 6E 67 64 65 66 61 63 65 72 40 6D 73 6E 2E 63 6F 6D 3C 62 72 3E}
// 		$s17 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 45 5F 45 52 52 4F 52 20 7C 20 45 5F 57 41 52 4E 49 4E 47 20 7C 20 45 5F 50 41 52 53 45 29 3B}
// 		$s18 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 73 69 7A 65 3D 27 31 27 20 63 6F 6C 6F 72 3D 27 23 39 39 39 39 39 39 27 3E 44 6F 6E 74 20 69 6E 20 77 69 6E 64 6F 77 73 5C 22 3B}
// 		$s20 = {24 43 6F 6D 6D 65 6E 74 73 3D 24 5F 50 4F 53 54 5B 27 43 6F 6D 6D 65 6E 74 73 27 5D 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_DTool_Pro
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file DTool Pro.php"
// 		author = "Florian Roth"
// 		hash = "e2ee1c7ba7b05994f65710b7bbf935954f2c3353"

// 	strings:
// 		$s1 = {66 75 6E 63 74 69 6F 6E 20 50 48 50 67 65 74 28 29 7B 69 6E 63 6C 56 61 72 28 29 3B 20 69 66 28 63 6F 6E 66 69 72 6D 28 5C 22 4F 20 50 48 50 67 65 74 20 61 67 6F 72 61 20 6F 66 65 72 65 63 65 20 75 6D 61 20 6C 69 73 74 61 20 70 72 6F 6E 74}
// 		$s2 = {3C 66 6F 6E 74 20 73 69 7A 65 3D 33 3E 62 79 20 72 33 76 33 6E 67 34 6E 73 20 2D 20 72 65 76 65 6E 67 61 6E 73 40 67 6D 61 69 6C 2E 63 6F 6D 20 3C 2F 66 6F 6E 74 3E}
// 		$s3 = {66 75 6E 63 74 69 6F 6E 20 50 48 50 77 72 69 74 65 72 28 29 7B 69 6E 63 6C 56 61 72 28 29 3B 76 61 72 20 75 72 6C 3D 70 72 6F 6D 70 74 28 5C 22 5B 20 50 48 50 77 72 69 74 65 72 20 5D 20 62 79 20 72 33 76 33 6E 67 34 6E 73 5C 5C 6E 44 69 67}
// 		$s11 = {2F 2F 54 75 72 6E 73 20 74 68 65 20 27 6C 73 27 20 63 6F 6D 6D 61 6E 64 20 6D 6F 72 65 20 75 73 65 66 75 6C 6C 2C 20 73 68 6F 77 69 6E 67 20 69 74 20 61 73 20 69 74 20 6C 6F 6F 6B 73 20 69 6E 20 74 68 65 20 73 68 65 6C 6C}
// 		$s13 = {69 66 20 28 40 66 69 6C 65 5F 65 78 69 73 74 73 28 5C 22 2F 75 73 72 2F 62 69 6E 2F 77 67 65 74 5C 22 29 29 20 24 70 72 6F 33 3D 5C 22 3C 69 3E 77 67 65 74 3C 2F 69 3E 20 61 74 20 2F 75 73 72 2F 62 69 6E 2F 77 67 65 74 2C 20 5C 22 3B}
// 		$s14 = {2F 2F 54 6F 20 6B 65 65 70 20 74 68 65 20 63 68 61 6E 67 65 73 20 69 6E 20 74 68 65 20 75 72 6C 2C 20 77 68 65 6E 20 75 73 69 6E 67 20 74 68 65 20 27 47 45 54 27 20 77 61 79 20 74 6F 20 73 65 6E 64 20 70 68 70 20 76 61 72 69 61 62 6C 65 73}
// 		$s16 = {66 75 6E 63 74 69 6F 6E 20 50 48 50 66 28 29 7B 69 6E 63 6C 56 61 72 28 29 3B 76 61 72 20 6F 3D 70 72 6F 6D 70 74 28 5C 22 5B 20 50 48 50 66 69 6C 45 64 69 74 6F 72 20 5D 20 62 79 20 72 33 76 33 6E 67 34 6E 73 5C 5C 6E 44 69 67 69 74 65 20}
// 		$s18 = {69 66 28 65 6D 70 74 79 28 24 66 75 29 29 20 24 66 75 20 3D 20 40 24 5F 47 45 54 5B 27 66 75 27 5D 3B}

// 	condition:
// 		3 of them
// }

// rule WebShell_ironshell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file ironshell.php"
// 		author = "Florian Roth"
// 		hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"

// 	strings:
// 		$s0 = {3C 74 69 74 6C 65 3E 27 2E 67 65 74 65 6E 76 28 5C 22 48 54 54 50 5F 48 4F 53 54 5C 22 29 2E 27 20 7E 20 53 68 65 6C 6C 20 49 3C 2F 74 69 74 6C 65 3E}
// 		$s2 = {24 6C 69 6E 6B 20 3D 20 6D 79 73 71 6C 5F 63 6F 6E 6E 65 63 74 28 24 5F 50 4F 53 54 5B 27 68 6F 73 74 27 5D 2C 20 24 5F 50 4F 53 54 5B 27 75 73 65 72 6E 61 6D 65 27 5D 2C 20 24 5F 50 4F 53 54}
// 		$s4 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 30 29 3B 20 2F 2F 49 66 20 74 68 65 72 65 20 69 73 20 61 6E 20 65 72 72 6F 72 2C 20 77 65 27 6C 6C 20 73 68 6F 77 20 69 74 2C 20 6B 3F}
// 		$s8 = {70 72 69 6E 74 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 6D 65 2E 5C 22 3F 70 3D 63 68 6D 6F 64 26 66 69 6C 65 3D 5C 22 2E 24 63 6F 6E 74 65 6E 74 2E 5C 22 26 64}
// 		$s15 = {69 66 28 21 69 73 5F 6E 75 6D 65 72 69 63 28 24 5F 50 4F 53 54 5B 27 74 69 6D 65 6C 69 6D 69 74 27 5D 29 29}
// 		$s16 = {69 66 28 24 5F 50 4F 53 54 5B 27 63 68 61 72 73 27 5D 20 3D 3D 20 5C 22 39 39 39 39 5C 22 29}
// 		$s17 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 61 7A 5C 5C 5C 22 3E 61 20 2D 20 7A 7A 7A 7A 7A 3C 2F 6F 70 74 69 6F 6E 3E}
// 		$s18 = {70 72 69 6E 74 20 73 68 65 6C 6C 5F 65 78 65 63 28 24 63 6F 6D 6D 61 6E 64 29 3B}

// 	condition:
// 		3 of them
// }

// rule WebShell_indexer_asp_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
// 		author = "Florian Roth"
// 		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"

// 	strings:
// 		$s0 = {3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 5C 22 43 6F 6E 74 65 6E 74 2D 4C 61 6E 67 75 61 67 65 5C 22 20 63 6F 6E 74 65 6E 74 3D 5C 22 74 72 5C 22 3E}
// 		$s1 = {3C 74 69 74 6C 65 3E 57 77 57 2E 53 61 4E 61 4C 54 65 52 6F 52 2E 4F 72 47 20 2D 20 69 6E 44 45 58 45 52 20 41 6E 64 20 52 65 61 44 65 72 3C 2F 74 69 74 6C 65 3E}
// 		$s2 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3F 47 6F 6E 64 65 72 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 3E}
// 		$s4 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3F 6F 6B 75 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 3E}
// 		$s7 = {76 61 72 20 6D 65 73 73 61 67 65 3D 5C 22 53 61 4E 61 4C 54 65 52 6F 52 20 2D 20}
// 		$s8 = {6E 44 65 78 45 72 20 2D 20 52 65 61 64 65 72 5C 22}

// 	condition:
// 		3 of them
// }

// rule WebShell_toolaspshell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file toolaspshell.php"
// 		author = "Florian Roth"
// 		hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"

// 	strings:
// 		$s0 = {63 70 72 74 68 74 6D 6C 20 3D 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 27 61 72 69 61 6C 27 20 73 69 7A 65 3D 27 31 27 3E 52 48 54 4F 4F 4C 53 20 31 2E 35 20 42 45 54 41 28 50 56 54 29 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66}
// 		$s12 = {62 61 72 72 61 70 6F 73 20 3D 20 43 49 6E 74 28 49 6E 73 74 72 52 65 76 28 4C 65 66 74 28 72 61 69 7A 2C 4C 65 6E 28 72 61 69 7A 29 20 2D 20 31 29 2C 5C 22 5C 5C 5C 22 29 29 20 2D 20 31}
// 		$s20 = {64 65 73 74 69 6E 6F 33 20 3D 20 66 6F 6C 64 65 72 49 74 65 6D 2E 70 61 74 68 20 26 20 5C 22 5C 5C 69 6E 64 65 78 2E 61 73 70 5C 22}

// 	condition:
// 		2 of them
// }

// rule WebShell_b374k_mini_shell_php_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
// 		author = "Florian Roth"
// 		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"

// 	strings:
// 		$s0 = {40 65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 30 29 3B}
// 		$s2 = {40 65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 63 6F 64 65 29 29 29 3B}
// 		$s3 = {40 73 65 74 5F 74 69 6D 65 5F 6C 69 6D 69 74 28 30 29 3B 20}

// 	condition:
// 		all of them
// }

// rule WebShell_Sincap_1_0
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Sincap 1.0.php"
// 		author = "Florian Roth"
// 		hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"

// 	strings:
// 		$s4 = {3C 2F 66 6F 6E 74 3E 3C 2F 73 70 61 6E 3E 3C 61 20 68 72 65 66 3D 5C 22 6D 61 69 6C 74 6F 3A 73 68 6F 70 65 6E 40 61 76 65 6E 74 67 72 75 70 2E 6E 65 74 5C 22 3E}
// 		$s5 = {3C 74 69 74 6C 65 3E 3A 3A 20 41 76 65 6E 74 47 72 75 70 20 3A 3A 2E 2E 20 2D 20 53 69 6E 63 61 70 20 31 2E 30 20 7C 20 53 65 73 73 69 6F 6E 28 4F 74 75 72 75 6D 29 20 42}
// 		$s9 = {3C 2F 73 70 61 6E 3E 41 76 72 61 73 79 61 20 56 65 72 69 20 76 65 20 4E 65 74 57 6F 72 6B 20 54 65 6B 6E 6F 6C 6F 6A 69 6C 65 72 69 20 47 65 6C 69}
// 		$s12 = {77 68 69 6C 65 20 28 28 24 65 6B 69 6E 63 69 3D 72 65 61 64 64 69 72 20 28 24 73 65 64 61 74 29 29 29 7B}
// 		$s19 = {24 64 65 67 65 72 32 3D 20 5C 22 24 69 63 68 5B 24 74 61 6D 70 6F 6E 34 5D 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_b374k_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file b374k.php.php"
// 		author = "Florian Roth"
// 		hash = "04c99efd187cf29dc4e5603c51be44170987bce2"

// 	strings:
// 		$s0 = {2F 2F 20 65 6E 63 72 79 70 74 20 79 6F 75 72 20 70 61 73 73 77 6F 72 64 20 74 6F 20 6D 64 35 20 68 65 72 65 20 68 74 74 70 3A 2F 2F 6B 65 72 69 6E 63 69 2E 6E 65 74 2F 3F 78 3D 64 65 63 6F 64 65}
// 		$s6 = {2F 2F 20 70 61 73 73 77 6F 72 64 20 28 64 65 66 61 75 6C 74 20 69 73 3A 20 62 33 37 34 6B 29}
// 		$s8 = {2F 2F 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A}
// 		$s9 = {2F 2F 20 62 33 37 34 6B 20 32 2E 32}
// 		$s10 = {65 76 61 6C 28 5C 22 3F 3E 5C 22 2E 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28}

// 	condition:
// 		3 of them
// }

// rule WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
// 		author = "Florian Roth"
// 		hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"

// 	strings:
// 		$s4 = {26 6E 62 73 70 3B 49 72 61 6E 69 61 6E 20 48 61 63 6B 65 72 73 20 3A 20 57 57 57 2E 53 49 4D 4F 52 47 48 2D 45 56 2E 43 4F 4D 20 3C 62 72 3E}
// 		$s5 = {2F 2F 66 61 6B 65 20 6D 61 69 6C 20 3D 20 55 73 65 20 76 69 63 74 69 6D 20 73 65 72 76 65 72 20 34 20 44 4F 53 20 2D 20 66 61 6B 65 20 6D 61 69 6C 20}
// 		$s10 = {3C 61 20 73 74 79 6C 65 3D 5C 22 54 45 58 54 2D 44 45 43 4F 52 41 54 49 4F 4E 3A 20 6E 6F 6E 65 5C 22 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 73 69 6D 6F 72 67 68 2D 65 76 2E 63 6F 6D 5C 22 3E}
// 		$s16 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 45 5F 45 52 52 4F 52 20 7C 20 45 5F 57 41 52 4E 49 4E 47 20 7C 20 45 5F 50 41 52 53 45 29 3B}
// 		$s17 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 73 69 7A 65 3D 27 31 27 20 63 6F 6C 6F 72 3D 27 23 39 39 39 39 39 39 27 3E 44 6F 6E 74 20 69 6E 20 77 69 6E 64 6F 77 73 5C 22 3B}
// 		$s19 = {24 43 6F 6D 6D 65 6E 74 73 3D 24 5F 50 4F 53 54 5B 27 43 6F 6D 6D 65 6E 74 73 27 5D 3B}
// 		$s20 = {56 69 63 74 69 6D 20 4D 61 69 6C 20 3A 3C 62 72 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 27 74 65 78 74 27 20 6E 61 6D 65 3D 27 74 6F 27 20 3E 3C 62 72 3E}

// 	condition:
// 		3 of them
// }

// rule WebShell_h4ntu_shell__powered_by_tsoi_
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
// 		author = "Florian Roth"
// 		hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"

// 	strings:
// 		$s11 = {3C 74 69 74 6C 65 3E 68 34 6E 74 75 20 73 68 65 6C 6C 20 5B 70 6F 77 65 72 65 64 20 62 79 20 74 73 6F 69 5D 3C 2F 74 69 74 6C 65 3E}
// 		$s13 = {24 63 6D 64 20 3D 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3B}
// 		$s16 = {24 75 6E 61 6D 65 20 3D 20 70 6F 73 69 78 5F 75 6E 61 6D 65 28 20 29 3B}
// 		$s17 = {69 66 28 21 24 77 68 6F 61 6D 69 29 24 77 68 6F 61 6D 69 3D 65 78 65 63 28 5C 22 77 68 6F 61 6D 69 5C 22 29 3B}
// 		$s18 = {65 63 68 6F 20 5C 22 3C 70 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 32 20 66 61 63 65 3D 56 65 72 64 61 6E 61 3E 3C 62 3E 54 68 69 73 20 49 73 20 54 68 65 20 53 65 72 76 65 72 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E}
// 		$s20 = {6F 62 5F 65 6E 64 5F 63 6C 65 61 6E 28 29 3B}

// 	condition:
// 		3 of them
// }

// rule WebShell_php_webshells_MyShell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file MyShell.php"
// 		author = "Florian Roth"
// 		hash = "42e283c594c4d061f80a18f5ade0717d3fb2f76d"

// 	strings:
// 		$s3 = {3C 74 69 74 6C 65 3E 4D 79 53 68 65 6C 6C 20 65 72 72 6F 72 20 2D 20 41 63 63 65 73 73 20 44 65 6E 69 65 64 3C 2F 74 69 74 6C 65 3E}
// 		$s4 = {24 61 64 6D 69 6E 45 6D 61 69 6C 20 3D 20 5C 22 79 6F 75 72 65 6D 61 69 6C 40 79 6F 75 72 73 65 72 76 65 72 2E 63 6F 6D 5C 22 3B}
// 		$s5 = {2F 2F 41 20 77 6F 72 6B 64 69 72 20 68 61 73 20 62 65 65 6E 20 61 73 6B 65 64 20 66 6F 72 20 2D 20 77 65 20 63 68 64 69 72 20 74 6F 20 74 68 61 74 20 64 69 72 2E}
// 		$s6 = {73 79 73 74 65 6D 28 24 63 6F 6D 6D 61 6E 64 20 2E 20 5C 22 20 31 3E 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 20 32 3E 26 31 3B 20 63 61 74 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 3B 20 72 6D 20 2F 74 6D 70 2F 6F}
// 		$s13 = {23 24 61 75 74 6F 45 72 72 6F 72 54 72 61 70 20 45 6E 61 62 6C 65 20 61 75 74 6F 6D 61 74 69 63 20 65 72 72 6F 72 20 74 72 61 70 69 6E 67 20 69 66 20 63 6F 6D 6D 61 6E 64 20 72 65 74 75 72 6E 73 20 65 72 72 6F 72 2E}
// 		$s14 = {2F 2A 20 4E 6F 20 77 6F 72 6B 5F 64 69 72 20 2D 20 77 65 20 63 68 64 69 72 20 74 6F 20 24 44 4F 43 55 4D 45 4E 54 5F 52 4F 4F 54 20 2A 2F}
// 		$s19 = {23 65 76 65 72 79 20 63 6F 6D 6D 61 6E 64 20 79 6F 75 20 65 78 63 65 63 75 74 65 2E}
// 		$s20 = {3C 66 6F 72 6D 20 6E 61 6D 65 3D 5C 22 73 68 65 6C 6C 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 3E}

// 	condition:
// 		3 of them
// }

// rule WebShell_php_webshells_pws
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file pws.php"
// 		author = "Florian Roth"
// 		hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"

// 	strings:
// 		$s6 = {69 66 20 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 7B}
// 		$s7 = {24 63 6D 64 20 3D 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3B}
// 		$s10 = {65 63 68 6F 20 5C 22 46 49 4C 45 20 55 50 4C 4F 41 44 45 44 20 54 4F 20 24 64 65 7A 5C 22 3B}
// 		$s11 = {69 66 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 24 75 70 6C 6F 61 64 65 64 29 29 20 7B}
// 		$s12 = {63 6F 70 79 28 24 75 70 6C 6F 61 64 65 64 2C 20 24 64 65 7A 29 3B}
// 		$s17 = {70 61 73 73 74 68 72 75 28 24 63 6D 64 29 3B}

// 	condition:
// 		4 of them
// }

// rule WebShell_reader_asp_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
// 		author = "Florian Roth"
// 		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"

// 	strings:
// 		$s5 = {73 74 65 72 5C 22 20 6E 61 6D 65 3D 73 75 62 6D 69 74 3E 20 3C 2F 46 6F 6E 74 3E 20 26 6E 62 73 70 3B 20 26 6E 62 73 70 3B 20 26 6E 62 73 70 3B 20 3C 61 20 68 72 65 66 3D 6D 61 69 6C 74 6F 3A 6D 61 69 6C 62 6F 6D 62 40 68 6F 74 6D 61 69 6C}
// 		$s12 = {20 48 41 43 4B 49 4E 47 20}
// 		$s16 = {46 4F 4E 54 2D 57 45 49 47 48 54 3A 20 62 6F 6C 64 3B 20 42 41 43 4B 47 52 4F 55 4E 44 3A 20 23 66 66 66 66 66 66 20 75 72 6C 28 27 69 6D 61 67 65 73 2F 63 65 6C 6C 70 69 63 31 2E 67 69 66 27 29 3B 20 54 45 58 54 2D 49 4E 44 45 4E 54 3A 20}
// 		$s20 = {50 41 44 44 49 4E 47 2D 52 49 47 48 54 3A 20 38 70 78 3B 20 50 41 44 44 49 4E 47 2D 4C 45 46 54 3A 20 38 70 78 3B 20 46 4F 4E 54 2D 57 45 49 47 48 54 3A 20 62 6F 6C 64 3B 20 46 4F 4E 54 2D 53 49 5A 45 3A 20 31 31 70 78 3B 20 42 41 43 4B 47}

// 	condition:
// 		3 of them
// }

// rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
// 		author = "Florian Roth"
// 		hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"

// 	strings:
// 		$s1 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 47 65 74 20 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}
// 		$s6 = {62 79 20 50 48 50 20 45 6D 70 65 72 6F 72 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3E}
// 		$s9 = {5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 66 69 6C 65 29 2E 5C 22 20 68 61 73 20 62 65 65 6E 20 61 6C 72 65 61 64 79 20 6C 6F 61 64 65 64 2E 20 50 48 50 20 45 6D 70 65 72 6F 72 20 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E}
// 		$s11 = {64 69 65 28 5C 22 3C 46 4F 4E 54 20 43 4F 4C 4F 52 3D 5C 5C 5C 22 52 45 44 5C 5C 5C 22 3E 3C 43 45 4E 54 45 52 3E 53 6F 72 72 79 2E 2E 2E 20 46 69 6C 65}
// 		$s15 = {69 66 28 65 6D 70 74 79 28 24 5F 47 45 54 5B 27 66 69 6C 65 27 5D 29 29 7B}
// 		$s16 = {65 63 68 6F 20 5C 22 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 53 61 66 65 20 4D 6F 64 65 20 53 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E 3C 2F 68 65 61 64 3E 5C 22 3B 20}

// 	condition:
// 		3 of them
// }

// rule WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
// 		author = "Florian Roth"
// 		hash = "b2b797707e09c12ff5e632af84b394ad41a46fa4"

// 	strings:
// 		$s4 = {24 6C 69 7A 30 7A 69 6D 3D 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 50 4F 53 54 5B 6C 69 7A 30 5D 29 3B 20}
// 		$s6 = {24 6C 69 7A 30 3D 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 50 4F 53 54 5B 62 61 62 61 5D 29 3B 20}
// 		$s9 = {65 63 68 6F 20 5C 22 3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 3E 4C 69 7A 30 7A 69 4D 20 50 72 69 76 61 74 65 20 53 61 66 65 20 4D 6F 64 65 20 43 6F 6D 6D 61 6E 64 20 45 78 65 63 75 72 69 74 6F 6E 20 42 79 70 61 73 73 20 45}
// 		$s12 = {20 3A 3D 29 20 3A 3C 2F 66 6F 6E 74 3E 3C 73 65 6C 65 63 74 20 73 69 7A 65 3D 5C 22 31 5C 22 20 6E 61 6D 65 3D 5C 22 6C 69 7A 30 5C 22 3E}
// 		$s13 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 61 74 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}

// 	condition:
// 		1 of them
// }

// rule WebShell_php_backdoor
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file php-backdoor.php"
// 		author = "Florian Roth"
// 		hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"

// 	strings:
// 		$s5 = {68 74 74 70 3A 2F 2F 3C 3F 20 65 63 68 6F 20 24 53 45 52 56 45 52 5F 4E 41 4D 45 2E 24 52 45 51 55 45 53 54 5F 55 52 49 3B 20 3F 3E 3F 64 3D 2F 65 74 63 20 6F 6E 20 2A 6E 69 78}
// 		$s6 = {2F 2F 20 61 20 73 69 6D 70 6C 65 20 70 68 70 20 62 61 63 6B 64 6F 6F 72 20 7C 20 63 6F 64 65 64 20 62 79 20 7A 30 6D 62 69 65 20 5B 33 30 2E 30 38 2E 30 33 5D 20 7C 20 68 74 74 70 3A 2F 2F 66 72 65 65 6E 65 74 2E 61 6D 2F 7E 7A 6F 6D 62 69}
// 		$s11 = {69 66 28 21 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 64 69 72 27 5D 29 29 20 64 69 65 28 27 68 65 79 2C 73 70 65 63 69 66 79 20 64 69 72 65 63 74 6F 72 79 21 27 29 3B}
// 		$s13 = {65 6C 73 65 20 65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 66 3D 24 64 2F 24 64 69 72 27 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 61 63 6B 3E 5C 22 3B}
// 		$s15 = {3C 70 72 65 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 20 65 63 68 6F 20 24 50 48 50 5F 53 45 4C 46 3B 20 3F 3E 5C 22 20 4D 45 54 48 4F 44 3D 47 45 54 20 3E 65 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 3A 20 3C 69 6E 70 75 74 20}

// 	condition:
// 		1 of them
// }

// rule WebShell_Worse_Linux_Shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
// 		author = "Florian Roth"
// 		hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"

// 	strings:
// 		$s4 = {69 66 28 20 24 5F 50 4F 53 54 5B 27 5F 61 63 74 27 5D 20 3D 3D 20 5C 22 55 70 6C 6F 61 64 21 5C 22 20 29 20 7B}
// 		$s5 = {70 72 69 6E 74 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 68 31 3E 23 77 6F 72 73 74 20 40 64 61 6C 2E 6E 65 74 3C 2F 68 31 3E 3C 2F 63 65 6E 74 65 72 3E 5C 22 3B}
// 		$s7 = {70 72 69 6E 74 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 68 31 3E 4C 69 6E 75 78 20 53 68 65 6C 6C 73 3C 2F 68 31 3E 3C 2F 63 65 6E 74 65 72 3E 5C 22 3B}
// 		$s8 = {24 63 75 72 72 65 6E 74 43 4D 44 20 3D 20 5C 22 6C 73 20 2D 6C 61 5C 22 3B}
// 		$s14 = {70 72 69 6E 74 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 62 3E 53 79 73 74 65 6D 20 74 79 70 65 3A 3C 2F 62 3E 3C 2F 74 64 3E 3C 74 64 3E 24 55 4E 61 6D 65 3C 2F 74 64 3E 3C 2F 74 72 3E 5C 22 3B}
// 		$s19 = {24 63 75 72 72 65 6E 74 43 4D 44 20 3D 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22 2C 5C 22 5C 5C 5C 5C 5C 22 2C 24 5F 50 4F 53 54 5B 27 5F 63 6D 64 27 5D 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_php_webshells_pHpINJ
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file pHpINJ.php"
// 		author = "Florian Roth"
// 		hash = "75116bee1ab122861b155cc1ce45a112c28b9596"

// 	strings:
// 		$s3 = {65 63 68 6F 20 27 3C 61 20 68 72 65 66 3D 27 2E 24 65 78 70 75 72 6C 2E 27 3E 20 43 6C 69 63 6B 20 48 65 72 65 20 74 6F 20 45 78 70 6C 6F 69 74 20 3C 2F 61 3E 20 3C 62 72 20 2F 3E 27 3B}
// 		$s10 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 20 3D 20 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 5C 22 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 5C 22 20 3B 20 3F 3E 5C 22 20 6D 65 74 68 6F 64 20 3D 20 5C 22 70 6F 73 74 5C 22 3E}
// 		$s11 = {24 73 71 6C 20 3D 20 5C 22 30 27 20 55 4E 49 4F 4E 20 53 45 4C 45 43 54 20 27 30 27 20 2C 20 27 3C 3F 20 73 79 73 74 65 6D 28 5C 5C 24 5F 47 45 54 5B 63 70 63 5D 29 3B 65 78 69 74 3B 20 3F 3E 27 20 2C 30 20 2C 30 20 2C 30 20 2C 30 20 49 4E}
// 		$s13 = {46 75 6C 6C 20 73 65 72 76 65 72 20 70 61 74 68 20 74 6F 20 61 20 77 72 69 74 61 62 6C 65 20 66 69 6C 65 20 77 68 69 63 68 20 77 69 6C 6C 20 63 6F 6E 74 61 69 6E 20 74 68 65 20 50 68 70 20 53 68 65 6C 6C 20 3C 62 72 20 2F 3E}
// 		$s14 = {24 65 78 70 75 72 6C 3D 20 24 75 72 6C 2E 5C 22 3F 69 64 3D 5C 22 2E 24 73 71 6C 20 3B}
// 		$s15 = {3C 68 65 61 64 65 72 3E 7C 7C 20 20 20 2E 3A 3A 4E 65 77 73 20 50 48 50 20 53 68 65 6C 6C 20 49 6E 6A 65 63 74 69 6F 6E 3A 3A 2E 20 20 20 7C 7C 3C 2F 68 65 61 64 65 72 3E 20 3C 62 72 20 2F 3E 20 3C 62 72 20 2F 3E}
// 		$s16 = {3C 69 6E 70 75 74 20 74 79 70 65 20 3D 20 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 20 3D 20 5C 22 43 72 65 61 74 65 20 45 78 70 6C 6F 69 74 5C 22 3E 20 3C 62 72 20 2F 3E 20 3C 62 72 20 2F 3E}

// 	condition:
// 		1 of them
// }

// rule WebShell_php_webshells_NGH
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file NGH.php"
// 		author = "Florian Roth"
// 		hash = "c05b5deecfc6de972aa4652cb66da89cfb3e1645"

// 	strings:
// 		$s0 = {3C 74 69 74 6C 65 3E 57 65 62 63 6F 6D 6D 61 6E 64 65 72 20 61 74 20 3C 3F 3D 24 5F 53 45 52 56 45 52 5B 5C 22 48 54 54 50 5F 48 4F 53 54 5C 22 5D 3F 3E 3C 2F 74 69 74 6C 65 3E}
// 		$s2 = {2F 2A 20 57 65 62 63 6F 6D 6D 61 6E 64 65 72 20 62 79 20 43 72 34 73 68 5F 61 6B 61 5F 52 4B 4C 20 76 30 2E 33 2E 39 20 4E 47 48 20 65 64 69 74 69 6F 6E 20 3A 70 20 2A 2F}
// 		$s5 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 62 69 6E 64 73 68 65 6C 6C 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
// 		$s9 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 62 61 63 6B 63 6F 6E 6E 65 63 74 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
// 		$s11 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 6D 6B 64 69 72 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
// 		$s16 = {64 69 65 28 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 44 46 30 30 30 30 3E 4C 6F 67 69 6E 20 65 72 72 6F 72 3C 2F 66 6F 6E 74 3E 5C 22 29 3B}
// 		$s20 = {3C 62 3E 42 69 6E 64 20 2F 62 69 6E 2F 62 61 73 68 20 61 74 20 70 6F 72 74 3A 20 3C 2F 62 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 6E 61 6D 65 3D 70 6F 72 74 20 73 69 7A 65 3D 38 3E}

// 	condition:
// 		2 of them
// }

// rule WebShell_php_webshells_matamu
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file matamu.php"
// 		author = "Florian Roth"
// 		hash = "d477aae6bd2f288b578dbf05c1c46b3aaa474733"

// 	strings:
// 		$s2 = {24 63 6F 6D 6D 61 6E 64 20 2E 3D 20 27 20 2D 46 27 3B}
// 		$s3 = {2F 2A 20 57 65 20 74 72 79 20 61 6E 64 20 6D 61 74 63 68 20 61 20 63 64 20 63 6F 6D 6D 61 6E 64 2E 20 2A 2F}
// 		$s4 = {64 69 72 65 63 74 6F 72 79 2E 2E 2E 20 54 72 75 73 74 20 6D 65 20 2D 20 69 74 20 77 6F 72 6B 73 20 3A 2D 29 20 2A 2F}
// 		$s5 = {24 63 6F 6D 6D 61 6E 64 20 2E 3D 20 5C 22 20 31 3E 20 24 74 6D 70 66 69 6C 65 20 32 3E 26 31 3B 20 5C 22 20 2E}
// 		$s10 = {24 6E 65 77 5F 64 69 72 20 3D 20 24 72 65 67 73 5B 31 5D 3B 20 2F 2F 20 27 63 64 20 2F 73 6F 6D 65 74 68 69 6E 67 2F 2E 2E 2E 27}
// 		$s16 = {2F 2A 20 54 68 65 20 6C 61 73 74 20 2F 20 69 6E 20 77 6F 72 6B 5F 64 69 72 20 77 65 72 65 20 74 68 65 20 66 69 72 73 74 20 63 68 61 72 65 63 74 65 72 2E}

// 	condition:
// 		2 of them
// }

// rule WebShell_ru24_post_sh
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file ru24_post_sh.php"
// 		author = "Florian Roth"
// 		hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"

// 	strings:
// 		$s1 = {68 74 74 70 3A 2F 2F 77 77 77 2E 72 75 32 34 2D 74 65 61 6D 2E 6E 65 74}
// 		$s4 = {69 66 20 28 28 21 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 20 7C 7C 20 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 3D 5C 22 5C 22 29 29 20 7B 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 5C 22 69 64 3B 70 77 64 3B 75 6E 61 6D 65 20 2D 61}
// 		$s6 = {52 75 32 34 50 6F 73 74 57 65 62 53 68 65 6C 6C}
// 		$s7 = {57 72 69 74 65 64 20 62 79 20 44 72 65 41 6D 65 52 7A}
// 		$s9 = {24 66 75 6E 63 74 69 6F 6E 3D 70 61 73 73 74 68 72 75 3B 20 2F 2F 20 73 79 73 74 65 6D 2C 20 65 78 65 63 2C 20 63 6D 64}

// 	condition:
// 		1 of them
// }

// rule WebShell_hiddens_shell_v1
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file hiddens shell v1.php"
// 		author = "Florian Roth"
// 		hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"

// 	strings:
// 		$s0 = {3C 3F 24 64 3D 27 47 37 6D 48 57 51 39 76 76 58 69 4C 2F 51 58 32 6F 5A 32 56 54 44 70 6F 36 67 33 46 59 41 61 36 58 2B 38 44 4D 49 7A 63 44 30 65 48 5A 61 42 5A 48 37 6A 46 70 5A 7A 55 7A 37 58 4E 65 6E 78 53 59 76 42 50 32 57 79 33 36 55}

// 	condition:
// 		all of them
// }

// rule WebShell_c99_madnet
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file c99_madnet.php"
// 		author = "Florian Roth"
// 		hash = "17613df393d0a99fd5bea18b2d4707f566cff219"

// 	strings:
// 		$s0 = {24 6D 64 35 5F 70 61 73 73 20 3D 20 5C 22 5C 22 3B 20 2F 2F 49 66 20 6E 6F 20 70 61 73 73 20 74 68 65 6E 20 68 61 73 68}
// 		$s1 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}
// 		$s2 = {24 70 61 73 73 20 3D 20 5C 22 70 61 73 73 5C 22 3B 20 20 2F 2F 50 61 73 73}
// 		$s3 = {24 6C 6F 67 69 6E 20 3D 20 5C 22 75 73 65 72 5C 22 3B 20 2F 2F 4C 6F 67 69 6E}
// 		$s4 = {20 20 20 20 20 20 20 20 20 20 20 20 20 2F 2F 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E}

// 	condition:
// 		all of them
// }

// rule WebShell_c99_locus7s
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file c99_locus7s.php"
// 		author = "Florian Roth"
// 		hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"

// 	strings:
// 		$s8 = {24 65 6E 63 6F 64 65 64 20 3D 20 62 61 73 65 36 34 5F 65 6E 63 6F 64 65 28 66 69 6C 65 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 24 64 2E 24 66 29 29 3B 20}
// 		$s9 = {24 66 69 6C 65 20 3D 20 24 74 6D 70 64 69 72 2E 5C 22 64 75 6D 70 5F 5C 22 2E 67 65 74 65 6E 76 28 5C 22 53 45 52 56 45 52 5F 4E 41 4D 45 5C 22 29 2E 5C 22 5F 5C 22 2E 24 64 62 2E 5C 22 5F 5C 22 2E 64 61 74 65 28 5C 22 64 2D 6D 2D 59}
// 		$s10 = {65 6C 73 65 20 7B 24 74 6D 70 20 3D 20 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 5C 22 2E 2F 64 75 6D 70 5F 5C 22 2E 67 65 74 65 6E 76 28 5C 22 53 45 52 56 45 52 5F 4E 41 4D 45 5C 22 29 2E 5C 22 5F 5C 22 2E 24 73 71}
// 		$s11 = {24 63 39 39 73 68 5F 73 6F 75 72 63 65 73 75 72 6C 20 3D 20 5C 22 68 74 74 70 3A 2F 2F 6C 6F 63 75 73 37 73 2E 63 6F 6D 2F 5C 22 3B 20 2F 2F 53 6F 75 72 63 65 73 2D 73 65 72 76 65 72 20}
// 		$s19 = {24 6E 69 78 70 77 64 70 65 72 70 61 67 65 20 3D 20 31 30 30 3B 20 2F 2F 20 47 65 74 20 66 69 72 73 74 20 4E 20 6C 69 6E 65 73 20 66 72 6F 6D 20 2F 65 74 63 2F 70 61 73 73 77 64 20}

// 	condition:
// 		2 of them
// }

// rule WebShell_JspWebshell_1_2
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
// 		author = "Florian Roth"
// 		hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"

// 	strings:
// 		$s0 = {53 79 73 74 65 6D 2E 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 43 72 65 61 74 65 41 6E 64 44 65 6C 65 74 65 46 6F 6C 64 65 72 20 69 73 20 65 72 72 6F 72 3A 5C 22 2B 65 78 29 3B 20}
// 		$s1 = {53 74 72 69 6E 67 20 70 61 73 73 77 6F 72 64 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 3B}
// 		$s3 = {3C 25 40 20 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 47 42 4B 5C 22 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E}
// 		$s7 = {53 74 72 69 6E 67 20 65 64 69 74 66 69 6C 65 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 65 64 69 74 66 69 6C 65 5C 22 29 3B}
// 		$s8 = {2F 2F 53 74 72 69 6E 67 20 74 65 6D 70 66 69 6C 65 6E 61 6D 65 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 69 6C 65 5C 22 29 3B}
// 		$s12 = {70 61 73 73 77 6F 72 64 20 3D 20 28 53 74 72 69 6E 67 29 73 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 3B}

// 	condition:
// 		3 of them
// }

// rule WebShell_safe0ver
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file safe0ver.php"
// 		author = "Florian Roth"
// 		hash = "366639526d92bd38ff7218b8539ac0f154190eb8"

// 	strings:
// 		$s3 = {24 73 63 72 69 70 74 69 64 65 6E 74 20 3D 20 5C 22 24 73 63 72 69 70 74 54 69 74 6C 65 20 42 79 20 45 76 69 6C 63 30 64 65 72 2E 63 6F 6D 5C 22 3B}
// 		$s4 = {77 68 69 6C 65 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 5C 22 24 6C 61 73 74 64 69 72 2F 6E 65 77 66 69 6C 65 24 69 2E 74 78 74 5C 22 29 29}
// 		$s5 = {65 6C 73 65 20 7B 20 2F 2A 20 3C 21 2D 2D 20 54 68 65 6E 20 69 74 20 6D 75 73 74 20 62 65 20 61 20 46 69 6C 65 2E 2E 2E 20 2D 2D 3E 20 2A 2F}
// 		$s7 = {24 63 6F 6E 74 65 6E 74 73 20 2E 3D 20 68 74 6D 6C 65 6E 74 69 74 69 65 73 28 20 24 6C 69 6E 65 20 29 20 3B}
// 		$s8 = {3C 62 72 3E 3C 70 3E 3C 62 72 3E 53 61 66 65 20 4D 6F 64 65 20 42 79 50 41 73 73 3C 70 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 3E}
// 		$s14 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 29 20 7B 20 2F 2A 20 3C 21 2D 2D 20 55 70 6C 6F 61 64 20 46 69 6C 65 20 66 6F 72 6D 20 2D 2D 3E 20 2A 2F 20}
// 		$s20 = {2F 2A 20 3C 21 2D 2D 20 45 6E 64 20 6F 66 20 41 63 74 69 6F 6E 73 20 2D 2D 3E 20 2A 2F}

// 	condition:
// 		3 of them
// }

// rule WebShell_Uploader
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Uploader.php"
// 		author = "Florian Roth"
// 		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"

// 	strings:
// 		$s1 = {6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 2C 20 5C 22 65 6E 74 72 69 6B 61 2E 70 68 70 5C 22 29 3B 20}

// 	condition:
// 		all of them
// }

// rule WebShell_php_webshells_kral
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file kral.php"
// 		author = "Florian Roth"
// 		hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"

// 	strings:
// 		$s1 = {24 61 64 72 65 73 3D 67 65 74 68 6F 73 74 62 79 6E 61 6D 65 28 24 69 70 29 3B}
// 		$s3 = {63 75 72 6C 5F 73 65 74 6F 70 74 28 24 63 68 2C 43 55 52 4C 4F 50 54 5F 50 4F 53 54 46 49 45 4C 44 53 2C 5C 22 64 6F 6D 61 69 6E 3D 5C 22 2E 24 73 69 74 65 29 3B}
// 		$s4 = {24 65 6B 6C 65 3D 5C 22 2F 69 6E 64 65 78 2E 70 68 70 3F 6F 70 74 69 6F 6E 3D 63 6F 6D 5F 75 73 65 72 26 76 69 65 77 3D 72 65 73 65 74 26 6C 61 79 6F 75 74 3D 63 6F 6E 66 69 72 6D 5C 22 3B}
// 		$s16 = {65 63 68 6F 20 24 73 6F 6E 2E 27 20 3C 62 72 3E 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 67 72 65 65 6E 5C 22 3E 41 63 63 65 73 73 3C 2F 66 6F 6E 74 3E 3C 62 72 3E 27 3B}
// 		$s17 = {3C 70 3E 6B 6F 64 6C 61 6D 61 20 62 79 20 3C 61 20 68 72 65 66 3D 5C 22 6D 61 69 6C 74 6F 3A 70 72 69 76 38 63 6F 64 65 72 40 67 6D 61 69 6C 2E 63 6F 6D 5C 22 3E 42 4C 61 53 54 45 52 3C 2F 61 3E 3C 62 72 20 2F}
// 		$s20 = {3C 70 3E 3C 73 74 72 6F 6E 67 3E 53 65 72 76 65 72 20 6C 69 73 74 65 6C 65 79 69 63 69 3C 2F 73 74 72 6F 6E 67 3E 3C 62 72 20 2F 3E}

// 	condition:
// 		2 of them
// }

// rule WebShell_cgitelnet
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file cgitelnet.php"
// 		author = "Florian Roth"
// 		hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"

// 	strings:
// 		$s9 = {23 20 41 75 74 68 6F 72 20 48 6F 6D 65 70 61 67 65 3A 20 68 74 74 70 3A 2F 2F 77 77 77 2E 72 6F 68 69 74 61 62 2E 63 6F 6D 2F}
// 		$s10 = {65 6C 73 69 66 28 24 41 63 74 69 6F 6E 20 65 71 20 5C 22 63 6F 6D 6D 61 6E 64 5C 22 29 20 23 20 75 73 65 72 20 77 61 6E 74 73 20 74 6F 20 72 75 6E 20 61 20 63 6F 6D 6D 61 6E 64}
// 		$s18 = {23 20 69 6E 20 61 20 63 6F 6D 6D 61 6E 64 20 6C 69 6E 65 20 6F 6E 20 57 69 6E 64 6F 77 73 20 4E 54 2E}
// 		$s20 = {70 72 69 6E 74 20 5C 22 54 72 61 6E 73 66 65 72 65 64 20 24 54 61 72 67 65 74 46 69 6C 65 53 69 7A 65 20 42 79 74 65 73 2E 3C 62 72 3E 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_simple_backdoor
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file simple-backdoor.php"
// 		author = "Florian Roth"
// 		hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"

// 	strings:
// 		$s0 = {3C 21 2D 2D 20 53 69 6D 70 6C 65 20 50 48 50 20 62 61 63 6B 64 6F 6F 72 20 62 79 20 44 4B 20 28 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 29 20 2D 2D 3E}
// 		$s1 = {3C 21 2D 2D 20 20 20 20 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 20 20 20 32 30 30 36 20 20 20 20 2D 2D 3E}
// 		$s2 = {55 73 61 67 65 3A 20 68 74 74 70 3A 2F 2F 74 61 72 67 65 74 2E 63 6F 6D 2F 73 69 6D 70 6C 65 2D 62 61 63 6B 64 6F 6F 72 2E 70 68 70 3F 63 6D 64 3D 63 61 74 2B 2F 65 74 63 2F 70 61 73 73 77 64}
// 		$s3 = {20 20 20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 2F 70 72 65 3E 5C 22 3B}
// 		$s4 = {20 20 20 20 20 20 20 20 24 63 6D 64 20 3D 20 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 3B}
// 		$s5 = {20 20 20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 70 72 65 3E 5C 22 3B}
// 		$s6 = {69 66 28 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
// 		$s7 = {20 20 20 20 20 20 20 20 64 69 65 3B}
// 		$s8 = {20 20 20 20 20 20 20 20 73 79 73 74 65 6D 28 24 63 6D 64 29 3B}

// 	condition:
// 		all of them
// }

// rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
// 		author = "Florian Roth"
// 		hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"

// 	strings:
// 		$s1 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 47 65 74 20 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}
// 		$s3 = {78 62 35 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3C 2F 46 4F 4E 54 3E 3C 2F 43 45 4E 54 45 52 3E 3C 2F 42 3E 5C 22 29 3B}
// 		$s4 = {24 76 20 3D 20 40 69 6E 69 5F 67 65 74 28 5C 22 6F 70 65 6E 5F 62 61 73 65 64 69 72 5C 22 29 3B}
// 		$s6 = {62 79 20 50 48 50 20 45 6D 70 65 72 6F 72 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3E}

// 	condition:
// 		2 of them
// }

// rule WebShell_NTDaddy_v1_9
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
// 		author = "Florian Roth"
// 		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"

// 	strings:
// 		$s2 = {7C 20 20 20 20 20 2D 6F 62 7A 65 72 76 65 20 3A 20 6D 72 5F 6F 40 69 68 61 74 65 63 6C 6F 77 6E 73 2E 63 6F 6D 20 7C}
// 		$s6 = {73 7A 54 65 6D 70 46 69 6C 65 20 3D 20 5C 22 43 3A 5C 5C 5C 22 20 26 20 6F 46 69 6C 65 53 79 73 2E 47 65 74 54 65 6D 70 4E 61 6D 65 28 20 29}
// 		$s13 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 6E 74 64 61 64 64 79 2E 61 73 70 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E}
// 		$s17 = {72 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 28 5C 22 3C 45 52 52 4F 52 3A 20 54 48 49 53 20 49 53 20 4E 4F 54 20 41 20 54 45 58 54 20 46 49 4C 45 3E 5C 22 29}

// 	condition:
// 		2 of them
// }

// rule WebShell_lamashell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file lamashell.php"
// 		author = "Florian Roth"
// 		hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"

// 	strings:
// 		$s0 = {69 66 28 28 24 5F 50 4F 53 54 5B 27 65 78 65 27 5D 29 20 3D 3D 20 5C 22 45 78 65 63 75 74 65 5C 22 29 20 7B}
// 		$s8 = {24 63 75 72 63 6D 64 20 3D 20 24 5F 50 4F 53 54 5B 27 6B 69 6E 67 27 5D 3B}
// 		$s16 = {5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 77 33 2E 6F 72 67 2F 54 52 2F 68 74 6D 6C 34 2F 6C 6F 6F 73 65 2E 64 74 64 5C 22 3E}
// 		$s18 = {3C 74 69 74 6C 65 3E 6C 61 6D 61 27 73 27 68 65 6C 6C 20 76 2E 20 33 2E 30 3C 2F 74 69 74 6C 65 3E}
// 		$s19 = {5F 7C 5F 20 20 4F 20 20 20 20 5F 20 20 20 20 4F 20 20 5F 7C 5F}
// 		$s20 = {24 63 75 72 63 6D 64 20 3D 20 5C 22 6C 73 20 2D 6C 61 68 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_Simple_PHP_backdoor_by_DK
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
// 		author = "Florian Roth"
// 		hash = "03f6215548ed370bec0332199be7c4f68105274e"
// 		score = 70

// 	strings:
// 		$s0 = {3C 21 2D 2D 20 53 69 6D 70 6C 65 20 50 48 50 20 62 61 63 6B 64 6F 6F 72 20 62 79 20 44 4B 20 28 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 29 20 2D 2D 3E}
// 		$s1 = {3C 21 2D 2D 20 20 20 20 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 20 20 20 32 30 30 36 20 20 20 20 2D 2D 3E}
// 		$s2 = {55 73 61 67 65 3A 20 68 74 74 70 3A 2F 2F 74 61 72 67 65 74 2E 63 6F 6D 2F 73 69 6D 70 6C 65 2D 62 61 63 6B 64 6F 6F 72 2E 70 68 70 3F 63 6D 64 3D 63 61 74 2B 2F 65 74 63 2F 70 61 73 73 77 64}
// 		$s6 = {69 66 28 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
// 		$s8 = {73 79 73 74 65 6D 28 24 63 6D 64 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
// 		author = "Florian Roth"
// 		hash = "31e5473920a2cc445d246bc5820037d8fe383201"

// 	strings:
// 		$s4 = {24 63 6F 6E 74 65 6E 74 20 3D 20 63 68 75 6E 6B 5F 73 70 6C 69 74 28 62 61 73 65 36 34 5F 65 6E 63 6F 64 65 28 24 63 6F 6E 74 65 6E 74 29 29 3B 20}
// 		$s12 = {70 72 69 6E 74 20 5C 22 53 65 6E 64 69 6E 67 20 6D 61 69 6C 20 74 6F 20 24 74 6F 2E 2E 2E 2E 2E 2E 2E 20 5C 22 3B 20}
// 		$s16 = {69 66 20 28 21 24 66 72 6F 6D 20 26 26 20 21 24 73 75 62 6A 65 63 74 20 26 26 20 21 24 6D 65 73 73 61 67 65 20 26 26 20 21 24 65 6D 61 69 6C 6C 69 73 74 29 7B 20}

// 	condition:
// 		all of them
// }

// rule WebShell_C99madShell_v__2_0_madnet_edition
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
// 		author = "Florian Roth"
// 		hash = "f99f8228eb12746847f54bad45084f19d1a7e111"

// 	strings:
// 		$s0 = {24 6D 64 35 5F 70 61 73 73 20 3D 20 5C 22 5C 22 3B 20 2F 2F 49 66 20 6E 6F 20 70 61 73 73 20 74 68 65 6E 20 68 61 73 68}
// 		$s1 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}
// 		$s2 = {24 70 61 73 73 20 3D 20 5C 22 5C 22 3B 20 20 2F 2F 50 61 73 73}
// 		$s3 = {24 6C 6F 67 69 6E 20 3D 20 5C 22 5C 22 3B 20 2F 2F 4C 6F 67 69 6E}
// 		$s4 = {2F 2F 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E}

// 	condition:
// 		all of them
// }

// rule WebShell_CmdAsp_asp_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
// 		author = "Florian Roth"
// 		hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"

// 	strings:
// 		$s1 = {73 7A 54 65 6D 70 46 69 6C 65 20 3D 20 5C 22 43 3A 5C 5C 5C 22 20 26 20 6F 46 69 6C 65 53 79 73 2E 47 65 74 54 65 6D 70 4E 61 6D 65 28 20 29}
// 		$s4 = {27 20 41 75 74 68 6F 72 3A 20 4D 61 63 65 6F 20 3C 6D 61 63 65 6F 20 40 20 64 6F 67 6D 69 6C 65 2E 63 6F 6D 3E}
// 		$s5 = {27 20 2D 2D 20 55 73 65 20 61 20 70 6F 6F 72 20 6D 61 6E 27 73 20 70 69 70 65 20 2E 2E 2E 20 61 20 74 65 6D 70 20 66 69 6C 65 20 2D 2D 20 27}
// 		$s6 = {27 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 6F 30 6F 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D}
// 		$s8 = {27 20 46 69 6C 65 3A 20 43 6D 64 41 73 70 2E 61 73 70}
// 		$s11 = {3C 2D 2D 20 43 6D 64 41 73 70 2E 61 73 70 20 2D 2D 3E}
// 		$s14 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}
// 		$s16 = {53 65 74 20 6F 53 63 72 69 70 74 4E 65 74 20 3D 20 53 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 57 53 43 52 49 50 54 2E 4E 45 54 57 4F 52 4B 5C 22 29}
// 		$s19 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}

// 	condition:
// 		4 of them
// }

// rule WebShell_NCC_Shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file NCC-Shell.php"
// 		author = "Florian Roth"
// 		hash = "64d4495875a809b2730bd93bec2e33902ea80a53"

// 	strings:
// 		$s0 = {20 69 66 20 28 69 73 73 65 74 28 24 5F 46 49 4C 45 53 5B 27 70 72 6F 62 65 27 5D 29 20 61 6E 64 20 21 20 24 5F 46 49 4C 45 53 5B 27 70 72 6F 62 65 27 5D 5B 27 65 72 72 6F 72 27 5D 29 20 7B}
// 		$s1 = {3C 62 3E 2D 2D 43 6F 64 65 64 20 62 79 20 53 69 6C 76 65 72}
// 		$s2 = {3C 74 69 74 6C 65 3E 55 70 6C 6F 61 64 20 2D 20 53 68 65 6C 6C 2F 44 61 74 65 69 3C 2F 74 69 74 6C 65 3E}
// 		$s8 = {3C 61 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 6E 2D 63 2D 63 2E 36 78 2E 74 6F 5C 22 20 74 61 72 67 65 74 3D 5C 22 5F 62 6C 61 6E 6B 5C 22 3E 2D 2D 3E 4E 43 43 3C 2D 2D 3C 2F 61 3E 3C 2F 63 65 6E 74 65 72 3E 3C 2F 62 3E 3C}
// 		$s14 = {7E 7C 5F 54 65 61 6D 20 2E 3A 4E 61 74 69 6F 6E 61 6C 20 43 72 61 63 6B 65 72 20 43 72 65 77 3A 2E 5F 7C 7E 3C 62 72 3E}
// 		$s18 = {70 72 69 6E 74 66 28 5C 22 53 69 65 20 69 73 74 20 25 75 20 42 79 74 65 73 20 67 72 6F}

// 	condition:
// 		3 of them
// }

// rule WebShell_php_webshells_README
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file README.md"
// 		author = "Florian Roth"
// 		hash = "ef2c567b4782c994db48de0168deb29c812f7204"

// 	strings:
// 		$s0 = {43 6F 6D 6D 6F 6E 20 70 68 70 20 77 65 62 73 68 65 6C 6C 73 2E 20 44 6F 20 6E 6F 74 20 68 6F 73 74 20 74 68 65 20 66 69 6C 65 28 73 29 20 69 6E 20 79 6F 75 72 20 73 65 72 76 65 72 21}
// 		$s1 = {70 68 70 2D 77 65 62 73 68 65 6C 6C 73}

// 	condition:
// 		all of them
// }

// rule WebShell_backupsql
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file backupsql.php"
// 		author = "Florian Roth"
// 		hash = "863e017545ec8e16a0df5f420f2d708631020dd4"

// 	strings:
// 		$s0 = {24 68 65 61 64 65 72 73 20 2E 3D 20 5C 22 5C 5C 6E 4D 49 4D 45 2D 56 65 72 73 69 6F 6E 3A 20 31 2E 30 5C 5C 6E 5C 22 20 2E 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 6D 75 6C 74 69 70 61 72 74 2F 6D 69 78 65 64 3B 5C 5C 6E 5C 22 20 2E}
// 		$s1 = {24 66 74 70 63 6F 6E 6E 65 63 74 20 3D 20 5C 22 6E 63 66 74 70 70 75 74 20 2D 75 20 24 66 74 70 5F 75 73 65 72 5F 6E 61 6D 65 20 2D 70 20 24 66 74 70 5F 75 73 65 72 5F 70 61 73 73 20 2D 64 20 64 65 62 73 65 6E 64 65 72 5F 66 74 70 6C 6F 67}
// 		$s2 = {2A 20 61 73 20 65 6D 61 69 6C 20 61 74 74 61 63 68 6D 65 6E 74 2C 20 6F 72 20 73 65 6E 64 20 74 6F 20 61 20 72 65 6D 6F 74 65 20 66 74 70 20 73 65 72 76 65 72 20 62 79}
// 		$s16 = {2A 20 4E 65 61 67 75 20 4D 69 68 61 69 3C 6E 65 61 67 75 6D 69 68 61 69 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3E}
// 		$s17 = {24 66 72 6F 6D 20 20 20 20 3D 20 5C 22 4E 65 75 2D 43 6F 6F 6C 40 65 6D 61 69 6C 2E 63 6F 6D 5C 22 3B 20 20 2F 2F 20 57 68 6F 20 73 68 6F 75 6C 64 20 74 68 65 20 65 6D 61 69 6C 73 20 62 65 20 73 65 6E 74 20 66 72 6F 6D 3F 2C 20 6D 61 79 20}

// 	condition:
// 		2 of them
// }

// rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
// 		author = "Florian Roth"
// 		hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"

// 	strings:
// 		$s8 = {2D 20 41 4B 2D 37 34 20 53 65 63 75 72 69 74 79 20 54 65 61 6D 20 57 65 62 20 53 69 74 65 3A 20 77 77 77 2E 61 6B 37 34 2D 74 65 61 6D 2E 6E 65 74}
// 		$s9 = {3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 38 33 30 30 30 30 3E 38 2E 20 58 20 46 6F 72 77 61 72 64 65 64 20 46 6F 72 20 49 50 20 2D 20 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 38 33 30 30 30 30 3E 27 2E}
// 		$s10 = {3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 38 33 30 30 30 3E 45 78 65 63 75 74 65 20 73 79 73 74 65 6D 20 63 6F 6D 6D 61 6E 64 73 21 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E}

// 	condition:
// 		1 of them
// }

// rule WebShell_php_webshells_cpanel
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file cpanel.php"
// 		author = "Florian Roth"
// 		hash = "433dab17106b175c7cf73f4f094e835d453c0874"

// 	strings:
// 		$s0 = {66 75 6E 63 74 69 6F 6E 20 66 74 70 5F 63 68 65 63 6B 28 24 68 6F 73 74 2C 24 75 73 65 72 2C 24 70 61 73 73 2C 24 74 69 6D 65 6F 75 74 29 7B}
// 		$s3 = {63 75 72 6C 5F 73 65 74 6F 70 74 28 24 63 68 2C 20 43 55 52 4C 4F 50 54 5F 55 52 4C 2C 20 5C 22 68 74 74 70 3A 2F 2F 24 68 6F 73 74 3A 32 30 38 32 5C 22 29 3B}
// 		$s4 = {5B 20 75 73 65 72 40 61 6C 74 75 72 6B 73 2E 63 6F 6D 20 5D 23 20 69 6E 66 6F 3C 62 3E 3C 62 72 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 74 61 68 6F 6D 61 3E 3C 62 72 3E}
// 		$s12 = {63 75 72 6C 5F 73 65 74 6F 70 74 28 24 63 68 2C 20 43 55 52 4C 4F 50 54 5F 46 54 50 4C 49 53 54 4F 4E 4C 59 2C 20 31 29 3B}
// 		$s13 = {50 6F 77 65 72 66 75 6C 20 74 6F 6F 6C 20 2C 20 66 74 70 20 61 6E 64 20 63 50 61 6E 65 6C 20 62 72 75 74 65 20 66 6F 72 63 65 72 20 2C 20 70 68 70 20 35 2E 32 2E 39 20 73 61 66 65 5F 6D 6F 64 65 20 26 20 6F 70 65 6E 5F 62 61 73 65 64 69 72}
// 		$s20 = {3C 62 72 3E 3C 62 3E 50 6C 65 61 73 65 20 65 6E 74 65 72 20 79 6F 75 72 20 55 53 45 52 4E 41 4D 45 20 61 6E 64 20 50 41 53 53 57 4F 52 44 20 74 6F 20 6C 6F 67 6F 6E 3C 62 72 3E}

// 	condition:
// 		2 of them
// }

// rule WebShell_accept_language
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file accept_language.php"
// 		author = "Florian Roth"
// 		hash = "180b13576f8a5407ab3325671b63750adbcb62c9"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 70 61 73 73 74 68 72 75 28 67 65 74 65 6E 76 28 5C 22 48 54 54 50 5F 41 43 43 45 50 54 5F 4C 41 4E 47 55 41 47 45 5C 22 29 29 3B 20 65 63 68 6F 20 27 3C 62 72 3E 20 62 79 20 71 31 77 32 65 33 72 34 27 3B 20 3F 3E}

// 	condition:
// 		all of them
// }

// rule WebShell_php_webshells_529
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file 529.php"
// 		author = "Florian Roth"
// 		hash = "ba3fb2995528307487dff7d5b624d9f4c94c75d3"

// 	strings:
// 		$s0 = {3C 70 3E 4D 6F 72 65 3A 20 3C 61 20 68 72 65 66 3D 5C 22 2F 5C 22 3E 4D 64 35 43 72 61 63 6B 69 6E 67 2E 43 6F 6D 20 43 72 65 77 3C 2F 61 3E 20}
// 		$s7 = {68 72 65 66 3D 5C 22 2F 5C 22 20 74 69 74 6C 65 3D 5C 22 53 65 63 75 72 69 74 79 68 6F 75 73 65 5C 22 3E 53 65 63 75 72 69 74 79 20 48 6F 75 73 65 20 2D 20 53 68 65 6C 6C 20 43 65 6E 74 65 72 20 2D 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E}
// 		$s9 = {65 63 68 6F 20 27 3C 50 52 45 3E 3C 50 3E 54 68 69 73 20 69 73 20 65 78 70 6C 6F 69 74 20 66 72 6F 6D 20 3C 61 20}
// 		$s10 = {54 68 69 73 20 45 78 70 6C 6F 69 74 20 57 61 73 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72}
// 		$s13 = {73 61 66 65 5F 6D 6F 64 65 20 61 6E 64 20 6F 70 65 6E 5F 62 61 73 65 64 69 72 20 42 79 70 61 73 73 20 50 48 50 20 35 2E 32 2E 39 20}
// 		$s14 = {24 68 61 72 64 73 74 79 6C 65 20 3D 20 65 78 70 6C 6F 64 65 28 5C 22 2F 5C 22 2C 20 24 66 69 6C 65 29 3B 20}
// 		$s20 = {77 68 69 6C 65 28 24 6C 65 76 65 6C 2D 2D 29 20 63 68 64 69 72 28 5C 22 2E 2E 5C 22 29 3B 20}

// 	condition:
// 		2 of them
// }

// rule WebShell_STNC_WebShell_v0_8
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
// 		author = "Florian Roth"
// 		hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"

// 	strings:
// 		$s3 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 5C 22 61 63 74 69 6F 6E 5C 22 5D 29 29 20 24 61 63 74 69 6F 6E 20 3D 20 24 5F 50 4F 53 54 5B 5C 22 61 63 74 69 6F 6E 5C 22 5D 3B}
// 		$s8 = {65 6C 73 65 69 66 28 66 65 28 5C 22 73 79 73 74 65 6D 5C 22 29 29 7B 6F 62 5F 73 74 61 72 74 28 29 3B 73 79 73 74 65 6D 28 24 73 29 3B 24 72 3D 6F 62 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 29 3B 6F 62 5F 65 6E 64 5F 63 6C 65 61 6E 28 29}
// 		$s13 = {7B 20 24 70 77 64 20 3D 20 24 5F 50 4F 53 54 5B 5C 22 70 77 64 5C 22 5D 3B 20 24 74 79 70 65 20 3D 20 66 69 6C 65 74 79 70 65 28 24 70 77 64 29 3B 20 69 66 28 24 74 79 70 65 20 3D 3D 3D 20 5C 22 64 69 72 5C 22 29 63 68 64 69 72 28 24 70 77}

// 	condition:
// 		2 of them
// }

// rule WebShell_php_webshells_tryag
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file tryag.php"
// 		author = "Florian Roth"
// 		hash = "42d837e9ab764e95ed11b8bd6c29699d13fe4c41"

// 	strings:
// 		$s1 = {3C 74 69 74 6C 65 3E 54 72 59 61 47 20 54 65 61 6D 20 2D 20 54 72 59 61 47 2E 70 68 70 20 2D 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 3C 2F 74 69 74 6C 65 3E}
// 		$s3 = {24 74 61 62 6C 65 64 75 6D 70 20 3D 20 5C 22 44 52 4F 50 20 54 41 42 4C 45 20 49 46 20 45 58 49 53 54 53 20 24 74 61 62 6C 65 3B 5C 5C 6E 5C 22 3B 20}
// 		$s6 = {24 73 74 72 69 6E 67 20 3D 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 73 74 72 69 6E 67 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 73 74 72 69 6E 67 27 5D 20 3A 20 30 3B 20}
// 		$s7 = {24 74 61 62 6C 65 64 75 6D 70 20 2E 3D 20 5C 22 43 52 45 41 54 45 20 54 41 42 4C 45 20 24 74 61 62 6C 65 20 28 5C 5C 6E 5C 22 3B 20}
// 		$s14 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 64 69 76 20 69 64 3D 6C 6F 67 6F 73 74 72 69 70 3E 45 64 69 74 20 66 69 6C 65 3A 20 24 65 64 69 74 66 69 6C 65 20 3C 2F 64 69 76 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 27 24 52 45 51 55 45}

// 	condition:
// 		3 of them
// }

// rule WebShell_dC3_Security_Crew_Shell_PRiV_2
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
// 		author = "Florian Roth"
// 		hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"

// 	strings:
// 		$s0 = {40 72 6D 64 69 72 28 24 5F 47 45 54 5B 27 66 69 6C 65 27 5D 29 20 6F 72 20 64 69 65 20 28 5C 22 5B 2D 5D 45 72 72 6F 72 20 64 65 6C 65 74 69 6E 67 20 64 69 72 21 5C 22 29 3B}
// 		$s9 = {68 65 61 64 65 72 28 5C 22 4C 61 73 74 2D 4D 6F 64 69 66 69 65 64 3A 20 5C 22 2E 64 61 74 65 28 5C 22 72 5C 22 2C 66 69 6C 65 6D 74 69 6D 65 28 5F 5F 46 49 4C 45 5F 5F 29 29 29 3B}
// 		$s13 = {68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 74 79 70 65 3A 20 69 6D 61 67 65 2F 67 69 66 5C 22 29 3B}
// 		$s14 = {40 63 6F 70 79 28 24 66 69 6C 65 2C 24 74 6F 29 20 6F 72 20 64 69 65 20 28 5C 22 5B 2D 5D 45 72 72 6F 72 20 63 6F 70 79 69 6E 67 20 66 69 6C 65 21 5C 22 29 3B}
// 		$s20 = {69 66 20 28 69 73 73 65 74 28 24 5F 47 45 54 5B 27 72 65 6E 61 6D 65 5F 61 6C 6C 27 5D 29 29 20 7B}

// 	condition:
// 		3 of them
// }

// rule WebShell_qsd_php_backdoor
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
// 		author = "Florian Roth"
// 		hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"

// 	strings:
// 		$s1 = {2F 2F 20 41 20 72 6F 62 75 73 74 20 62 61 63 6B 64 6F 6F 72 20 73 63 72 69 70 74 20 6D 61 64 65 20 62 79 20 44 61 6E 69 65 6C 20 42 65 72 6C 69 6E 65 72 20 2D 20 68 74 74 70 3A 2F 2F 77 77 77 2E 71 73 64 63 6F 6E 73 75 6C 74 69 6E 67 2E 63}
// 		$s2 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 5C 22 6E 65 77 63 6F 6E 74 65 6E 74 5C 22 5D 29 29}
// 		$s3 = {66 6F 72 65 61 63 68 28 24 70 61 72 74 73 20 61 73 20 24 76 61 6C 29 2F 2F 41 73 73 65 6D 62 6C 65 20 74 68 65 20 70 61 74 68 20 62 61 63 6B 20 74 6F 67 65 74 68 65 72}
// 		$s7 = {24 5F 50 4F 53 54 5B 5C 22 6E 65 77 63 6F 6E 74 65 6E 74 5C 22 5D 3D 75 72 6C 64 65 63 6F 64 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 5F 50 4F 53 54 5B 5C 22 6E 65 77 63 6F 6E 74 65 6E 74 5C 22 5D 29 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_php_webshells_spygrup
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file spygrup.php"
// 		author = "Florian Roth"
// 		hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"

// 	strings:
// 		$s2 = {6B 69 6E 67 64 65 66 61 63 65 72 40 6D 73 6E 2E 63 6F 6D 3C 2F 46 4F 4E 54 3E 3C 2F 43 45 4E 54 45 52 3E 3C 2F 42 3E 5C 22 29 3B}
// 		$s6 = {69 66 28 24 5F 50 4F 53 54 5B 27 72 6F 6F 74 27 5D 29 20 24 72 6F 6F 74 20 3D 20 24 5F 50 4F 53 54 5B 27 72 6F 6F 74 27 5D 3B}
// 		$s12 = {5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 66 69 6C 65 29 2E 5C 22 20 42 75 20 44 6F 73 79 61 20 7A 61 74 65 6E 20 47 6F 72 75 6E 74 75 6C 65 6E 69 79 6F 72 3C 6B 69 6E 67 64 65 66 61 63 65 72 40 6D 73 6E 2E 63 6F 6D 3E}
// 		$s18 = {42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 20 46 72 6F 6D 20 53 70 79 67 72 75 70 2E 6F 72 67 3E}

// 	condition:
// 		3 of them
// }

// rule WebShell_Web_shell__c_ShAnKaR
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
// 		author = "Florian Roth"
// 		hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"

// 	strings:
// 		$s0 = {68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 5C 22 2E 66 69 6C 65 73 69 7A 65 28 24 5F 50 4F 53 54 5B 27 64 6F 77 6E 66 27 5D 29 29 3B}
// 		$s5 = {69 66 28 24 5F 50 4F 53 54 5B 27 73 61 76 65 27 5D 3D 3D 30 29 7B 65 63 68 6F 20 5C 22 3C 74 65 78 74 61 72 65 61 20 63 6F 6C 73 3D 37 30 20 72 6F 77 73 3D 31 30 3E 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 64 75 6D 70}
// 		$s6 = {77 72 69 74 65 28 5C 22 23 5C 5C 6E 23 53 65 72 76 65 72 20 3A 20 5C 22 2E 67 65 74 65 6E 76 28 27 53 45 52 56 45 52 5F 4E 41 4D 45 27 29 2E 5C 22}
// 		$s12 = {66 6F 72 65 61 63 68 28 40 66 69 6C 65 28 24 5F 50 4F 53 54 5B 27 70 61 73 73 77 64 27 5D 29 20 61 73 20 24 66 65 64 29 65 63 68 6F 20 24 66 65 64 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
// 		author = "Florian Roth"
// 		hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"

// 	strings:
// 		$s7 = {3C 6D 65 74 61 20 6E 61 6D 65 3D 5C 22 43 6F 70 79 72 69 67 68 74 5C 22 20 63 6F 6E 74 65 6E 74 3D 54 6F 75 43 68 20 42 79 20 69 4A 4F 6F 5C 22 3E}
// 		$s11 = {64 69 72 65 63 74 6F 72 79 2E 2E 2E 20 54 72 75 73 74 20 6D 65 20 2D 20 69 74 20 77 6F 72 6B 73 20 3A 2D 29 20 2A 2F}
// 		$s15 = {2F 2A 20 6C 73 20 6C 6F 6F 6B 73 20 6D 75 63 68 20 62 65 74 74 65 72 20 77 69 74 68 20 27 20 2D 46 27 2C 20 49 4D 48 4F 2E 20 2A 2F}
// 		$s16 = {7D 20 65 6C 73 65 20 69 66 20 28 24 63 6F 6D 6D 61 6E 64 20 3D 3D 20 27 6C 73 27 29 20 7B}

// 	condition:
// 		3 of them
// }

// rule WebShell_Gamma_Web_Shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
// 		author = "Florian Roth"
// 		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"

// 	strings:
// 		$s4 = {24 6F 6B 5F 63 6F 6D 6D 61 6E 64 73 20 3D 20 5B 27 6C 73 27 2C 20 27 6C 73 20 2D 6C 27 2C 20 27 70 77 64 27 2C 20 27 75 70 74 69 6D 65 27 5D 3B}
// 		$s8 = {23 23 23 20 47 61 6D 6D 61 20 47 72 6F 75 70 20 3C 68 74 74 70 3A 2F 2F 77 77 77 2E 67 61 6D 6D 61 63 65 6E 74 65 72 2E 63 6F 6D 3E}
// 		$s15 = {6D 79 20 24 65 72 72 6F 72 20 3D 20 5C 22 54 68 69 73 20 63 6F 6D 6D 61 6E 64 20 69 73 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65 20 69 6E 20 74 68 65 20 72 65 73 74 72 69 63 74 65 64 20 6D 6F 64 65 2E 5C 5C 6E 5C 22 3B}
// 		$s20 = {6D 79 20 24 63 6F 6D 6D 61 6E 64 20 3D 20 24 73 65 6C 66 2D 3E 71 75 65 72 79 28 27 63 6F 6D 6D 61 6E 64 27 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_php_webshells_aspydrv
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file aspydrv.php"
// 		author = "Florian Roth"
// 		hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"

// 	strings:
// 		$s0 = {54 61 72 67 65 74 20 3D 20 5C 22 44 3A 5C 5C 68 73 68 6F 6D 65 5C 5C 6D 61 73 74 65 72 68 72 5C 5C 6D 61 73 74 65 72 68 72 2E 63 6F 6D 5C 5C 5C 22 20 20 27 20 2D 2D 2D 44 69 72 65 63 74 6F 72 79 20 74 6F 20 77 68 69 63 68 20 66 69 6C 65 73}
// 		$s1 = {6E 50 6F 73 20 3D 20 49 6E 73 74 72 42 28 6E 50 6F 73 45 6E 64 2C 20 62 69 44 61 74 61 2C 20 43 42 79 74 65 53 74 72 69 6E 67 28 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 5C 22 29 29}
// 		$s3 = {44 6F 63 75 6D 65 6E 74 2E 66 72 6D 53 51 4C 2E 6D 50 61 67 65 2E 76 61 6C 75 65 20 3D 20 44 6F 63 75 6D 65 6E 74 2E 66 72 6D 53 51 4C 2E 6D 50 61 67 65 2E 76 61 6C 75 65 20 2D 20 31}
// 		$s17 = {49 66 20 72 65 71 75 65 73 74 2E 71 75 65 72 79 73 74 72 69 6E 67 28 5C 22 67 65 74 44 52 56 73 5C 22 29 3D 5C 22 40 5C 22 20 74 68 65 6E}
// 		$s20 = {27 20 2D 2D 2D 43 6F 70 79 20 54 6F 6F 20 46 6F 6C 64 65 72 20 72 6F 75 74 69 6E 65 20 53 74 61 72 74}

// 	condition:
// 		3 of them
// }

// rule WebShell_JspWebshell_1_2_2
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
// 		author = "Florian Roth"
// 		hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"

// 	strings:
// 		$s0 = {53 79 73 74 65 6D 2E 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 43 72 65 61 74 65 41 6E 64 44 65 6C 65 74 65 46 6F 6C 64 65 72 20 69 73 20 65 72 72 6F 72 3A 5C 22 2B 65 78 29 3B 20}
// 		$s3 = {3C 25 40 20 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 47 42 4B 5C 22 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E}
// 		$s4 = {2F 2F 20 53 74 72 69 6E 67 20 74 65 6D 70 66 69 6C 65 70 61 74 68 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 69 6C 65 70 61 74 68 5C 22 29 3B}
// 		$s15 = {65 6E 64 50 6F 69 6E 74 3D 72 61 6E 64 6F 6D 31 2E 67 65 74 46 69 6C 65 50 6F 69 6E 74 65 72 28 29 3B}
// 		$s20 = {69 66 20 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 63 6F 6D 6D 61 6E 64 5C 22 29 20 21 3D 20 6E 75 6C 6C 29 20 7B}

// 	condition:
// 		3 of them
// }

// rule WebShell_g00nshell_v1_3
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
// 		author = "Florian Roth"
// 		hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"

// 	strings:
// 		$s10 = {23 54 6F 20 65 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 73 2C 20 73 69 6D 70 6C 79 20 69 6E 63 6C 75 64 65 20 3F 63 6D 64 3D 5F 5F 5F 20 69 6E 20 74 68 65 20 75 72 6C 2E 20 23}
// 		$s15 = {24 71 75 65 72 79 20 3D 20 5C 22 53 48 4F 57 20 43 4F 4C 55 4D 4E 53 20 46 52 4F 4D 20 5C 22 20 2E 20 24 5F 47 45 54 5B 27 74 61 62 6C 65 27 5D 3B}
// 		$s16 = {24 75 61 6B 65 79 20 3D 20 5C 22 37 32 34 65 61 30 35 35 62 39 37 35 36 32 31 62 39 64 36 37 39 66 37 30 37 37 32 35 37 62 64 39 5C 22 3B 20 2F 2F 20 4D 44 35 20 65 6E 63 6F 64 65 64 20 75 73 65 72 2D 61 67 65 6E 74}
// 		$s17 = {65 63 68 6F 28 5C 22 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 27 47 45 54 27 20 6E 61 6D 65 3D 27 73 68 65 6C 6C 27 3E 5C 22 29 3B}
// 		$s18 = {65 63 68 6F 28 5C 22 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 27 70 6F 73 74 27 20 61 63 74 69 6F 6E 3D 27 3F 61 63 74 3D 73 71 6C 27 3E 5C 22 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_WinX_Shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file WinX Shell.php"
// 		author = "Florian Roth"
// 		hash = "a94d65c168344ad9fa406d219bdf60150c02010e"

// 	strings:
// 		$s4 = {2F 2F 20 49 74 27 73 20 73 69 6D 70 6C 65 20 73 68 65 6C 6C 20 66 6F 72 20 61 6C 6C 20 57 69 6E 20 4F 53 2E}
// 		$s5 = {2F 2F 2D 2D 2D 2D 2D 2D 2D 20 5B 6E 65 74 73 74 61 74 20 2D 61 6E 5D 20 61 6E 64 20 5B 69 70 63 6F 6E 66 69 67 5D 20 61 6E 64 20 5B 74 61 73 6B 6C 69 73 74 5D 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D}
// 		$s6 = {3C 68 74 6D 6C 3E 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 2D 3A 5B 47 72 65 65 6E 77 6F 6F 44 5D 3A 2D 20 57 69 6E 58 20 53 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E 3C 2F 68 65 61 64 3E}
// 		$s13 = {2F 2F 20 43 72 65 61 74 65 64 20 62 79 20 67 72 65 65 6E 77 6F 6F 64 20 66 72 6F 6D 20 6E 35 37}
// 		$s20 = {20 69 66 20 28 69 73 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 29 29 20 7B}

// 	condition:
// 		3 of them
// }

// rule WebShell_PHANTASMA
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file PHANTASMA.php"
// 		author = "Florian Roth"
// 		hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"

// 	strings:
// 		$s12 = {5C 22 20 20 20 20 70 72 69 6E 74 66 28 5C 5C 5C 22 55 73 61 67 65 3A 20 25 73 20 5B 48 6F 73 74 5D 20 3C 70 6F 72 74 3E 5C 5C 5C 5C 6E 5C 5C 5C 22 2C 20 61 72 67 76 5B 30 5D 29 3B 5C 5C 6E 5C 22 20 2E}
// 		$s15 = {69 66 20 28 24 70 6F 72 74 73 63 61 6E 20 21 3D 20 5C 22 5C 22 29 20 7B}
// 		$s16 = {65 63 68 6F 20 5C 22 3C 62 72 3E 42 61 6E 6E 65 72 3A 20 24 67 65 74 20 3C 62 72 3E 3C 62 72 3E 5C 22 3B}
// 		$s20 = {24 64 6F 6E 6F 20 3D 20 67 65 74 5F 63 75 72 72 65 6E 74 5F 75 73 65 72 28 20 29 3B}

// 	condition:
// 		3 of them
// }

// rule WebShell_php_webshells_cw
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file cw.php"
// 		author = "Florian Roth"
// 		hash = "e65e0670ef6edf0a3581be6fe5ddeeffd22014bf"

// 	strings:
// 		$s1 = {2F 2F 20 44 75 6D 70 20 44 61 74 61 62 61 73 65 20 5B 70 61 63 75 63 63 69 2E 63 6F 6D 5D}
// 		$s2 = {24 64 75 6D 70 20 3D 20 5C 22 2D 2D 20 44 61 74 61 62 61 73 65 3A 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 64 62 27 5D 20 2E 5C 22 20 5C 5C 6E 5C 22 3B}
// 		$s7 = {24 61 69 64 73 20 3D 20 70 61 73 73 74 68 72 75 28 5C 22 70 65 72 6C 20 63 62 73 2E 70 6C 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6F 6E 6E 68 6F 73 74 27 5D 2E 5C 22 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6F 6E 6E 70 6F 72 74 27 5D 29 3B}
// 		$s8 = {3C 62 3E 49 50 3A 3C 2F 62 3E 20 3C 75 3E 5C 22 20 2E 20 24 5F 53 45 52 56 45 52 5B 27 52 45 4D 4F 54 45 5F 41 44 44 52 27 5D 20 2E 5C 22 3C 2F 75 3E 20 2D 20 53 65 72 76 65 72 20 49 50 3A 3C 2F 62 3E 20 3C 61 20 68 72 65 66 3D 27 68 74 74}
// 		$s14 = {24 64 75 6D 70 20 2E 3D 20 5C 22 2D 2D 20 43 79 62 65 72 2D 57 61 72 72 69 6F 72 2E 4F 72 67 5C 5C 6E 5C 22 3B}
// 		$s20 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 64 6F 65 64 69 74 27 5D 29 20 26 26 20 24 5F 50 4F 53 54 5B 27 65 64 69 74 66 69 6C 65 27 5D 20 21 3D 20 24 64 69 72 29}

// 	condition:
// 		3 of them
// }

// rule WebShell_php_include_w_shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file php-include-w-shell.php"
// 		author = "Florian Roth"
// 		hash = "1a7f4868691410830ad954360950e37c582b0292"

// 	strings:
// 		$s13 = {23 20 64 75 6D 70 20 76 61 72 69 61 62 6C 65 73 20 28 44 45 42 55 47 20 53 43 52 49 50 54 29 20 4E 45 45 44 53 20 4D 4F 44 49 46 49 4E 59 20 46 4F 52 20 42 36 34 20 53 54 41 54 55 53 21 21}
// 		$s17 = {5C 22 70 68 70 73 68 65 6C 6C 61 70 70 5C 22 20 3D 3E 20 5C 22 65 78 70 6F 72 74 20 54 45 52 4D 3D 78 74 65 72 6D 3B 20 62 61 73 68 20 2D 69 5C 22 2C}
// 		$s19 = {65 6C 73 65 20 69 66 28 24 6E 75 6D 68 6F 73 74 73 20 3D 3D 20 31 29 20 24 73 74 72 4F 75 74 70 75 74 20 2E 3D 20 5C 22 4F 6E 20 31 20 68 6F 73 74 2E 2E 5C 5C 6E 5C 22 3B}

// 	condition:
// 		1 of them
// }

// rule WebShell_mysql_tool
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file mysql_tool.php"
// 		author = "Florian Roth"
// 		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"

// 	strings:
// 		$s12 = {24 64 75 6D 70 20 2E 3D 20 5C 22 2D 2D 20 44 75 6D 70 69 6E 67 20 64 61 74 61 20 66 6F 72 20 74 61 62 6C 65 20 27 24 74 61 62 6C 65 27 5C 5C 6E 5C 22 3B}
// 		$s20 = {24 64 75 6D 70 20 2E 3D 20 5C 22 43 52 45 41 54 45 20 54 41 42 4C 45 20 24 74 61 62 6C 65 20 28 5C 5C 6E 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_PhpSpy_Ver_2006
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
// 		author = "Florian Roth"
// 		hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"

// 	strings:
// 		$s2 = {76 61 72 5F 64 75 6D 70 28 40 24 73 68 65 6C 6C 2D 3E 52 65 67 52 65 61 64 28 24 5F 50 4F 53 54 5B 27 72 65 61 64 72 65 67 6E 61 6D 65 27 5D 29 29 3B}
// 		$s12 = {24 70 72 6F 67 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 20 3A 20 5C 22 2F 63 20 6E 65 74 20 73 74 61 72 74 20 3E 20 5C 22 2E 24 70 61 74 68 6E 61 6D 65 2E}
// 		$s19 = {24 70 72 6F 67 72 61 6D 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 72 6F 67 72 61 6D 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 70 72 6F 67 72 61 6D 27 5D 20 3A 20 5C 22 63 3A 5C 5C 77 69 6E 6E 74 5C 5C 73 79 73 74 65 6D 33 32}
// 		$s20 = {24 72 65 67 76 61 6C 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 72 65 67 76 61 6C 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 72 65 67 76 61 6C 27 5D 20 3A 20 27 63 3A 5C 5C 77 69 6E 6E 74 5C 5C 62 61 63 6B 64 6F 6F 72 2E 65 78 65 27}

// 	condition:
// 		1 of them
// }

// rule WebShell_ZyklonShell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file ZyklonShell.php"
// 		author = "Florian Roth"
// 		hash = "3fa7e6f3566427196ac47551392e2386a038d61c"

// 	strings:
// 		$s0 = {54 68 65 20 72 65 71 75 65 73 74 65 64 20 55 52 4C 20 2F 4E 65 6D 6F 2F 73 68 65 6C 6C 2F 7A 79 6B 6C 6F 6E 73 68 65 6C 6C 2E 74 78 74 20 77 61 73 20 6E 6F 74 20 66 6F 75 6E 64 20 6F 6E 20 74 68 69 73 20 73 65 72 76 65 72 2E 3C 50 3E}
// 		$s1 = {3C 21 44 4F 43 54 59 50 45 20 48 54 4D 4C 20 50 55 42 4C 49 43 20 5C 22 2D 2F 2F 49 45 54 46 2F 2F 44 54 44 20 48 54 4D 4C 20 32 2E 30 2F 2F 45 4E 5C 22 3E}
// 		$s2 = {3C 54 49 54 4C 45 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E 64 3C 2F 54 49 54 4C 45 3E}
// 		$s3 = {3C 48 31 3E 4E 6F 74 20 46 6F 75 6E 64 3C 2F 48 31 3E}

// 	condition:
// 		all of them
// }

// rule WebShell_php_webshells_myshell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file myshell.php"
// 		author = "Florian Roth"
// 		hash = "5bd52749872d1083e7be076a5e65ffcde210e524"

// 	strings:
// 		$s0 = {69 66 28 24 6F 6B 3D 3D 66 61 6C 73 65 20 26 26 24 73 74 61 74 75 73 20 26 26 20 24 61 75 74 6F 45 72 72 6F 72 54 72 61 70 29 73 79 73 74 65 6D 28 24 63 6F 6D 6D 61 6E 64 20 2E 20 5C 22 20 31 3E 20 2F 74 6D 70 2F 6F 75 74 70 75}
// 		$s5 = {73 79 73 74 65 6D 28 24 63 6F 6D 6D 61 6E 64 20 2E 20 5C 22 20 31 3E 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 20 32 3E 26 31 3B 20 63 61 74 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 3B 20 72 6D 20 2F 74 6D 70 2F 6F}
// 		$s15 = {3C 74 69 74 6C 65 3E 24 4D 79 53 68 65 6C 6C 56 65 72 73 69 6F 6E 20 2D 20 41 63 63 65 73 73 20 44 65 6E 69 65 64 3C 2F 74 69 74 6C 65 3E}
// 		$s16 = {7D 24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20 24 5F 53 45 52 56 45 52 5B 27 48 54 54}

// 	condition:
// 		1 of them
// }

// rule WebShell_php_webshells_lolipop
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file lolipop.php"
// 		author = "Florian Roth"
// 		hash = "86f23baabb90c93465e6851e40104ded5a5164cb"

// 	strings:
// 		$s3 = {24 63 6F 6D 6D 61 6E 64 65 72 20 3D 20 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61 6E 64 65 72 27 5D 3B 20}
// 		$s9 = {24 73 6F 75 72 63 65 67 6F 20 3D 20 24 5F 50 4F 53 54 5B 27 73 6F 75 72 63 65 67 6F 27 5D 3B 20}
// 		$s20 = {24 72 65 73 75 6C 74 20 3D 20 6D 79 73 71 6C 5F 71 75 65 72 79 28 24 6C 6F 6C 69 31 32 29 20 6F 72 20 64 69 65 20 28 6D 79 73 71 6C 5F 65 72 72 6F 72 28 29 29 3B 20}

// 	condition:
// 		all of them
// }

// rule WebShell_simple_cmd
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file simple_cmd.php"
// 		author = "Florian Roth"
// 		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"

// 	strings:
// 		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 54 45 58 54 20 6E 61 6D 65 3D 5C 22 2D 63 6D 64 5C 22 20 73 69 7A 65 3D 36 34 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 63 6D 64 3F 3E 5C 22 20}
// 		$s2 = {3C 74 69 74 6C 65 3E 47 2D 53 65 63 75 72 69 74 79 20 57 65 62 73 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E}
// 		$s4 = {3C 3F 20 69 66 28 24 63 6D 64 20 21 3D 20 5C 22 5C 22 29 20 70 72 69 6E 74 20 53 68 65 6C 6C 5F 45 78 65 63 28 24 63 6D 64 29 3B 3F 3E}
// 		$s6 = {3C 3F 20 24 63 6D 64 20 3D 20 24 5F 52 45 51 55 45 53 54 5B 5C 22 2D 63 6D 64 5C 22 5D 3B 3F 3E}

// 	condition:
// 		1 of them
// }

// rule WebShell_go_shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file go-shell.php"
// 		author = "Florian Roth"
// 		hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"

// 	strings:
// 		$s0 = {23 63 68 61 6E 67 65 20 74 68 69 73 20 70 61 73 73 77 6F 72 64 3B 20 66 6F 72 20 70 6F 77 65 72 20 73 65 63 75 72 69 74 79 20 2D 20 64 65 6C 65 74 65 20 74 68 69 73 20 66 69 6C 65 20 3D 29}
// 		$s2 = {69 66 20 28 21 64 65 66 69 6E 65 64 24 70 61 72 61 6D 7B 63 6D 64 7D 29 7B 24 70 61 72 61 6D 7B 63 6D 64 7D 3D 5C 22 6C 73 20 2D 6C 61 5C 22 7D 3B}
// 		$s11 = {6F 70 65 6E 28 46 49 4C 45 48 41 4E 44 4C 45 2C 20 5C 22 63 64 20 24 70 61 72 61 6D 7B 64 69 72 7D 26 26 24 70 61 72 61 6D 7B 63 6D 64 7D 7C 5C 22 29 3B}
// 		$s12 = {70 72 69 6E 74 20 3C 3C 20 5C 22 5B 6B 61 6C 61 62 61 6E 67 61 5D 5C 22 3B}
// 		$s13 = {3C 74 69 74 6C 65 3E 47 4F 2E 63 67 69 3C 2F 74 69 74 6C 65 3E}

// 	condition:
// 		1 of them
// }

// rule WebShell_aZRaiLPhp_v1_0
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
// 		author = "Florian Roth"
// 		hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"

// 	strings:
// 		$s0 = {3C 66 6F 6E 74 20 73 69 7A 65 3D 27 2B 31 27 63 6F 6C 6F 72 3D 27 23 30 30 30 30 46 46 27 3E 61 5A 52 61 69 4C 50 68 50 27 6E 69 6E 20 55 52 4C 27 73 69 3A 20 68 74 74 70 3A 2F 2F 24 48 54 54 50 5F 48 4F 53 54 24 52 45 44}
// 		$s4 = {24 66 69 6C 65 70 65 72 6D 3D 62 61 73 65 5F 63 6F 6E 76 65 72 74 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 70 65 72 6D 27 5D 2C 38 2C 31 30 29 3B}
// 		$s19 = {74 6F 75 63 68 20 28 5C 22 24 70 61 74 68 2F 24 64 69 73 6D 69 5C 22 29 20 6F 72 20 64 69 65 28 5C 22 44 6F 73 79 61 20 4F 6C 75}
// 		$s20 = {65 63 68 6F 20 5C 22 3C 64 69 76 20 61 6C 69 67 6E 3D 6C 65 66 74 3E 3C 61 20 68 72 65 66 3D 27 2E 2F 24 74 68 69 73 5F 66 69 6C 65 3F 64 69 72 3D 24 70 61 74 68 2F 24 66 69 6C 65 27 3E 47}

// 	condition:
// 		2 of them
// }

// rule WebShell_webshells_zehir4
// {
// 	meta:
// 		description = "Webshells Github Archive - file zehir4"
// 		author = "Florian Roth"
// 		hash = "788928ae87551f286d189e163e55410acbb90a64"
// 		score = 55

// 	strings:
// 		$s0 = {66 72 61 6D 65 73 2E 62 79 5A 65 68 69 72 2E 64 6F 63 75 6D 65 6E 74 2E 65 78 65 63 43 6F 6D 6D 61 6E 64 28 63 6F 6D 6D 61 6E 64 2C 20 66 61 6C 73 65 2C 20 6F 70 74 69 6F 6E 29 3B}
// 		$s8 = {72 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 74 69 74 6C 65 3E 5A 65 68 69 72 49 56 20 2D 2D 3E 20 50 6F 77 65 72 65 64 20 42 79 20 5A 65 68 69 72 20 26 6C 74 3B 7A 65 68 69 72 68 61 63 6B 65 72 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D}

// 	condition:
// 		1 of them
// }

// rule WebShell_zehir4_asp_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
// 		author = "Florian Roth"
// 		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"

// 	strings:
// 		$s4 = {72 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 74 69 74 6C 65 3E 7A 65 68 69 72 33 20 2D 2D 3E 20 70 6F 77 65 72 65 64 20 62 79 20 7A 65 68 69 72 20 26 6C 74 3B 7A 65 68 69 72 68 61 63 6B 65 72 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 26}
// 		$s11 = {66 72 61 6D 65 73 2E 62 79 5A 65 68 69 72 2E 64 6F 63 75 6D 65 6E 74 2E 65 78 65 63 43 6F 6D 6D 61 6E 64 28}
// 		$s15 = {66 72 61 6D 65 73 2E 62 79 5A 65 68 69 72 2E 64 6F 63 75 6D 65 6E 74 2E 65 78 65 63 43 6F 6D 6D 61 6E 64 28 63 6F}

// 	condition:
// 		2 of them
// }

// rule WebShell_php_webshells_lostDC
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file lostDC.php"
// 		author = "Florian Roth"
// 		hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"

// 	strings:
// 		$s0 = {24 69 6E 66 6F 20 2E 3D 20 27 5B 7E 5D 53 65 72 76 65 72 3A 20 27 20 2E 24 5F 53 45 52 56 45 52 5B 27 48 54 54 50 5F 48 4F 53 54 27 5D 20 2E 27 3C 62 72 20 2F 3E 27 3B}
// 		$s4 = {68 65 61 64 65 72 20 28 20 5C 22 43 6F 6E 74 65 6E 74 2D 44 65 73 63 72 69 70 74 69 6F 6E 3A 20 44 6F 77 6E 6C 6F 61 64 20 6D 61 6E 61 67 65 72 5C 22 20 29 3B}
// 		$s5 = {70 72 69 6E 74 20 5C 22 3C 63 65 6E 74 65 72 3E 5B 20 47 65 6E 65 72 61 74 69 6F 6E 20 74 69 6D 65 3A 20 5C 22 2E 72 6F 75 6E 64 28 67 65 74 54 69 6D 65 28 29 2D 73 74 61 72 74 54 69 6D 65 2C 34 29 2E 5C 22 20 73 65 63 6F 6E 64}
// 		$s9 = {69 66 20 28 6D 6B 64 69 72 28 24 5F 50 4F 53 54 5B 27 64 69 72 27 5D 2C 20 30 37 37 37 29 20 3D 3D 20 66 61 6C 73 65 29 20 7B}
// 		$s12 = {24 72 65 74 20 3D 20 73 68 65 6C 6C 65 78 65 63 28 24 63 6F 6D 6D 61 6E 64 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_CasuS_1_5
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file CasuS 1.5.php"
// 		author = "Florian Roth"
// 		hash = "7eee8882ad9b940407acc0146db018c302696341"

// 	strings:
// 		$s2 = {3C 66 6F 6E 74 20 73 69 7A 65 3D 27 2B 31 27 63 6F 6C 6F 72 3D 27 23 30 30 30 30 46 46 27 3E 3C 75 3E 43 61 73 75 53 20 31 2E 35 27 69 6E 20 55 52 4C 27 73 69 3C 2F 75 3E 3A 20 68 74 74 70 3A 2F 2F 24 48 54 54 50 5F 48 4F}
// 		$s8 = {24 66 6F 6E 6B 5F 6B 61 70 20 3D 20 67 65 74 5F 63 66 67 5F 76 61 72 28 5C 22 66 6F 6E 6B 73 69 79 6F 6E 6C 61 72 79 5F 6B 61 70 61 74 5C 22 29 3B}
// 		$s18 = {69 66 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 5C 22 46 3A 5C 5C 5C 5C 5C 22 29 29 7B}

// 	condition:
// 		1 of them
// }

// rule WebShell_ftpsearch
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - file ftpsearch.php"
// 		author = "Florian Roth"
// 		hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 5B 2D 5D 20 45 72 72 6F 72 20 3A 20 63 6F 75 64 6E 27 74 20 72 65 61 64 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3B}
// 		$s9 = {40 24 66 74 70 3D 66 74 70 5F 63 6F 6E 6E 65 63 74 28 27 31 32 37 2E 30 2E 30 2E 31 27 29 3B}
// 		$s12 = {65 63 68 6F 20 5C 22 3C 74 69 74 6C 65 3E 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 3C 2F 74 69 74 6C 65 3E 3C 62 6F 64 79 3E 5C 22 3B}
// 		$s19 = {65 63 68 6F 20 5C 22 5B 2B 5D 20 46 6F 75 6E 64 65 64 20 5C 22 2E 73 69 7A 65 6F 66 28 24 75 73 65 72 73 29 2E 5C 22 20 65 6E 74 72 79 73 20 69 6E 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 5C 6E 5C 22 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
// 		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
// 		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"

// 	strings:
// 		$s4 = {20 3C 61 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 63 79 62 65 72 6C 6F 72 64 73 2E 6E 65 74 5C 22 20 74 61 72 67 65 74 3D 5C 22 5F 62 6C 61 6E 6B 5C 22 3E 43 79 62 65 72 20 4C 6F 72 64 73 20 43 6F 6D 6D 75 6E 69 74 79 3C 2F}
// 		$s10 = {65 63 68 6F 20 5C 22 3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 52 65 66 72 65 73 68 20 63 6F 6E 74 65 6E 74 3D 5C 5C 5C 22 30 3B 20 75 72 6C 3D 24 50 48 50 5F 53 45 4C 46 3F 65 64 69 74 3D 24 6E 61 6D 65 6F 66 66 69 6C 65 26 73 68}
// 		$s11 = {20 2A 20 20 20 43 6F 64 65 64 20 62 79 20 50 69 78 63 68 65 72}
// 		$s16 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 73 69 7A 65 3D 35 35 20 6E 61 6D 65 3D 6E 65 77 66 69 6C 65 20 76 61 6C 75 65 3D 5C 22 24 64 2F 6E 65 77 66 69 6C 65 2E 70 68 70 5C 22 3E}

// 	condition:
// 		2 of them
// }

// rule WebShell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_soldierofallah
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
// 		hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
// 		hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"

// 	strings:
// 		$s1 = {27 52 65 61 64 20 2F 65 74 63 2F 70 61 73 73 77 64 27 20 3D 3E 20 5C 22 72 75 6E 63 6F 6D 6D 61 6E 64 28 27 65 74 63 70 61 73 73 77 64 66 69 6C 65 27 2C 27 47 45 54 27 29 5C 22 2C}
// 		$s2 = {27 52 75 6E 6E 69 6E 67 20 70 72 6F 63 65 73 73 65 73 27 20 3D 3E 20 5C 22 72 75 6E 63 6F 6D 6D 61 6E 64 28 27 70 73 20 2D 61 75 78 27 2C 27 47 45 54 27 29 5C 22 2C}
// 		$s3 = {24 64 74 20 3D 20 24 5F 50 4F 53 54 5B 27 66 69 6C 65 63 6F 6E 74 65 6E 74 27 5D 3B}
// 		$s4 = {27 4F 70 65 6E 20 70 6F 72 74 73 27 20 3D 3E 20 5C 22 72 75 6E 63 6F 6D 6D 61 6E 64 28 27 6E 65 74 73 74 61 74 20 2D 61 6E 20 7C 20 67 72 65 70 20 2D 69 20 6C 69 73 74 65 6E 27 2C 27 47 45 54 27 29 5C 22 2C}
// 		$s6 = {70 72 69 6E 74 20 5C 22 53 6F 72 72 79 2C 20 6E 6F 6E 65 20 6F 66 20 74 68 65 20 63 6F 6D 6D 61 6E 64 20 66 75 6E 63 74 69 6F 6E 73 20 77 6F 72 6B 73 2E 5C 22 3B}
// 		$s11 = {64 6F 63 75 6D 65 6E 74 2E 63 6D 64 66 6F 72 6D 2E 63 6F 6D 6D 61 6E 64 2E 76 61 6C 75 65 3D 27 27 3B}
// 		$s12 = {65 6C 73 65 69 66 28 69 73 73 65 74 28 24 5F 47 45 54 5B 27 73 61 76 65 66 69 6C 65 27 5D 29 20 26 26 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 74 6F 73 61 76 65 27 5D 29 20 26 26 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54}

// 	condition:
// 		3 of them
// }

// rule WebShell_Generic_PHP_7
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Mysql interface v1.0.php, MySQL Web Interface Version 0.8.php, Mysql_interface_v1.0.php, MySQL_Web_Interface_Version_0.8.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "de98f890790756f226f597489844eb3e53a867a9"
// 		hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
// 		hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
// 		hash3 = "715f17e286416724e90113feab914c707a26d456"

// 	strings:
// 		$s0 = {68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 64 69 73 70 6F 73 69 74 69 6F 6E 3A 20 66 69 6C 65 6E 61 6D 65 3D 24 66 69 6C 65 6E 61 6D 65 2E 73 71 6C 5C 22 29 3B}
// 		$s1 = {65 6C 73 65 20 69 66 28 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 64 75 6D 70 54 61 62 6C 65 5C 22 20 7C 7C 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 64 75 6D 70 44 42 5C 22 20 29 20 7B}
// 		$s2 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 3E 5B 24 55 53 45 52 4E 41 4D 45 5D 3C 2F 66 6F 6E 74 3E 20 2D 20 5C 5C 6E 5C 22 3B}
// 		$s4 = {69 66 28 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 64 75 6D 70 54 61 62 6C 65 5C 22 20 29}

// 	condition:
// 		2 of them
// }

// rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "b148ead15d34a55771894424ace2a92983351dda"
// 		hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
// 		hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
// 		hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"

// 	strings:
// 		$s2 = {69 66 28 21 24 72 65 73 75 6C 74 32 29 24 64 75 6D 70 5F 66 69 6C 65 2E 3D 27 23 65 72 72 6F 72 20 74 61 62 6C 65 20 27 2E 24 72 6F 77 73 5B 30 5D 3B}
// 		$s4 = {69 66 28 21 28 40 6D 79 73 71 6C 5F 73 65 6C 65 63 74 5F 64 62 28 24 64 62 5F 64 75 6D 70 2C 24 6D 79 73 71 6C 5F 6C 69 6E 6B 29 29 29 65 63 68 6F 28 27 44 42 20 65 72 72 6F 72 27 29 3B}
// 		$s6 = {68 65 61 64 65 72 28 27 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 27 2E 73 74 72 6C 65 6E 28 24 64 75 6D 70 5F 66 69 6C 65 29 2E 5C 22 5C 5C 6E 5C 22 29 3B}
// 		$s20 = {65 63 68 6F 28 27 44 75 6D 70 20 66 6F 72 20 27 2E 24 64 62 5F 64 75 6D 70 2E 27 20 6E 6F 77 20 69 6E 20 27 2E 24 74 6F 5F 66 69 6C 65 29 3B}

// 	condition:
// 		2 of them
// }

// rule WebShell_Generic_PHP_8
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Macker's Private PHPShell.php, PHP Shell.php, Safe0ver Shell -Safe Mod Bypass By Evilc0der.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "fc1ae242b926d70e32cdb08bbe92628bc5bd7f99"
// 		hash1 = "9ad55629c4576e5a31dd845012d13a08f1c1f14e"
// 		hash2 = "c4aa2cf665c784553740c3702c3bfcb5d7af65a3"

// 	strings:
// 		$s1 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 66 69 6C 65 5C 22 20 29 20 7B 20 2F 2A 20 3C 21 2D 2D 20 56 69 65 77 20 61 20 66 69 6C 65 20 69 6E 20 74 65 78 74 20 2D 2D 3E 20 2A 2F}
// 		$s2 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 29 20 7B 20 2F 2A 20 3C 21 2D 2D 20 55 70 6C 6F 61 64 20 46 69 6C 65 20 66 6F 72 6D 20 2D 2D 3E 20 2A 2F 20}
// 		$s3 = {2F 2A 20 49 20 61 64 64 65 64 20 74 68 69 73 20 74 6F 20 65 6E 73 75 72 65 20 74 68 65 20 73 63 72 69 70 74 20 77 69 6C 6C 20 72 75 6E 20 63 6F 72 72 65 63 74 6C 79 2E 2E 2E}
// 		$s14 = {3C 21 2D 2D 20 20 20 20 3C 2F 66 6F 72 6D 3E 20 20 20 2D 2D 3E}
// 		$s15 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 3E}
// 		$s20 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 64 6F 77 6E 6C 5C 22 20 29 20 7B 20 2F 2A 3C 21 2D 2D 20 53 61 76 65 20 74 68 65 20 65 64 69 74 65 64 20 66 69 6C 65 20 62 61 63 6B 20 74 6F 20 61 20 66 69 6C 65 20 2D 2D 3E 20 2A 2F}

// 	condition:
// 		3 of them
// }

// rule WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
// 		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
// 		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
// 		hash3 = "4f83bc2836601225a115b5ad54496428a507a361"

// 	strings:
// 		$s1 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 30 30 30 30 30 30 5C 22 3E 53 69 6C 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E}
// 		$s5 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 31 32 32 5C 22 20 68 65 69 67 68 74 3D 5C 22 31 37 5C 22 20 62 67 63 6F 6C 6F 72 3D 5C 22 23 39 46 39 46 39 46 5C 22 3E}
// 		$s6 = {6F 6E 66 6F 63 75 73 3D 5C 22 69 66 20 28 74 68 69 73 2E 76 61 6C 75 65 20 3D 3D 20 27 4B 75 6C 6C 61 6E}
// 		$s16 = {3C 69 6D 67 20 62 6F 72 64 65 72 3D 5C 22 30 5C 22 20 73 72 63 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 61 76 65 6E 74 67 72 75 70 2E 6E 65 74 2F 61 72 73 69 76 2F 6B 6C 61 73 76 61 79 76 2F 31 2E 30 2F 32 2E 67 69 66 5C 22 3E}

// 	condition:
// 		2 of them
// }

// rule WebShell_Generic_PHP_9
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
// 		hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
// 		hash2 = "0daed818cac548324ad0c5905476deef9523ad73"

// 	strings:
// 		$s2 = {3A 3C 62 3E 5C 22 20 2E 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 5F 50 4F 53 54 5B 27 74 6F 74 27 5D 29 2E 20 5C 22 3C 2F 62 3E 5C 22 3B}
// 		$s6 = {69 66 20 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 77 71 27 5D 29 20 26 26 20 24 5F 50 4F 53 54 5B 27 77 71 27 5D 3C 3E 5C 22 5C 22 29 20 7B}
// 		$s12 = {69 66 20 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 63 27 5D 29 29 7B}
// 		$s13 = {70 61 73 73 74 68 72 75 28 24 5F 50 4F 53 54 5B 27 63 27 5D 29 3B}
// 		$s16 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 72 61 64 69 6F 5C 22 20 6E 61 6D 65 3D 5C 22 74 61 63 5C 22 20 76 61 6C 75 65 3D 5C 22 31 5C 22 3E 42 36 34 20 44 65 63 6F 64 65 3C 62 72 3E}
// 		$s20 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 72 61 64 69 6F 5C 22 20 6E 61 6D 65 3D 5C 22 74 61 63 5C 22 20 76 61 6C 75 65 3D 5C 22 33 5C 22 3E 6D 64 35 20 48 61 73 68}

// 	condition:
// 		3 of them
// }

// rule WebShell__PH_Vayv_PHVayv_PH_Vayv
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
// 		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
// 		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"

// 	strings:
// 		$s4 = {3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 65 63 68 6F 20 5C 22 50 48 56 61 79 76 2E 70 68 70 3F 64 75 7A 6B 61 79 64 65 74 3D 24 64 69 7A 69 6E 2F 24 64 75 7A 65 6E 6C 65}
// 		$s12 = {3C 3F 20 69 66 20 28 24 65 6B 69 6E 63 69 3D 3D 5C 22 2E 5C 22 20 6F 72 20 20 24 65 6B 69 6E 63 69 3D 3D 5C 22 2E 2E 5C 22 29 20 7B}
// 		$s17 = {6E 61 6D 65 3D 5C 22 64 75 7A 65 6E 78 32 5C 22 20 76 61 6C 75 65 3D 5C 22 4B 6C 61 73}

// 	condition:
// 		2 of them
// }

// rule WebShell_Generic_PHP_1
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Dive Shell 1.0 - Emperor Hacking Team.php, Dive_Shell_1.0_Emperor_Hacking_Team.php, SimShell 1.0 - Simorgh Security MGZ.php, SimShell_1.0_-_Simorgh_Security_MGZ.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b"
// 		hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
// 		hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
// 		hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"

// 	strings:
// 		$s1 = {24 74 6F 6B 65 6E 20 3D 20 73 75 62 73 74 72 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20 30 2C 20 24 6C 65 6E 67 74 68 29 3B}
// 		$s4 = {76 61 72 20 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 20 3D 20 6E 65 77 20 41 72 72 61 79 28 3C 3F 70 68 70 20 65 63 68 6F 20 24 6A 73 5F 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 20 3F 3E 29 3B}
// 		$s7 = {24 5F 53 45 53 53 49 4F 4E 5B 27 6F 75 74 70 75 74 27 5D 20 2E 3D 20 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 66 67 65 74 73 28 24 69 6F 5B 31 5D 29 2C}
// 		$s9 = {64 6F 63 75 6D 65 6E 74 2E 73 68 65 6C 6C 2E 63 6F 6D 6D 61 6E 64 2E 76 61 6C 75 65 20 3D 20 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 5B 63 75 72 72 65 6E 74 5F 6C 69 6E 65 5D 3B}
// 		$s16 = {24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 20 3D 20 24 61 6C 69 61 73 65 73 5B 24 74 6F 6B 65 6E 5D 20 2E 20 73 75 62 73 74 72 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20 24}
// 		$s19 = {69 66 20 28 65 6D 70 74 79 28 24 5F 53 45 53 53 49 4F 4E 5B 27 63 77 64 27 5D 29 20 7C 7C 20 21 65 6D 70 74 79 28 24 5F 52 45 51 55 45 53 54 5B 27 72 65 73 65 74 27 5D 29 29 20 7B}
// 		$s20 = {69 66 20 28 65 2E 6B 65 79 43 6F 64 65 20 3D 3D 20 33 38 20 26 26 20 63 75 72 72 65 6E 74 5F 6C 69 6E 65 20 3C 20 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 2E 6C 65 6E 67 74 68 2D 31 29 20 7B}

// 	condition:
// 		5 of them
// }

// rule WebShell_Generic_PHP_2
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
// 		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
// 		hash2 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
// 		hash3 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

// 	strings:
// 		$s3 = {69 66 28 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 74 6F 27 5D 29 29 7C 7C 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 66 72 6F 6D 27 5D 29 29 29}
// 		$s4 = {5C 5C 24 70 6F 72 74 20 3D 20 7B 24 5F 50 4F 53 54 5B 27 70 6F 72 74 27 5D 7D 3B}
// 		$s5 = {24 5F 50 4F 53 54 5B 27 69 6E 73 74 61 6C 6C 70 61 74 68 27 5D 20 3D 20 5C 22 74 65 6D 70 2E 70 6C 5C 22 3B 7D}
// 		$s14 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 6F 73 74 27 5D 29 20 61 6E 64 20 24 5F 50 4F 53 54 5B 27 70 6F 73 74 27 5D 20 3D 3D 20 5C 22 79 65 73 5C 22 20 61 6E 64 20 40 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 5C 22 75}
// 		$s16 = {63 6F 70 79 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 5C 22 75 73 65 72 66 69 6C 65 5C 22 5D 5B 5C 22 74 6D 70 5F 6E 61 6D 65 5C 22 5D 2C 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 5C 22 75 73 65 72 66 69 6C 65 5C 22 5D}

// 	condition:
// 		4 of them
// }

// rule WebShell__CrystalShell_v_1_erne_stres
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
// 		hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
// 		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

// 	strings:
// 		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 27 73 75 62 6D 69 74 27 20 76 61 6C 75 65 3D 27 20 20 6F 70 65 6E 20 28 73 68 69 6C 6C 2E 74 78 74 29 20 27 3E}
// 		$s4 = {76 61 72 5F 64 75 6D 70 28 63 75 72 6C 5F 65 78 65 63 28 24 63 68 29 29 3B}
// 		$s7 = {69 66 28 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 4D 6F 68 61 6A 65 72 32 32 27 5D 29 29 7B}
// 		$s10 = {24 6D 3D 24 5F 50 4F 53 54 5B 27 63 75 72 6C 27 5D 3B}
// 		$s13 = {24 75 31 70 3D 24 5F 50 4F 53 54 5B 27 63 6F 70 79 27 5D 3B}
// 		$s14 = {69 66 28 65 6D 70 74 79 28 5C 5C 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
// 		$s15 = {24 73 74 72 69 6E 67 20 3D 20 65 78 70 6C 6F 64 65 28 5C 22 7C 5C 22 2C 24 73 74 72 69 6E 67 29 3B}
// 		$s16 = {24 73 74 72 65 61 6D 20 3D 20 69 6D 61 70 5F 6F 70 65 6E 28 5C 22 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 2C 20 5C 22 5C 22 2C 20 5C 22 5C 22 29 3B}

// 	condition:
// 		5 of them
// }

// rule WebShell_Generic_PHP_3
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Antichat Shell v1.3.php, Antichat Shell. Modified by Go0o$E.php, Antichat Shell.php, fatal.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "d829e87b3ce34460088c7775a60bded64e530cd4"
// 		hash1 = "d710c95d9f18ec7c76d9349a28dd59c3605c02be"
// 		hash2 = "f044d44e559af22a1a7f9db72de1206f392b8976"
// 		hash3 = "41780a3e8c0dc3cbcaa7b4d3c066ae09fb74a289"

// 	strings:
// 		$s0 = {68 65 61 64 65 72 28 27 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 27 2E 66 69 6C 65 73 69 7A 65 28 24 66 69 6C 65 29 2E 27 27 29 3B}
// 		$s4 = {3C 74 65 78 74 61 72 65 61 20 6E 61 6D 65 3D 5C 5C 5C 22 63 6F 6D 6D 61 6E 64 5C 5C 5C 22 20 72 6F 77 73 3D 5C 5C 5C 22 35 5C 5C 5C 22 20 63 6F 6C 73 3D 5C 5C 5C 22 31 35 30 5C 5C 5C 22 3E 5C 22 2E 40 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61}
// 		$s7 = {69 66 28 66 69 6C 65 74 79 70 65 28 24 64 69 72 20 2E 20 24 66 69 6C 65 29 3D 3D 5C 22 66 69 6C 65 5C 22 29 24 66 69 6C 65 73 5B 5D 3D 24 66 69 6C 65 3B}
// 		$s14 = {65 6C 73 65 69 66 20 28 28 24 70 65 72 6D 73 20 26 20 30 78 36 30 30 30 29 20 3D 3D 20 30 78 36 30 30 30 29 20 7B 24 69 6E 66 6F 20 3D 20 27 62 27 3B 7D 20}
// 		$s20 = {24 69 6E 66 6F 20 2E 3D 20 28 28 24 70 65 72 6D 73 20 26 20 30 78 30 30 30 34 29 20 3F 20 27 72 27 20 3A 20 27 2D 27 29 3B}

// 	condition:
// 		all of them
// }

// rule WebShell_Generic_PHP_4
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, nshell.php, Loaderz WEB Shell.php, stres.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
// 		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
// 		hash2 = "86bc40772de71b1e7234d23cab355e1ff80c474d"
// 		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
// 		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

// 	strings:
// 		$s0 = {69 66 20 28 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 5C 22 20 61 6E 64 20 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 2E 5C 22 29 7B}
// 		$s2 = {24 6F 77 6E 65 72 5B 5C 22 77 72 69 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 32 30 30 29 20 3F 20 27 77 27 20 3A 20 27 2D 27 3B}
// 		$s5 = {24 6F 77 6E 65 72 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 31 30 30 29 20 3F 20 27 78 27 20 3A 20 27 2D 27 3B}
// 		$s6 = {24 77 6F 72 6C 64 5B 5C 22 77 72 69 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 30 32 29 20 3F 20 27 77 27 20 3A 20 27 2D 27 3B}
// 		$s7 = {24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 30 31 29 20 3F 20 27 78 27 20 3A 20 27 2D 27 3B}
// 		$s10 = {66 6F 72 65 61 63 68 20 28 24 61 72 72 20 61 73 20 24 66 69 6C 65 6E 61 6D 65 29 20 7B}
// 		$s19 = {65 6C 73 65 20 69 66 28 20 24 6D 6F 64 65 20 26 20 30 78 36 30 30 30 20 29 20 7B 20 24 74 79 70 65 3D 27 62 27 3B 20 7D}

// 	condition:
// 		all of them
// }

// rule WebShell_GFS
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files GFS web-shell ver 3.1.7 - PRiV8.php, Predator.php, GFS_web-shell_ver_3.1.7_-_PRiV8.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "c2f1ef6b11aaec255d4dd31efad18a3869a2a42c"
// 		hash1 = "34f6640985b07009dbd06cd70983451aa4fe9822"
// 		hash2 = "d25ef72bdae3b3cb0fc0fdd81cfa58b215812a50"

// 	strings:
// 		$s0 = {4F 4B 54 73 4E 43 6D 4E 73 62 33 4E 6C 4B 46 4E 55 52 45 39 56 56 43 6B 37 44 51 70 6A 62 47 39 7A 5A 53 68 54 56 45 52 46 55 6C 49 70 4F 77 3D 3D 5C 22 3B}
// 		$s1 = {6C 49 45 4E 50 54 6B 34 37 44 51 70 6C 65 47 6C 30 49 44 41 37 44 51 70 39 44 51 70 39 5C 22 3B}
// 		$s2 = {4F 77 30 4B 49 47 52 31 63 44 49 6F 5A 6D 51 73 49 44 49 70 4F 77 30 4B 49 47 56 34 5A 57 4E 73 4B 43 49 76 59 6D 6C 75 4C 33 4E 6F 49 69 77 69 63 32 67 67 4C 57 6B 69 4C 43 42 4F 56 55 78 4D 4B 54 73 4E 43 69 42 6A 62 47 39 7A 5A 53 68 6D}

// 	condition:
// 		all of them
// }

// rule WebShell__CrystalShell_v_1_sosyete_stres
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, sosyete.php, stres.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
// 		hash1 = "e32405e776e87e45735c187c577d3a4f98a64059"
// 		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

// 	strings:
// 		$s1 = {41 3A 76 69 73 69 74 65 64 20 7B 20 43 4F 4C 4F 52 3A 62 6C 75 65 3B 20 54 45 58 54 2D 44 45 43 4F 52 41 54 49 4F 4E 3A 20 6E 6F 6E 65 7D}
// 		$s4 = {41 3A 61 63 74 69 76 65 20 7B 43 4F 4C 4F 52 3A 62 6C 75 65 3B 20 54 45 58 54 2D 44 45 43 4F 52 41 54 49 4F 4E 3A 20 6E 6F 6E 65 7D}
// 		$s11 = {73 63 72 6F 6C 6C 62 61 72 2D 64 61 72 6B 73 68 61 64 6F 77 2D 63 6F 6C 6F 72 3A 20 23 31 30 31 38 34 32 3B}
// 		$s15 = {3C 61 20 62 6F 6F 6B 6D 61 72 6B 3D 5C 22 6D 69 6E 69 70 61 6E 65 6C 5C 22 3E}
// 		$s16 = {62 61 63 6B 67 72 6F 75 6E 64 2D 63 6F 6C 6F 72 3A 20 23 45 42 45 41 45 41 3B}
// 		$s18 = {63 6F 6C 6F 72 3A 20 23 44 35 45 43 46 39 3B}
// 		$s19 = {3C 63 65 6E 74 65 72 3E 3C 54 41 42 4C 45 20 73 74 79 6C 65 3D 5C 22 42 4F 52 44 45 52 2D 43 4F 4C 4C 41 50 53 45 3A 20 63 6F 6C 6C 61 70 73 65 5C 22 20 68 65 69 67 68 74 3D 31 20 63 65 6C 6C 53 70 61 63 69 6E 67 3D 30 20 62 6F 72 64 65 72}

// 	condition:
// 		all of them
// }

// rule WebShell_Generic_PHP_10
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php, PHPRemoteView.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
// 		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
// 		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
// 		hash3 = "7d5b54c7cab6b82fb7d131d7bbb989fd53cb1b57"

// 	strings:
// 		$s2 = {24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 77 6F 72 6C 64 5B 27 65 78 65 63 75 74 65 27 5D 3D 3D 27 78 27 29 20 3F 20 27 74 27 20 3A 20 27 54 27 3B 20}
// 		$s6 = {24 6F 77 6E 65 72 5B 5C 22 77 72 69 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 32 30 30 29 20 3F 20 27 77 27 20 3A 20 27 2D 27 3B 20}
// 		$s11 = {24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 30 31 29 20 3F 20 27 78 27 20 3A 20 27 2D 27 3B 20}
// 		$s12 = {65 6C 73 65 20 69 66 28 20 24 6D 6F 64 65 20 26 20 30 78 41 30 30 30 20 29 20}
// 		$s17 = {24 73 3D 73 70 72 69 6E 74 66 28 5C 22 25 31 73 5C 22 2C 20 24 74 79 70 65 29 3B 20}
// 		$s20 = {66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 3B}

// 	condition:
// 		all of them
// }

// rule WebShell_Generic_PHP_11
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
// 		hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
// 		hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
// 		hash3 = "80aba3348434c66ac471daab949871ab16c50042"

// 	strings:
// 		$s5 = {24 66 69 6C 65 6E 61 6D 65 20 3D 20 24 62 61 63 6B 75 70 73 74 72 69 6E 67 2E 5C 22 24 66 69 6C 65 6E 61 6D 65 5C 22 3B}
// 		$s6 = {77 68 69 6C 65 20 28 24 66 69 6C 65 20 3D 20 72 65 61 64 64 69 72 28 24 66 6F 6C 64 65 72 29 29 20 7B}
// 		$s7 = {69 66 28 24 66 69 6C 65 20 21 3D 20 5C 22 2E 5C 22 20 26 26 20 24 66 69 6C 65 20 21 3D 20 5C 22 2E 2E 5C 22 29}
// 		$s9 = {24 62 61 63 6B 75 70 73 74 72 69 6E 67 20 3D 20 5C 22 63 6F 70 79 5F 6F 66 5F 5C 22 3B}
// 		$s10 = {69 66 28 20 66 69 6C 65 5F 65 78 69 73 74 73 28 24 66 69 6C 65 5F 6E 61 6D 65 29 29}
// 		$s13 = {67 6C 6F 62 61 6C 20 24 66 69 6C 65 5F 6E 61 6D 65 2C 20 24 66 69 6C 65 6E 61 6D 65 3B}
// 		$s16 = {63 6F 70 79 28 24 66 69 6C 65 2C 5C 22 24 66 69 6C 65 6E 61 6D 65 5C 22 29 3B}
// 		$s18 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 34 39 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 31 34 32 5C 22 3E}

// 	condition:
// 		all of them
// }

// rule WebShell__findsock_php_findsock_shell_php_reverse_shell
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
// 		hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
// 		hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"

// 	strings:
// 		$s1 = {2F 2F 20 6D 65 20 61 74 20 70 65 6E 74 65 73 74 6D 6F 6E 6B 65 79 40 70 65 6E 74 65 73 74 6D 6F 6E 6B 65 79 2E 6E 65 74}

// 	condition:
// 		all of them
// }

// rule WebShell_Generic_PHP_6
// {
// 	meta:
// 		description = "PHP Webshells Github Archive - from files c0derz shell [csh] v. 0.1.1 release.php, CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
// 		author = "Florian Roth"
// 		super_rule = 1
// 		hash0 = "1a08f5260c4a2614636dfc108091927799776b13"
// 		hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
// 		hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
// 		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
// 		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

// 	strings:
// 		$s2 = {40 65 76 61 6C 28 73 74 72 69 70 73 6C 61 73 68 65 73 28 24 5F 50 4F 53 54 5B 27 70 68 70 63 6F 64 65 27 5D 29 29 3B}
// 		$s5 = {65 63 68 6F 20 73 68 65 6C 6C 5F 65 78 65 63 28 24 63 6F 6D 29 3B}
// 		$s7 = {69 66 28 24 73 65 72 74 79 70 65 20 3D 3D 20 5C 22 77 69 6E 64 61 5C 22 29 7B}
// 		$s8 = {66 75 6E 63 74 69 6F 6E 20 65 78 65 63 75 74 65 28 24 63 6F 6D 29}
// 		$s12 = {65 63 68 6F 20 64 65 63 6F 64 65 28 65 78 65 63 75 74 65 28 24 63 6D 64 29 29 3B}
// 		$s15 = {65 63 68 6F 20 73 79 73 74 65 6D 28 24 63 6F 6D 29 3B}

// 	condition:
// 		4 of them
// }

// rule Unpack_Injectt
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Injectt.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8a5d2158a566c87edc999771e12d42c5"

// 	strings:
// 		$s2 = {25 73 20 2D 52 75 6E 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2D 2D 3E 54 6F 20 49 6E 73 74 61 6C 6C 20 41 6E 64 20 52 75 6E 20 54 68 65 20 53 65 72 76 69 63 65}
// 		$s3 = {25 73 20 2D 55 6E 69 6E 73 74 61 6C 6C 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2D 2D 3E 54 6F 20 55 6E 69 6E 73 74 61 6C 6C 20 54 68 65 20 53 65 72 76 69 63 65}
// 		$s4 = {28 53 54 41 4E 44 41 52 44 5F 52 49 47 48 54 53 5F 52 45 51 55 49 52 45 44 20 7C 53 43 5F 4D 41 4E 41 47 45 52 5F 43 4F 4E 4E 45 43 54 20 7C 53 43 5F 4D 41 4E 41 47 45 52 5F 43 52 45 41 54 45 5F 53 45 52 56 49 43 45 20 7C 53 43 5F 4D 41 4E}

// 	condition:
// 		all of them
// }

// rule HYTop_DevPack_fso
// {
// 	meta:
// 		description = "Webshells Auto-generated - file fso.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b37f3cde1a08890bd822a182c3a881f6"

// 	strings:
// 		$s0 = {3C 21 2D 2D 20 50 61 67 65 46 53 4F 20 42 65 6C 6F 77 20 2D 2D 3E}
// 		$s1 = {74 68 65 46 69 6C 65 2E 77 72 69 74 65 4C 69 6E 65 28 5C 22 3C 73 63 72 69 70 74 20 6C 61 6E 67 75 61 67 65 3D 5C 22 5C 22 76 62 73 63 72 69 70 74 5C 22 5C 22 20 72 75 6E 61 74 3D 73 65 72 76 65 72 3E 69 66 20 72 65 71 75 65 73 74 28 5C 22 5C 22 5C 22 26 63 6C 69}

// 	condition:
// 		all of them
// }

// rule FeliksPack3___PHP_Shells_ssh
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ssh.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1aa5307790d72941589079989b4f900e"

// 	strings:
// 		$s0 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 73 74 72 5F 72 6F 74 31 33 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}

// 	condition:
// 		all of them
// }

// rule Debug_BDoor
// {
// 	meta:
// 		description = "Webshells Auto-generated - file BDoor.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "e4e8e31dd44beb9320922c5f49739955"

// 	strings:
// 		$s1 = {5C 5C 42 44 6F 6F 72 5C 5C}
// 		$s4 = {53 4F 46 54 57 41 52 45 5C 5C 4D 69 63 72 6F 73 6F 66 74 5C 5C 57 69 6E 64 6F 77 73 5C 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 5C 52 75 6E}

// 	condition:
// 		all of them
// }

// rule bin_Client
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Client.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5f91a5b46d155cacf0cc6673a2a5461b"

// 	strings:
// 		$s0 = {52 65 63 69 65 76 65 64 20 72 65 73 70 6F 6E 64 20 66 72 6F 6D 20 73 65 72 76 65 72 21 21}
// 		$s4 = {70 61 63 6B 65 74 20 64 6F 6F 72 20 63 6C 69 65 6E 74}
// 		$s5 = {69 6E 70 75 74 20 73 6F 75 72 63 65 20 70 6F 72 74 28 77 68 61 74 65 76 65 72 20 79 6F 75 20 77 61 6E 74 29 3A}
// 		$s7 = {50 61 63 6B 65 74 20 73 65 6E 74 2C 77 61 69 74 69 6E 67 20 66 6F 72 20 72 65 70 6C 79 2E 2E 2E}

// 	condition:
// 		all of them
// }

// rule ZXshell2_0_rar_Folder_ZXshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ZXshell.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "246ce44502d2f6002d720d350e26c288"

// 	strings:
// 		$s0 = {57 50 72 65 76 69 65 77 50 61 67 65 73 6E}
// 		$s1 = {44 41 21 4F 4C 55 54 45 4C 59 20 4E}

// 	condition:
// 		all of them
// }

// rule RkNTLoad
// {
// 	meta:
// 		description = "Webshells Auto-generated - file RkNTLoad.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "262317c95ced56224f136ba532b8b34f"

// 	strings:
// 		$s1 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 68 74 74 70 3A 2F 2F 75 70 78 2E 74 73 78 2E 6F 72 67 20 24}
// 		$s2 = {35 70 75 72 2B 76 69 72 74 75 21}
// 		$s3 = {75 67 68 20 73 70 61 63 23 6E}
// 		$s4 = {78 63 45 78 33 57 72 69 4C 34}
// 		$s5 = {72 75 6E 74 69 6D 65 20 65 72 72 6F 72}
// 		$s6 = {6C 6F 73 65 48 57 61 69 74 2E 53 72 2E}
// 		$s7 = {65 73 73 61 67 65 42 6F 78 41 77}
// 		$s8 = {24 49 64 3A 20 55 50 58 20 31 2E 30 37 20 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 36 2D 32 30 30 31 20 74 68 65 20 55 50 58 20 54 65 61 6D 2E 20 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 20 24}

// 	condition:
// 		all of them
// }

// rule binder2_binder2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file binder2.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "d594e90ad23ae0bc0b65b59189c12f11"

// 	strings:
// 		$s0 = {49 73 43 68 61 72 41 6C 70 68 61 4E 75 6D 65 72 69 63 41}
// 		$s2 = {57 69 64 65 43 68 61 72 54 6F 4D}
// 		$s4 = {67 20 35 70 75 72 2B 76 69 72 74 75 21}
// 		$s5 = {5C 5C 73 79 73 6C 6F 67 2E 65 6E}
// 		$s6 = {68 65 61 70 37 27 37 6F 71 6B 3F 6E 6F 74 3D}
// 		$s8 = {2D 20 4B 61 62 6C 74 6F 20 69 6E}

// 	condition:
// 		all of them
// }

// rule thelast_orice2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file orice2.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "aa63ffb27bde8d03d00dda04421237ae"

// 	strings:
// 		$s0 = {20 24 61 61 20 3D 20 24 5F 47 45 54 5B 27 61 61 27 5D 3B}
// 		$s1 = {65 63 68 6F 20 24 61 61 3B}

// 	condition:
// 		all of them
// }

// rule FSO_s_sincap
// {
// 	meta:
// 		description = "Webshells Auto-generated - file sincap.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "dc5c2c2392b84a1529abd92e98e9aa5b"

// 	strings:
// 		$s0 = {20 20 20 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 45 35 45 35 45 35 5C 22 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 3B 20 66 6F 6E 74 2D 77 65 69 67 68 74 3A 20 37 30 30 5C 22 20 66 61 63 65 3D 5C 22 41 72 69 61 6C 5C 22 3E}
// 		$s4 = {3C 62 6F 64 79 20 74 65 78 74 3D 5C 22 23 30 30 38 30 30 30 5C 22 20 62 67 63 6F 6C 6F 72 3D 5C 22 23 38 30 38 30 38 30 5C 22 20 74 6F 70 6D 61 72 67 69 6E 3D 5C 22 30 5C 22 20 6C 65 66 74 6D 61 72 67 69 6E 3D 5C 22 30 5C 22 20 72 69 67 68 74 6D 61 72 67 69 6E 3D}

// 	condition:
// 		all of them
// }

// rule PhpShell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file PhpShell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "539baa0d39a9cf3c64d65ee7a8738620"

// 	strings:
// 		$s2 = {68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 67 69 6D 70 73 74 65 72 2E 63 6F 6D 2F 77 69 6B 69 2F 50 68 70 53 68 65 6C 6C 5C 22 3E 77 77 77 2E 67 69 6D 70 73 74 65 72 2E 63 6F 6D 2F 77 69 6B 69 2F 50 68 70 53 68 65 6C 6C 3C 2F 61 3E 2E}

// 	condition:
// 		all of them
// }

// rule HYTop_DevPack_config
// {
// 	meta:
// 		description = "Webshells Auto-generated - file config.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b41d0e64e64a685178a3155195921d61"

// 	strings:
// 		$s0 = {63 6F 6E 73 74 20 61 64 6D 69 6E 50 61 73 73 77 6F 72 64 3D 5C 22}
// 		$s2 = {63 6F 6E 73 74 20 75 73 65 72 50 61 73 73 77 6F 72 64 3D 5C 22}
// 		$s3 = {63 6F 6E 73 74 20 6D 56 65 72 73 69 6F 6E 3D}

// 	condition:
// 		all of them
// }

// rule sendmail
// {
// 	meta:
// 		description = "Webshells Auto-generated - file sendmail.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "75b86f4a21d8adefaf34b3a94629bd17"

// 	strings:
// 		$s3 = {5F 4E 65 78 74 50 79 43 38 30 38}
// 		$s6 = {43 6F 70 79 72 69 67 68 74 20 28 43 29 20 32 30 30 30 2C 20 44 69 61 6D 6F 6E 64 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 50 74 79 2E 20 4C 74 64 2E 20 28 77 77 77 2E 64 69 61 6D 6F 6E 64 63 73 2E 63 6F 6D 2E 61 75 29}

// 	condition:
// 		all of them
// }

// rule FSO_s_zehir4
// {
// 	meta:
// 		description = "Webshells Auto-generated - file zehir4.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5b496a61363d304532bcf52ee21f5d55"

// 	strings:
// 		$s5 = {20 62 79 4D 65 73 61 6A 20}

// 	condition:
// 		all of them
// }

// rule hkshell_hkshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file hkshell.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "168cab58cee59dc4706b3be988312580"

// 	strings:
// 		$s1 = {50 72 53 65 73 73 4B 45 52 4E 45 4C 55}
// 		$s2 = {43 75 72 33 6E 74 56 37 73 69 6F 6E}
// 		$s3 = {45 78 70 6C 6F 72 65 72 38}

// 	condition:
// 		all of them
// }

// rule iMHaPFtp
// {
// 	meta:
// 		description = "Webshells Auto-generated - file iMHaPFtp.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "12911b73bc6a5d313b494102abcf5c57"

// 	strings:
// 		$s1 = {65 63 68 6F 20 5C 22 5C 5C 74 3C 74 68 20 63 6C 61 73 73 3D 5C 5C 5C 22 70 65 72 6D 69 73 73 69 6F 6E 5F 68 65 61 64 65 72 5C 5C 5C 22 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 24 73 65 6C 66 3F 7B 24 64 7D 73 6F 72 74 3D 70 65 72 6D 69 73 73 69 6F 6E 24 72 5C 5C 5C 22 3E}

// 	condition:
// 		all of them
// }

// rule Unpack_TBack
// {
// 	meta:
// 		description = "Webshells Auto-generated - file TBack.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a9d1007823bf96fb163ab38726b48464"

// 	strings:
// 		$s5 = {5C 5C 66 69 6E 61 6C 5C 5C 6E 65 77 5C 5C 6C 63 63 5C 5C 70 75 62 6C 69 63 2E 64 6C 6C}

// 	condition:
// 		all of them
// }

// rule DarkSpy105
// {
// 	meta:
// 		description = "Webshells Auto-generated - file DarkSpy105.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "f0b85e7bec90dba829a3ede1ab7d8722"

// 	strings:
// 		$s7 = {53 6F 72 72 79 2C 44 61 72 6B 53 70 79 20 67 6F 74 20 61 6E 20 75 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74 69 6F 6E 2C 70 6C 65 61 73 65 20 72 65 2D 72 75 6E 20 69 74 2C 74 68 61 6E 6B 73 21}

// 	condition:
// 		all of them
// }

// rule EditServer_Webshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file EditServer.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "f945de25e0eba3bdaf1455b3a62b9832"

// 	strings:
// 		$s2 = {53 65 72 76 65 72 20 25 73 20 48 61 76 65 20 42 65 65 6E 20 43 6F 6E 66 69 67 75 72 65 64}
// 		$s5 = {54 68 65 20 53 65 72 76 65 72 20 50 61 73 73 77 6F 72 64 20 45 78 63 65 65 64 73 20 33 32 20 43 68 61 72 61 63 74 65 72 73}
// 		$s8 = {39 2D 2D 53 65 74 20 50 72 6F 63 65 63 65 73 73 20 4E 61 6D 65 20 54 6F 20 49 6E 6A 65 63 74 20 44 4C 4C}

// 	condition:
// 		all of them
// }

// rule FSO_s_reader
// {
// 	meta:
// 		description = "Webshells Auto-generated - file reader.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"

// 	strings:
// 		$s2 = {6D 61 69 6C 74 6F 3A 6D 61 69 6C 62 6F 6D 62 40 68 6F 74 6D 61 69 6C 2E}

// 	condition:
// 		all of them
// }

// rule ASP_CmdAsp
// {
// 	meta:
// 		description = "Webshells Auto-generated - file CmdAsp.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "79d4f3425f7a89befb0ef3bafe5e332f"

// 	strings:
// 		$s2 = {27 20 2D 2D 20 52 65 61 64 20 74 68 65 20 6F 75 74 70 75 74 20 66 72 6F 6D 20 6F 75 72 20 63 6F 6D 6D 61 6E 64 20 61 6E 64 20 72 65 6D 6F 76 65 20 74 68 65 20 74 65 6D 70 20 66 69 6C 65 20 2D 2D 20 27}
// 		$s6 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}
// 		$s9 = {27 20 2D 2D 20 63 72 65 61 74 65 20 74 68 65 20 43 4F 4D 20 6F 62 6A 65 63 74 73 20 74 68 61 74 20 77 65 20 77 69 6C 6C 20 62 65 20 75 73 69 6E 67 20 2D 2D 20 27}

// 	condition:
// 		all of them
// }

// rule KA_uShell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file KA_uShell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "685f5d4f7f6751eaefc2695071569aab"

// 	strings:
// 		$s5 = {69 66 28 65 6D 70 74 79 28 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 50 57 27 5D 29 20 7C 7C 20 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 50 57 27 5D 3C 3E 24 70 61 73 73}
// 		$s6 = {69 66 20 28 24 5F 50 4F 53 54 5B 27 70 61 74 68 27 5D 3D 3D 5C 22 5C 22 29 7B 24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 5F 46 49 4C 45 53 5B 27 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B 7D}

// 	condition:
// 		all of them
// }

// rule PHP_Backdoor_v1
// {
// 	meta:
// 		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "0506ba90759d11d78befd21cabf41f3d"

// 	strings:
// 		$s5 = {65 63 68 6F 5C 22 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 65 64 69 74 3D 5C 22 2E 24 74 68}
// 		$s8 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 70 72 6F 78 79}

// 	condition:
// 		all of them
// }

// rule svchostdll
// {
// 	meta:
// 		description = "Webshells Auto-generated - file svchostdll.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "0f6756c8cb0b454c452055f189e4c3f4"

// 	strings:
// 		$s0 = {49 6E 73 74 61 6C 6C 53 65 72 76 69 63 65}
// 		$s1 = {52 75 6E 64 6C 6C 49 6E 73 74 61 6C 6C 41}
// 		$s2 = {55 6E 69 6E 73 74 61 6C 6C 53 65 72 76 69 63 65}
// 		$s3 = {26 47 33 20 55 73 65 72 73 20 49 6E 20 52 65 67 69 73 74 72 79 44}
// 		$s4 = {4F 4C 5F 53 48 55 54 44 4F 57 4E 3B 49}
// 		$s5 = {53 76 63 48 6F 73 74 44 4C 4C 2E 64 6C 6C}
// 		$s6 = {52 75 6E 64 6C 6C 55 6E 69 6E 73 74 61 6C 6C 41}
// 		$s7 = {49 6E 74 65 72 6E 65 74 4F 70 65 6E 41}
// 		$s8 = {43 68 65 63 6B 20 43 6C 6F 6E 65 6F 6D 70 6C 65 74 65}

// 	condition:
// 		all of them
// }

// rule HYTop_DevPack_server
// {
// 	meta:
// 		description = "Webshells Auto-generated - file server.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1d38526a215df13c7373da4635541b43"

// 	strings:
// 		$s0 = {3C 21 2D 2D 20 50 61 67 65 53 65 72 76 65 72 20 42 65 6C 6F 77 20 2D 2D 3E}

// 	condition:
// 		all of them
// }

// rule vanquish
// {
// 	meta:
// 		description = "Webshells Auto-generated - file vanquish.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "684450adde37a93e8bb362994efc898c"

// 	strings:
// 		$s3 = {59 6F 75 20 63 61 6E 6E 6F 74 20 64 65 6C 65 74 65 20 70 72 6F 74 65 63 74 65 64 20 66 69 6C 65 73 2F 66 6F 6C 64 65 72 73 21 20 49 6E 73 74 65 61 64 2C 20 79 6F 75 72 20 61 74 74 65 6D 70 74 20 68 61 73 20 62 65 65 6E 20 6C 6F 67 67 65 64}
// 		$s8 = {3F 56 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 40 40 59 47 48 50 42 44 50 41 44 50 41 55 5F 53 45 43 55 52 49 54 59 5F 41 54 54 52 49 42 55 54 45 53 40 40 32 48 4B 50 41 58 30 50 41 55 5F 53 54 41 52 54 55 50 49 4E 46 4F 41 40 40 50 41 55}
// 		$s9 = {3F 56 46 69 6E 64 46 69 72 73 74 46 69 6C 65 45 78 57 40 40 59 47 50 41 58 50 42 47 57 34 5F 46 49 4E 44 45 58 5F 49 4E 46 4F 5F 4C 45 56 45 4C 53 40 40 50 41 58 57 34 5F 46 49 4E 44 45 58 5F 53 45 41 52 43 48 5F 4F 50 53 40 40 32 4B 40 5A}

// 	condition:
// 		all of them
// }

// rule winshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file winshell.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "3144410a37dd4c29d004a814a294ea26"

// 	strings:
// 		$s0 = {53 6F 66 74 77 61 72 65 5C 5C 4D 69 63 72 6F 73 6F 66 74 5C 5C 57 69 6E 64 6F 77 73 5C 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 5C 52 75 6E 53 65 72 76 69 63 65 73}
// 		$s1 = {57 69 6E 53 68 65 6C 6C 20 53 65 72 76 69 63 65}
// 		$s2 = {5F 5F 47 4C 4F 42 41 4C 5F 48 45 41 50 5F 53 45 4C 45 43 54 45 44}
// 		$s3 = {5F 5F 4D 53 56 43 52 54 5F 48 45 41 50 5F 53 45 4C 45 43 54}
// 		$s4 = {50 72 6F 76 69 64 65 20 57 69 6E 64 6F 77 73 20 43 6D 64 53 68 65 6C 6C 20 53 65 72 76 69 63 65}
// 		$s5 = {55 52 4C 44 6F 77 6E 6C 6F 61 64 54 6F 46 69 6C 65 41}
// 		$s6 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6F 63 65 73 73}
// 		$s7 = {47 65 74 4D 6F 64 75 6C 65 42 61 73 65 4E 61 6D 65 41}
// 		$s8 = {57 69 6E 53 68 65 6C 6C 20 76 35 2E 30 20 28 43 29 32 30 30 32 20 6A 61 6E 6B 65 72 2E 6F 72 67}

// 	condition:
// 		all of them
// }

// rule FSO_s_remview
// {
// 	meta:
// 		description = "Webshells Auto-generated - file remview.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b4a09911a5b23e00b55abe546ded691c"

// 	strings:
// 		$s2 = {20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 68 72 20 73 69 7A 65 3D 31 20 6E 6F 73 68 61 64 65 3E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 22}
// 		$s3 = {20 20 20 20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 73 63 72 69 70 74 3E 73 74 72 24 69 3D 5C 5C 5C 22 5C 22 2E 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 22 5C 22 2C 5C 22 5C 5C 5C 5C 5C 5C 5C 22 5C 22 2C 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22}
// 		$s4 = {20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 68 72 20 73 69 7A 65 3D 31 20 6E 6F 73 68 61 64 65 3E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 3C}

// 	condition:
// 		all of them
// }

// rule saphpshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file saphpshell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "d7bba8def713512ddda14baf9cd6889a"

// 	strings:
// 		$s0 = {3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 63 6F 6D 6D 61 6E 64 5C 22 20 73 69 7A 65 3D 5C 22 36 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 3F 3E}

// 	condition:
// 		all of them
// }

// rule HYTop2006_rar_Folder_2006Z
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2006Z.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "fd1b6129abd4ab177fed135e3b665488"

// 	strings:
// 		$s1 = {77 61 6E 67 79 6F 6E 67 2C 63 7A 79 2C 61 6C 6C 65 6E 2C 6C 63 78 2C 4D 61 72 63 6F 73 2C 6B 45 76 69 6E 31 39 38 36 2C 6D 79 74 68}
// 		$s8 = {53 79 73 74 65 6D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 4B 65 79 62 6F 61 72 64 20 4C 61 79 6F 75 74 73 5C 5C 25 2E 38 78}

// 	condition:
// 		all of them
// }

// rule admin_ad
// {
// 	meta:
// 		description = "Webshells Auto-generated - file admin-ad.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"

// 	strings:
// 		$s6 = {3C 74 64 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 20 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 63 6D 64 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 69 64 3D 5C 22 63 6D 64 5C 22 20 73 69 7A}
// 		$s7 = {52 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 5C 22 3C 61 20 68 72 65 66 3D 27 5C 22 26 75 72 6C 26 5C 22 3F 70 61 74 68 3D 5C 22 26 52 65 71 75 65 73 74 28 5C 22 6F 6C 64 70 61 74 68 5C 22 29 26 5C 22 26 61 74 74 72 69 62 3D 5C 22 26 61 74 74 72 69 62 26 5C 22 27 3E 3C}

// 	condition:
// 		all of them
// }

// rule FSO_s_casus15
// {
// 	meta:
// 		description = "Webshells Auto-generated - file casus15.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8d155b4239d922367af5d0a1b89533a3"

// 	strings:
// 		$s6 = {69 66 28 28 69 73 5F 64 69 72 28 5C 22 24 64 65 6C 64 69 72 2F 24 66 69 6C 65 5C 22 29 29 20 41 4E 44 20 28 24 66 69 6C 65 21 3D 5C 22 2E 5C 22 29 20 41 4E 44 20 28 24 66 69 6C 65 21 3D 5C 22 2E 2E 5C 22 29 29}

// 	condition:
// 		all of them
// }

// rule BIN_Client
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Client.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"

// 	strings:
// 		$s0 = {3D 3D 3D 3D 3D 52 65 6D 6F 74 65 20 53 68 65 6C 6C 20 43 6C 6F 73 65 64 3D 3D 3D 3D 3D}
// 		$s2 = {41 6C 6C 20 46 69 6C 65 73 28 2A 2E 2A 29 7C 2A 2E 2A 7C 7C}
// 		$s6 = {57 53 41 53 74 61 72 74 75 70 20 45 72 72 6F 72 21}
// 		$s7 = {53 48 47 65 74 46 69 6C 65 49 6E 66 6F 41}
// 		$s8 = {43 72 65 61 74 65 54 68 72 65 61 64 20 46 61 6C 73 65 21}
// 		$s9 = {50 6F 72 74 20 4E 75 6D 62 65 72 20 45 72 72 6F 72}

// 	condition:
// 		4 of them
// }

// rule shelltools_g0t_root_uptime
// {
// 	meta:
// 		description = "Webshells Auto-generated - file uptime.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"

// 	strings:
// 		$s0 = {4A 44 69 61 6D 6F 6E 64 43 53 6C 43 7E}
// 		$s1 = {43 68 61 72 61 63 74 51 41}
// 		$s2 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 24}
// 		$s5 = {48 61 6E 64 6C 65 72 65 61 74 65 43 6F 6E 73 6F}
// 		$s7 = {49 4F 4E 5C 5C 53 79 73 74 65 6D 5C 5C 46 6C 6F 61 74 69 6E 67 50 6F}

// 	condition:
// 		all of them
// }

// rule Simple_PHP_BackDooR
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a401132363eecc3a1040774bec9cb24f"

// 	strings:
// 		$s0 = {3C 68 72 3E 74 6F 20 62 72 6F 77 73 65 20 67 6F 20 74 6F 20 68 74 74 70 3A 2F 2F 3C 3F 20 65 63 68 6F 20 24 53 45 52 56 45 52 5F 4E 41 4D 45 2E 24 52 45 51 55 45 53 54 5F 55 52 49 3B 20 3F 3E 3F 64 3D 5B 64 69 72 65 63 74 6F 72 79 20 68 65}
// 		$s6 = {69 66 28 21 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 66 69 6C 65 5F 6E 61 6D 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 64 69 72 2E 24 66 6E}
// 		$s9 = {2F 2F 20 61 20 73 69 6D 70 6C 65 20 70 68 70 20 62 61 63 6B 64 6F 6F 72}

// 	condition:
// 		1 of them
// }

// rule sig_2005Gray
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2005Gray.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "75dbe3d3b70a5678225d3e2d78b604cc"

// 	strings:
// 		$s0 = {53 43 52 4F 4C 4C 42 41 52 2D 46 41 43 45 2D 43 4F 4C 4F 52 3A 20 23 65 38 65 37 65 37 3B}
// 		$s4 = {65 63 68 6F 20 5C 22 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 22 5C 22 2F 5C 22 26 65 6E 63 6F 64 65 46 6F 72 55 72 6C 28 74 68 65 48 72 65 66 2C 66 61 6C 73 65 29 26 5C 22 5C 22 5C 22 20 74 61 72 67 65 74 3D 5F 62 6C 61 6E 6B 3E 5C 22 26 72 65 70 6C 61 63 65}
// 		$s8 = {74 68 65 48 72 65 66 3D 6D 69 64 28 72 65 70 6C 61 63 65 28 6C 63 61 73 65 28 6C 69 73 74 2E 70 61 74 68 29 2C 6C 63 61 73 65 28 73 65 72 76 65 72 2E 6D 61 70 50 61 74 68 28 5C 22 2F 5C 22 29 29 2C 5C 22 5C 22 29 2C 32 29}
// 		$s9 = {53 43 52 4F 4C 4C 42 41 52 2D 33 44 4C 49 47 48 54 2D 43 4F 4C 4F 52 3A 20 23 63 63 63 63 63 63 3B}

// 	condition:
// 		all of them
// }

// rule DllInjection
// {
// 	meta:
// 		description = "Webshells Auto-generated - file DllInjection.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a7b92283a5102886ab8aee2bc5c8d718"

// 	strings:
// 		$s0 = {5C 5C 42 44 6F 6F 72 5C 5C 44 6C 6C 49 6E 6A 65 63 74 69}

// 	condition:
// 		all of them
// }

// rule Mithril_v1_45_Mithril
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Mithril.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "f1484f882dc381dde6eaa0b80ef64a07"

// 	strings:
// 		$s2 = {63 72 65 73 73 2E 65 78 65}
// 		$s7 = {5C 5C 44 65 62 75 67 5C 5C 4D 69 74 68 72 69 6C 2E}

// 	condition:
// 		all of them
// }

// rule hkshell_hkrmv
// {
// 	meta:
// 		description = "Webshells Auto-generated - file hkrmv.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"

// 	strings:
// 		$s5 = {2F 54 48 55 4D 42 50 4F 53 49 54 49 4F 4E 37}
// 		$s6 = {5C 5C 45 76 69 6C 42 6C 61 64 65 5C 5C}

// 	condition:
// 		all of them
// }

// rule phpshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phpshell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1dccb1ea9f24ffbd085571c88585517b"

// 	strings:
// 		$s1 = {65 63 68 6F 20 5C 22 3C 69 6E 70 75 74 20 73 69 7A 65 3D 5C 5C 5C 22 31 30 30 5C 5C 5C 22 20 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 6E 65 77 66 69 6C 65 5C 5C 5C 22 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 69 6E 70 75 74 66 69 6C 65 5C 5C 5C 22 3E 3C 62}
// 		$s2 = {24 69 6D 67 5B 24 69 64 5D 20 3D 20 5C 22 3C 69 6D 67 20 68 65 69 67 68 74 3D 5C 5C 5C 22 31 36 5C 5C 5C 22 20 77 69 64 74 68 3D 5C 5C 5C 22 31 36 5C 5C 5C 22 20 62 6F 72 64 65 72 3D 5C 5C 5C 22 30 5C 5C 5C 22 20 73 72 63 3D 5C 5C 5C 22 24 52 45 4D 4F 54 45 5F 49 4D 41 47 45 5F 55 52}
// 		$s3 = {24 66 69 6C 65 20 3D 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 20 5C 22 2F 5C 22 2C 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 2F 2F 5C 22 2C 20 5C 22 2F 5C 22 2C 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22 2C 20 5C 22 5C 5C 5C 5C 5C 22 2C 20}

// 	condition:
// 		all of them
// }

// // duplicated
// /* rule FSO_s_cmd
// {
// 	meta:
// 		description = "Webshells Auto-generated - file cmd.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "cbe8e365d41dd3cd8e462ca434cf385f"

// 	strings:
// 		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}
// 		$s1 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}

// 	condition:
// 		all of them
// }*/

// rule FeliksPack3___PHP_Shells_phpft
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phpft.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "60ef80175fcc6a879ca57c54226646b1"

// 	strings:
// 		$s6 = {50 48 50 20 46 69 6C 65 73 20 54 68 69 65 66}
// 		$s11 = {68 74 74 70 3A 2F 2F 77 77 77 2E 34 6E 67 65 6C 2E 6E 65 74}

// 	condition:
// 		all of them
// }

// rule FSO_s_indexer
// {
// 	meta:
// 		description = "Webshells Auto-generated - file indexer.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "135fc50f85228691b401848caef3be9e"

// 	strings:
// 		$s3 = {3C 74 64 3E 4E 65 72 65 79 65 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 65 79 65 5C 22 20 73 69 7A 65 3D 32 35 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 72}

// 	condition:
// 		all of them
// }

// rule r57shell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file r57shell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8023394542cddf8aee5dec6072ed02b5"

// 	strings:
// 		$s11 = {20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 5C 22 65 63 68 6F 20 5C 5C 5C 22 4E 6F 77 20 73 63 72 69 70 74 20 74 72 79 20 63 6F 6E 6E 65 63 74 20 74 6F}

// 	condition:
// 		all of them
// }

// rule bdcli100
// {
// 	meta:
// 		description = "Webshells Auto-generated - file bdcli100.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b12163ac53789fb4f62e4f17a8c2e028"

// 	strings:
// 		$s5 = {75 6E 61 62 6C 65 20 74 6F 20 63 6F 6E 6E 65 63 74 20 74 6F 20}
// 		$s8 = {62 61 63 6B 64 6F 6F 72 20 69 73 20 63 6F 72 72 75 70 74 65 64 20 6F 6E 20}

// 	condition:
// 		all of them
// }

// rule HYTop_DevPack_2005Red
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2005Red.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"

// 	strings:
// 		$s0 = {73 63 72 6F 6C 6C 62 61 72 2D 64 61 72 6B 73 68 61 64 6F 77 2D 63 6F 6C 6F 72 3A 23 46 46 39 44 42 42 3B}
// 		$s3 = {65 63 68 6F 20 5C 22 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 22 5C 22 2F 5C 22 26 65 6E 63 6F 64 65 46 6F 72 55 72 6C 28 74 68 65 48 72 65 66 2C 66 61 6C 73 65 29 26 5C 22 5C 22 5C 22 20 74 61 72 67 65 74 3D 5F 62 6C 61 6E 6B 3E 5C 22 26 72 65 70 6C 61 63 65}
// 		$s9 = {74 68 65 48 72 65 66 3D 6D 69 64 28 72 65 70 6C 61 63 65 28 6C 63 61 73 65 28 6C 69 73 74 2E 70 61 74 68 29 2C 6C 63 61 73 65 28 73 65 72 76 65 72 2E 6D 61 70 50 61 74 68 28 5C 22 2F 5C 22 29 29 2C 5C 22 5C 22 29 2C 32 29}

// 	condition:
// 		all of them
// }

// rule HYTop2006_rar_Folder_2006X2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2006X2.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "cc5bf9fc56d404ebbc492855393d7620"

// 	strings:
// 		$s2 = {50 6F 77 65 72 65 64 20 42 79 20}
// 		$s3 = {20 5C 22 20 6F 6E 43 6C 69 63 6B 3D 5C 22 74 68 69 73 2E 66 6F 72 6D 2E 73 68 61 72 70 2E 6E 61 6D 65 3D 74 68 69 73 2E 66 6F 72 6D 2E 70 61 73 73 77 6F 72 64 2E 76 61 6C 75 65 3B 74 68 69 73 2E 66 6F 72 6D 2E 61 63 74 69 6F 6E 3D 74 68 69 73 2E}

// 	condition:
// 		all of them
// }

// rule rdrbs084
// {
// 	meta:
// 		description = "Webshells Auto-generated - file rdrbs084.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "ed30327b255816bdd7590bf891aa0020"

// 	strings:
// 		$s0 = {43 72 65 61 74 65 20 6D 61 70 70 65 64 20 70 6F 72 74 2E 20 59 6F 75 20 68 61 76 65 20 74 6F 20 73 70 65 63 69 66 79 20 64 6F 6D 61 69 6E 20 77 68 65 6E 20 75 73 69 6E 67 20 48 54 54 50 20 74 79 70 65 2E}
// 		$s8 = {3C 4C 4F 43 41 4C 20 50 4F 52 54 3E 20 3C 4D 41 50 50 49 4E 47 20 53 45 52 56 45 52 3E 20 3C 4D 41 50 50 49 4E 47 20 53 45 52 56 45 52 20 50 4F 52 54 3E 20 3C 54 41 52 47 45 54 20 53 45 52 56 45 52 3E 20 3C 54 41 52 47 45 54}

// 	condition:
// 		all of them
// }

// rule HYTop_CaseSwitch_2005
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2005.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8bf667ee9e21366bc0bd3491cb614f41"

// 	strings:
// 		$s1 = {4D 53 43 6F 6D 44 6C 67 2E 43 6F 6D 6D 6F 6E 44 69 61 6C 6F 67}
// 		$s2 = {43 6F 6D 6D 6F 6E 44 69 61 6C 6F 67 31}
// 		$s3 = {5F 5F 76 62 61 45 78 63 65 70 74 48 61 6E 64 6C 65 72}
// 		$s4 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 52 65 6C 65 61 73 65}
// 		$s5 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 41 64 64 52 65 66}
// 		$s6 = {42 79 20 4D 61 72 63 6F 73}
// 		$s7 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 51 75 65 72 79 49 6E 74 65 72 66 61 63 65}
// 		$s8 = {4D 65 74 68 43 61 6C 6C 45 6E 67 69 6E 65}

// 	condition:
// 		all of them
// }

// rule eBayId_index3
// {
// 	meta:
// 		description = "Webshells Auto-generated - file index3.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "0412b1e37f41ea0d002e4ed11608905f"

// 	strings:
// 		$s8 = {24 65 72 72 20 3D 20 5C 22 3C 69 3E 59 6F 75 72 20 4E 61 6D 65 3C 2F 69 3E 20 4E 6F 74 20 45 6E 74 65 72 65 64 21 3C 2F 66 6F 6E 74 3E 3C 2F 68 32 3E 53 6F 72 72 79 2C 20 5C 5C 5C 22 59 6F 75}

// 	condition:
// 		all of them
// }

// rule FSO_s_phvayv
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phvayv.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "205ecda66c443083403efb1e5c7f7878"

// 	strings:
// 		$s2 = {77 72 61 70 3D 5C 22 4F 46 46 5C 22 3E 58 58 58 58 3C 2F 74 65 78 74 61 72 65 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65}

// 	condition:
// 		all of them
// }

// rule byshell063_ntboot
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ntboot.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"

// 	strings:
// 		$s0 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 53 65 72 76 69 63 65 73 5C 5C 4E 74 42 6F 6F 74}
// 		$s1 = {46 61 69 6C 75 72 65 20 2E 2E 2E 20 41 63 63 65 73 73 20 69 73 20 44 65 6E 69 65 64 20 21}
// 		$s2 = {44 75 6D 70 69 6E 67 20 44 65 73 63 72 69 70 74 69 6F 6E 20 74 6F 20 52 65 67 69 73 74 72 79 2E 2E 2E}
// 		$s3 = {4F 70 65 6E 69 6E 67 20 53 65 72 76 69 63 65 20 2E 2E 2E 2E 20 46 61 69 6C 75 72 65 20 21}

// 	condition:
// 		all of them
// }

// rule FSO_s_casus15_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file casus15.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8d155b4239d922367af5d0a1b89533a3"

// 	strings:
// 		$s0 = {63 6F 70 79 20 28 20 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72}

// 	condition:
// 		all of them
// }

// rule installer
// {
// 	meta:
// 		description = "Webshells Auto-generated - file installer.cmd"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a507919ae701cf7e42fa441d3ad95f8f"

// 	strings:
// 		$s0 = {52 65 73 74 6F 72 65 20 4F 6C 64 20 56 61 6E 71 75 69 73 68}
// 		$s4 = {52 65 49 6E 73 74 61 6C 6C 20 56 61 6E 71 75 69 73 68}

// 	condition:
// 		all of them
// }

// // duplicated
// /* rule uploader
// {
// 	meta:
// 		description = "Webshells Auto-generated - file uploader.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b9a9aab319964351b46bd5fc9d6246a8"

// 	strings:
// 		$s0 = {6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 2C 20 5C 22 65 6E 74 72 69 6B 61 2E 70 68 70 5C 22 29 3B 20}

// 	condition:
// 		all of them
// }*/

// rule FSO_s_remview_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file remview.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b4a09911a5b23e00b55abe546ded691c"

// 	strings:
// 		$s0 = {3C 78 6D 70 3E 24 6F 75 74 3C 2F}
// 		$s1 = {2E 6D 6D 28 5C 22 45 76 61 6C 20 50 48 50 20 63 6F 64 65 5C 22 29 2E}

// 	condition:
// 		all of them
// }

// rule FeliksPack3___PHP_Shells_r57
// {
// 	meta:
// 		description = "Webshells Auto-generated - file r57.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "903908b77a266b855262cdbce81c3f72"

// 	strings:
// 		$s1 = {24 73 71 6C 20 3D 20 5C 22 4C 4F 41 44 20 44 41 54 41 20 49 4E 46 49 4C 45 20 5C 5C 5C 22 5C 22 2E 24 5F 50 4F 53 54 5B 27 74 65 73 74 33 5F 66 69 6C 65 27 5D 2E}

// 	condition:
// 		all of them
// }

// rule HYTop2006_rar_Folder_2006X
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2006X.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"

// 	strings:
// 		$s1 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 74 79 70 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 69 64 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22}
// 		$s6 = {6E 61 6D 65 3D 5C 22 74 68 65 41 63 74 69 6F 6E 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 69 64 3D 5C 22 74 68 65 41 63 74 69 6F 6E 5C 22}

// 	condition:
// 		all of them
// }

// rule FSO_s_phvayv_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phvayv.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "205ecda66c443083403efb1e5c7f7878"

// 	strings:
// 		$s2 = {72 6F 77 73 3D 5C 22 32 34 5C 22 20 63 6F 6C 73 3D 5C 22 31 32 32 5C 22 20 77 72 61 70 3D 5C 22 4F 46 46 5C 22 3E 58 58 58 58 3C 2F 74 65 78 74 61 72 65 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74}

// 	condition:
// 		all of them
// }

// rule elmaliseker
// {
// 	meta:
// 		description = "Webshells Auto-generated - file elmaliseker.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "ccf48af0c8c09bbd038e610a49c9862e"

// 	strings:
// 		$s0 = {6A 61 76 61 73 63 72 69 70 74 3A 43 6F 6D 6D 61 6E 64 28 27 44 6F 77 6E 6C 6F 61 64 27}
// 		$s5 = {7A 6F 6D 62 69 65 5F 61 72 72 61 79 3D 61 72 72 61 79 28}

// 	condition:
// 		all of them
// }

// rule shelltools_g0t_root_resolve
// {
// 	meta:
// 		description = "Webshells Auto-generated - file resolve.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "69bf9aa296238610a0e05f99b5540297"

// 	strings:
// 		$s0 = {33 5E 6E 36 42 28 45 64 33}
// 		$s1 = {5E 75 6C 64 6E 27 56 74 28 78}
// 		$s2 = {5C 5C 3D 20 75 50 4B 66 70}
// 		$s3 = {27 72 2E 61 78 56 3C 61 64}
// 		$s4 = {70 2C 6D 6F 64 6F 69 24 3D 73 72 28}
// 		$s5 = {44 69 61 6D 6F 6E 64 43 38 53 20 74}
// 		$s6 = {60 6C 51 39 66 58 3C 5A 76 4A 57}

// 	condition:
// 		all of them
// }

// rule FSO_s_RemExp
// {
// 	meta:
// 		description = "Webshells Auto-generated - file RemExp.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b69670ecdbb40012c73686cd22696eeb"

// 	strings:
// 		$s1 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 53 75 62 46 6F 6C 64 65 72 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 3C 25 3D 52 65 71 75 65 73 74 2E 53 65 72}
// 		$s5 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 46 69 6C 65 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 73 68 6F 77 63 6F 64 65 2E 61 73 70 3F 66 3D 3C 25 3D 46}
// 		$s6 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 61 6C 69 67 6E 3D 5C 22 72 69 67 68 74 5C 22 3E 3C 25 3D 41 74 74 72 69 62 75 74 65 73 28 53 75 62 46 6F 6C 64 65 72 2E 41 74 74 72 69 62 75 74 65 73 29 25 3E 3C 2F}

// 	condition:
// 		all of them
// }

// rule FSO_s_tool
// {
// 	meta:
// 		description = "Webshells Auto-generated - file tool.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "3a1e1e889fdd974a130a6a767b42655b"

// 	strings:
// 		$s7 = {5C 22 5C 22 25 77 69 6E 64 69 72 25 5C 5C 5C 5C 63 61 6C 63 2E 65 78 65 5C 22 5C 22 29}

// 	condition:
// 		all of them
// }

// rule FeliksPack3___PHP_Shells_2005
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2005.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "97f2552c2fafc0b2eb467ee29cc803c8"

// 	strings:
// 		$s0 = {77 69 6E 64 6F 77 2E 6F 70 65 6E 28 5C 22 5C 22 26 75 72 6C 26 5C 22 3F 69 64 3D 65 64 69 74 26 70 61 74 68 3D 5C 22 2B 73 66 69 6C 65 2B 5C 22 26 6F 70 3D 63 6F 70 79 26 61 74 74 72 69 62 3D 5C 22 2B 61 74 74 72 69 62 2B 5C 22 26 64 70 61 74 68 3D 5C 22 2B 6C 70}
// 		$s3 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 64 62 6E 61 6D 65 5C 22 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 69 64 3D 5C 22 64 62 6E 61 6D 65 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 72 65 71 75 65 73 74 28 5C 22 64 62 6E 61 6D 65 5C 22 29 25 3E 5C 22 3E}

// 	condition:
// 		all of them
// }

// rule byloader
// {
// 	meta:
// 		description = "Webshells Auto-generated - file byloader.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "0f0d6dc26055653f5844ded906ce52df"

// 	strings:
// 		$s0 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 53 65 72 76 69 63 65 73 5C 5C 4E 74 66 73 43 68 6B}
// 		$s1 = {46 61 69 6C 75 72 65 20 2E 2E 2E 20 41 63 63 65 73 73 20 69 73 20 44 65 6E 69 65 64 20 21}
// 		$s2 = {4E 54 46 53 20 44 69 73 6B 20 44 72 69 76 65 72 20 43 68 65 63 6B 69 6E 67 20 53 65 72 76 69 63 65}
// 		$s3 = {44 75 6D 70 69 6E 67 20 44 65 73 63 72 69 70 74 69 6F 6E 20 74 6F 20 52 65 67 69 73 74 72 79 2E 2E 2E}
// 		$s4 = {4F 70 65 6E 69 6E 67 20 53 65 72 76 69 63 65 20 2E 2E 2E 2E 20 46 61 69 6C 75 72 65 20 21}

// 	condition:
// 		all of them
// }

// rule shelltools_g0t_root_Fport
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Fport.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "dbb75488aa2fa22ba6950aead1ef30d5"

// 	strings:
// 		$s4 = {43 6F 70 79 72 69 67 68 74 20 32 30 30 30 20 62 79 20 46 6F 75 6E 64 73 74 6F 6E 65 2C 20 49 6E 63 2E}
// 		$s5 = {59 6F 75 20 6D 75 73 74 20 68 61 76 65 20 61 64 6D 69 6E 69 73 74 72 61 74 6F 72 20 70 72 69 76 69 6C 65 67 65 73 20 74 6F 20 72 75 6E 20 66 70 6F 72 74 20 2D 20 65 78 69 74 69 6E 67 2E 2E 2E}

// 	condition:
// 		all of them
// }

// rule BackDooR__fr_
// {
// 	meta:
// 		description = "Webshells Auto-generated - file BackDooR (fr).php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a79cac2cf86e073a832aaf29a664f4be"

// 	strings:
// 		$s3 = {70 72 69 6E 74 28 5C 22 3C 70 20 61 6C 69 67 6E 3D 5C 5C 5C 22 63 65 6E 74 65 72 5C 5C 5C 22 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 5C 5C 5C 22 35 5C 5C 5C 22 3E 45 78 70 6C 6F 69 74 20 69 6E 63 6C 75 64 65 20}

// 	condition:
// 		all of them
// }

// rule FSO_s_ntdaddy
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ntdaddy.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"

// 	strings:
// 		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 2E 43 4D 44 5C 22 20 73 69 7A 65 3D 5C 22 34 35 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 20 73 7A 43 4D 44 20 25 3E 5C 22 3E 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73}

// 	condition:
// 		all of them
// }

// rule nstview_nstview
// {
// 	meta:
// 		description = "Webshells Auto-generated - file nstview.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "3871888a0c1ac4270104918231029a56"

// 	strings:
// 		$s4 = {6F 70 65 6E 20 53 54 44 49 4E 2C 5C 5C 5C 22 3C 26 58 5C 5C 5C 22 3B 6F 70 65 6E 20 53 54 44 4F 55 54 2C 5C 5C 5C 22 3E 26 58 5C 5C 5C 22 3B 6F 70 65 6E 20 53 54 44 45 52 52 2C 5C 5C 5C 22 3E 26 58 5C 5C 5C 22 3B 65 78 65 63 28 5C 5C 5C 22 2F 62 69 6E 2F 73 68 20 2D 69 5C 5C 5C 22 29 3B}

// 	condition:
// 		all of them
// }

// rule HYTop_DevPack_upload
// {
// 	meta:
// 		description = "Webshells Auto-generated - file upload.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b09852bda534627949f0259828c967de"

// 	strings:
// 		$s0 = {3C 21 2D 2D 20 50 61 67 65 55 70 6C 6F 61 64 20 42 65 6C 6F 77 20 2D 2D 3E}

// 	condition:
// 		all of them
// }

// rule PasswordReminder
// {
// 	meta:
// 		description = "Webshells Auto-generated - file PasswordReminder.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"

// 	strings:
// 		$s3 = {54 68 65 20 65 6E 63 6F 64 65 64 20 70 61 73 73 77 6F 72 64 20 69 73 20 66 6F 75 6E 64 20 61 74 20 30 78 25 38 2E 38 6C 78 20 61 6E 64 20 68 61 73 20 61 20 6C 65 6E 67 74 68 20 6F 66 20 25 64 2E}

// 	condition:
// 		all of them
// }

// rule Pack_InjectT
// {
// 	meta:
// 		description = "Webshells Auto-generated - file InjectT.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "983b74ccd57f6195a0584cdfb27d55e8"

// 	strings:
// 		$s3 = {61 69 6C 20 54 6F 20 4F 70 65 6E 20 52 65 67 69 73 74 72 79}
// 		$s4 = {33 32 66 44 73 73 69 67 6E 69 6D}
// 		$s5 = {76 69 64 65 20 49 6E 74 65 72 6E 65 74 20 53}
// 		$s6 = {64 5D 53 6F 66 74 77 61 72 65 5C 5C 4D}
// 		$s7 = {54 49 6E 6A 65 63 74 2E 44 6C 6C}

// 	condition:
// 		all of them
// }

// rule FSO_s_RemExp_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file RemExp.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b69670ecdbb40012c73686cd22696eeb"

// 	strings:
// 		$s2 = {20 54 68 65 6E 20 52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22}
// 		$s3 = {3C 61 20 68 72 65 66 3D 20 5C 22 3C 25 3D 52 65 71 75 65 73 74 2E 53 65 72 76 65 72 56 61 72 69 61 62 6C 65 73 28 5C 22 73 63 72 69 70 74 5F 6E 61 6D 65 5C 22 29 25 3E}

// 	condition:
// 		all of them
// }

// rule FSO_s_c99
// {
// 	meta:
// 		description = "Webshells Auto-generated - file c99.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5f9ba02eb081bba2b2434c603af454d0"

// 	strings:
// 		$s2 = {5C 22 74 78 74 5C 22 2C 5C 22 63 6F 6E 66 5C 22 2C 5C 22 62 61 74 5C 22 2C 5C 22 73 68 5C 22 2C 5C 22 6A 73 5C 22 2C 5C 22 62 61 6B 5C 22 2C 5C 22 64 6F 63 5C 22 2C 5C 22 6C 6F 67 5C 22 2C 5C 22 73 66 63 5C 22 2C 5C 22 63 66 67 5C 22 2C 5C 22 68 74 61 63 63 65}

// 	condition:
// 		all of them
// }

// rule rknt_zip_Folder_RkNT
// {
// 	meta:
// 		description = "Webshells Auto-generated - file RkNT.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5f97386dfde148942b7584aeb6512b85"

// 	strings:
// 		$s0 = {50 61 74 68 53 74 72 69 70 50 61 74 68 41}
// 		$s1 = {60 63 4C 47 65 74 21 41 64 64 72 25}
// 		$s2 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 68 74 74 70 3A 2F 2F 75 70 78 2E 74 73 78 2E 6F 72 67 20 24}
// 		$s3 = {6F 51 54 6F 4F 65 6D 42 75 66 66 2A 20 3C 3D}
// 		$s4 = {69 6F 6E 43 64 75 6E 41 73 77 5B 55 73 27}
// 		$s6 = {43 72 65 61 74 65 50 72 6F 63 65 73 73 57 3A 20 25 53}
// 		$s7 = {49 6D 61 67 65 44 69 72 65 63 74 6F 72 79 45 6E 74 72 79 54 6F 44 61 74 61}

// 	condition:
// 		all of them
// }

// rule dbgntboot
// {
// 	meta:
// 		description = "Webshells Auto-generated - file dbgntboot.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "4d87543d4d7f73c1529c9f8066b475ab"

// 	strings:
// 		$s2 = {6E 6F 77 20 44 4F 53 20 69 73 20 77 6F 72 6B 69 6E 67 20 61 74 20 6D 6F 64 65 20 25 64 2C 66 61 6B 65 74 79 70 65 20 25 64 2C 61 67 61 69 6E 73 74 20 25 73 2C 68 61 73 20 77 6F 72 6B 65 64 20 25 64 20 6D 69 6E 75 74 65 73 2C 62 79 20 73 70}
// 		$s3 = {73 74 68 20 6A 75 6E 6B 20 74 68 65 20 4D 24 20 57 69 6E 64 30 77 5A 20 72 65 74 75 72}

// 	condition:
// 		all of them
// }

// rule PHP_shell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file shell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "45e8a00567f8a34ab1cccc86b4bc74b9"

// 	strings:
// 		$s0 = {41 52 38 69 52 4F 45 54 36 6D 4D 6E 72 71 54 70 43 36 57 31 4B 70 2F 44 73 54 67 78 4E 62 79 39 48 31 78 68 69 73 77 66 77 67 6F 41 74 45 44 30 79 36 77 45 58 54 69 68 6F 41 74 49 43 6B 49 58 36 4C 31 2B 76 54 55 59 57 75 57 7A}
// 		$s11 = {31 48 4C 70 31 71 6E 6C 43 79 6C 35 67 6B 6F 38 72 44 6C 57 48 71 66 38 2F 4A 6F 50 4B 76 47 77 45 6D 39 51 34 6E 56 4B 76 45 68 30 62 30 50 4B 6C 65 33 7A 65 46 69 4A 4E 79 6A 78 4F 69 56 65 70 4D 53 70 66 6C 4A 6B 50 76 35 73}

// 	condition:
// 		all of them
// }

// rule hxdef100
// {
// 	meta:
// 		description = "Webshells Auto-generated - file hxdef100.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "55cc1769cef44910bd91b7b73dee1f6c"

// 	strings:
// 		$s0 = {52 74 6C 41 6E 73 69 53 74 72 69 6E 67 54 6F 55 6E 69 63 6F 64 65 53 74 72 69 6E 67}
// 		$s8 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 53 61 66 65 42 6F 6F 74 5C 5C}
// 		$s9 = {5C 5C 5C 5C 2E 5C 5C 6D 61 69 6C 73 6C 6F 74 5C 5C 68 78 64 65 66 2D 72 6B 31 30 30 73 41 42 43 44 45 46 47 48}

// 	condition:
// 		all of them
// }

// rule rdrbs100
// {
// 	meta:
// 		description = "Webshells Auto-generated - file rdrbs100.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "7c752bcd6da796d80a6830c61a632bff"

// 	strings:
// 		$s3 = {53 65 72 76 65 72 20 61 64 64 72 65 73 73 20 6D 75 73 74 20 62 65 20 49 50 20 69 6E 20 41 2E 42 2E 43 2E 44 20 66 6F 72 6D 61 74 2E}
// 		$s4 = {20 6D 61 70 70 65 64 20 70 6F 72 74 73 20 69 6E 20 74 68 65 20 6C 69 73 74 2E 20 43 75 72 72 65 6E 74 6C 79 20}

// 	condition:
// 		all of them
// }

// rule Mithril_Mithril
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Mithril.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "017191562d72ab0ca551eb89256650bd"

// 	strings:
// 		$s0 = {4F 70 65 6E 50 72 6F 63 65 73 73 20 65 72 72 6F 72 21}
// 		$s1 = {57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 20 65 72 72 6F 72 21}
// 		$s4 = {47 65 74 50 72 6F 63 41 64 64 72 65 73 73 20 65 72 72 6F 72 21}
// 		$s5 = {48 48 74 60 48 48 74 5C 5C}
// 		$s6 = {43 6D 61 75 64 69 30}
// 		$s7 = {43 72 65 61 74 65 52 65 6D 6F 74 65 54 68 72 65 61 64 20 65 72 72 6F 72 21}
// 		$s8 = {4B 65 72 6E 65 6C 33 32}
// 		$s9 = {56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 20 65 72 72 6F 72 21}

// 	condition:
// 		all of them
// }

// rule hxdef100_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file hxdef100.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"

// 	strings:
// 		$s0 = {5C 5C 5C 5C 2E 5C 5C 6D 61 69 6C 73 6C 6F 74 5C 5C 68 78 64 65 66 2D 72 6B 63 30 30 30}
// 		$s2 = {53 68 61 72 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C 5C 4F 6E 20 41 63 63 65 73 73 20 53 63 61 6E 6E 65 72 5C 5C 42 65 68 61 76 69 6F 75 72 42 6C 6F}
// 		$s6 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 53 61 66 65 42 6F 6F 74 5C 5C}

// 	condition:
// 		all of them
// }

// rule Release_dllTest
// {
// 	meta:
// 		description = "Webshells Auto-generated - file dllTest.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "76a59fc3242a2819307bb9d593bef2e0"

// 	strings:
// 		$s0 = {3B 3B 3B 59 3B 60 3B 64 3B 68 3B 6C 3B 70 3B 74 3B 78 3B 7C 3B}
// 		$s1 = {30 20 30 26 30 30 30 36 30 4B 30 52 30 58 30 66 30 6C 30 71 30 77 30}
// 		$s2 = {3A 20 3A 24 3A 28 3A 2C 3A 30 3A 34 3A 38 3A 44 3A 60 3D 64 3D}
// 		$s3 = {34 40 35 50 35 54 35 5C 5C 35 54 37 5C 5C 37 64 37 6C 37 74 37 7C 37}
// 		$s4 = {31 2C 31 32 31 3E 31 43 31 4B 31 51 31 58 31 5E 31 65 31 6B 31 73 31 79 31}
// 		$s5 = {39 20 39 24 39 28 39 2C 39 50 39 58 39 5C 5C 39 60 39 64 39 68 39 6C 39 70 39 74 39 78 39 7C 39}
// 		$s6 = {30 29 30 4F 30 5C 5C 30 61 30 6F 30 5C 22 31 45 31 50 31 71 31}
// 		$s7 = {3C 2E 3C 49 3C 64 3C 68 3C 6C 3C 70 3C 74 3C 78 3C 7C 3C}
// 		$s8 = {33 26 33 31 33 38 33 3E 33 46 33 51 33 58 33 60 33 66 33 77 33 7C 33}
// 		$s9 = {38 40 3B 44 3B 48 3B 4C 3B 50 3B 54 3B 58 3B 5C 5C 3B 61 3B 39 3D 57 3D 7A 3D}

// 	condition:
// 		all of them
// }

// rule webadmin
// {
// 	meta:
// 		description = "Webshells Auto-generated - file webadmin.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "3a90de401b30e5b590362ba2dde30937"

// 	strings:
// 		$s0 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 5C 5C 22 65 64 69 74 66 69 6C 65 6E 61 6D 65 5C 5C 5C 22 20 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 20 63 6C 61 73 73 3D 5C 5C 5C 22 73 74 79 6C 65 31 5C 5C 5C 22 20 76 61 6C 75 65 3D 27 5C 22 2E 24 74 68 69 73 2D 3E 69 6E 70 75}

// 	condition:
// 		all of them
// }

// rule commands
// {
// 	meta:
// 		description = "Webshells Auto-generated - file commands.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "174486fe844cb388e2ae3494ac2d1ec2"

// 	strings:
// 		$s1 = {49 66 20 43 68 65 63 6B 52 65 63 6F 72 64 28 5C 22 53 45 4C 45 43 54 20 43 4F 55 4E 54 28 49 44 29 20 46 52 4F 4D 20 56 69 63 74 69 6D 44 65 74 61 69 6C 20 57 48 45 52 45 20 56 69 63 74 69 6D 49 44 20 3D 20 5C 22 20 26 20 56 69 63 74 69 6D 49 44}
// 		$s2 = {70 72 6F 78 79 41 72 72 20 3D 20 41 72 72 61 79 20 28 5C 22 48 54 54 50 5F 58 5F 46 4F 52 57 41 52 44 45 44 5F 46 4F 52 5C 22 2C 5C 22 48 54 54 50 5F 56 49 41 5C 22 2C 5C 22 48 54 54 50 5F 43 41 43 48 45 5F 43 4F 4E 54 52 4F 4C 5C 22 2C 5C 22 48 54 54 50 5F 46}

// 	condition:
// 		all of them
// }

// rule hkdoordll
// {
// 	meta:
// 		description = "Webshells Auto-generated - file hkdoordll.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b715c009d47686c0e62d0981efce2552"

// 	strings:
// 		$s6 = {43 61 6E 27 74 20 75 6E 69 6E 73 74 61 6C 6C 2C 6D 61 79 62 65 20 74 68 65 20 62 61 63 6B 64 6F 6F 72 20 69 73 20 6E 6F 74 20 69 6E 73 74 61 6C 6C 65 64 20 6F 72 2C 74 68 65 20 50 61 73 73 77 6F 72 64 20 79 6F 75 20 49 4E 50 55 54 20 69 73}

// 	condition:
// 		all of them
// }

// rule r57shell_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file r57shell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8023394542cddf8aee5dec6072ed02b5"

// 	strings:
// 		$s2 = {65 63 68 6F 20 5C 22 3C 62 72 3E 5C 22 2E 77 73 28 32 29 2E 5C 22 48 44 44 20 46 72 65 65 20 3A 20 3C 62 3E 5C 22 2E 76 69 65 77 5F 73 69 7A 65 28 24 66 72 65 65 29 2E 5C 22 3C 2F 62 3E 20 48 44 44 20 54 6F 74 61 6C 20 3A 20 3C 62 3E 5C 22 2E 76 69 65 77 5F}

// 	condition:
// 		all of them
// }

// rule Mithril_v1_45_dllTest
// {
// 	meta:
// 		description = "Webshells Auto-generated - file dllTest.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1b9e518aaa62b15079ff6edb412b21e9"

// 	strings:
// 		$s3 = {73 79 73 70 61 74 68}
// 		$s4 = {5C 5C 4D 69 74 68 72 69 6C}
// 		$s5 = {2D 2D 6C 69 73 74 20 74 68 65 20 73 65 72 76 69 63 65 73 20 69 6E 20 74 68 65 20 63 6F 6D 70 75 74 65 72}

// 	condition:
// 		all of them
// }

// rule dbgiis6cli
// {
// 	meta:
// 		description = "Webshells Auto-generated - file dbgiis6cli.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "3044dceb632b636563f66fee3aaaf8f3"

// 	strings:
// 		$s0 = {55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 35 2E 30 31 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 30 29}
// 		$s5 = {23 23 23 63 6F 6D 6D 61 6E 64 3A 28 4E 4F 20 6D 6F 72 65 20 74 68 61 6E 20 31 30 30 20 62 79 74 65 73 21 29}

// 	condition:
// 		all of them
// }

// rule remview_2003_04_22
// {
// 	meta:
// 		description = "Webshells Auto-generated - file remview_2003_04_22.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "17d3e4e39fbca857344a7650f7ea55e3"

// 	strings:
// 		$s1 = {5C 22 3C 62 3E 5C 22 2E 6D 6D 28 5C 22 45 76 61 6C 20 50 48 50 20 63 6F 64 65 5C 22 29 2E 5C 22 3C 2F 62 3E 20 28 5C 22 2E 6D 6D 28 5C 22 64 6F 6E 27 74 20 74 79 70 65 5C 22 29 2E 5C 22 20 5C 5C 5C 22 26 6C 74 3B 3F 5C 5C 5C 22}

// 	condition:
// 		all of them
// }

// rule FSO_s_test
// {
// 	meta:
// 		description = "Webshells Auto-generated - file test.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "82cf7b48da8286e644f575b039a99c26"

// 	strings:
// 		$s0 = {24 79 61 7A 69 20 3D 20 5C 22 74 65 73 74 5C 22 20 2E 20 5C 22 5C 5C 72 5C 5C 6E 5C 22 3B}
// 		$s2 = {66 77 72 69 74 65 20 28 24 66 70 2C 20 5C 22 24 79 61 7A 69 5C 22 29 3B}

// 	condition:
// 		all of them
// }

// rule Debug_cress
// {
// 	meta:
// 		description = "Webshells Auto-generated - file cress.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "36a416186fe010574c9be68002a7286a"

// 	strings:
// 		$s0 = {5C 5C 4D 69 74 68 72 69 6C 20}
// 		$s4 = {4D 69 74 68 72 69 6C 2E 65 78 65}

// 	condition:
// 		all of them
// }

// rule webshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file webshell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "f2f8c02921f29368234bfb4d4622ad19"

// 	strings:
// 		$s0 = {52 68 56 69 52 59 4F 7A 7A}
// 		$s1 = {64 5C 5C 4F 21 6A 57 57}
// 		$s2 = {62 63 21 6A 57 57}
// 		$s3 = {30 57 5B 26 7B 6C}
// 		$s4 = {5B 49 4E 68 51 40 5C 5C}

// 	condition:
// 		all of them
// }

// rule FSO_s_EFSO_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file EFSO_2.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a341270f9ebd01320a7490c12cb2e64c"

// 	strings:
// 		$s0 = {3B 21 2B 2F 44 52 6B 6E 44 37 2B 2E 5C 5C 6D 44 72 43 28 56 2B 6B 63 4A 7A 6E 6E 64 6D 5C 5C 66 7C 6E 7A 4B 75 4A 62 27 72 40 21 26 30 4B 55 59 40 2A 4A 62 40 23 40 26 58 6C 5C 22 64 4B 56 63 4A 5C 5C 43 73 6C 55 2C 29 2C 40 21 30 4B 78 44 7E 6D 4B 56}
// 		$s4 = {5C 5C 63 6F 21 56 56 32 43 44 74 53 4A 27 45 2A 23 40 23 40 26 6D 4B 78 2F 44 50 31 34 6C 4D 2F 6E 59 7B 4A 43 38 31 4E 2B 36 4C 74 62 4C 33 5E 68 55 57 61 3B 4D 2F 4F 45 2D 41 58 58 5C 22 62 7E 2F 66 41 73 21 75 26 39 7C 4A 5C 5C 67 72 4B 70 5C 22 6A}

// 	condition:
// 		all of them
// }

// rule thelast_index3
// {
// 	meta:
// 		description = "Webshells Auto-generated - file index3.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "cceff6dc247aaa25512bad22120a14b4"

// 	strings:
// 		$s5 = {24 65 72 72 20 3D 20 5C 22 3C 69 3E 59 6F 75 72 20 4E 61 6D 65 3C 2F 69 3E 20 4E 6F 74 20 45 6E 74 65 72 65 64 21 3C 2F 66 6F 6E 74 3E 3C 2F 68 32 3E 53 6F 72 72 79 2C 20 5C 5C 5C 22 59 6F 75 72 20 4E 61 6D 65 5C 5C 5C 22 20 66 69 65 6C 64 20 69 73 20 72}

// 	condition:
// 		all of them
// }

// rule adjustcr
// {
// 	meta:
// 		description = "Webshells Auto-generated - file adjustcr.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "17037fa684ef4c90a25ec5674dac2eb6"

// 	strings:
// 		$s0 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 24}
// 		$s2 = {24 4C 69 63 65 6E 73 65 3A 20 4E 52 56 20 66 6F 72 20 55 50 58 20 69 73 20 64 69 73 74 72 69 62 75 74 65 64 20 75 6E 64 65 72 20 73 70 65 63 69 61 6C 20 6C 69 63 65 6E 73 65 20 24}
// 		$s6 = {41 64 6A 75 73 74 43 52 20 43 61 72 72}
// 		$s7 = {49 4F 4E 5C 5C 53 79 73 74 65 6D 5C 5C 46 6C 6F 61 74 69 6E 67 50 6F}

// 	condition:
// 		all of them
// }

// rule FeliksPack3___PHP_Shells_xIShell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file xIShell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "997c8437c0621b4b753a546a53a88674"

// 	strings:
// 		$s3 = {69 66 20 28 21 24 6E 69 78 29 20 7B 20 24 78 69 64 20 3D 20 69 6D 70 6C 6F 64 65 28 65 78 70 6C 6F 64 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 24 78 69 64 29 2C 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22 29 3B 7D 65 63 68 6F 20 28 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 4A 61 76 61}

// 	condition:
// 		all of them
// }

// rule HYTop_AppPack_2005
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2005.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"

// 	strings:
// 		$s6 = {5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 74 68 69 73 2E 66 6F 72 6D 2E 73 71 6C 53 74 72 2E 76 61 6C 75 65 3D 27 65 3A 5C 5C 68 79 74 6F 70 2E 6D 64 62}

// 	condition:
// 		all of them
// }

// rule xssshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file xssshell.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"

// 	strings:
// 		$s1 = {69 66 28 20 21 67 65 74 52 65 71 75 65 73 74 28 43 4F 4D 4D 41 4E 44 53 5F 55 52 4C 20 2B 20 5C 22 3F 76 3D 5C 22 20 2B 20 56 49 43 54 49 4D 20 2B 20 5C 22 26 72 3D 5C 22 20 2B 20 67 65 6E 65 72 61 74 65 49 44 28 29 2C 20 5C 22 70 75 73 68 43 6F 6D 6D 61}

// 	condition:
// 		all of them
// }

// rule FeliksPack3___PHP_Shells_usr
// {
// 	meta:
// 		description = "Webshells Auto-generated - file usr.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "ade3357520325af50c9098dc8a21a024"

// 	strings:
// 		$s0 = {3C 3F 70 68 70 20 24 69 64 5F 69 6E 66 6F 20 3D 20 61 72 72 61 79 28 27 6E 6F 74 69 66 79 27 20 3D 3E 20 27 6F 66 66 27 2C 27 73 75 62 27 20 3D 3E 20 27 61 61 73 64 27 2C 27 73 5F 6E 61 6D 65 27 20 3D 3E 20 27 6E 75 72 75 6C 6C 61 68 6F 72}

// 	condition:
// 		all of them
// }

// rule FSO_s_phpinj
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phpinj.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "dd39d17e9baca0363cc1c3664e608929"

// 	strings:
// 		$s4 = {65 63 68 6F 20 27 3C 61 20 68 72 65 66 3D 27 2E 24 65 78 70 75 72 6C 2E 27 3E 20 43 6C 69 63 6B 20 48 65 72 65 20 74 6F 20 45 78 70 6C 6F 69 74 20 3C 2F 61 3E 20 3C 62 72 20 2F 3E 27 3B}

// 	condition:
// 		all of them
// }

// rule xssshell_db
// {
// 	meta:
// 		description = "Webshells Auto-generated - file db.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "cb62e2ec40addd4b9930a9e270f5b318"

// 	strings:
// 		$s8 = {27 2F 2F 20 42 79 20 46 65 72 72 75 68 20 4D 61 76 69 74 75 6E 61 20 7C 20 68 74 74 70 3A 2F 2F 66 65 72 72 75 68 2E 6D 61 76 69 74 75 6E 61 2E 63 6F 6D}

// 	condition:
// 		all of them
// }

// rule PHP_sh
// {
// 	meta:
// 		description = "Webshells Auto-generated - file sh.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1e9e879d49eb0634871e9b36f99fe528"

// 	strings:
// 		$s1 = {5C 22 40 24 53 45 52 56 45 52 5F 4E 41 4D 45 20 5C 22 2E 65 78 65 63 28 5C 22 70 77 64 5C 22 29}

// 	condition:
// 		all of them
// }

// rule xssshell_default
// {
// 	meta:
// 		description = "Webshells Auto-generated - file default.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "d156782ae5e0b3724de3227b42fcaf2f"

// 	strings:
// 		$s3 = {49 66 20 50 72 6F 78 79 44 61 74 61 20 3C 3E 20 5C 22 5C 22 20 54 68 65 6E 20 50 72 6F 78 79 44 61 74 61 20 3D 20 52 65 70 6C 61 63 65 28 50 72 6F 78 79 44 61 74 61 2C 20 44 41 54 41 5F 53 45 50 45 52 41 54 4F 52 2C 20 5C 22 3C 62 72 20 2F 3E 5C 22 29}

// 	condition:
// 		all of them
// }

// rule EditServer_Webshell_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file EditServer.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"

// 	strings:
// 		$s0 = {40 48 4F 54 4D 41 49 4C 2E 43 4F 4D}
// 		$s1 = {50 72 65 73 73 20 41 6E 79 20 4B 65}
// 		$s3 = {67 6C 69 73 68 20 4D 65 6E 75 5A}

// 	condition:
// 		all of them
// }

// rule by064cli
// {
// 	meta:
// 		description = "Webshells Auto-generated - file by064cli.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "10e0dff366968b770ae929505d2a9885"

// 	strings:
// 		$s7 = {70 61 63 6B 65 74 20 64 72 6F 70 70 65 64 2C 72 65 64 69 72 65 63 74 69 6E 67}
// 		$s9 = {69 6E 70 75 74 20 74 68 65 20 70 61 73 73 77 6F 72 64 28 74 68 65 20 64 65 66 61 75 6C 74 20 6F 6E 65 20 69 73 20 27 62 79 27 29}

// 	condition:
// 		all of them
// }

// rule Mithril_dllTest
// {
// 	meta:
// 		description = "Webshells Auto-generated - file dllTest.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"

// 	strings:
// 		$s0 = {70 6C 65 61 73 65 20 65 6E 74 65 72 20 74 68 65 20 70 61 73 73 77 6F 72 64 3A}
// 		$s3 = {5C 5C 64 6C 6C 54 65 73 74 2E 70 64 62}

// 	condition:
// 		all of them
// }

// rule peek_a_boo
// {
// 	meta:
// 		description = "Webshells Auto-generated - file peek-a-boo.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "aca339f60d41fdcba83773be5d646776"

// 	strings:
// 		$s0 = {5F 5F 76 62 61 48 72 65 73 75 6C 74 43 68 65 63 6B 4F 62 6A}
// 		$s1 = {5C 5C 56 42 5C 5C 56 42 35 2E 4F 4C 42}
// 		$s2 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6F 6E 41}
// 		$s3 = {5F 5F 76 62 61 45 78 63 65 70 74 48 61 6E 64 6C 65 72}
// 		$s4 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 52 65 6C 65 61 73 65}
// 		$s8 = {5F 5F 76 62 61 45 72 72 6F 72 4F 76 65 72 66 6C 6F 77}

// 	condition:
// 		all of them
// }

// rule fmlibraryv3
// {
// 	meta:
// 		description = "Webshells Auto-generated - file fmlibraryv3.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "c34c248fed6d5a20d8203924a2088acc"

// 	strings:
// 		$s3 = {45 78 65 4E 65 77 52 73 2E 43 6F 6D 6D 61 6E 64 54 65 78 74 20 3D 20 5C 22 55 50 44 41 54 45 20 5C 22 20 26 20 74 61 62 6C 65 6E 61 6D 65 20 26 20 5C 22 20 53 45 54 20 5C 22 20 26 20 45 78 65 4E 65 77 52 73 56 61 6C 75 65 73 20 26 20 5C 22 20 57 48 45 52}

// 	condition:
// 		all of them
// }

// rule Debug_dllTest_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file dllTest.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1b9e518aaa62b15079ff6edb412b21e9"

// 	strings:
// 		$s4 = {5C 5C 44 65 62 75 67 5C 5C 64 6C 6C 54 65 73 74 2E 70 64 62}
// 		$s5 = {2D 2D 6C 69 73 74 20 74 68 65 20 73 65 72 76 69 63 65 73 20 69 6E 20 74 68 65 20 63 6F 6D 70 75 74 65 72}

// 	condition:
// 		all of them
// }

// rule connector
// {
// 	meta:
// 		description = "Webshells Auto-generated - file connector.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "3ba1827fca7be37c8296cd60be9dc884"

// 	strings:
// 		$s2 = {49 66 20 28 20 41 74 74 61 63 6B 49 44 20 3D 20 42 52 4F 41 44 43 41 53 54 5F 41 54 54 41 43 4B 20 29}
// 		$s4 = {41 64 64 20 55 4E 49 51 55 45 20 49 44 20 66 6F 72 20 76 69 63 74 69 6D 73 20 2F 20 7A 6F 6D 62 69 65 73}

// 	condition:
// 		all of them
// }

// rule shelltools_g0t_root_HideRun
// {
// 	meta:
// 		description = "Webshells Auto-generated - file HideRun.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "45436d9bfd8ff94b71eeaeb280025afe"

// 	strings:
// 		$s0 = {55 73 61 67 65 20 2D 2D 20 68 69 64 65 72 75 6E 20 5B 41 70 70 4E 61 6D 65 5D}
// 		$s7 = {50 56 41 58 20 53 57 2C 20 41 6C 65 78 65 79 20 41 2E 20 50 6F 70 6F 66 66 2C 20 4D 6F 73 63 6F 77 2C 20 31 39 39 37 2E}

// 	condition:
// 		all of them
// }

// rule regshell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file regshell.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "db2fdc821ca6091bab3ebd0d8bc46ded"

// 	strings:
// 		$s0 = {43 68 61 6E 67 65 73 20 74 68 65 20 62 61 73 65 20 68 69 76 65 20 74 6F 20 48 4B 45 59 5F 43 55 52 52 45 4E 54 5F 55 53 45 52 2E}
// 		$s4 = {44 69 73 70 6C 61 79 73 20 61 20 6C 69 73 74 20 6F 66 20 76 61 6C 75 65 73 20 61 6E 64 20 73 75 62 2D 6B 65 79 73 20 69 6E 20 61 20 72 65 67 69 73 74 72 79 20 48 69 76 65 2E}
// 		$s5 = {45 6E 74 65 72 20 61 20 6D 65 6E 75 20 73 65 6C 65 63 74 69 6F 6E 20 6E 75 6D 62 65 72 20 28 31 20 2D 20 33 29 20 6F 72 20 39 39 20 74 6F 20 45 78 69 74 3A 20}

// 	condition:
// 		all of them
// }

// rule PHP_Shell_v1_7
// {
// 	meta:
// 		description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b5978501c7112584532b4ca6fb77cba5"

// 	strings:
// 		$s8 = {3C 74 69 74 6C 65 3E 5B 41 44 44 49 54 49 4E 41 4C 20 54 49 54 54 4C 45 5D 2D 70 68 70 53 68 65 6C 6C 20 62 79 3A 5B 59 4F 55 52 4E 41 4D 45 5D}

// 	condition:
// 		all of them
// }

// rule xssshell_save
// {
// 	meta:
// 		description = "Webshells Auto-generated - file save.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "865da1b3974e940936fe38e8e1964980"

// 	strings:
// 		$s4 = {52 61 77 43 6F 6D 6D 61 6E 64 20 3D 20 43 6F 6D 6D 61 6E 64 20 26 20 43 4F 4D 4D 41 4E 44 5F 53 45 50 45 52 41 54 4F 52 20 26 20 50 61 72 61 6D 20 26 20 43 4F 4D 4D 41 4E 44 5F 53 45 50 45 52 41 54 4F 52 20 26 20 41 74 74 61 63 6B 49 44}
// 		$s5 = {56 69 63 74 69 6D 49 44 20 3D 20 66 6D 5F 4E 53 74 72 28 56 69 63 74 69 6D 73 28 69 29 29}

// 	condition:
// 		all of them
// }

// rule screencap
// {
// 	meta:
// 		description = "Webshells Auto-generated - file screencap.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "51139091dea7a9418a50f2712ea72aa6"

// 	strings:
// 		$s0 = {47 65 74 44 49 42 43 6F 6C 6F 72 54 61 62 6C 65}
// 		$s1 = {53 63 72 65 65 6E 2E 62 6D 70}
// 		$s2 = {43 72 65 61 74 65 44 43 41}

// 	condition:
// 		all of them
// }

// rule FSO_s_phpinj_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phpinj.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "dd39d17e9baca0363cc1c3664e608929"

// 	strings:
// 		$s9 = {3C 3F 20 73 79 73 74 65 6D 28 5C 5C 24 5F 47 45 54 5B 63 70 63 5D 29 3B 65 78 69 74 3B 20 3F 3E 27 20 2C 30 20 2C 30 20 2C 30 20 2C 30 20 49 4E 54 4F}

// 	condition:
// 		all of them
// }

// rule ZXshell2_0_rar_Folder_zxrecv
// {
// 	meta:
// 		description = "Webshells Auto-generated - file zxrecv.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"

// 	strings:
// 		$s0 = {52 79 46 6C 75 73 68 42 75 66 66}
// 		$s1 = {74 65 54 6F 57 69 64 65 43 68 61 72 5E 46 69 59 50}
// 		$s2 = {6D 64 65 73 63 2B 38 46 20 44}
// 		$s3 = {5C 5C 76 6F 6E 37 36 73 74 64}
// 		$s4 = {35 70 75 72 2B 76 69 72 74 75 6C}
// 		$s5 = {2D 20 4B 61 62 6C 74 6F 20 69 6F}
// 		$s6 = {61 63 23 66 7B 6C 6F 77 69 38 61}

// 	condition:
// 		all of them
// }

// rule FSO_s_ajan
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ajan.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "22194f8c44524f80254e1b5aec67b03e"

// 	strings:
// 		$s4 = {65 6E 74 72 69 6B 61 2E 77 72 69 74 65 20 5C 22 42 69 6E 61 72 79 53 74 72 65 61 6D 2E 53 61 76 65 54 6F 46 69 6C 65}

// 	condition:
// 		all of them
// }

// rule c99shell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file c99shell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "90b86a9c63e2cd346fe07cea23fbfc56"

// 	strings:
// 		$s0 = {3C 62 72 20 2F 3E 49 6E 70 75 74 26 6E 62 73 70 3B 55 52 4C 3A 26 6E 62 73 70 3B 26 6C 74 3B 69 6E 70 75 74 26 6E 62 73 70 3B 6E 61 6D 65 3D 5C 5C 5C 22 75 70 6C 6F 61 64 75 72 6C 5C 5C 5C 22 26 6E 62 73 70 3B 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 26}

// 	condition:
// 		all of them
// }

// rule phpspy_2005_full
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phpspy_2005_full.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "d1c69bb152645438440e6c903bac16b2"

// 	strings:
// 		$s7 = {65 63 68 6F 20 5C 22 20 20 3C 74 64 20 61 6C 69 67 6E 3D 5C 5C 5C 22 63 65 6E 74 65 72 5C 5C 5C 22 20 6E 6F 77 72 61 70 20 76 61 6C 69 67 6E 3D 5C 5C 5C 22 74 6F 70 5C 5C 5C 22 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 3F 64 6F 77 6E 66 69 6C 65 3D 5C 22 2E 75 72 6C 65 6E 63 6F}

// 	condition:
// 		all of them
// }

// rule FSO_s_zehir4_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file zehir4.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "5b496a61363d304532bcf52ee21f5d55"

// 	strings:
// 		$s4 = {5C 22 50 72 6F 67 72 61 6D 20 46 69 6C 65 73 5C 5C 53 65 72 76 2D 75 5C 5C 53 65 72 76}

// 	condition:
// 		all of them
// }

// rule httpdoor
// {
// 	meta:
// 		description = "Webshells Auto-generated - file httpdoor.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "6097ea963455a09474471a9864593dc3"

// 	strings:
// 		$s4 = {27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 44 61 4A 4B 48 50 61 6D}
// 		$s5 = {6F 2C 57 69 64 65 43 68 61 72 52 5D 21 6E 5D}
// 		$s6 = {48 41 75 74 6F 43 6F 6D 70 6C 65 74 65}
// 		$s7 = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 5C 22 31 2E 30 5C 22 20 65 6E 63 6F 64 69 6E 67 3D 5C 22 55 54 46 2D 38 5C 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 5C 22 79 65 73 5C 22 3F 3E 20 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C 6E 73 3D 5C 22 75 72 6E 3A 73 63 68}

// 	condition:
// 		all of them
// }

// rule FSO_s_indexer_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file indexer.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "135fc50f85228691b401848caef3be9e"

// 	strings:
// 		$s5 = {3C 74 64 3E 4E 65 72 64 65 6E 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 64 65 6E 5C 22 20 73 69 7A 65 3D 32 35 20 76 61 6C 75 65 3D 69 6E 64 65 78 2E 68 74 6D 6C 3E 3C 2F 74 64 3E}

// 	condition:
// 		all of them
// }

// rule HYTop_DevPack_2005
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2005.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"

// 	strings:
// 		$s7 = {74 68 65 48 72 65 66 3D 65 6E 63 6F 64 65 46 6F 72 55 72 6C 28 6D 69 64 28 72 65 70 6C 61 63 65 28 6C 63 61 73 65 28 6C 69 73 74 2E 70 61 74 68 29 2C 6C 63 61 73 65 28 73 65 72 76 65 72 2E 6D 61 70 50 61 74 68 28 5C 22 2F 5C 22 29 29 2C 5C 22 5C 22 29}
// 		$s8 = {73 63 72 6F 6C 6C 62 61 72 2D 64 61 72 6B 73 68 61 64 6F 77 2D 63 6F 6C 6F 72 3A 23 39 43 39 43 44 33 3B}
// 		$s9 = {73 63 72 6F 6C 6C 62 61 72 2D 66 61 63 65 2D 63 6F 6C 6F 72 3A 23 45 34 45 34 46 33 3B}

// 	condition:
// 		all of them
// }

// rule _root_040_zip_Folder_deploy
// {
// 	meta:
// 		description = "Webshells Auto-generated - file deploy.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "2c9f9c58999256c73a5ebdb10a9be269"

// 	strings:
// 		$s5 = {68 61 6C 6F 6E 20 73 79 6E 73 63 61 6E 20 31 32 37 2E 30 2E 30 2E 31 20 31 2D 36 35 35 33 36}
// 		$s8 = {4F 62 76 69 6F 75 73 6C 79 20 79 6F 75 20 72 65 70 6C 61 63 65 20 74 68 65 20 69 70 20 61 64 64 72 65 73 73 20 77 69 74 68 20 74 68 61 74 20 6F 66 20 74 68 65 20 74 61 72 67 65 74 2E}

// 	condition:
// 		all of them
// }

// rule by063cli
// {
// 	meta:
// 		description = "Webshells Auto-generated - file by063cli.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "49ce26eb97fd13b6d92a5e5d169db859"

// 	strings:
// 		$s2 = {23 70 6F 70 6D 73 67 68 65 6C 6C 6F 2C 61 72 65 20 79 6F 75 20 61 6C 6C 20 72 69 67 68 74 3F}
// 		$s4 = {63 6F 6E 6E 65 63 74 20 66 61 69 6C 65 64 2C 63 68 65 63 6B 20 79 6F 75 72 20 6E 65 74 77 6F 72 6B 20 61 6E 64 20 72 65 6D 6F 74 65 20 69 70 2E}

// 	condition:
// 		all of them
// }

// rule icyfox007v1_10_rar_Folder_asp
// {
// 	meta:
// 		description = "Webshells Auto-generated - file asp.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "2c412400b146b7b98d6e7755f7159bb9"

// 	strings:
// 		$s0 = {3C 53 43 52 49 50 54 20 52 55 4E 41 54 3D 53 45 52 56 45 52 20 4C 41 4E 47 55 41 47 45 3D 4A 41 56 41 53 43 52 49 50 54 3E 65 76 61 6C 28 52 65 71 75 65 73 74 2E 66 6F 72 6D 28 27 23 27 29 2B 27 27 29 3C 2F 53 43 52 49 50 54 3E}

// 	condition:
// 		all of them
// }

// // duplicated
// /* rule FSO_s_EFSO_2_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file EFSO_2.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "a341270f9ebd01320a7490c12cb2e64c"

// 	strings:
// 		$s0 = {3B 21 2B 2F 44 52 6B 6E 44 37 2B 2E 5C 5C 6D 44 72 43 28 56 2B 6B 63 4A 7A 6E 6E 64 6D 5C 5C 66 7C 6E 7A 4B 75 4A 62 27 72 40 21 26 30 4B 55 59 40 2A 4A 62 40 23 40 26 58 6C 5C 22 64 4B 56 63 4A 5C 5C 43 73 6C 55 2C 29 2C 40 21 30 4B 78 44 7E 6D 4B 56}
// 		$s4 = {5C 5C 63 6F 21 56 56 32 43 44 74 53 4A 27 45 2A 23 40 23 40 26 6D 4B 78 2F 44 50 31 34 6C 4D 2F 6E 59 7B 4A 43 38 31 4E 2B 36 4C 74 62 4C 33 5E 68 55 57 61 3B 4D 2F 4F 45 2D 41 58 58 5C 22 62 7E 2F 66 41 73 21 75 26 39 7C 4A 5C 5C 67 72 4B 70 5C 22 6A}

// 	condition:
// 		all of them
// }*/

// rule byshell063_ntboot_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ntboot.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"

// 	strings:
// 		$s6 = {4F 4B 2C 6A 6F 62 20 77 61 73 20 64 6F 6E 65 2C 63 75 7A 20 77 65 20 68 61 76 65 20 6C 6F 63 61 6C 73 79 73 74 65 6D 20 26 20 53 45 5F 44 45 42 55 47 5F 4E 41 4D 45 3A 29}

// 	condition:
// 		all of them
// }

// rule u_uay
// {
// 	meta:
// 		description = "Webshells Auto-generated - file uay.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"

// 	strings:
// 		$s1 = {65 78 65 63 20 5C 22 63 3A 5C 5C 57 49 4E 44 4F 57 53 5C 5C 53 79 73 74 65 6D 33 32 5C 5C 66 72 65 65 63 65 6C 6C 2E 65 78 65}
// 		$s9 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 53 65 72 76 69 63 65 73 5C 5C 75 61 79 2E 73 79 73 5C 5C 53 65 63 75 72 69 74 79}

// 	condition:
// 		1 of them
// }

// rule bin_wuaus
// {
// 	meta:
// 		description = "Webshells Auto-generated - file wuaus.dll"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "46a365992bec7377b48a2263c49e4e7d"

// 	strings:
// 		$s1 = {39 28 39 30 39 38 39 40 39 56 39 5E 39 66 39 6E 39 76 39}
// 		$s2 = {3A 28 3A 2C 3A 30 3A 34 3A 38 3A 43 3A 48 3A 4E 3A 54 3A 59 3A 5F 3A 65 3A 6F 3A 79 3A}
// 		$s3 = {3B 28 3D 40 3D 47 3D 4F 3D 54 3D 58 3D 5C 5C 3D}
// 		$s4 = {54 43 50 20 53 65 6E 64 20 45 72 72 6F 72 21 21}
// 		$s5 = {31 5C 22 31 3B 31 58 31 5E 31 65 31 6D 31 77 31 7E 31}
// 		$s8 = {3D 24 3D 29 3D 2F 3D 3C 3D 59 3D 5F 3D 6A 3D 70 3D 7A 3D}

// 	condition:
// 		all of them
// }

// rule pwreveal
// {
// 	meta:
// 		description = "Webshells Auto-generated - file pwreveal.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "b4e8447826a45b76ca45ba151a97ad50"

// 	strings:
// 		$s0 = {2A 3C 42 6C 61 6E 6B 20 2D 20 6E 6F 20 65 73}
// 		$s3 = {4A 44 69 61 6D 6F 6E 64 43 53 20}
// 		$s8 = {73 77 6F 72 64 20 73 65 74 3E 20 5B 4C 65 69 74 68 3D 30 20 62 79 74 65 73 5D}
// 		$s9 = {49 4F 4E 5C 5C 53 79 73 74 65 6D 5C 5C 46 6C 6F 61 74 69 6E 67 2D}

// 	condition:
// 		all of them
// }

// rule shelltools_g0t_root_xwhois
// {
// 	meta:
// 		description = "Webshells Auto-generated - file xwhois.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "0bc98bd576c80d921a3460f8be8816b4"

// 	strings:
// 		$s1 = {72 74 69 6E 67 21 20}
// 		$s2 = {61 54 79 70 43 6F 67 28}
// 		$s5 = {44 69 61 6D 6F 6E 64}
// 		$s6 = {72 29 72 3D 72 51 72 65 72 79 72}

// 	condition:
// 		all of them
// }

// rule vanquish_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file vanquish.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "2dcb9055785a2ee01567f52b5a62b071"

// 	strings:
// 		$s2 = {56 61 6E 71 75 69 73 68 20 2D 20 44 4C 4C 20 69 6E 6A 65 63 74 69 6F 6E 20 66 61 69 6C 65 64 3A}

// 	condition:
// 		all of them
// }

// rule down_rar_Folder_down
// {
// 	meta:
// 		description = "Webshells Auto-generated - file down.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "db47d7a12b3584a2e340567178886e71"

// 	strings:
// 		$s0 = {72 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 20 73 69 7A 65 3D 32 3E 4E 65 74 42 69 6F 73 20 4E 61 6D 65 3A 20 5C 5C 5C 5C 5C 22 20 20 26 20 53 6E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26}

// 	condition:
// 		all of them
// }

// rule cmdShell
// {
// 	meta:
// 		description = "Webshells Auto-generated - file cmdShell.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "8a9fef43209b5d2d4b81dfbb45182036"

// 	strings:
// 		$s1 = {69 66 20 63 6D 64 50 61 74 68 3D 5C 22 77 73 63 72 69 70 74 53 68 65 6C 6C 5C 22 20 74 68 65 6E}

// 	condition:
// 		all of them
// }

// rule ZXshell2_0_rar_Folder_nc
// {
// 	meta:
// 		description = "Webshells Auto-generated - file nc.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"

// 	strings:
// 		$s0 = {57 53 4F 43 4B 33 32 2E 64 6C 6C}
// 		$s1 = {3F 62 53 55 4E 4B 4E 4F 57 4E 56}
// 		$s7 = {70 40 67 72 61 6D 20 4A 6D 36 68 29}
// 		$s8 = {73 65 72 33 32 2E 64 6C 6C 43 4F 4E 46 50 40}

// 	condition:
// 		all of them
// }

// rule portlessinst
// {
// 	meta:
// 		description = "Webshells Auto-generated - file portlessinst.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "74213856fc61475443a91cd84e2a6c2f"

// 	strings:
// 		$s2 = {46 61 69 6C 20 54 6F 20 4F 70 65 6E 20 52 65 67 69 73 74 72 79}
// 		$s3 = {66 3C 2D 57 4C 45 67 67 44 72 5C 22}
// 		$s6 = {6F 4D 65 6D 6F 72 79 43 72 65 61 74 65 50}

// 	condition:
// 		all of them
// }

// rule SetupBDoor
// {
// 	meta:
// 		description = "Webshells Auto-generated - file SetupBDoor.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "41f89e20398368e742eda4a3b45716b6"

// 	strings:
// 		$s1 = {5C 5C 42 44 6F 6F 72 5C 5C 53 65 74 75 70 42 44 6F 6F 72}

// 	condition:
// 		all of them
// }

// rule phpshell_3
// {
// 	meta:
// 		description = "Webshells Auto-generated - file phpshell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"

// 	strings:
// 		$s3 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 73 75 62 6D 69 74 5F 62 74 6E 5C 22 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 45 78 65 63 75 74 65 20 43 6F 6D 6D 61 6E 64 5C 22 3E 3C 2F 70 3E}
// 		$s5 = {20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 77 6F 72 6B 5F 64 69 72 5C 5C 5C 22 20 73 65 6C 65 63 74 65 64 3E 43 75 72 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E 5C 5C 6E 5C 22 3B}

// 	condition:
// 		all of them
// }

// rule BIN_Server
// {
// 	meta:
// 		description = "Webshells Auto-generated - file Server.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"

// 	strings:
// 		$s0 = {63 6F 6E 66 69 67 73 65 72 76 65 72}
// 		$s1 = {47 65 74 4C 6F 67 69 63 61 6C 44 72 69 76 65 73}
// 		$s2 = {57 69 6E 45 78 65 63}
// 		$s4 = {66 78 66 74 65 73 74}
// 		$s5 = {75 70 66 69 6C 65 6F 6B}
// 		$s7 = {75 70 66 69 6C 65 65 72}

// 	condition:
// 		all of them
// }

// rule HYTop2006_rar_Folder_2006
// {
// 	meta:
// 		description = "Webshells Auto-generated - file 2006.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "c19d6f4e069188f19b08fa94d44bc283"

// 	strings:
// 		$s6 = {73 74 72 42 61 63 6B 44 6F 6F 72 20 3D 20 73 74 72 42 61 63 6B 44 6F 6F 72 20}

// 	condition:
// 		all of them
// }

// rule r57shell_3
// {
// 	meta:
// 		description = "Webshells Auto-generated - file r57shell.php"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "87995a49f275b6b75abe2521e03ac2c0"

// 	strings:
// 		$s1 = {3C 62 3E 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D}

// 	condition:
// 		all of them
// }

// rule HDConfig
// {
// 	meta:
// 		description = "Webshells Auto-generated - file HDConfig.exe"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "7d60e552fdca57642fd30462416347bd"

// 	strings:
// 		$s0 = {41 6E 20 65 6E 63 72 79 70 74 69 6F 6E 20 6B 65 79 20 69 73 20 64 65 72 69 76 65 64 20 66 72 6F 6D 20 74 68 65 20 70 61 73 73 77 6F 72 64 20 68 61 73 68 2E 20}
// 		$s3 = {41 20 68 61 73 68 20 6F 62 6A 65 63 74 20 68 61 73 20 62 65 65 6E 20 63 72 65 61 74 65 64 2E 20}
// 		$s4 = {45 72 72 6F 72 20 64 75 72 69 6E 67 20 43 72 79 70 74 43 72 65 61 74 65 48 61 73 68 21}
// 		$s5 = {41 20 6E 65 77 20 6B 65 79 20 63 6F 6E 74 61 69 6E 65 72 20 68 61 73 20 62 65 65 6E 20 63 72 65 61 74 65 64 2E}
// 		$s6 = {54 68 65 20 70 61 73 73 77 6F 72 64 20 68 61 73 20 62 65 65 6E 20 61 64 64 65 64 20 74 6F 20 74 68 65 20 68 61 73 68 2E 20}

// 	condition:
// 		all of them
// }

// rule FSO_s_ajan_2
// {
// 	meta:
// 		description = "Webshells Auto-generated - file ajan.asp"
// 		author = "Yara Bulk Rule Generator by Florian Roth"
// 		hash = "22194f8c44524f80254e1b5aec67b03e"

// 	strings:
// 		$s2 = {5C 22 53 65 74 20 57 73 68 53 68 65 6C 6C 20 3D 20 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 5C 22 57 53 63 72 69 70 74 2E 53 68 65 6C 6C 5C 22 5C 22 29}
// 		$s3 = {2F 66 69 6C 65 2E 7A 69 70}

// 	condition:
// 		all of them
// }

// rule Webshell_and_Exploit_CN_APT_HK : Webshell
// {
// 	meta:
// 		author = "Florian Roth"
// 		description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
// 		date = "10.10.2014"
// 		score = 50

// 	strings:
// 		$a0 = {3C 73 63 72 69 70 74 20 6C 61 6E 67 75 61 67 65 3D 6A 61 76 61 73 63 72 69 70 74 20 73 72 63 3D 68 74 74 70 3A 2F 2F 6A 61 76 61 2D 73 65 2E 63 6F 6D 2F 6F 2E 6A 73 3C 2F 73 63 72 69 70 74 3E}
// 		$s0 = {3C 73 70 61 6E 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 3A 31 31 70 78 20 56 65 72 64 61 6E 61 3B 5C 22 3E 50 61 73 73 77 6F 72 64 3A 20 3C 2F 73 70 61 6E 3E 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 74 79 70 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 73 69 7A 65 3D 5C 22 32 30 5C 22 3E}
// 		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 64 6F 69 6E 67 5C 22 20 76 61 6C 75 65 3D 5C 22 6C 6F 67 69 6E 5C 22 3E}

// 	condition:
// 		$a0 or ( all of ($s*))
// }

// rule JSP_Browser_APT_webshell
// {
// 	meta:
// 		description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
// 		author = "F.Roth"
// 		date = "10.10.2014"
// 		score = 60

// 	strings:
// 		$a1a = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 66 69 6E 61 6C 20 53 74 72 69 6E 67 5B 5D 20 43 4F 4D 4D 41 4E 44 5F 49 4E 54 45 52 50 52 45 54 45 52 20 3D 20 7B 5C 22}
// 		$a1b = {63 6D 64 5C 22 2C 20 5C 22 2F 43 5C 22 7D 3B 20 2F 2F 20 44 6F 73 2C 57 69 6E 64 6F 77 73}
// 		$a2 = {50 72 6F 63 65 73 73 20 6C 73 5F 70 72 6F 63 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 63 6F 6D 6D 2C 20 6E 75 6C 6C 2C 20 6E 65 77 20 46 69 6C 65 28 64 69 72 29 29 3B}
// 		$a3 = {72 65 74 2E 61 70 70 65 6E 64 28 5C 22 21 21 21 21 20 50 72 6F 63 65 73 73 20 68 61 73 20 74 69 6D 65 64 20 6F 75 74 2C 20 64 65 73 74 72 6F 79 65 64 20 21 21 21 21 21 5C 22 29 3B}

// 	condition:
// 		all of them
// }

// rule JSP_jfigueiredo_APT_webshell
// {
// 	meta:
// 		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
// 		author = "F.Roth"
// 		date = "12.10.2014"
// 		score = 60
// 		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"

// 	strings:
// 		$a1 = {53 74 72 69 6E 67 20 66 68 69 64 64 65 6E 20 3D 20 6E 65 77 20 53 74 72 69 6E 67 28 42 61 73 65 36 34 2E 65 6E 63 6F 64 65 42 61 73 65 36 34 28 70 61 74 68 2E 67 65 74 42 79 74 65 73 28 29 29 29 3B}
// 		$a2 = {3C 66 6F 72 6D 20 69 64 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 6E 61 6D 65 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 53 65 72 76 46 4D 55 70 6C 6F 61 64 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 20 65 6E 63 74 79 70 65 3D 5C 22 6D 75 6C 74 69 70 61 72 74 2F 66 6F 72 6D 2D 64 61 74 61 5C 22 3E}

// 	condition:
// 		all of them
// }

// rule JSP_jfigueiredo_APT_webshell_2
// {
// 	meta:
// 		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
// 		author = "F.Roth"
// 		date = "12.10.2014"
// 		score = 60
// 		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"

// 	strings:
// 		$a1 = {3C 64 69 76 20 69 64 3D 5C 22 62 6B 6F 72 6F 74 61 74 6F 72 5C 22 3E 3C 69 6D 67 20 61 6C 74 3D 5C 22 5C 22 20 73 72 63 3D 5C 22 69 6D 61 67 65 73 2F 72 6F 74 61 74 6F 72 2F 31 2E 6A 70 67 5C 22 3E 3C 2F 64 69 76 3E}
// 		$a2 = {24 28 5C 22 23 64 69 61 6C 6F 67 5C 22 29 2E 64 69 61 6C 6F 67 28 5C 22 64 65 73 74 72 6F 79 5C 22 29 3B}
// 		$s1 = {3C 66 6F 72 6D 20 69 64 3D 5C 22 66 6F 72 6D 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 53 65 72 76 46 4D 55 70 6C 6F 61 64 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 20 65 6E 63 74 79 70 65 3D 5C 22 6D 75 6C 74 69 70 61 72 74 2F 66 6F 72 6D 2D 64 61 74 61 5C 22 3E}
// 		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 69 64 3D 5C 22 66 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 66 68 69 64 64 65 6E 5C 22 20 76 61 6C 75 65 3D 5C 22 4C 33 42 6B 5A 69 38 3D 5C 22 20 2F 3E}

// 	condition:
// 		all of ($a*) or all of ($s*)
// }

// rule AJAX_FileUpload_webshell
// {
// 	meta:
// 		description = "AJAX JS/CSS components providing web shell by APT groups"
// 		author = "F.Roth"
// 		date = "12.10.2014"
// 		score = 75
// 		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/ajaxfileupload.js"

// 	strings:
// 		$a1 = {76 61 72 20 66 72 61 6D 65 49 64 20 3D 20 27 6A 55 70 6C 6F 61 64 46 72 61 6D 65 27 20 2B 20 69 64 3B}
// 		$a2 = {76 61 72 20 66 6F 72 6D 20 3D 20 6A 51 75 65 72 79 28 27 3C 66 6F 72 6D 20 20 61 63 74 69 6F 6E 3D 5C 22 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 20 6E 61 6D 65 3D 5C 22 27 20 2B 20 66 6F 72 6D 49 64 20 2B 20 27 5C 22 20 69 64 3D 5C 22 27 20 2B 20 66 6F 72 6D 49 64 20 2B 20 27 5C 22 20 65 6E 63 74 79 70 65 3D 5C 22 6D 75 6C 74 69 70 61 72 74 2F 66 6F 72 6D 2D 64 61 74 61 5C 22 3E 3C 2F 66 6F 72 6D 3E 27 29 3B}
// 		$a3 = {6A 51 75 65 72 79 28 5C 22 3C 64 69 76 3E 5C 22 29 2E 68 74 6D 6C 28 64 61 74 61 29 2E 65 76 61 6C 53 63 72 69 70 74 73 28 29 3B}

// 	condition:
// 		all of them
// }

// rule Webshell_Insomnia
// {
// 	meta:
// 		description = "Insomnia Webshell - file InsomniaShell.aspx"
// 		author = "Florian Roth"
// 		reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
// 		date = "2014/12/09"
// 		hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"
// 		score = 80

// 	strings:
// 		$s0 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 28 5C 22 2D 20 46 61 69 6C 65 64 20 74 6F 20 63 72 65 61 74 65 20 6E 61 6D 65 64 20 70 69 70 65 3A 5C 22 29 3B}
// 		$s1 = {52 65 73 70 6F 6E 73 65 2E 4F 75 74 70 75 74 2E 57 72 69 74 65 28 5C 22 2B 20 53 65 6E 64 69 6E 67 20 7B 30 7D 3C 62 72 3E 5C 22 2C 20 63 6F 6D 6D 61 6E 64 29 3B}
// 		$s2 = {53 74 72 69 6E 67 20 63 6F 6D 6D 61 6E 64 20 3D 20 5C 22 65 78 65 63 20 6D 61 73 74 65 72 2E 2E 78 70 5F 63 6D 64 73 68 65 6C 6C 20 27 64 69 72 20 3E 20 5C 5C 5C 5C 5C 5C 5C 5C 31 32 37 2E 30 2E 30 2E 31}
// 		$s3 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 28 5C 22 2D 20 45 72 72 6F 72 20 47 65 74 74 69 6E 67 20 55 73 65 72 20 49 6E 66 6F 3C 62 72 3E 5C 22 29 3B}
// 		$s4 = {73 74 72 69 6E 67 20 6C 70 43 6F 6D 6D 61 6E 64 4C 69 6E 65 2C 20 72 65 66 20 53 45 43 55 52 49 54 59 5F 41 54 54 52 49 42 55 54 45 53 20 6C 70 50 72 6F 63 65 73 73 41 74 74 72 69 62 75 74 65 73 2C}
// 		$s5 = {5B 44 6C 6C 49 6D 70 6F 72 74 28 5C 22 41 64 76 61 70 69 33 32 2E 64 6C 6C 5C 22 2C 20 53 65 74 4C 61 73 74 45 72 72 6F 72 20 3D 20 74 72 75 65 29 5D}
// 		$s9 = {75 73 65 72 6E 61 6D 65 20 3D 20 44 75 6D 70 41 63 63 6F 75 6E 74 53 69 64 28 74 6F 6B 55 73 65 72 2E 55 73 65 72 2E 53 69 64 29 3B}
// 		$s14 = {2F 2F 52 65 73 70 6F 6E 73 65 2E 4F 75 74 70 75 74 2E 57 72 69 74 65 28 5C 22 4F 70 65 6E 65 64 20 70 72 6F 63 65 73 73 20 50 49 44 3A 20 7B 30 7D 20 3A 20 7B 31 7D 3C 62 72 3E 5C 22 2C 20 70}

// 	condition:
// 		3 of them
// }

// rule HawkEye_PHP_Panel
// {
// 	meta:
// 		description = "Detects HawkEye Keyloggers PHP Panel"
// 		author = "Florian Roth"
// 		date = "2014/12/14"
// 		score = 60

// 	strings:
// 		$s0 = {24 66 6E 61 6D 65 20 3D 20 24 5F 47 45 54 5B 27 66 6E 61 6D 65 27 5D 3B}
// 		$s1 = {24 64 61 74 61 20 3D 20 24 5F 47 45 54 5B 27 64 61 74 61 27 5D 3B}
// 		$s2 = {75 6E 6C 69 6E 6B 28 24 66 6E 61 6D 65 29 3B}
// 		$s3 = {65 63 68 6F 20 5C 22 53 75 63 63 65 73 73 5C 22 3B}

// 	condition:
// 		all of ($s*) and filesize <600
// }

// rule SoakSoak_Infected_Wordpress
// {
// 	meta:
// 		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
// 		reference = "http://goo.gl/1GzWUX"
// 		author = "Florian Roth"
// 		date = "2014/12/15"
// 		score = 60

// 	strings:
// 		$s0 = {77 70 5F 65 6E 71 75 65 75 65 5F 73 63 72 69 70 74 28 5C 22 73 77 66 6F 62 6A 65 63 74 5C 22 29 3B}
// 		$s1 = {66 75 6E 63 74 69 6F 6E 20 46 75 6E 63 51 75 65 75 65 4F 62 6A 65 63 74 28 29}
// 		$s2 = {61 64 64 5F 61 63 74 69 6F 6E 28 5C 22 77 70 5F 65 6E 71 75 65 75 65 5F 73 63 72 69 70 74 73 5C 22 2C 20 27 46 75 6E 63 51 75 65 75 65 4F 62 6A 65 63 74 27 29 3B}

// 	condition:
// 		all of ($s*)
// }

// rule Pastebin_Webshell
// {
// 	meta:
// 		description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
// 		author = "Florian Roth"
// 		score = 70
// 		date = "13.01.2015"
// 		reference = "http://goo.gl/7dbyZs"

// 	strings:
// 		$s0 = {66 69 6C 65 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 5C 22 68 74 74 70 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D}
// 		$s1 = {78 63 75 72 6C 28 27 68 74 74 70 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 2F 64 6F 77 6E 6C 6F 61 64 2E 70 68 70}
// 		$s2 = {78 63 75 72 6C 28 27 68 74 74 70 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 2F 72 61 77 2E 70 68 70}
// 		$x0 = {69 66 28 24 63 6F 6E 74 65 6E 74 29 7B 75 6E 6C 69 6E 6B 28 27 65 76 65 78 2E 70 68 70 27 29 3B}
// 		$x1 = {24 66 68 32 20 3D 20 66 6F 70 65 6E 28 5C 22 65 76 65 78 2E 70 68 70 5C 22 2C 20 27 61 27 29 3B}
// 		$y0 = {66 69 6C 65 5F 70 75 74 5F 63 6F 6E 74 65 6E 74 73 28 24 70 74 68}
// 		$y1 = {65 63 68 6F 20 5C 22 3C 6C 6F 67 69 6E 5F 6F 6B 3E}
// 		$y2 = {73 74 72 5F 72 65 70 6C 61 63 65 28 27 2A 20 40 70 61 63 6B 61 67 65 20 57 6F 72 64 70 72 65 73 73 27 2C 24 74 65 6D 70}

// 	condition:
// 		1 of ($s*) or all of ($x*) or all of ($y*)
// }

// rule ASPXspy2
// {
// 	meta:
// 		description = "Web shell - file ASPXspy2.aspx"
// 		author = "Florian Roth"
// 		reference = "not set"
// 		date = "2015/01/24"
// 		hash = "5642387d92139bfe9ae11bfef6bfe0081dcea197"

// 	strings:
// 		$s0 = {73 74 72 69 6E 67 20 69 56 44 54 3D 5C 22 2D 53 45 54 55 53 45 52 53 45 54 55 50 5C 5C 72 5C 5C 6E 2D 49 50 3D 30 2E 30 2E 30 2E 30 5C 5C 72 5C 5C 6E 2D 50 6F 72 74 4E 6F 3D 35 32 35 32 31 5C 5C 72 5C 5C 6E 2D 55 73 65 72 3D 62 69 6E}
// 		$s1 = {53 51 4C 45 78 65 63 20 3A 20 3C 61 73 70 3A 44 72 6F 70 44 6F 77 6E 4C 69 73 74 20 72 75 6E 61 74 3D 5C 22 73 65 72 76 65 72 5C 22 20 49 44 3D 5C 22 46 47 45 79 5C 22 20 41 75 74 6F 50 6F 73 74 42 61 63 6B 3D 5C 22 54 72 75 65 5C 22 20 4F}
// 		$s3 = {50 72 6F 63 65 73 73 5B 5D 20 70 3D 50 72 6F 63 65 73 73 2E 47 65 74 50 72 6F 63 65 73 73 65 73 28 29 3B}
// 		$s4 = {52 65 73 70 6F 6E 73 65 2E 43 6F 6F 6B 69 65 73 2E 41 64 64 28 6E 65 77 20 48 74 74 70 43 6F 6F 6B 69 65 28 76 62 68 4C 6E 2C 50 61 73 73 77 6F 72 64 29 29 3B}
// 		$s5 = {5B 44 6C 6C 49 6D 70 6F 72 74 28 5C 22 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 5C 22 2C 45 6E 74 72 79 50 6F 69 6E 74 3D 5C 22 47 65 74 44 72 69 76 65 54 79 70 65 41 5C 22 29 5D}
// 		$s6 = {3C 70 3E 43 6F 6E 6E 53 74 72 69 6E 67 20 3A 20 3C 61 73 70 3A 54 65 78 74 42 6F 78 20 69 64 3D 5C 22 4D 61 73 52 5C 22 20 73 74 79 6C 65 3D 5C 22 77 69 64 74 68 3A 37 30 25 3B 6D 61 72 67 69 6E 3A 30 20 38 70 78 3B 5C 22 20 43 73 73 43 6C}
// 		$s7 = {53 65 72 76 69 63 65 43 6F 6E 74 72 6F 6C 6C 65 72 5B 5D 20 6B 51 6D 52 75 3D 53 79 73 74 65 6D 2E 53 65 72 76 69 63 65 50 72 6F 63 65 73 73 2E 53 65 72 76 69 63 65 43 6F 6E 74 72 6F 6C 6C 65 72 2E 47 65 74 53 65 72 76 69 63 65 73 28 29 3B}
// 		$s8 = {43 6F 70 79 72 69 67 68 74 20 26 63 6F 70 79 3B 20 32 30 30 39 20 42 69 6E 20 2D 2D 20 3C 61 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 72 6F 6F 74 6B 69 74 2E 6E 65 74 2E 63 6E 5C 22 20 74 61 72 67 65 74 3D 5C 22 5F 62 6C 61}
// 		$s10 = {52 65 73 70 6F 6E 73 65 2E 41 64 64 48 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 44 69 73 70 6F 73 69 74 69 6F 6E 5C 22 2C 5C 22 61 74 74 61 63 68 6D 65 6E 74 3B 66 69 6C 65 6E 61 6D 65 3D 5C 22 2B 48 74 74 70 55 74 69 6C 69 74 79 2E}
// 		$s11 = {6E 78 65 44 52 2E 43 6F 6D 6D 61 6E 64 2B 3D 6E 65 77 20 43 6F 6D 6D 61 6E 64 45 76 65 6E 74 48 61 6E 64 6C 65 72 28 74 68 69 73 2E 69 56 6B 29 3B}
// 		$s12 = {3C 25 40 20 69 6D 70 6F 72 74 20 4E 61 6D 65 73 70 61 63 65 3D 5C 22 53 79 73 74 65 6D 2E 53 65 72 76 69 63 65 50 72 6F 63 65 73 73 5C 22 25 3E}
// 		$s13 = {66 6F 72 65 61 63 68 28 73 74 72 69 6E 67 20 69 6E 6E 65 72 53 75 62 4B 65 79 20 69 6E 20 73 6B 2E 47 65 74 53 75 62 4B 65 79 4E 61 6D 65 73 28 29 29}
// 		$s17 = {52 65 73 70 6F 6E 73 65 2E 52 65 64 69 72 65 63 74 28 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 72 6F 6F 74 6B 69 74 2E 6E 65 74 2E 63 6E 5C 22 29 3B}
// 		$s20 = {65 6C 73 65 20 69 66 28 52 65 67 5F 50 61 74 68 2E 53 74 61 72 74 73 57 69 74 68 28 5C 22 48 4B 45 59 5F 55 53 45 52 53 5C 22 29 29}

// 	condition:
// 		6 of them
// }

// rule Webshell_27_9_c66_c99
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php ..."
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
// 		hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
// 		hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
// 		hash4 = "80ec7831ae888d5603ed28d81225ed8b256c831077bb8feb235e0a1a9b68b748"
// 		hash5 = "6ce99e07aa98ba6dc521c34cf16fbd89654d0ba59194878dffca857a4c34e57b"
// 		hash6 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
// 		hash7 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
// 		hash8 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
// 		hash9 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
// 		hash10 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"

// 	strings:
// 		$s4 = {69 66 20 28 21 65 6D 70 74 79 28 24 75 6E 73 65 74 5F 73 75 72 6C 29 29 20 7B 73 65 74 63 6F 6F 6B 69 65 28 5C 22 63 39 39 73 68 5F 73 75 72 6C 5C 22 29 3B 20 24 73 75 72 6C 20 3D 20 5C 22 5C 22 3B 7D}
// 		$s6 = {40 65 78 74 72 61 63 74 28 24 5F 52 45 51 55 45 53 54 5B 5C 22 63 39 39 73 68 63 6F 6F 6B 5C 22 5D 29 3B}
// 		$s7 = {69 66 20 28 21 66 75 6E 63 74 69 6F 6E 5F 65 78 69 73 74 73 28 5C 22 63 39 39 5F 62 75 66 66 5F 70 72 65 70 61 72 65 5C 22 29 29}

// 	condition:
// 		filesize <685KB and 1 of them
// }

// rule Webshell_acid_AntiSecShell_3
// {
// 	meta:
// 		description = "Detects Webshell Acid"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
// 		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
// 		hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
// 		hash4 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
// 		hash5 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
// 		hash6 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
// 		hash7 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
// 		hash8 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
// 		hash9 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
// 		hash10 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
// 		hash11 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
// 		hash12 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
// 		hash13 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
// 		hash14 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
// 		hash15 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
// 		hash16 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
// 		hash17 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
// 		hash18 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 64 65 6C 65 74 65 5C 22 2E 28 24 64 73 70 61 63 74 20 3D 3D 20 5C 22 64 65 6C 65 74 65 5C 22 3F 5C 22 20 73 65 6C 65 63 74 65 64 5C 22 3A 5C 22 5C 22 29 2E 5C 22 3E 44 65 6C 65 74 65 3C 2F 6F 70 74 69 6F 6E 3E 5C 22 3B}
// 		$s1 = {69 66 20 28 21 69 73 5F 72 65 61 64 61 62 6C 65 28 24 6F 29 29 20 7B 72 65 74 75 72 6E 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 5C 22 2E 76 69 65 77 5F 70 65 72 6D 73 28 66 69 6C 65 70 65 72 6D 73 28 24 6F 29 29 2E 5C 22 3C 2F 66 6F 6E 74 3E 5C 22 3B 7D}

// 	condition:
// 		filesize <900KB and all of them
// }

// rule Webshell_c99_4
// {
// 	meta:
// 		description = "Detects C99 Webshell"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
// 		hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
// 		hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
// 		hash4 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
// 		hash5 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
// 		hash6 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
// 		hash7 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
// 		hash8 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
// 		hash9 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
// 		hash10 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
// 		hash11 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
// 		hash12 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
// 		hash13 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
// 		hash14 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

// 	strings:
// 		$s1 = {64 69 73 70 6C 61 79 73 65 63 69 6E 66 6F 28 5C 22 4C 69 73 74 20 6F 66 20 41 74 74 72 69 62 75 74 65 73 5C 22 2C 6D 79 73 68 65 6C 6C 65 78 65 63 28 5C 22 6C 73 61 74 74 72 20 2D 61 5C 22 29 29 3B}
// 		$s2 = {64 69 73 70 6C 61 79 73 65 63 69 6E 66 6F 28 5C 22 52 41 4D 5C 22 2C 6D 79 73 68 65 6C 6C 65 78 65 63 28 5C 22 66 72 65 65 20 2D 6D 5C 22 29 29 3B}
// 		$s3 = {64 69 73 70 6C 61 79 73 65 63 69 6E 66 6F 28 5C 22 57 68 65 72 65 20 69 73 20 70 65 72 6C 3F 5C 22 2C 6D 79 73 68 65 6C 6C 65 78 65 63 28 5C 22 77 68 65 72 65 69 73 20 70 65 72 6C 5C 22 29 29 3B}
// 		$s4 = {24 72 65 74 20 3D 20 6D 79 73 68 65 6C 6C 65 78 65 63 28 24 68 61 6E 64 6C 65 72 29 3B}
// 		$s5 = {69 66 20 28 70 6F 73 69 78 5F 6B 69 6C 6C 28 24 70 69 64 2C 24 73 69 67 29 29 20 7B 65 63 68 6F 20 5C 22 4F 4B 2E 5C 22 3B 7D}

// 	condition:
// 		filesize <900KB and 1 of them
// }

// rule Webshell_r57shell_2
// {
// 	meta:
// 		description = "Detects Webshell R57"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
// 		hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
// 		hash3 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
// 		hash4 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
// 		hash5 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
// 		hash6 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
// 		hash7 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
// 		hash8 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
// 		hash9 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
// 		hash10 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
// 		hash11 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
// 		hash12 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
// 		hash13 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"

// 	strings:
// 		$s1 = {24 63 6F 6E 6E 65 63 74 69 6F 6E 20 3D 20 40 66 74 70 5F 63 6F 6E 6E 65 63 74 28 24 66 74 70 5F 73 65 72 76 65 72 2C 24 66 74 70 5F 70 6F 72 74 2C 31 30 29 3B}
// 		$s2 = {65 63 68 6F 20 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 39 38 27 5D 2E 24 73 75 63 2E 5C 22 5C 5C 72 5C 5C 6E 5C 22 3B}

// 	condition:
// 		filesize <900KB and all of them
// }

// rule Webshell_27_9_acid_c99_locus7s
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
// 		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
// 		hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
// 		hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
// 		hash5 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
// 		hash6 = "5ae121f868555fba112ca2b1a9729d4414e795c39d14af9e599ce1f0e4e445d3"
// 		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
// 		hash8 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"

// 	strings:
// 		$s0 = {24 62 6C 61 68 20 3D 20 65 78 28 24 70 32 2E 5C 22 20 2F 74 6D 70 2F 62 61 63 6B 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 6F 6E 6E 65 63 74 69 70 27 5D 2E 5C 22 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 6F 6E 6E 65 63 74 70 6F 72 74 27 5D 2E 5C 22 20 26 5C 22 29 3B}
// 		$s1 = {24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 63 6F 6E 6E 6D 73 67 65 27 5D 3D 5C 22 3C 2F 62 72 3E 3C 2F 62 72 3E 3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 20 73 69 7A 65 3D 33 3E 45 72 72 6F 72 3A 3C 2F 66 6F 6E 74 3E 20 43 61 6E 27 74 20 62 61 63 6B 64 6F 6F 72 20 68 6F 73 74 21 3C 2F 62 3E 5C 22 3B}

// 	condition:
// 		filesize <1711KB and 1 of them
// }

// rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
// 		hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
// 		hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
// 		hash4 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
// 		hash5 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
// 		hash6 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
// 		hash7 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
// 		hash8 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
// 		hash9 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
// 		hash10 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
// 		hash11 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"

// 	strings:
// 		$s1 = {24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 20 3D 20 77 68 69 63 68 28 27}
// 		$s2 = {24 62 6C 61 68 20 3D 20 65 78 28}

// 	condition:
// 		filesize <600KB and all of them
// }

// rule Webshell_c100
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files c100 v. 777shell"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
// 		hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
// 		hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
// 		hash4 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
// 		hash5 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
// 		hash6 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
// 		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"

// 	strings:
// 		$s0 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 77 67 65 74 20 68 74 74 70 3A 2F 2F 66 74 70 2E 70 6F 77 65 72 6E 65 74 2E 63 6F 6D 2E 74 72 2F 73 75 70 65 72 6D 61 69 6C 2F 64 65 62 75 67 2F 6B 33 5C 22 3E 4B 65 72 6E 65 6C 20 61 74 74 61 63 6B 20 28 4B 72 61 64 2E 63 29 20 50 54 31 20 28 49 66 20 77 67 65 74 20 69 6E 73 74 61 6C 6C 65 64 29}
// 		$s1 = {3C 63 65 6E 74 65 72 3E 4B 65 72 6E 65 6C 20 49 6E 66 6F 3A 20 3C 66 6F 72 6D 20 6E 61 6D 65 3D 5C 22 66 6F 72 6D 31 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 68 74 74 70 3A 2F 2F 67 6F 6F 67 6C 65 2E 63 6F 6D 2F 73 65 61 72 63 68 5C 22 3E}
// 		$s3 = {63 75 74 20 2D 64 3A 20 2D 66 31 2C 32 2C 33 20 2F 65 74 63 2F 70 61 73 73 77 64 20 7C 20 67 72 65 70 20 3A 3A}
// 		$s4 = {77 68 69 63 68 20 77 67 65 74 20 63 75 72 6C 20 77 33 6D 20 6C 79 6E 78}
// 		$s6 = {6E 65 74 73 74 61 74 20 2D 61 74 75 70 20 7C 20 67 72 65 70 20 49 53 54}

// 	condition:
// 		filesize <685KB and 2 of them
// }

// rule Webshell_AcidPoison
// {
// 	meta:
// 		description = "Detects Poison Sh3ll - Webshell"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
// 		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
// 		hash3 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
// 		hash4 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
// 		hash5 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
// 		hash6 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
// 		hash7 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
// 		hash8 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
// 		hash9 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
// 		hash10 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"

// 	strings:
// 		$s1 = {65 6C 73 65 69 66 20 28 20 65 6E 61 62 6C 65 64 28 5C 22 65 78 65 63 5C 22 29 20 29 20 7B 20 65 78 65 63 28 24 63 6D 64 2C 24 6F 29 3B 20 24 6F 75 74 70 75 74 20 3D 20 6A 6F 69 6E 28 5C 22 5C 5C 72 5C 5C 6E 5C 22 2C 24 6F 29 3B 20 7D}

// 	condition:
// 		filesize <550KB and all of them
// }

// rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files acid.php, FaTaLisTiCz_Fx.txt, fx.txt, p0isoN.sh3ll.txt, x0rg.byp4ss.txt"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
// 		hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
// 		hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
// 		hash4 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
// 		hash5 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

// 	strings:
// 		$s0 = {3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 68 69 64 64 65 6E 20 6E 61 6D 65 3D 61 63 74 20 76 61 6C 75 65 3D 5C 22 6C 73 5C 22 3E}
// 		$s2 = {66 6F 72 65 61 63 68 28 24 71 75 69 63 6B 6C 61 75 6E 63 68 32 20 61 73 20 24 69 74 65 6D 29 20 7B}

// 	condition:
// 		filesize <882KB and all of them
// }

// rule Webshell_Ayyildiz
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files Ayyildiz Tim  -AYT- Shell v 2.1 Biz.txt, Macker's Private PHPShell.php, matamu.txt, myshell.txt, PHP Shell.txt"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
// 		hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
// 		hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
// 		hash4 = "77a63b26f52ba341dd2f5e8bbf5daf05ebbdef6b3f7e81cec44ce97680e820f9"
// 		hash5 = "61c4fcb6e788c0dffcf0b672ae42b1676f8a9beaa6ec7453fc59ad821a4a8127"

// 	strings:
// 		$s0 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 5C 22 2E 20 73 74 72 72 65 76 28 73 75 62 73 74 72 28 73 74 72 73 74 72 28 73 74 72 72 65 76 28 24 77 6F 72 6B 5F 64 69 72 29 2C 20 5C 22 2F 5C 22 29 2C 20 31 29 29 20 2E 5C 22 5C 5C 5C 22 3E 50 61 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E 5C 5C 6E 5C 22 3B}
// 		$s1 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 77 6F 72 6B 5F 64 69 72 5C 5C 5C 22 20 73 65 6C 65 63 74 65 64 3E 43 75 72 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E 5C 5C 6E 5C 22 3B}

// 	condition:
// 		filesize <112KB and all of them
// }

// rule Webshell_zehir
// {
// 	meta:
// 		description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
// 		author = "Florian Roth"
// 		reference = "https://github.com/nikicat/web-malware-collection"
// 		date = "2016-01-11"
// 		score = 70
// 		hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
// 		hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
// 		hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
// 		hash4 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d"
// 		hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"

// 	strings:
// 		$s1 = {66 6F 72 20 28 69 3D 31 3B 20 69 3C 3D 66 72 6D 55 70 6C 6F 61 64 2E 6D 61 78 2E 76 61 6C 75 65 3B 20 69 2B 2B 29 20 73 74 72 2B 3D 27 46 69 6C 65 20 27 2B 69 2B 27 3A 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 66 69 6C 65 20 6E 61 6D 65 3D 66 69 6C 65 27 2B 69 2B 27 3E 3C 62 72 3E 27 3B}
// 		$s2 = {69 66 20 28 66 72 6D 55 70 6C 6F 61 64 2E 6D 61 78 2E 76 61 6C 75 65 3C 3D 30 29 20 66 72 6D 55 70 6C 6F 61 64 2E 6D 61 78 2E 76 61 6C 75 65 3D 31 3B}

// 	condition:
// 		filesize <200KB and 1 of them
// }

