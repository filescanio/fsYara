/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// source: https://github.com/Yara-Rules/rules/blob/master/exploit_kits/EK_Blackhole.yar

rule blackhole2_jar : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "86946ec2d2031f2b456e804cac4ade6d"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "k0/3;N"
   $string1 = "g:WlY0"
   $string2 = "(ww6Ou"
   $string3 = "SOUGX["
   $string4 = "7X2ANb"
   $string5 = "r8L<;zYH)"
   $string6 = "fbeatbea/fbeatbee.classPK"
   $string7 = "fbeatbea/fbeatbec.class"
   $string8 = "fbeatbea/fbeatbef.class"
   $string9 = "fbeatbea/fbeatbef.classPK"
   $string10 = "fbeatbea/fbeatbea.class"
   $string11 = "fbeatbea/fbeatbeb.classPK"
   $string12 = "nOJh-2"
   $string13 = "[af:Fr"
condition:
   13 of them
}
rule blackhole2_jar2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "add1d01ba06d08818ff6880de2ee74e8"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "6_O6d09"
   $string1 = "juqirvs.classPK"
   $string2 = "hw.classPK"
   $string3 = "a.classPK"
   $string4 = "w.classuS]w"
   $string5 = "w.classPK"
   $string6 = "YE}0vCZ"
   $string7 = "v)Q,Ff"
   $string8 = "%8H%t("
   $string9 = "hw.class"
   $string10 = "a.classmV"
   $string11 = "2CniYFU"
   $string12 = "juqirvs.class"
condition:
   12 of them
}
rule blackhole2_jar3 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "c7abd2142f121bd64e55f145d4b860fa"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "69/sj]]o"
   $string1 = "GJk5Nd"
   $string2 = "vcs.classu"
   $string3 = "T<EssB"
   $string4 = "1vmQmQ"
   $string5 = "Kf1Ewr"
   $string6 = "c$WuuuKKu5"
   $string7 = "m.classPK"
   $string8 = "chcyih.classPK"
   $string9 = "hw.class"
   $string10 = "f';;;;{"
   $string11 = "vcs.classPK"
   $string12 = "Vbhf_6"
condition:
   12 of them
}
rule blackhole1_jar
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BlackHole1 Exploit Kit Detection"
   hash0 = "724acccdcf01cf2323aa095e6ce59cae"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "Created-By: 1.6.0_18 (Sun Microsystems Inc.)"
   $string1 = "workpack/decoder.classmQ]S"
   $string2 = "workpack/decoder.classPK"
   $string3 = "workpack/editor.classPK"
   $string4 = "xmleditor/GUI.classmO"
   $string5 = "xmleditor/GUI.classPK"
   $string6 = "xmleditor/peers.classPK"
   $string7 = "v(SiS]T"
   $string8 = ",R3TiV"
   $string9 = "META-INF/MANIFEST.MFPK"
   $string10 = "xmleditor/PK"
   $string11 = "Z[Og8o"
   $string12 = "workpack/PK"
condition:
   12 of them
}
