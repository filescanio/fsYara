// contains SPECIFIC rules from MALW_Miscelanea.yar
// moved from source: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MALW_Miscelanea.yar 
// source: https://github.com/Neo23x0/signature-base/blob/2ccd5f772b3f626a0130dd562f1ae68602dcade0/yara/pup_lightftp.yar
// + other sources


rule PUP_InstallRex_AntiFWb {
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth"
		date = "2015-05-13"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		score = 65
	strings:
		$s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
		$s7 = "GetModuleFileName() failed => %u" fullword ascii
		$s8 = "TSULoader.exe" fullword wide
		$s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
		$s17 = "Tsu%08lX.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule LightFTP_fftp_x86_64 {
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 4 of them
}

rule LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide
	condition:
		uint16(0) == 0xfeff and filesize < 1KB and all of them
}


rule CrowdStrike_CSA_240838_01 : daolpu stealer 
{
    meta:
        copyright = "(c) 2024 CrowdStrike Inc."
        description = "C++ stealer delivered via Word documents with macros impersonating CS"
        reports = "CSA-240838"
        version = "202407221342"
        last_modified = "2024-07-22"
        malware_family = "Daolpu"
        score = 75
	reference = "https://www.crowdstrike.com/blog/fake-recovery-manual-used-to-deliver-unidentified-stealer/"
    strings:
        $ = "C:\\Windows\\Temp\\result.txt"
        $ = "D:\\c++\\Mal_Cookie_x64\\x64\\Release\\mscorsvc.pdb"
    condition:
        all of them
}


rule ZXProxy {
    meta:
    	author = "ThreatConnect Intelligence Research Team"
    	
    strings:
    	$C = "\\Control\\zxplug" nocase wide ascii
    	$h = "http://www.facebook.com/comment/update.exe" wide ascii
    	$S = "Shared a shell to %s:%s Successfully" nocase wide ascii
    condition:
    	any of them
}

rule OrcaRAT {
    meta:
        Author      = "PwC Cyber Threat Operations"
        Date        = "2014/10/20" 
        Description = "Strings inside"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2014/10/orcarat-a-whale-of-a-tale.html"

    strings:
        $MZ = "MZ"
        $apptype1 = "application/x-ms-application"
        $apptype2 = "application/x-ms-xbap"
        $apptype3 = "application/vnd.ms-xpsdocument"
        $apptype4 = "application/xaml+xml"
        $apptype5 = "application/x-shockwave-flash"
        $apptype6 = "image/pjpeg"
        $err1 = "Set return time error =   %d!"
        $err2 = "Set return time   success!"
        $err3 = "Quit success!"

    condition:
        $MZ at 0 and filesize < 500KB and (all of ($apptype*) and 1 of ($err*))
}

rule SpyGate_v2_9 {
    meta:
        date = "2014/09"
        maltype = "Spygate v2.9 Remote Access Trojan"
        filetype = "exe"
        reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"
    strings:
        $1 = "shutdowncomputer" wide
        $2 = "shutdown -r -t 00" wide
        $3 = "blockmouseandkeyboard" wide
        $4 = "ProcessHacker"
        $5 = "FileManagerSplit" wide
    condition:
        all of them
}

rule ice_ix_12xy : banker {
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "ICE-IX 1.2.x.y trojan banker"
        date = "2013-01-12"
        filetype = "memory"
        version = "1.0" 
    
    strings:
        $regexp1= /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
        $a = "bn1="
        $b = "&sk1="
        $c = "mario"                                //HardDrive GUID artifact
        $d = "FIXME"
        $e = "RFB 003.003"                          //VNC artifact
        $ggurl = "http://www.google.com/webhp"

    condition:
        $regexp1 or ($a and $b) or all of ($c,$d,$e,$ggurl) 
}

rule qadars : banker {
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Qadars - Mobile part. Maybe Perkele."
        version = "1.0" 
        filetype = "memory"
        ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

    strings:
        $cmd1 = "m?D"
        $cmd2 = "m?S"
        $cmd3 = "ALL"
        $cmd4 = "FILTER"
        $cmd5 = "NONE"
        $cmd6 = "KILL"
        $cmd7 = "CANCEL"
        $cmd8 = "SMS"
        $cmd9 = "DIVERT"
        $cmd10 = "MESS"
        $nofilter = "nofilter1111111"
        $botherderphonenumber1 = "+380678409210"

    condition:
        all of ($cmd*) or $nofilter or any of ($botherderphonenumber*)
}

rule shylock :  banker {
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Shylock Banker"
        date = "2013-12-12" 
        version = "1.0" 
        ref1 = "http://iocbucket.com/iocs/1b4660d57928df5ca843c21df0b2adb117026cba"
        ref2 = "http://www.trusteer.com/blog/merchant-fraud-returns-%E2%80%93-shylock-polymorphic-financial-malware-infections-rise"
        ref3 = "https://www.csis.dk/en/csis/blog/3811/"

    strings:
        $process1 = "MASTER"
        $process2 = "_SHUTDOWN"
        $process3 = "EVT_VNC"
        $process4 = "EVT_BACK"
        $process5 = "EVT_VNC"
        $process6 = "IE_Hook::GetRequestInfo"
        $process7 = "FF_Hook::getRequestInfo"
        $process8 = "EX_Hook::CreateProcess"
        $process9 = "hijackdll.dll"
        $process10 = "MTX_"
        $process11 = "FF::PR_WriteHook entry"
        $process12 = "FF::PR_WriteHook exit"
        $process13 = "HijackProcessAttach::*** MASTER *** MASTER *** MASTER *** %s PID=%u"
        $process14 = "HijackProcessAttach::entry"
        $process15 = "FF::BEFORE INJECT"
        $process16 = "FF::AFTER INJECT"
        $process17 = "IE::AFTER INJECT"
        $process18 = "IE::BEFORE INJECT"
        $process19 = "*** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** %s"
        $process20 = "*** LOG INJECTS *** %s"
        $process21 = "*** inject to process %s not allowed"
        $process22 = "*** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** %s"
        $process23 = ".?AVFF_Hook@@"
        $process24 = ".?AVIE_Hook@@"
        $process25 = "Inject::InjectDllFromMemory"
        $process26 = "BadSocks.dll" 
        $domain1 = "extensadv.cc"
        $domain2 = "topbeat.cc"
        $domain3 = "brainsphere.cc"
        $domain4 = "commonworldme.cc"
        $domain5 = "gigacat.cc"
        $domain6 = "nw-serv.cc"
        $domain7 = "paragua-analyst.cc"
        
    condition:
        3 of ($process*) or any of ($domain*)
}


rule memory_shylock

{
   meta:
	  author = "https://github.com/jackcr/"

   strings:
      $a = /pipe\\[A-F0-9]{32}/     //Named pipe created by the malware
      $b = /id=[A-F0-9]{32}/     //Portion or the uri beacon
      $c = /MASTER_[A-F0-9]{32}/     //Mutex created by the malware
      $d = "***Load injects by PIPE (%s)" //String found in binary
      $e = "***Load injects url=%s (%s)" //String found in binary
      $f = "*********************** Ping Ok ************************" //String found in binary
      $g = "*** LOG INJECTS *** %s"     //String found in binary

   condition: 
      any of them

}


rule potential_banker : refined
//rule spyeye : banker
{
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "SpyEye X.Y memory"
        date = "2012-05-23" 
        version = "1.0" 
        filetype = "memory"

    strings:
        $spyeye = "SpyEye"
        $a = "%BOTNAME%"
        $b = "globplugins"
        $c = "data_inject"
        $d = "data_before"
        $e = "data_after"
        $f = "data_end"
        $g = "bot_version"
        $h = "bot_guid"
        $i = "TakeBotGuid"
        $j = "TakeGateToCollector"
        $k = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
        $l = "[ERROR] : Update is not successfull for some reason"
        $m = "[ERROR] : dwErr == %u"
        $n = "GRABBED DATA"
        
    condition:
        //$spyeye or (any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
    $spyeye or (2 of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
}

rule spyeye_plugins : banker refined
{
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "SpyEye X.Y Plugins memory"
        date = "2012-05-23" 
        version = "1.0" 
        filetype = "memory"

    strings:
        $a = "webfakes.dll"
        //$b = "config.dat"         //may raise some FP
        $c = "collectors.txt"
        $d = "webinjects.txt"
        $e = "screenshots.txt"
        $f = "billinghammer.dll"
        $g = "block.dll"            //may raise some FP
        $h = "bugreport.dll"        //may raise some FP
        $i = "ccgrabber.dll"
        $j = "connector2.dll"
        $k = "creditgrab.dll"
        $l = "customconnector.dll"
        $m = "ffcertgrabber.dll"
        $n = "ftpbc.dll"
        $o = "rdp.dll"              //may raise some FP
        $p = "rt_2_4.dll"
        //$q = "socks5.dll"         //may raise some FP
        $r = "spySpread.dll"
        $s = "w2chek4_4.dll"
        $t = "w2chek4_6.dll"
    
    condition:
        any of them
}

// same as RAT_Pandora in executable/PE-ELF/specific/rats_malwareconfig.yar
//rule Pandora {
//    meta:
//        author = " Kevin Breen <kevin@techanarchy.net>"
//        date = "2014/04"
//        ref = "http://malwareconfig.com/stats/Pandora"
//        maltype = "Remote Access Trojan"
//        filetype = "exe"
//
//    strings:
//        $a = "Can't get the Windows version"
//        $b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
//        $c = "JPEG error #%d" wide
//        $d = "Cannot assign a %s to a %s" wide
//        $g = "%s, ProgID:"
//        $h = "clave"
//        $i = "Shell_TrayWnd"
//        $j = "melt.bat"
//        $k = "\\StubPath"
//        $l = "\\logs.dat"
//        $m = "1027|Operation has been canceled!"
//        $n = "466|You need to plug-in! Double click to install... |"
//        $0 = "33|[Keylogger Not Activated!]"
//
//    condition:
//        all of them
//}


rule Invoke_mimikittenz {
    meta:
        description = "Detects Mimikittenz - file Invoke-mimikittenz.ps1"
        author = "Florian Roth"
        reference = "https://github.com/putterpanda/mimikittenz"
        date = "2016-07-19"
        score = 90
        hash1 = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a"
    strings:
        $x1 = "[mimikittenz.MemProcInspector]" ascii

        $s1 = "PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |" fullword ascii
        $s2 = "IntPtr processHandle = MInterop.OpenProcess(MInterop.PROCESS_WM_READ | MInterop.PROCESS_QUERY_INFORMATION, false, process.Id);" fullword ascii
        $s3 = "&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1=" ascii
        $s4 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii
    condition:
        ( uint16(0) == 0x7566 and filesize < 60KB and 2 of them ) or $x1
}
