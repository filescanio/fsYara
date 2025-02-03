rule BlackShades_3 : Trojan RAT hardened
{
	meta:
		description = "BlackShades RAT"
		author = "botherder https://github.com/botherder"

	strings:
		$mod1 = /(m)odAPI/
		$mod2 = /(m)odAudio/
		$mod3 = /(m)odBtKiller/
		$mod4 = /(m)odCrypt/
		$mod5 = /(m)odFuctions/
		$mod6 = /(m)odHijack/
		$mod7 = /(m)odICallBack/
		$mod8 = /(m)odIInet/
		$mod9 = /(m)odInfect/
		$mod10 = /(m)odInjPE/
		$mod11 = /(m)odLaunchWeb/
		$mod12 = /(m)odOS/
		$mod13 = /(m)odPWs/
		$mod14 = /(m)odRegistry/
		$mod15 = /(m)odScreencap/
		$mod16 = /(m)odSniff/
		$mod17 = /(m)odSocketMaster/
		$mod18 = /(m)odSpread/
		$mod19 = /(m)odSqueezer/
		$mod20 = /(m)odSS/
		$mod21 = /(m)odTorrentSeed/
		$tmr1 = /(t)mrAlarms/
		$tmr2 = /(t)mrAlive/
		$tmr3 = /(t)mrAnslut/
		$tmr4 = /(t)mrAudio/
		$tmr5 = /(t)mrBlink/
		$tmr6 = /(t)mrCheck/
		$tmr7 = /(t)mrCountdown/
		$tmr8 = /(t)mrCrazy/
		$tmr9 = /(t)mrDOS/
		$tmr10 = /(t)mrDoWork/
		$tmr11 = /(t)mrFocus/
		$tmr12 = /(t)mrGrabber/
		$tmr13 = /(t)mrInaktivitet/
		$tmr14 = /(t)mrInfoTO/
		$tmr15 = /(t)mrIntervalUpdate/
		$tmr16 = /(t)mrLiveLogger/
		$tmr17 = /(t)mrPersistant/
		$tmr18 = /(t)mrScreenshot/
		$tmr19 = /(t)mrSpara/
		$tmr20 = /(t)mrSprid/
		$tmr21 = /(t)mrTCP/
		$tmr22 = /(t)mrUDP/
		$tmr23 = /(t)mrWebHide/

	condition:
		10 of ( $mod* ) or 10 of ( $tmr* )
}

rule BlackShades_4 : rat hardened
{
	meta:
		description = "BlackShades"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0"

	strings:
		$a = { 42 00 6C 00 61 00 63 00 6B 00 73 00 68 00 61 00 64 00 65 00 73 }
		$b = { 36 00 3C 00 32 00 20 00 32 00 32 00 26 00 31 00 39 00 3E 00 1D 00 17 00 17 00 1C 00 07 00 1B 00 03 00 07 00 28 00 23 00 0C 00 1D 00 10 00 1B 00 12 00 00 00 28 00 37 00 10 00 01 00 06 00 11 00 0B 00 07 00 22 00 11 00 17 00 00 00 1D 00 1B 00 0B 00 2F 00 26 00 01 00 0B }
		$c = { 62 73 73 5F 73 65 72 76 65 72 }
		$d = { 43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44 }
		$e = { 6D 6F 64 49 6E 6A 50 45 }
		$apikey = {66 34 35 65 33 37 33 34 32 39 63 30 64 65 66 33 35 35 65 64 39 66 65 66 66 33 30 65 66 66 39 63 61 32 31 65 65 63 30 66 61 66 61 31 65 39 36 30 62 65 61 36 30 36 38 66 33 34 32 30 39 34 33 39}

	condition:
		any of ( $a , $b , $c , $d , $e ) or $apikey
}

rule BlackShades : Trojan hardened
{
	meta:
		author = "Kevin Falcoz"
		date = "26/06/2013"
		description = "BlackShades Server"

	strings:
		$signature1 = {62 73 73 5F 73 65 72 76 65 72}
		$signature2 = {43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
		$signature3 = {6D 6F 64 49 6E 6A 50 45}

	condition:
		$signature1 and $signature2 and $signature3
}

rule BlackShades_25052015 : hardened
{
	meta:
		author = "Brian Wallace (@botnet_hunter)"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PoisonIvy"
		ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
		family = "blackshades"
		score = 50

	strings:
		$string1 = {62 73 73 5f 73 65 72 76 65 72}
		$string2 = {74 78 74 43 68 61 74}
		$string3 = {55 44 50 46 6c 6f 6f 64}

	condition:
		all of them
}

