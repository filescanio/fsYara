// source: https://www.incibe.es/sites/default/files/contenidos/estudios/doc/incibe-cert_flubot_analysis_study_2021_v1.pdf
rule FluBot: FluBot
{
meta:
 description = "FluBot Core"
 author = "Incibe"
 version = "0.1"
 score = 70

strings:
$s1 = "Bot.java"
$s2 = "BotId.java"
$s3 = "BrowserActivity.java"
$s4 = "BuildConfig.java"
$s5 = "DGA.java"
$s6 = "SocksClient.java"
$s7 = "SmsReceiver.java"
$s8 = "Spammer.java"
condition:
 all of them
}
