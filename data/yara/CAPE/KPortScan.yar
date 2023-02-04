rule KPortScan
{
meta:
	description = "Identifies KPortScan, port scanner."
	author = "@bartblaze"
	date = "2020-08"
	tlp = "White"
	cape_type = "KPortScan Payload"

strings:
	$s1 = "KPortScan 3.0" ascii wide
	$s2 = "KPortScan3.exe" ascii wide

	$x1 = "Count of goods:" ascii wide
	$x2 = "Current range:" ascii wide
	$x3 = "IP ranges list is clear" ascii wide
	$x4 = "ip,port,state" ascii wide
	$x5 = "on_loadFinished(QNetworkReply*)" ascii wide
	$x6 = "on_scanDiapFinished()" ascii wide
	$x7 = "on_scanFinished()" ascii wide
	$x8 = "scanDiapFinished()" ascii wide
	$x9 = "scanFinished()" ascii wide
	$x10 = "with port" ascii wide
	$x11 = "without port" ascii wide

condition:
	any of ($s*) or 3 of ($x*)
}
