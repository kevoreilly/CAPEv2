from lib.cuckoo.common.abstracts import Signature

filesDeleted = (
	"Log.zip",
	"sqlite3.dll",
	"ff-funcs.zip",
	"passwords.txt",
	"CC.txt",
	"chrome_cookie.txt",
	"firefox_cookie.txt",
	"chrome_autofill.txt",
	"machineinfo.txt",
	"screen.png",
)

filesSearched = (
	"AppData\\Roaming\\WaterFox\\Profiles\\*",
	"AppData\\Roaming\\WaterFox\\Profiles\\*",
	"AppData\\Roaming\\Mozilla\\SeaMonkey\\Profiles\\*",
	"AppData\\Roaming\\Mozilla\\SeaMonkey\\Profiles\\*",
	"AppData\\Roaming\\Moonchild Productions\\Pale Moon\\Profiles\\*",
	"AppData\\Roaming\\Thunderbird\\Profiles\\*",
	"AppData\\Roaming\\Thunderbird\\Profiles\\*",
	"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates\\*",
	"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CRLs\\*",
	"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CTLs\\*",
	"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates\\*",
	"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CRLs\\*",
	"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CTLs\\*",
	"AppData\\Local\\Google\\Chrome\\User Data\\*",
	"AppData\\Local\\Xpom\\User Data\\*",
	"AppData\\Local\\Comodo\\Dragon\\User Data\\*",
	"AppData\\Local\\Amigo\\User Data\\*",
	"AppData\\Local\\Orbitum\\User Data\\*",
	"AppData\\Local\\Bromium\\User Data\\*",
	"AppData\\Local\\Nichrome\\User Data\\* ",
	"AppData\\Local\\RockMelt\\User Data\\*",
	"AppData\\Local\\360Browser\\Browser\\User Data\\*",
	"AppData\\Local\\Vivaldi\\User Data\\*",
	"AppData\\Roaming\\Opera Software\\*",
	"AppData\\Local\\Go!\\User Data\\*",
	"AppData\\Local\\Sputnik\\Sputnik\\User Data\\*",
	"AppData\\Local\\Kometa\\User Data\\*",
	"AppData\\Local\\uCozMedia\\Uran\\User Data\\*",
	"AppData\\Local\\QIP Surf\\User Data\\*",
	"AppData\\Local\\Epic Privacy Browser\\User Data\\*",
	"AppData\\Local\\CocCoc\\Browser\\User Data\\*",
	"AppData\\Local\\CentBrowser\\User Data\\*",
	"AppData\\Local\\7Star\\7Star\\User Data\\*",
	"AppData\\Local\\Elements Browser\\User Data\\*",
	"AppData\\Local\\TorBro\\Profile\\*",
	"AppData\\Local\\Suhba\\User Data\\*",
	"AppData\\Local\\Safer Technologies\\Secure Browser\\User Data\\*",
	"AppData\\Local\\Rafotech\\Mustang\\User Data\\*",
	"AppData\\Local\\Superbird\\User Data\\*",
	"AppData\\Local\\Chedot\\User Data\\*",
	"AppData\\Local\\Torch\\User Data\\*"
)

infoWrited = (
	"Raccoon Stealer",
	"Build compiled on",
	"Launched at:",
	"Bot_ID:",
	"System Information:",
	"System Language:",
	"Username:",
	"IP:",
	"Windows version:",
	"Product name:",
	"System arch:",
	"CPU:",
	"RAM:",
	"Screen resolution:",
	"Display devices:",
	"Installed Apps:",

)

class raccoon(Signature):
	name = "Raccoon Behavior"
	description = "Detects Raccoon Behavior"
	weight = 3
	severity = 3
	categories = ["Infostealer"]
	families = ["Raccoon"]
	authors = ["@NaxoneZ"]
	minimum = "1.2"
	evented = True
	samples = {
	"Raccoon":
		{
			"1": "726aa7c9d286afab16c956639ffe01a47ce556bc893f46d487b3148608a019d7", #variant1
		}
	}

	def __init__(self, *args, **kwargs):
		Signature.__init__(self, *args, **kwargs)
		self.badness_filesSearched = 0
		self.badness_filesDeleted = 0
		self.badness_infoWrited = 0

	filter_apinames = set(["DeleteFileW","FindFirstFileExW","NtWriteFile"])

	def on_call(self, call, process):

		if call["api"] == "DeleteFileW":
			node = self.get_argument(call,"FileName")
			for i in filesDeleted:
				if i in node:
					self.badness_filesDeleted += 1

		if call["api"] == "FindFirstFileExW":
			node = self.get_argument(call,"FileName")
			for i in filesSearched:
				if i in node:
					self.badness_filesSearched += 1

		if call["api"] == "NtWriteFile":
			node = self.get_argument(call,"Buffer")
			for i in infoWrited:
				if i in node:
					self.badness_infoWrited += 1

	def on_complete(self):
		if self.badness_filesSearched > 50 and self.badness_filesDeleted > 9 and self.badness_infoWrited > 15:
			return True
		else:
			return False
