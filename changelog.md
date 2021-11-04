### [04-11-2021]
* Move Office hook options from packages to monitor
* Monitor: Disable NtWaitForSingleObject hook for 32-bit Windows 8+ due to crashes

### [03-11-2021]
* Add MongoDB multifield index for all SHA256 fields.
    * if you using any other fields for frequent lookup, add indexes for that on your side to speedup database

### [01-11-2021]
* Allow download reports as zip via API
* Fix python analysis support in Windows

### [22-10-2021]
* POC: AntiRansomware:
    * Can be enabled in `processing.conf` it will disable processing of files with extensions that are not in allowed list, see `modules/processing/antiransomware.py`
    * Specially useful to disable them in CAPE.py that gather all the metadata, yara etc and can consume a lot of ram

### [21-10-2021]
* Monitor update: Monitor fix for scan crashes in e.g. Equation Editor/Cmd (thanks Will)

### [19-10-2021]
* Monitor update: Monitor fix for NtSuspendThread hook issue (thanks Intezer)

### CENTS - Configuration Extraction to Network Traffic Signatures
* For full description [read](https://github.com/kevoreilly/CAPEv2/pull/605)

### [17-10-2021]
* Monitor update: Win10x64 deadlock fix & other misc fixes (see capemon repo for details)

### [2-10-2021] Hacktoberfest
* Add test module to extraction framework to ensure that they are loaded properly: CAPE, MWCP, RATDecoders, Malduck
* Monitor update: Fixes/hardening of dumps (PE & memory) and yara scans (e.g. SquirrelWaffle)
* Handled errors that was giving problem to use `init_yara` sometime, used in Qakbot extractor
    * `OSError: /opt/CAPEv2/lib/cuckoo/common/blzpack_lib.so: failed to map segment from shared object`
* Bingraph:
    * matplotlib `forward` deprication fixed
    * moved to external dependency, we host CAPE's version here https://github.com/CAPESandbox/binGraph.
    * __ACTION REQUIRED__
        * `pip3 install -U git+https://github.com/CAPESandbox/binGraph`


### [23-09-2021]
* Monitor update: Add CLSIDs and IsValidUrl hook for CVE-2021-40444

### [22-09-2021]
* SquirrelWaffle detection & config extraction
* Monitor improvements:
    * Dumping stability improvements (ScanForDisguisedPE, IsDisguisedPEHeader, DumpMemory, DumpRegion)
    * Add config option to allow enable/disable scans/dumps while loader lock held
    * Monitor updates: dump/scan stability improvements, configurable loader lock scans/dumps, window hook fixes

### [14-09-2021]
* Update Lockbit yara sig
* Update Bazar yara sig
* We spot that some extractors only works with `mwcp==3.2.1`, requirements updated
* FLARE-CAPA v3

### [11-09-2021]
* Monitor improvements:
    * Restrict debugger breakpoint protection to current process (NtSetContextThread)
    * Limit "Dropped file limit reached" messages to just one per process

### [02-09-2021]
* Monitor fixes:
    * Some dropped files being missed (file_handle_terminate())
    * Disable ntdll write-protection for Office processes

### [06-09-2021]
* Sflock update with more PE checks, as in many cases PE has other formats strings inside
* __ACTION REQUIRED__
    * `pip3 install -U sflock2`

### [02-09-2021]
* Monitor: Remove case-sensitivity from check for dll path (e.g. Hancitor maldoc-spawned dlls)

### [28-08-2021]
* Monitor: revert changes to IsPeImageRaw() while crashes (e.g. BazarLoader) are investigated

### [25-08-2021]
* __ACTION REQUIRED__
    * `pip3 install -U pyattck`

### [19-08-2021]
* Move office settings from package options to in-monitor (automatic)
* Fix issue with tlsdump/lsass being assigned 'first process' in analyzer
* Usage graph moved to under statistics block

### [18-08-2021]
* Monitor update: stability fixes (window hooks, ...) & debugger improvements

### [11-08-2021]
* Distributed. Master node stop picking pending tasks when `node=X` is specified and master_storage_only=False

### [10-08-2021]
* Monitor update: Remove unnecessary check in TestPERequirements causing failed PE dumps
* Search by hash now will cover any file in CAPE that contains hash.
    * It searches in binary/Dropped files/CAPE payloads/ProcessDump
    * payloads: md5 <- as example not needed anymore and will be deprecated in next month

### [08-08-2021]
* Monitor update: debugger improvements
* Loader: fix debug output for shellcode start address including offset
* Allow start offsets into shellcode to be set for Shellcode packages (offset=x)

### [07-08-2021]
* Monitor update: fix issue causing occasional crashes on x64 when calling ScyllaGetExportDirectory on apphelp.dll
* XLMMacroDeobfuscator moved to `on_demand`

### [28-07-2021]
* bzip archives was replaced with zip with password, default infected, can be changes in conf/web.conf -> zipped_download -> zip_pwd
    * use 7zip or pyzipper to extract

### [23-07-2021] Distribute task based on route
* Add hability to have different exit nodes on each cape worker in cluster, that will auto pickup proper worker server based on route.
    * To update current nodes details on main db server, do the request with pull request

### [21-07-2021] [Xll support](https://www.fortinet.com/blog/threat-research/signed-sealed-and-delivered-signed-xll-file-delivers-buer-loader)
* __ACTION REQUIRED__
    * `pip3 install -U sflock2`

### [07-07-2021] Signature testing
* Allow to execute one specific signature, loading data from mongo or json report. Specially useful for signature based extractors.
    * python3 utils/process.py -r ID -sig -sn cape_detected_threat

### [06-07-2021] [Malduck](https://github.com/CERT-Polska/malduck)
* Integration of part of [mwcfg-modules](https://github.com/c3rb3ru5d3d53c/mwcfg-modules) by [@c3rb3ru5d3d53c](https://github.com/c3rb3ru5d3d53c)

### [05-07-2021]
* Add support for archives in static extraction, so you don't need to submit them one by one

### [20-06-2021] [enter the sandman](https://www.youtube.com/watch?v=CD-E-LDc384) @doomedraven moved to CAPEv2
* Expect more fixes :)

### [17-06-2021]
* Updates to processing module & monitor to allow type strings to replace old type codes
* Updates to 'dump' Debugger action
* Hit counts added to debugger breakpoints

### [17-06-2021]
* add `username` field to be used for custom auth
* __ACTION REQUIRED__ if you using dist.py
    * `cd utils/db_migration && alembic upgrade head`

### [13-06-2021]
* Introdiced checker of available space in process.py to prevent system run out of memory and generate a lot of troubles

### [10-06-2021] dist.py
* Migrates from ht_user/ht_pass to apikey for proper apiv2 integration
* __ACTION REQUIRED__ if you using dist.py
    * `cd utils/db_migration_dist && alembic upgrade head`

### [09-06-2021] RAMFS renamed to TMPFS
* As TMPFS is better and modernish, and it was a naming typo

```
# only if you using volatility to speedup IO
mkdir -p /mnt/tmpfs
mount -t tmpfs -o size=50g tmpfs /mnt/tmpfs
chown cape:cape /mnt/tmpfs
vim /etc/fstab
tmpfs       /mnt/tmpfs tmpfs   nodev,nosuid,noexec,nodiratime,size=50g   0 0
```

* [ORJson](https://pypi.org/project/orjson/) library is now used for json report if installed
    * orjson is a fast JSON library for Python. It benchmarks as the fastest Python library for JSON. Its serialization performance is 2x to 3x the nearest other library and 4.5x to 11.5x the standard library.

### [07-06-2021] MongoDB auth fixed
* [Example of user/role creation](https://pymongo.readthedocs.io/en/stable/examples/authentication.html)
```
use admin

# To Create root user
use admin
db.createUser(
      {
          user: "username",
          pwd:  passwordPrompt(),   // or cleartext password
          roles: [ "root" ]
      }
  )

# To create user with perm RW on db
db.createUser(
    {
        user: "WORKER_USERNAME",
        pwd:  passwordPrompt(),   // or cleartext password
        roles: [{ role: "readWrite", db: "cuckoo" }]
    }
)
```

### [06-06-2021] Ratelimit strikes again
* Reintroduce ratelimit to control abuses

### [04-06-2021]
* Allow anon users list reports and view them
    * `conf/web.conf ->  general -> anon_viewable`

### [31-05-2021]
* Monitor updates:
    * Fixes for NtCreateProcessEx hook, regsvr32 arg parsing, branch tracing (debugger)
    * Remove instruction filtering from ntdll protection
    * Add more debug logging to YaraHarness

### [15-05-2021]
* Reports download moved to main page, under file info as Strings, VirusTotal, Mitre

### [02-05-2021] [Square Hammer](https://youtu.be/VqoyKzgkqR4)
* Add button to ban user and their pending tasks on admin tab
    * __ACTION REQUIRED!__
        * `cd utils/db_migration/ && alembic upgrade head`
        * `sudo systemctl restart cape.service cape-web.service`

### [01-05-2021]
* Dirty cluster admin utils helper -> `admin/admin.py`, see `-h`

### [28-04-2021]
* Strings tab are under the file info on main page
* VirusTotal tab are also under the file info on main page
* VT apiv3 integrated

### [23-04-2021]
* Pyattck v3.0.1 support
* If you are using alternative location to `/opt/CAPEv2` and wants to use `MITRE TTPs` next action is required:
    * you need to update value of `data_path` in config `data/mitre/config.yml`

### [18-04-2021]
* Move MITRE ATT&CK from tab to collapse table after signatures

### [15-04-2021]
* Allow pass search patter in url: `analysis/search/detections:<family>/`

### [13-04-2021]
* Add example how to add custom auth, see `web/web/middleware.py`

### [06-04-2021] Small performance improvements
* New dependecy `ujson`
    * __REQUIRED ACTION:__ -> `pip3 install ujson -U`


### [23-03-2021] API Suscription
* Default 5/m, it can be changed using Django Admin in user profile. ratelimit is deprecated
* This was done with huge help from those writeups
    - [How to add susctiption based throtting to django](https://dev.to/mattschwartz/how-to-add-subscription-based-throttling-to-a-django-api-28j0)
    - [How to add custom fields to user profile](https://simpleisbetterthancomplex.com/tutorial/2016/11/23/how-to-add-user-profile-to-django-admin.html)

* __REQUIRED ACTION:__ -> `cd web && python3 manage.py migrate`


### [09-02-2021] Registration more configrations
* Allow enable/disable all new users to activate them by hand
* Disable new users after email verification if set `manual_approve` in `conf/web.conf`
* __REQUIRED ACTION:__ -> `pip3 install django-extensions`

### [05-02-2021] Volatility3 integration done, some future optimizations might come later
* ToDo: pass yara file to exec yarascan
* Thanks to Xabier Ugarte-Pedrero and dadokkio for their work
* `pip3 install volatility3`, then check
    * `conf/processing.conf` -> `[memory]`
    * `conf/memory.conf` for the plugins

* You will need to download `symbols`, see [volatility3 readme for details](https://github.com/volatilityfoundation/volatility3)

### [03-02-2021]
* ratelimit 4 upgrade -> `pip3 install django-ratelimit -U`

### [02-02-2021]
* Link task to user_id, to be able to ban spammers and bad users
* __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/utils/db_migration && alembic upgrade head`
* Instead of Volatility3 integration planned for today you got this, thanks spammers
* If registration enabled, allow to set manual approve of users and set them inactive by default

### [28-01-2021] CAPE 2.3
* APIv2 - [Django REST Framework](https://www.django-rest-framework.org) + [Token AUTH](https://simpleisbetterthancomplex.com/tutorial/2018/11/22/how-to-implement-token-authentication-using-django-rest-framework.html)
    * just replace `/api/` to `/apiv2/` in your urls
* Current API will be removed in future, so move toward new one
* Updated API [documentation](https://capev2.readthedocs.io/en/latest/usage/api.html)
* New dependency: `pip3 install djangorestframework`
* __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/web/`
    * `python3 manage.py migrate && python3 manage.py collectstatic`

### [24-01-2021] Disposable email services ban support
* To enable it see `[registration]` in `web.conf`
* List of domains can be placed in `data/safelist/disposable_domain_list.txt`
* Allow enable ReCaptcha for user registration to avoid bots
* Integrated [stopforumspam domain list](https://www.stopforumspam.com/downloads/toxic_domains_partial.txt)

### [21-01-2021] JA3 by Suricata no custom scripts anymore
* `sed -i 's|#ja3-fingerprints: auto|ja3-fingerprints: yes|g' /etc/suricata/suricata.yaml && sudo systemctl restart suricata`

### [20-01-2021]
* [TLSH hashing](https://github.com/trendmicro/tlsh) - Trend Micro Locality Sensitive Hash
* sha3-384

### [14-01-2021] [Headers Quality](https://adamj.eu/tech/2019/04/10/how-to-score-a+-for-security-headers-on-your-django-website/)
* [Content Security Policy](https://www.laac.dev/blog/content-security-policy-using-django/) - [writeup](https://www.laac.dev/blog/content-security-policy-using-django/)
* [2FA for Django Admin](https://hackernoon.com/5-ways-to-make-django-admin-safer-eb7753698ac8)
* New dependency: `pip3 install django-otp qrcode`
 __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/web/`
    * `python3 manage.py migrate` if no you will get `no such table: otp_totp_totpdevice`

### [13-01-2020] Social Media buttons for sign in
* Adding [bootstrap-social](https://github.com/peterblazejewicz/bootstrap-social) to simplify sign buttons integration
* Move SSO providers config to from `web/web/settings.py` to `web/web/local_settings.py`
* `[oauth]` added to `conf/web.conf` for future on/off of the buttons
* New dependency: `pip3 install django-settings-export`

### [10-01-2020] Scrappers&Bots nightmare :)
* Add Web signup/SSO, email verification - [more details](https://django-allauth.readthedocs.io/en/latest/overview.html) - Amazing [writeup](https://www.theophilusn.com/blog/django-with-bootstrap-4) was used for integration
* [ReCaptcha protected admin](https://github.com/axil/django-captcha-admin/)
* New dependencies -> `pip3 install django-allauth django-recaptcha==2.0.6 django-crispy-forms git+https://github.com/CAPESandbox/httpreplay.git`
* __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/web/`
    * `python3 manage.py migrate` if no you will get `No such table as django_site`
    * `python3 manage.py collectstatic` -> to enable django admin css -> requires web/web/local_settings.py modifiy `STATIC_ROOT`

### [02.01.02021] POST 2020
* Allow download http(s) Request/Response and Response 48bytes hex preview
* auth_only in api.conf to allow apikey/autentificated users hit the rest api

### [29.12.2020]
* YARA integrated to capemon, this allows to bypass anti-* aka capemon scripting, more [here](https://github.com/kevoreilly/CAPEv2/commit/9306e4e2629f569d4275e241d14aea65a74b421b)
* Docs and more anti bypasses and examples coming soon

### [22.12.2020] Peque edition
* TLS decrypt integration, huge thanks to Hatching team to release their code. WEBGUI integration isn't finished yet, but you already can see https requests there
* Safelists moved from network.py to `data/safelist/{domains,ips}.py`

### [08.12.2020] On demand
* Add uniq submission limitation, can be enabled in `conf/web.conf` to disable the same submission during X hours
* Bingraph, FLARE CAPA, vba2graph on demand
* Added `on_demand` feature.
    * This funcions aim to speedup processing but allow to user to generate parts of analysis that takes some time to finish and not used frequently. Example scripted submissions

### [02.12.2020] CAPE 2.2
* Malduck integration
* Bootrstarp 4.5.3 & font awesome 5
* Statistics
* Tag_tasks - allows you tag your jobs
* self.pefiles: introduced to prcessing/signatures modules, you can get PEFILE object by sha256 self.pefiles.get(sha256)
* Pending page now is much useful and show hashes to easilly spot duplicated
* Submission of file or resubmission will show all the jobs and detection for that file
* [Flare capa](https://github.com/fireeye/capa) integrated under static tab for original binary, procdump and cape (should be enabled in processing.conf), Rules can be pulled from community, but we will leave it community driven to sync them. So you can copy them from https://github.com/fireeye/capa-rules and place under `data/flare-capa`
* More soon ;)

### 16-11-2020
* `utils/cleaners.py` option `--delete-older-than-days` moved to bulk remove 10 in 10, to improve performance and decrease IO

### [31-10-2020] Pre Halloween edition
* [Box-js](https://github.com/kirk-sayre-work/box-js/) integration [docs](https://capev2.readthedocs.io/en/latest/integrations/box-js.html)
* Fixed support for office in x64 VMs

### [22-10-2020]
* cape.py rewrite so it affects `api/tasks/get/config/` so before it was list of configs and it has `cape_name`, now its like `[{malware_family:{config}}]`

### [20-10-2020]
* static config extraction lookup in database before scan file with yara and extract
* resubmit added to CAPE/procdump tabs

### [15-10-2020]
* Huge code unification and cleanup between `submission/views.py` and `api/views.py`
* Improve error messages on bulk submission, for failed samples/hashes
* Physical machinery updated by @hariomenkel, you can [read details in his writeup](https://mariohenkel.medium.com/using-cape-sandbox-and-fog-to-analyze-malware-on-physical-machines-4dda328d4e2c)

### [05-10-2020]
* Static extraction fix, thanks for testing it @nikhilh-20
* Static endpoint now will return config apart of the task id

### [01-10-2020] HacktoberFest edition
* Create zip files in memory (requires pyzipper) instead of using 7z and write them to temp folder
* Simplified parsing of arguments between submission/api views
* Created [docs](https://capev2.readthedocs.io/en/latest/development/current_module_improvement.html) on how to test `Curtain` and `Suricata`
* Static extraction api added
* Curtain module updated
* Code clenup
* Massive useless IO improved, read config once instead of on each file submit

### [14-09-2020]
* Added ability to enable/disable some of 3rd part services for malware detection, like: VirusTotal, ClamAV, Suricata

### [13-09-2020]
* Enable ratelimit on download any file, to avoid scrapping, to change limits, edit: `api.conf` -> `download_file`
* Error message for ratelimit can be configured in `web/web/settings.py`
* Fixed a lot of bugs/typos, thanks Flake8 + GitHub Actions :)

### [11-08-2020]
* Update suricata socket path in processing.conf as in cape2.sh from `/var/run/` to `/tmp/`
* Fix pebble pool restart on timeout
* Zip package reintroduced but it should be only used with option `file=X` when we need side load files

### [23-07-2020]
* Scan extracted macro with yara from macro/CAPE folder

### [11-07-2020]
* [ReadTheDocs](https://capev2.readthedocs.io/en/latest/#)

### [24-06-2020]
* Show url from where file was downloaded when using Download'n'Exec
* Zip package is depricate as it doesn't support AES etc, to upload with side files use file=X and submit in zip archive, for rest you have [sflock](https://github.com/doomedraven/sflock) <3

### [18-06-2020]
* Restore original dump file, don't dump inmediatelly
* CAPE tab now also loaded via ajax request

### [11-06-2020]
* Extended api search changed, now instead of return only ids, return some basic info, as detection, etc

### [31-05-2020]
* Rewrite /api/ ratelimit implementation to allow unlimited api for existing users([htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)), just set username and password as get/post arguments

### [17-05-2020]
* [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) from @DissectMalware integrated
* Yara now compiled once at processing start or reprocessing

### [15-05-2020]
* pyattck upgrade to >= 2.0.2
* moved many files from `/data/` to `community` -> `python3 utils/community.py -h`

### [07-05-2020]
* Behavior data/tab is now loaded via ajax request, to speedup webgui

### [06-05-2020]
* Add parent sample details to analysis
* Add Yara author to webgui, useful when yara name overlap with private yara

### [18-04-2020]
* All not core yara moved to community repo

### [17-04-2020]
* Dark theme is default now, to set old one just do
    * Backup current: `cp /opt/CAPEv2/web/templates/header.html /opt/CAPEv2/web/templates/header-dark.html`
    * Set old theme: `cp /opt/CAPEv2/web/templates/header-light.html /opt/CAPEv2/web/templates/header.html`

### [13-04-2020]
* TLP implemented for analysis, thanks @enzok

### [30-03-2020]
* /configdownload/ is moved to /api/tasks/get/config/<task_id>/ or /api/tasks/get/config/<task_id>/Family/
* Anti-api-spamming feature in monitor
* webgui optimizations(mongo queries improved a lot), thanks [MongoDB university](https://university.mongodb.com) for free cources :)

### [28-03-2020]
* CAPE 2.1 ;)
* A lot of small bug fixes, code cleanup, gui fixes, and monitor improvements
* Now insted if "None matched" we just hide field
* All VMs now are disabled on submission you need to enable it in web.conf
* To submit ZIP file for analisis you need to specify zip package, if no it will be extracted

### [24-03-2020]
* Big update of suricata name extraction/detection
* malscore now is off by default, can be enabled in conf/reporting.conf
* MalFamily renamed to detections

### [12-03-2020]
* community.py reintroduced to simplify everything
    * now all signatures and not core modules are moved to specific repo, please see `python3 utils/community.py -h`

### [29-02-2020]
* SIGHUP handling to stop submitting tasks and stop cuckoo.py, useful for when you need to reload it without breaking running jobs
    * `ps aux|grep "python3 cuckoo.py"|cut -d" " -f 5| xargs kill -1`

### [22-01-2020]
* Add qemu.py with support for x64/x86/MIPS/MIPSEL/ARM/ARMWRT/ARM64/PowerPC/PowerPC64/Sparc/Sparc64
* Basic linux integration is done thanks to @enzok

### [17-01-2020]
* Bson data compression to remove api spamming, [details](http://security.neurolabs.club/2019/12/inline-loop-detection-for-compressing.html), thanks @mabj
* Many bug fixes in cleaners.py, thanks @Enzok

### [14-01-2020]
* Fix local_settings
* move all in 1 dlls, example option to capemon: combo=1,extraction=1,injection=1,compression=1
* Fix ratelimit enabled/disabled in /api/
* Agent now by default set outout to StringIO to make it works with pythonw without extra args

### [08-01-2020]
* Screenshot deduplicacion algorithm is configurable now and default set to ahash, pr #10, thanks @wmetcalf
* Fixed pythonw compability problem, pr #7, thanks @wmetcalf
* Pillow 7 compatible, pr #9, thanks @wmetcalf
* Upgrade ClamAV support, pr #11, thanks @wmetcalf
* All cleaners from cuckoo.py and some from utils folder are moved to unique file utils/cleaners.py, see, -h @doomedraven
* distributed CAPE documentation updated
* m2crypto+swig replaced with cryptography library

### [25-12-2019]
* CAPEv2 is Python3 based
* Django 3 tested
* [ASGI support - async "wsgi"](https://docs.djangoproject.com/en/3.0/howto/deployment/asgi/)
* All found memleaks fixed
* A lot of code improved and bug fixed
* Malware parsers/extractors moved to use upstream libraries instead of include them to the project, to simplify maintaining and code bug fixes
* User experience improved
* Still might contain some bugs, so please let us know if you see any
* Thanks NaxoneZ for all your bug reports and hard testing <3
