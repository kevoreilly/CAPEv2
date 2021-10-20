=============
Web interface
=============

CAPE provides a full-fledged web interface in the form of a Django application.
This interface will allow you to submit files, browse through the reports as well
as search across all the analysis results.

Configuration
=============

The web interface pulls data from a Mongo database or from ElasticSearch, so having
either the MongoDB or ElasticSearchDB reporting modules enabled in ``reporting.conf``
is mandatory for this interface. If that's not the case, the application won't start
and it will raise an exception. Also, currently Django only supports having one of
the database modules enabled at a time.

The interface can be configured by editing ``local_settings.py`` under ``web/web/``::

    # If you want to customize your CAPE path set it here.
    # CAPE_PATH = "/where/CAPE/is/placed/"

    # Maximum upload size.
    MAX_UPLOAD_SIZE = 26214400

    # Override default secret key stored in secret_key.py
    # Make this unique, and don't share it with anybody.
    # SECRET_KEY = "YOUR_RANDOM_KEY"

    # Local time zone for this installation. Choices can be found here:
    # http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
    # although not all choices may be available on all operating systems.
    # On Unix systems, a value of None will cause Django to use the same
    # timezone as the operating system.
    # If running in a Windows environment this must be set to the same as your
    # system time zone.
    TIME_ZONE = "America/Chicago"

    # Language code for this installation. All choices can be found here:
    # http://www.i18nguy.com/unicode/language-identifiers.html
    LANGUAGE_CODE = "en-us"

    ADMINS = (
        # ("Your Name", "your_email@example.com"),
    )

    MANAGERS = ADMINS

    # Allow verbose debug error message in case of application fault.
    # It's strongly suggested to set it to False if you are serving the
    # web application from a web server front-end (i.e. Apache).
    DEBUG = True

    # A list of strings representing the host/domain names that this Django site
    # can serve.
    # Values in this list can be fully qualified names (e.g. 'www.example.com').
    # When DEBUG is True or when running tests, host validation is disabled; any
    # host will be accepted. Thus it's usually only necessary to set it in production.
    ALLOWED_HOSTS = ["*"]

Usage
=====

In order to start the web interface, you can simply run the following command
from the ``web/`` directory::

    $ python3 manage.py runserver

If you want to configure the web interface as listening for any IP on a
specified port, you can start it with the following command (replace PORT
with the desired port number)::

    $ python3 manage.py runserver 0.0.0.0:PORT

You can serve CAPE's web interface using WSGI interface with common web servers:
Apache, Nginx, Unicorn and so on.
Please refer both to the documentation of the web server of your choice as well as `Django documentation`_.

.. _`Django documentation`: https://docs.djangoproject.com/

Exposed to internet
===================

To get rid of many bots/scrappers so we suggest to deploy this amazing project `Nginx Ultimate bad bot blocker`_, follow readme for instalation steps

* Enable web auth with captcha in `conf/web.conf` preferly to avoid any bruteforce.
* Enable `ReCaptcha`_. You will need to set ``Public`` and ``Secret`` keys in ``web/web/settings.py``
* You might need to "Verify" and set as "Stuff user" to your admin in Django admin panel and add your domain to Sites in Django admin too
* `AllAuth`_ aka SSO autentification with Google, Github, etc. `Video Tutorial`_ & `StackOverflow Example`_:
    * Note ``SITE_ID=1`` in django admin is ``example.com`` rename it to your domain to get it working

.. _`AllAuth`: https://django-allauth.readthedocs.io/
.. _`Video Tutorial`: https://www.youtube.com/watch?v=1yqKNQ3ogKQ
.. _`StackOverflow example`: https://stackoverflow.com/a/64524223/1294762
.. _`Nginx Ultimate bad bot blocker`: https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/
.. _`ReCaptcha`: https://www.google.com/recaptcha/admin/


Some extra security TIP(s)
==========================
* `ModSecurity tutorial`_ - rejects requests
* `Fail2ban tutorial`_ - ban hosts
* `Fail2ban + CloudFlare`_ - how to ban on CloudFlare aka CDN firewall level

.. _`ModSecurity tutorial`: https://malware.expert/tutorial/writing-modsecurity-rules/
.. _`Fail2ban tutorial`: https://www.digitalocean.com/community/tutorials/how-to-protect-an-nginx-server-with-fail2ban-on-ubuntu-14-04
.. _`Fail2ban + CloudFlare`: https://guides.wp-bullet.com/integrate-fail2ban-cloudflare-api-v4-guide/


* Example of cloudflare action ban::

    # Author: Mike Andreasen from https://guides.wp-bullet.com
    # Adapted Source: https://github.com/fail2ban/fail2ban/blob/master/config/action.d/cloudflare.conf
    # Referenced from: https://www.normyee.net/blog/2012/02/02/adding-cloudflare-support-to-fail2ban by NORM YEE
    #
    # To get your Cloudflare API key: https://www.cloudflare.com/my-account, you should use GLOBAL KEY!

    [Definition]

    # Option:  actionstart
    # Notes.:  command executed once at the start of Fail2Ban.
    # Values:  CMD
    #
    actionstart =

    # Option:  actionstop
    # Notes.:  command executed once at the end of Fail2Ban
    # Values:  CMD
    #
    actionstop =

    # Option:  actioncheck
    # Notes.:  command executed once before each actionban command
    # Values:  CMD
    #
    actioncheck =

    # Option:  actionban
    # Notes.:  command executed when banning an IP. Take care that the
    #          command is executed with Fail2Ban user rights.
    # Tags:      IP address
    #            number of failures
    #            unix timestamp of the ban time
    # Values:  CMD

    actionban = curl -s -X POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" -H "X-Auth-Email: <cfuser>" -H "X-Auth-Key: <cftoken>" -H "Content-Type: application/json" --data '{"mode":"block","configuration":{"target":"ip","value":"<ip>"},"notes":"Fail2ban"}'

    # Option:  actionunban
    # Notes.:  command executed when unbanning an IP. Take care that the
    #          command is executed with Fail2Ban user rights.
    # Tags:      IP address
    #            number of failures
    #            unix timestamp of the ban time
    # Values:  CMD
    #

    actionunban = curl -s -X DELETE "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/$( \
                curl -s -X GET "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?mode=block&configuration_target=ip&configuration_value=<ip>&page=1&per_page=1&match=all" \
                -H "X-Auth-Email: <cfuser>" \
                -H "X-Auth-Key: <cftoken>" \
                -H "Content-Type: application/json" | awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'id'\042/){print $(i+1)}}}' | tr -d '"' | head -n 1)" \
                -H "X-Auth-Email: <cfuser>" \
                -H "X-Auth-Key: <cftoken>" \
                -H "Content-Type: application/json"

    [Init]

    # Option: cfuser
    # Notes.: Replaces <cfuser> in actionban and actionunban with cfuser value below
    # Values: Your CloudFlare user account

    cfuser = put-your-cloudflare-email-here

    # Option: cftoken
    # Notes.: Replaces <cftoken> in actionban and actionunban with cftoken value below
    # Values: Your CloudFlare API key
    cftoken = put-your-API-key-here

* Example of `fail2ban` rule to ban by path::

    # This will ban any host that trying to access /api/ for 3 times in 1 minute
    # Goes to /etc/fail2ban/filters.d/nginx-cape-api.conf
    [Definition]
    failregex = ^<HOST> -.*"(GET|POST|HEAD) /api/.*HTTP.*"
    ignoreregex =

    # goes to /etc/fail2ban/jail.local
    [cape-api]
    enabled = true
    port    = http,https
    filter  = nginx-cape-api
    logpath = /var/log/nginx/access.log
    maxretry = 3
    findtime = 60
    bantime = -1
    # Remove cloudflare line if you don't use it
    action = iptables-multiport
             cloudflare

    # This will ban any host that trying to access kinda bruteforce login or unauthorized requests for 5 times in 1 minute
    # Goes to /etc/fail2ban/filters.d/filter.d/nginx-cape-login.conf
    [Definition]
    failregex = ^<HOST> -.*"(GET|POST|HEAD) /accounts/login/\?next=.*HTTP.*"
    ignoreregex =

    # goes to /etc/fail2ban/jail.local
    [cape-login]
    enabled = true
    port    = http,https
    filter  = nginx-cape-login
    logpath = /var/log/nginx/access.log
    maxretry = 5
    findtime = 60
    bantime = -1
    # Remove cloudflare line if you don't use it
    action = iptables-multiport
              cloudflare

* To check banned hosts::

    $ sudo fail2ban-client status cape-api
