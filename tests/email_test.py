# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

# Cuckoo root
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
from lib.cuckoo.common.config import Config

email_config = Config("smtp_sinkhole")

if True:  # try:
    data = "cuckoo testing"
    timestamp = datetime.now()
    msg = MIMEMultipart()
    msg["Subject"] = "Email from smtp sinkhole: {0}".format(timestamp.strftime("%Y%-m%-d% H%:M:%S"))
    msg["From"] = email_config.email["server"]
    msg["To"] = email_config.email["to"]
    part = MIMEBase("application", "octet-stream")
    part.set_payload(data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", 'attachment; filename="cuckoo.eml"')
    msg.attach(part)
    """
    print(email_config.email["server"], email_config.email["port"])
    print(email_config.email)
    server = smtplib.SMTP_SSL(email_config.email["server"], int(email_config.email["port"]))
    server.login(email_config.email["user"], email_config.email["password"])
    server.set_debuglevel(1)
    server.sendmail(email_config.email["to"], email_config.email["to"].split(" ,"), data)
    server.quit()
    """

# except Exception as e:
#    logging.error(e)
