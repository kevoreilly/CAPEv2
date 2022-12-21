import os
import smtplib
import sys
from datetime import datetime
from email.encoders import encode_base64
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
    encode_base64(part)
    part.add_header("Content-Disposition", 'attachment; filename="cuckoo.eml"')
    msg.attach(part)
    print(email_config.email["server"], email_config.email["port"])
    print(email_config.email)
    server = smtplib.SMTP_SSL(email_config.email["server"], int(email_config.email["port"]))
    server.login(email_config.email["user"], email_config.email["password"])
    server.set_debuglevel(1)
    server.sendmail(email_config.email["to"], email_config.email["to"].split(" ,"), data)
    server.quit()

# except Exception as e:
#    logging.error(e)
