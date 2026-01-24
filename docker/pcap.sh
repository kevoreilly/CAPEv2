groupadd pcap
usermod -a -G pcap cape
chgrp pcap /usr/bin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump