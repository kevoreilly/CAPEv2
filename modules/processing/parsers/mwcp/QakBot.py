import datetime
from mwcp.parser import Parser

qakbot_map = {
    "10": "Botnet name",
    "11": "Number of C2 servers",
    "47": "Bot ID"
}
id_map = {
    b"22": "#1",
    b"23": "#2",
    b"24": "#3",
    b"25": "#4",
    b"26": "#5",
}

class QakBot(Parser):
    DESCRIPTION = 'Qakbot configuration parser.'
    AUTHOR = 'kevoreilly'

    def run(self):
        for line in self.file_object.file_data.splitlines():
            if b'=' in line:
                index = line.split(b'=')[0]
                data = line.split(b'=')[1]
                if index in qakbot_map:
                    ConfigItem = qakbot_map[index]
                    ConfigData = data
                    if ConfigData:
                        self.reporter.add_metadata('other', {ConfigItem: ConfigData})
                if index == b'3':
                    self.reporter.add_metadata('other', {
                        "Config timestamp": datetime.datetime.fromtimestamp(int(data)).strftime('%H:%M:%S %d-%m-%Y')}
                    )
                if index in (b'22', b'23', b'24', b'24', b'25', b'26'):
                    values = data.split(b':')
                    try:
                        self.reporter.add_metadata('other', {"Password {}".format(id_map[index]): values[2]})
                        self.reporter.add_metadata('other', { "Username {}".format(id_map[index]): values[1]})
                        self.reporter.add_metadata('other', {"C2 {}".format(id_map[index]): values[0]})
                    except:
                        pass
            elif b';0;' in line:
                try:
                    self.reporter.add_metadata('address', line.replace(b';0;', b':'))
                except:
                    pass
