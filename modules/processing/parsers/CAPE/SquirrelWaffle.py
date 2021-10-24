# Copyright (C) 2021 Kevin O'Reilly (kevoreilly@gmail.com)
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

def config(data):
    config = dict()
    try:
        data = data.decode("utf-8")
    except Exception as e:
        return config

    if data.startswith("HTTP/1.1") or "\t\t\n\r" in data:
        return config
    if '\r\n' in data and '|' not in data:
        try:
            config["IP Blocklist"] = list(filter(None, data.split("\r\n")))
        except Exception as e:
            print(e)
    elif '|' in data and '\r\n' not in data:
        try:
            config["URLs"] = list(filter(None, data.split("|")))
        except Exception as e:
            print(e)
    return config
