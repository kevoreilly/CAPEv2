# Copyright (C) 2020 King-Konsto
#
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

import gzip
import json
import logging
import os
import requests
import sys

try:
    from flor import BloomFilter
    HAVE_FLOR = True
except ImportError:
    HAVE_FLOR = False
    logging.error("Python library 'flor' is not installed -> pip3 install flor")

from lib.cuckoo.common.constants import CUCKOO_ROOT


API_URL = "https://dgarchive.caad.fkie.fraunhofer.de/today/1"
API_USER = ""
API_PW = ""

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    if not HAVE_FLOR:
        logging.error("Python library 'flor' is not installed -> pip3 install flor")
        sys.exit(-1)

    logging.info("Starting bloomfilter generation script")
    session = requests.Session()
    session.auth = (API_USER, API_PW)

    if not (API_URL and API_USER and API_PW and session):
        logging.error("Please put your credentials into API_USER, API_PW and API_URL")
        sys.exit(-1)

    # 1. call API and get json dict containing active DGA domains and DGA families
    # endpoint /today/1 means today, yesterday and tomorrow (today +/- 1)
    logging.info("Fetching data from Fraunhofer API")
    response = session.get(API_URL)
    if not response:
        logging.error("Fraunhofer DGA API call malformed or credentials invalid")
        sys.exit(-1)

    if response.status_code != 200:
        logging.error("Error while querying Fraunhofer DGA API: %s", response.status_code)
        sys.exit(-1)

    dga_json = response.json()
    if not dga_json:
        logging.error("API response could not be transformed into json dict")
        sys.exit(-1)

    # 2. create empty bloomfilter
    logging.info("Creating bloomfilter and DGA dict")
    bloom = BloomFilter(n=1000000, p=0.0001)

    # 3. insert DGA domains from json dict into bloomfilter and create dict for family lookup
    dga_lookup_dict = {}
    first_entry = False
    test_domain = None
    test_family = None
    for family, domain_list in dga_json.items():
        if not first_entry:
            test_domain = domain_list[0]
            test_family = family
            first_entry = True
        for domain in domain_list:
            # insert domain into bloomfilter
            if not domain.lower().encode("utf8") in bloom:
                bloom.add(domain.lower().encode("utf8"))

            # insert into family/domain lookup table
            dga_lookup_dict[domain] = family

    # test with first DGA domain/family pair that should be present in the bloomfilter and the dga_dict
    if not (first_entry and test_domain and test_family):
        logging.error("Unknown error while creating bloomfilter and DGA dict")
        sys.exit(-1)
    if test_domain.lower().encode("utf8") in bloom and dga_lookup_dict.get(test_domain.lower(), "") == test_family:
        logging.info("%s (%s)", test_domain, test_family)
        logging.info("Bloomfilter and DGA dict successfully created")
    else:
        logging.error("Unknown error while creating bloomfilter and DGA dict")
        sys.exit(-1)

    # 5. write bloomfilter and dga dict to a file so that the sandbox can use it in the python signature
    logging.info("Write bloomfilter and dga dict to files")
    bloom_path = os.path.join(CUCKOO_ROOT, "data",  "dga.bloom")
    with open(bloom_path, "wb") as f:
        bloom.write(f)

    lookup_path = os.path.join(CUCKOO_ROOT, "data", "dga_lookup_dict.json.gz")
    with gzip.GzipFile(lookup_path, "w") as fout:
        fout.write(json.dumps(dga_lookup_dict).encode("utf8"))

    logging.info("Successfully generated bloomfilter and dga dict file")
