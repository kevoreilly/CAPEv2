### This allows us to put custom modules without editing configs and easier to maintain private forks.

* `extract_details` is the entry point called by `file_extra_info.py`
* Here is a skeleton example of module:

```
import os
import sys
import logging

from lib.cuckoo.common.path_utils import path_write_file
from lib.cuckoo.common.integrations.file_extra_info_modules import time_tracker, ExtractorReturnType, extractor_ctx, collect_extracted_filenames


log = logging.getLogger(__name__)

# Enable/disable
enabled = True
# Module timeout
timeout = 100

@time_tracker
def extract_details(file, *, data_dictionary, **_) -> ExtractorReturnType:

    <your code goes here>

    with extractor_ctx(file, "NAME", prefix="PREFIX_NAME") as ctx:
        if extracted:
            tempdir = ctx["tempdir"]
            # You might need to change this 2 lines. See other examples in `file_extra_info.py`
            for i, block in enumerate(extracted):
                _ = path_write_file(os.path.join(tempdir, str(i)), block[1])
                ctx["extracted_files"] = collect_extracted_filenames(tempdir)
            ctx["data_dictionary"] = data_dictionary
    return ctx

```
