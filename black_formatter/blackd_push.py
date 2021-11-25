
import os
import traceback
from pathlib import Path

import httpx
from httpcore import ConnectError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed


def get_filepaths(directory):
    """
    This function will generate the file names in a directory
    tree by walking the tree either top-down or bottom-up. For each
    directory in the tree rooted at directory top (including top itself),
    it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List which will store all of the full filepaths.

    # Walk the tree.
    for root, directories, files in os.walk(directory):
        if "venv" not in root:
            for filename in files:
                if filename.endswith(".py") and "utils_pretty_print_funcs_data.py" not in filename:
                    # Join the two strings in order to form the full filepath.
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)  # Add it to the list.

    return file_paths  # Self-explanatory.


def print_line(response, file_name):
    formatted_name = file_name.lstrip("./").replace("/", ".")
    # See: https://github.com/psf/black/blob/master/docs/blackd.md#protocol
    if response.status_code == 204:
        print(f"{response.status_code} - {file_name} - input is already well-formatted")
    if response.status_code == 200:
        print(f"{response.status_code} - {file_name} - blackened code: {response.text}")
        Path(f"/tmp/200.blk_{formatted_name}.log").touch()
    if response.status_code == 400:
        print(f"{response.status_code} - {file_name} - input contains a syntax error: {response.text}")
        Path(f"/tmp/400.blk_{formatted_name}.log").touch()
    if response.status_code == 500:
        print(f"{response.status_code} - {file_name} - other kind of error while trying to format the input: {response.text}")


def submit_to_blackd(code, client):
    # Can't use localhost
    # OSError: [Errno 99] error while attempting to bind on address ('::1', 45484, 0, 0): cannot assign requested address
    url = "http://127.0.0.1:45484"
    headers = {"X-Line-Length": "132"}
    with open(code, mode="r") as file:
        contents = file.read()
    try:
        r = client_post(client, url, contents, headers)
        print_line(r, code)
        return code
    except Exception as e:
        # e is empty of text for some reason, but we can find out which file died
        print(f"Failed to check: {code}\nerror type: {e}\ntraceback: {traceback.print_exc()}")
        return None


@retry(retry=retry_if_exception_type(ConnectError), wait=wait_fixed(2), stop=stop_after_attempt(20))
def client_post(client, url, contents, headers):
    return client.post(url, data=contents, headers=headers, timeout=360)


def launch():
    # Run the above function and store its results in a variable.
    full_file_paths = get_filepaths(".")
    parsed = []
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=5)
    client = httpx.Client(verify=False, limits=limits)
    for file in full_file_paths:
        return_val = submit_to_blackd(file, client)
        if return_val:
            parsed.append(return_val)

    if len(parsed) != len(full_file_paths):
        print(f"Not parsed everything, {len(full_file_paths) - len(parsed)} remaining")


if __name__ == "__main__":
    launch()
