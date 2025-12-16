import os
import zipfile
import logging

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS

log = logging.getLogger(__name__)

# CONFIGURATION - allow non installed nodejs
# Best practice: Keep filenames in one place
# Grab a copy of https://nodejs.org/download/release/latest-v25.x/node-v25.2.1-win-x64.zip or another version of your interest
# Store it in extras as nodejs.zip
NODE_ZIP_NAME = "nodejs.zip"
NODE_DIR_NAME = "nodejs"


def setup_node_environment():
    """
    Attempts to unzip a portable Node environment.
    Returns: (path_to_node_exe, None) on success (None, error_message) on failure
    """
    try:
        # Determine paths
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Admin")
        install_path = os.path.join(user_profile, "AppData", "Local", "app")

        # Look for zip in absolute path relative to current execution or fixed 'extras'
        # Assuming 'extras' is in the current working dir of the analyzer
        node_zip_path = os.path.abspath(os.path.join("extras", NODE_ZIP_NAME))
        node_bin_path = os.path.join(install_path, NODE_DIR_NAME)

        if not os.path.exists(node_zip_path):
            return None, f"Zip not found at {node_zip_path}"

        if not os.path.exists(node_bin_path):
            os.makedirs(node_bin_path)

        node_exe_path = None

        # 1. Open Zip and Find node.exe BEFORE extracting
        with zipfile.ZipFile(node_zip_path, 'r') as z:
            # list of all files in zip
            file_list = z.namelist()

            # Find the internal path to node.exe
            # This works for both "node.exe" (root) and "node-v25.../node.exe" (subfolder)
            node_internal_path = next((f for f in file_list if f.lower().endswith("node.exe")), None)

            if not node_internal_path:
                return None, "Archive does not contain node.exe"

            # 2. Extract
            # We extract to a specific folder to avoid cluttering if it's a "root-files" zip
            # We use the zip name (minus extension) as a container folder
            extract_path = node_bin_path

            if not os.path.exists(extract_path):
                # Security: Check for path traversal before extraction.
                for member in z.infolist():
                    if member.filename.startswith("/") or ".." in member.filename:
                        return None, f"Aborting extraction. Zip contains potentially malicious path: {member.filename}"

                os.makedirs(extract_path)
                log.info("Extracting to %s...", extract_path)
                z.extractall(extract_path)

            # 3. Construct the full path
            # extract_path + internal_path_inside_zip
            # e.g. C:\Apps\node-v25\ + node-v25-win-x64/node.exe
            node_exe_path = os.path.join(extract_path, node_internal_path)

            # Normalizing path separators (fixes mix of / and \)
            node_exe_path = os.path.normpath(node_exe_path)

        # 4. Final Verification and Env Setup
        if node_exe_path and os.path.exists(node_exe_path):
            # Add the folder containing node.exe to PATH
            node_dir = os.path.dirname(node_exe_path)
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{node_dir};{current_path}"

            return node_exe_path, None
        else:
            return None, "Extraction finished but node.exe not found on disk."

    except (zipfile.BadZipFile, OSError) as e:
        return None, f"Exception during Node setup: {str(e)}"


class NodeJS(Package):
    """Package for executing JavaScript files using NodeJS."""

    PATHS = [
        # Standard 64-bit Install (most common)
        # Default folder is usually lowercase "nodejs"
        ("ProgramFiles", "nodejs", "node.exe"),

        # 32-bit Node on 64-bit Windows
        ("ProgramFiles(x86)", "nodejs", "node.exe"),

        # Your specific custom paths (Case insensitive, so NodeJS works too)
        ("LOCALAPPDATA", "Programs", "NodeJS", "node.exe"),

        # Fallback for manual installs at root
        ("SystemDrive", "nodejs", "node.exe"),
    ]

    summary = "Executes a JS sample using NodeJS."
    description = "Uses node.exe to execute JavaScript files."
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        path = check_file_extension(path, ".js")
        args = self.options.get(OPT_ARGUMENTS, "")

        # Prepare the argument list
        # CAPE expects a list of arguments for the process
        node_args = f'"{path}"'

        # Append additional arguments if they exist
        if args:
            node_args += f" {args}"

        # 1. Try to set up Custom Node
        binary = None

        # Check if the zip exists before trying setup
        if os.path.exists(os.path.join("extras", NODE_ZIP_NAME)):
            custom_bin, error = setup_node_environment()
            if custom_bin:
                binary = custom_bin
                log.info("Using Custom Node.js: %s", binary)
            else:
                log.error("Failed to setup Custom Node: %s", error)
                # Do NOT return here, fall through to system node

        # 2. Fallback to System Node if custom failed or zip missing
        if not binary:
            log.info("Falling back to system installed Node.js")
            binary = self.get_path("node.exe")

        # 3. Execution
        if not binary:
            raise Exception("Node.js executable not found in custom bundle OR system paths.")

        return self.execute(binary, node_args, path)
