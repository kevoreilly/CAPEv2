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
        node_exe = os.path.join(node_bin_path, "node.exe")

        # 1. Check if we need to install
        if not os.path.exists(node_exe):
            if not os.path.exists(node_zip_path):
                return None, f"Node zip not found at: {node_zip_path}"

            if not os.path.exists(install_path):
                os.makedirs(install_path)

            log.info(f"Extracting Node.js to {install_path}...")
            with zipfile.ZipFile(node_zip_path, 'r') as zip_ref:
                zip_ref.extractall(install_path)

        # 2. Update Environment Variable
        current_path = os.environ.get("PATH", "")
        # Prepend to ensure our node takes precedence
        os.environ["PATH"] = f"{node_bin_path};{current_path}"

        return node_exe, None

    except Exception as e:
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
                log.info(f"Using Custom Node.js: {binary}")
            else:
                log.error(f"Failed to setup Custom Node: {error}")
                # Do NOT return here, fall through to system node

        # 2. Fallback to System Node if custom failed or zip missing
        if not binary:
            log.info("Falling back to system installed Node.js")
            binary = self.get_path("node.exe")

        # 3. Execution
        if not binary:
            raise Exception("Node.js executable not found in custom bundle OR system paths.")

        return self.execute(binary, node_args, path)
