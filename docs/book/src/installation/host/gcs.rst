.. _installation-and-setup:

Installation and Setup
----------------------

Follow these steps to install and configure the GCS reporting module in your CAPE Sandbox environment.

Prerequisites: Google Cloud Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before installing the module, you need to prepare your Google Cloud environment.

1.  **Create a GCS Bucket:** If you don't already have one, create a new bucket in the `Google Cloud Console <https://console.cloud.google.com/storage/browser>`_.

2.  **Create a Service Account:**
    * Go to **IAM & Admin** > **Service Accounts** in the Google Cloud Console.
    * Click **Create Service Account** and give it a name (e.g., ``cape-sandbox-uploader``).
    * Grant it the **Storage Object Creator** or **Storage Object Admin** role. This permission is necessary to write files to the bucket.

3.  **Download JSON Key:**
    * This step is optional if you use ``auth_by=vm``
    * After creating the service account, go to its **Keys** tab.
    * Click **Add Key** > **Create new key**.
    * Select ``JSON`` as the key type and click **Create**. A JSON file will be downloaded.
    * **Securely move this JSON file to your CAPE server**, for example, to ``/opt/CAPEv2/data/gcp-credentials.json``.

    .. warning::
       Do not place the credentials file in a publicly accessible directory.


Module Installation and Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1.  **Install the Python Library:**
    The module depends on the official Google Cloud Storage library. Install it within your CAPE virtual environment.

    .. note::
       Install dependency ``poetry run pip install google-cloud-storage``.

2.  **Update Configuration:**
    * Edit ``/opt/CAPEv2/conf/reporting.conf``.
    * ``[gcs]`` section, enable ``enabled=yes``.
    * Set ``bucket_name`` to the name of your GCS bucket.
    * Set ``auth_by`` to ``vm`` if using system account or ``json`` if using credential file.
    * Set ``credentials_path`` to the **absolute path** where you saved your service account JSON key file.

3.  **Restart CAPE-processor:**
    Restart the CAPE service: ``systemctl restart cape-processor`` for the changes to take effect.
