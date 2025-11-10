import shutil
import os
import msal
import datetime

import sys

# Get the absolute path of the current file's directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the absolute path of the parent directory
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path
sys.path.insert(0, parent_dir)

# Now you can import modules from the parent directory
# For example, if you have a file named 'parent_module.py' in the parent directory
from voicemail_to_email import load_config, send_voicemail_email

TEST_RECIPIENT = 'saskling@madisonchildrensmuseum.org'

print("Loading configuration...")

if not os.path.exists('config.ini'):
    print("Error: config.ini file not found. The contents of config_template.ini have been copied to config.ini.")
    print("Please edit config.ini to add your configuration settings, then re-run the script.")

    template_path = 'config_template.ini'
    if os.path.exists(template_path):
        shutil.copyfile(template_path, 'config.ini')
    else:
        print("Error: config_template.ini file not found. Please ensure it exists in the script directory.")
        exit(1)

config = load_config()

print(f"""
Testing sending an email...
        
    Current configuration status:
        Sending from {config['O365']['sender_address']}

""")  

# Use MSAL client credentials flow (application authentication)
# This requires the app registration to have Microsoft Graph -> Application permissions -> Mail.Send
client_id = config['O365']['client_id']
tenant = config['O365']['tenant_id']
client_secret = config['O365']['client_secret']

if not client_secret or not client_id or not tenant:
    print("Client secret, client id, and tenant id must be configured!")
    exit(1)

# For client credentials you must request the .default scope
scopes = ["https://graph.microsoft.com/.default"]

authority = f"https://login.microsoftonline.com/{tenant}"

print("Signing in to Microsoft Graph...")

app = msal.ConfidentialClientApplication(client_id=client_id, client_credential=client_secret, authority=authority)
result = app.acquire_token_for_client(scopes=scopes)

if not result or 'access_token' not in result:
    print("Failed to acquire app-only token. Result:", result)
    exit(1)
else:
    print("Acquired Microsoft authentication token.")

access_token = result['access_token']

transcription = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

send_voicemail_email(access_token, TEST_RECIPIENT, 'Test', "October 22, 2025 at 05:31 PM", None, transcription=transcription)