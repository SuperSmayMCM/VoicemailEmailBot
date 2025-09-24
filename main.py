import configparser
import ftplib
import os
import json
from datetime import datetime
import msal
import requests
import base64
import mimetypes
from pydub import AudioSegment
import base64, json
import subprocess
import shutil

SCANNED_FILES_JSON_PATH = 'scanned_files.json'

# --- Configuration Loader ---
def load_config():
    """Loads configuration from the config.ini file."""
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config

def load_mailbox_emails() -> dict[str, list[str]]:
    """Loads mailbox to email mappings from mailbox_emails.json."""
    if os.path.exists('mailbox_emails.json'):
        with open('mailbox_emails.json', 'r') as f:
            return json.load(f)
    return {}

# --- File Management Module ---
def read_scanned_files() -> set[str]:
    """
    Reads the persistent list of scanned files.
    
    Returns:
        A set of scanned files
    """
    if os.path.exists(SCANNED_FILES_JSON_PATH):
        with open(SCANNED_FILES_JSON_PATH, 'r') as f:
            return set(json.load(f))
    return set()
    
def write_scanned_files(file_list: set[str]) -> None:
    """
    Writes the list of scanned files to a JSON file.

    Args:
        file_list (set[str]): The list of scanned files.
    """
    with open(SCANNED_FILES_JSON_PATH, 'w') as f:
        json.dump(list(file_list), f, indent=2)

# --- FTP Scanner Module ---
def scan_ftp_folder(ftp_connection, base_path, scanned_files):
    """
    Scans the FTP folder for new voicemail files by comparing against a
    list of previously scanned files.
    
    Args:
        ftp_connection: An active ftplib.FTP object.
        base_path: The base path of the voicemail folders on the FTP server.
        scanned_files: A set of file paths that have already been processed.
        
    Returns:
        A dictionary mapping mailbox numbers to a list of new file paths.
    """
    new_files = {}
    current_files = set()
    try:
        ftp_connection.cwd(base_path)
        mailboxes = ftp_connection.nlst()
        
        for mailbox in mailboxes:
            if mailbox.isdigit():
                mailbox_path = f"{base_path}/{mailbox}"
                try:
                    ftp_connection.cwd(mailbox_path)
                    files = ftp_connection.nlst()
                    
                    for filename in files:
                        if filename.endswith('.') or filename.endswith('..') or filename == "":
                            continue

                        full_path = f"{mailbox_path}/{filename}"
                        current_files.add(full_path)
                        
                        if full_path not in scanned_files:
                            if mailbox not in new_files:
                                new_files[mailbox] = []
                            new_files[mailbox].append(full_path)
                except ftplib.error_perm:
                    continue
    except ftplib.all_errors as e:
        print(f"FTP error: {e}")
    finally:
        ftp_connection.cwd('/')
        
    return new_files, current_files

# --- Audio Converter Module ---
def convert_ulaw_to_mp3(ulaw_path, output_path) -> bool:
    """
    Converts a raw u-law audio file to MP3 using ffmpeg.

    Args:
        ulaw_path (str): The file path to the input u-law audio file.
        output_path (str): The file path to the output MP3 audio file.

    Returns:
        bool: True if the conversion was successful, False otherwise.
    """
    try:
        

        # Prefer ffmpeg for reliable mu-law decoding (matches Audacity import: U-Law, 8000 Hz, mono)
        ffmpeg_path = shutil.which('ffmpeg')
        if ffmpeg_path:
            cmd = [
                ffmpeg_path,
                '-y',
                '-f', 'mulaw',
                '-ar', '8000',
                '-ac', '1',
                '-i', ulaw_path,
                '-acodec', 'libmp3lame',
                output_path
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                print(f"Successfully converted {ulaw_path} to {output_path} using ffmpeg")
                return True
            else:
                print(f"ffmpeg conversion failed (code {proc.returncode}). stderr:\n{proc.stderr}")

        # Fallback: try pydub/ffmpeg via AudioSegment with explicit 'mulaw' format
        try:
            audio = AudioSegment.from_file(ulaw_path, format='mulaw', frame_rate=8000, channels=1)
            audio.export(output_path, format='mp3')
            print(f"Successfully converted {ulaw_path} to {output_path} using pydub (mulaw)")
            return True
        except Exception:
            # Last-resort: try reading as raw PCM with the parameters Audacity uses
            audio = AudioSegment.from_file(ulaw_path, format='raw', frame_rate=8000, channels=1, sample_width=1)
            audio.export(output_path, format='mp3')
            print(f"Successfully converted {ulaw_path} to {output_path} using pydub (raw fallback)")
            return True

    except Exception as e:
        print(f"Audio conversion failed: {e}")
        return False

# --- Email Sender Module ---
def send_voicemail_email(access_token, sender_address, recipient, mailbox, timestamp, attachment_path):
    """Sends an email with a new voicemail attachment using Microsoft Graph sendMail.

    Tries /me/sendMail when possible, otherwise attempts /users/{sender}/sendMail.
    """
    try:
        # Build message
        subject = f"New Voicemail from Mailbox {mailbox}"
        body_content = (
            f"You have received a new voicemail.\n\n"
            f"From: Mailbox {mailbox}\n"
            f"Time: {timestamp}\n\n"
            "Please see the attached audio file."
        )

        # Read and base64-encode attachment
        with open(attachment_path, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode('utf-8')
        content_type, _ = mimetypes.guess_type(attachment_path)
        if content_type is None:
            content_type = 'application/octet-stream'

        attachment = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": os.path.basename(attachment_path),
            "contentBytes": b64,
            "contentType": content_type,
        }

        message = {
            "subject": subject,
            "body": {"contentType": "Text", "content": body_content},
            "toRecipients": [{"emailAddress": {"address": recipient}}],
            "attachments": [attachment]
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # attempt to send as specified sender
        url = f'https://graph.microsoft.com/v1.0/users/{sender_address}/sendMail'

        payload = {"message": message, "saveToSentItems": "true"}

        resp = requests.post(url, headers=headers, json=payload)
        if resp.status_code in (200, 202):
            print(f"Email sent successfully to {recipient} for mailbox {mailbox}.")
            return True
        else:
            print(f"Failed to send email to {recipient}. Status: {resp.status_code} Response: {resp.text}")
            return False

    except Exception as e:
        print(f"An error occurred while sending email: {e}")
        return False
    
def send_all_emails(new_files_found, config, access_token, ftp):

    mailbox_emails = load_mailbox_emails()

    for mailbox, file_paths in new_files_found.items():
        print(f"Found {len(file_paths)} new file(s) in mailbox {mailbox}.")

        recipients = mailbox_emails.get(mailbox, [])
        
        if not recipients:
            print(f"Warning: No recipients configured for mailbox {mailbox}. Skipping.")
            continue

        for file_path in file_paths:
            local_path = f"temp_{os.path.basename(file_path)}"
            try:
                with open(local_path, 'wb') as f:
                    ftp.retrbinary(f"RETR {file_path}", f.write)
            except ftplib.all_errors as e:
                print(f"Failed to download {file_path}: {e}")
                continue
            
            mp3_path = local_path.replace('temp_', '') + '.mp3'
            if convert_ulaw_to_mp3(local_path, mp3_path):
                for recipient in recipients:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    send_voicemail_email(access_token, config['O365']['sender_address'], recipient, mailbox, timestamp, mp3_path)
            
            os.remove(local_path)
            if os.path.exists(mp3_path):
                os.remove(mp3_path)

def token_has_mail_send(app_token: str) -> bool:
    try:
        parts = app_token.split('.')
        if len(parts) < 2:
            return False
        
        def _b64decode_segment(seg: str) -> bytes:
            # Base64url decode with padding
            seg += '=' * ((4 - len(seg) % 4) % 4)
            return base64.urlsafe_b64decode(seg)

        payload = json.loads(_b64decode_segment(parts[1]))
        # Application permissions appear in the 'roles' claim for app-only tokens
        roles = payload.get('roles') or []
        if isinstance(roles, str):
            roles = [roles]
        # Also check 'scp' just in case (delegated scopes)
        scp = payload.get('scp', '')
        if isinstance(scp, str):
            scp_list = [s.strip() for s in scp.split() if s.strip()]
        else:
            scp_list = []

        if 'Mail.Send' in roles or 'Mail.Send' in scp_list or 'mail.send' in [r.lower() for r in roles]:
            return True
        return False
    except Exception:
        return False

# --- Main Execution ---
def main():
    config = load_config()

    # Use MSAL client credentials flow (application authentication)
    # This requires the app registration to have Microsoft Graph -> Application permissions -> Mail.Send
    client_id = config['O365']['client_id']
    tenant = config['O365']['tenant_id']
    client_secret = config['O365']['client_secret']

    if not client_secret:
        print("client_secret missing in config.ini; required for app-only authentication")
        return

    # For client credentials you must request the .default scope
    scopes = ["https://graph.microsoft.com/.default"]

    authority = f"https://login.microsoftonline.com/{tenant}"
    app = msal.ConfidentialClientApplication(client_id=client_id, client_credential=client_secret, authority=authority)

    result = app.acquire_token_for_client(scopes=scopes)

    if not result or 'access_token' not in result:
        print("Failed to acquire app-only token. Result:", result)
        return

    access_token = result['access_token']

    # Verify the access token contains the application permission Mail.Send.
    if not token_has_mail_send(access_token):
        client_id = config['O365']['client_id']
        tenant = config['O365']['tenant_id']
        redirect = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        admin_consent_url = (
            f"https://login.microsoftonline.com/{tenant}/adminconsent?client_id={client_id}&redirect_uri={redirect}"
        )
        print("\nWARNING: the acquired app-only token does not appear to include the Mail.Send application permission.")
        print("This likely means the permission hasn't been granted by an administrator yet.")
        print("Ask an admin to grant admin consent, or open the admin consent URL below:")
        print(admin_consent_url)
        print("\nAfter an admin grants consent, re-run this script.")
        return

    # FTP connection
    try:
        ftp = ftplib.FTP(config['FTP']['host'])
        ftp.login(user=config['FTP']['user'], passwd=config['FTP']['password'])
        print("Connected to FTP server.")
    except ftplib.all_errors as e:
        print(f"Failed to connect to FTP server: {e}")
        return

    scanned_files_set = read_scanned_files()
    print(f"Loaded {len(scanned_files_set)} previously scanned files.")
    
    # Find new files since last scan, and collect current files on FTP
    new_files_found, current_files_on_ftp = scan_ftp_folder(ftp, config['FTP']['base_path'], scanned_files_set)

    if not new_files_found:
        print("No new files found.")
    else:
        send_all_emails(new_files_found, config, access_token, ftp)

    # Update the list of scanned files for the next run
    write_scanned_files(current_files_on_ftp)
    
    ftp.quit()
    print("FTP connection closed.")
    print("Scan complete.")

if __name__ == "__main__":
    main()