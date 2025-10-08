import configparser
import ftplib
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
import msal
import requests
import base64
import mimetypes
import base64, json
import subprocess
import shutil
import torch
import whisper
import concurrent.futures

SCANNED_FILES_JSON_PATH = 'scanned_files.json'
WHISPER_MODEL = 'medium'  # Change to desired model size: tiny, base, small, medium, large
FTP_TIME_OFFSET = timedelta(days=30)
TEMP_DIR = Path('temp')

# --- Configuration Loader ---
def load_config(config_path='config.ini') -> configparser.ConfigParser:
    """Loads configuration from the config.ini file."""
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

def load_mailbox_emails() -> dict[str, list[str]]:
    """Loads mailbox to email mappings from mailbox_emails.json."""
    if os.path.exists('mailbox_emails.json'):
        with open('mailbox_emails.json', 'r') as f:
            mailbox_emails = json.load(f)
            config = load_config()
            domain = config['O365'].get('recipient_domain', '').strip()
            for mailbox, emails in mailbox_emails.items():
                valid_emails = []
                for i in range(len(emails)):
                    email = emails[i]
                    # If emails are valid, continue
                    if '@' in email and '.' in email.split('@')[-1]:
                        valid_emails.append(email)
                    # Else, if they look like just a username, append the domain from config.ini
                    elif domain and '@' not in email:
                        full_email = f"{email}@{domain}"
                        valid_emails.append(full_email)
                    # Otherwise, skip invalid emails
                    elif not domain:
                        print(f"Warning: No default email domain configured. Skipping email '{email}'.")
                    else:
                        print(f"Warning: Invalid email address '{email}' for mailbox {mailbox}. Skipping.")
                # I know, I know, modifying a list while iterating over it is bad practice.
                mailbox_emails[mailbox] = valid_emails
            return mailbox_emails
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
def scan_ftp_folder(ftp_connection: ftplib.FTP, base_path: str, scanned_files: set[str]) -> tuple[dict[str, list[dict]], set[str]]:
    """
    Scans the FTP folder for new voicemail files by comparing against a
    list of previously scanned files.
    
    Args:
        ftp_connection: An active ftplib.FTP object.
        base_path: The base path of the voicemail folders on the FTP server.
        scanned_files: A set of file paths that have already been processed.
        
    Returns:
        A tuple (new_files, current_files) where:
            new_files: A dict mapping mailbox numbers to lists of new file info dicts.
            current_files: A set of all file paths currently found on the FTP server.
    """
    new_files = {}
    current_files = set()
    try:
        ftp_connection.cwd(base_path)
        mailboxes = ftp_connection.nlst()
        
        for mailbox_number in mailboxes:
            if mailbox_number.isdigit():
                mailbox_path = f"{base_path}/{mailbox_number}"
                try:
                    lines = []
                    ftp_connection.dir(mailbox_path, lines.append)
                    
                    for line in lines:
                        parts = line.split()
                        if len(parts) < 9:
                            continue
                        
                        filename = parts[-1]
                        if filename == '.' or filename == '..':
                            continue

                        full_path = f"{mailbox_path}/{filename}"
                        current_files.add(full_path)
                        
                        if full_path not in scanned_files:
                            try:
                                mod_time_str = ftp_connection.voidcmd(f"MDTM {full_path}")[4:].strip()
                                ftp_mod_time = parse_mitel_ftp_date(mod_time_str)
                            except ftplib.all_errors:
                                ftp_mod_time = datetime.now()

                            # Ensure dict entry exists
                            if mailbox_number not in new_files:
                                new_files[mailbox_number] = []

                            new_files[mailbox_number].append({'path': full_path, 'modified': ftp_mod_time})
                except ftplib.error_perm:
                    continue
    except ftplib.all_errors as e:
        print(f"FTP error: {e}")
    finally:
        ftp_connection.cwd('/')
        
    return new_files, current_files

def parse_mitel_ftp_date(date_string):
    """Parses the Mitel PBX date string by correcting the zero-based month index.
    Why is this needed? Who knows.
    Once again, thanks Gemini for this one."""
    
    # 1. Extract the components
    year = date_string[0:4]
    month_str = date_string[4:6]
    day_and_time = date_string[6:]
    
    # 2. Correct the Month Index
    # Convert '01' to integer 1, add 1 to get 2 (February), then convert back to '02'
    try:
        zero_based_month = int(month_str)
        # Check for invalid zero-based month index (should be 0-11)
        if not 0 <= zero_based_month <= 11:
             raise ValueError(f"Month index '{month_str}' is outside the expected 0-11 range.")

        correct_month = zero_based_month + 1
        
        # Convert back to a two-digit string (e.g., 2 -> '02')
        correct_month_str = str(correct_month).zfill(2)
        
    except ValueError as e:
        # Handle cases where month_str is not a number or is out of range
        raise ValueError(f"Could not parse or correct month component '{month_str}': {e}")
    
    # 3. Reconstruct the string
    corrected_date_string = year + correct_month_str + day_and_time
    
    # 4. Standard Parsing
    time_format = '%Y%m%d%H%M%S'
    dt_object = datetime.strptime(corrected_date_string, time_format)
    
    return dt_object

# --- Audio Converter Module ---
def convert_ulaw_to_mp3(ulaw_path: Path, output_path: Path) -> bool:
    """
    Converts a raw u-law audio file to MP3 using ffmpeg.

    Args:
        ulaw_path (Path): The file path to the input u-law audio file.
        output_path (Path): The file path to the output MP3 audio file.

    Returns:
        bool: True if the conversion was successful, False otherwise.
    """
    try:
        # Prefer ffmpeg for reliable u-law decoding (matches Audacity import: U-Law, 8000 Hz, mono)
        ffmpeg_path = shutil.which('ffmpeg')
        if ffmpeg_path:
            cmd = [
                ffmpeg_path,
                '-y',
                '-f', 'mulaw',
                '-ar', '8000',
                '-ac', '1',
                '-i', str(ulaw_path),
                '-acodec', 'libmp3lame',
                str(output_path)
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                print(f"Successfully converted {ulaw_path} to {output_path} using ffmpeg")
                return True
            else:
                print(f"ffmpeg conversion failed (code {proc.returncode}). stderr:\n{proc.stderr}")
                return False
        else:
            print("ffmpeg not found in PATH. Please install ffmpeg to enable audio conversion.")
            return False

    except Exception as e:
        print(f"Audio conversion failed: {e}")
        return False

# --- Transcription Module ---
def transcribe_audio_whisper(model: whisper.Whisper, audio_path: str, timeout: float) -> str:
    """
    Transcribes an audio file using the Whisper model with a 5-minute timeout.

    Args:
        model (whisper.Whisper): The Whisper model instance to use.
        audio_path (str): The path to the audio file to transcribe.
        timeout (float): The maximum time in seconds to allow for transcription.

    Returns:
        str: The transcribed text, or an empty string if it times out or fails.
    """
    print("Attempting to transcribe audio with Whisper...")
    
    def transcribe():
        return model.transcribe(audio_path)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(transcribe)
        try:
            result = future.result(timeout=timeout)
            print("Transcription successful.")
            return str(result['text'])
        except concurrent.futures.TimeoutError:
            print(f"Whisper transcription timed out after {timeout} seconds.")
            return ""
        except Exception as e:
            print(f"Whisper transcription failed: {e}")
            return ""

# --- Email Sender Module ---
def send_voicemail_email(access_token, sender_address, recipient, mailbox, timestamp, attachment_path, transcription=None):
    """Sends an email with a new voicemail attachment using Microsoft Graph sendMail.
    """
    try:
        # Build message
        subject = f"New Voicemail from Mailbox {mailbox}"

        # Build HTML body
        body_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; }}
                .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; max-width: 600px; }}
                .header {{ font-size: 1.2em; font-weight: bold; margin-bottom: 10px; }}
                .info-table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                .info-table td {{ padding: 8px; border: 1px solid #ddd; }}
                .transcription {{ margin-top: 20px; padding: 15px; background-color: #f9f9f9; border: 1px solid #eee; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">New Voicemail Received</div>
                <table class="info-table">
                    <tr><td><b>From:</b></td><td>Mailbox {mailbox}</td></tr>
                    <tr><td><b>Time:</b></td><td>{timestamp}</td></tr>
                </table>
                <p>Please see the attached audio file for the full message.</p>
        """

        if transcription:
            body_content += f"""
                <div class="transcription">
                    <b>Transcription:</b>
                    <p>{transcription}</p>
                </div>
            """
        
        body_content += """
            </div>
        </body>
        </html>
        """

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
            "body": {"contentType": "HTML", "content": body_content},
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

def process_files(new_files_found, prev_scanned_files, config, access_token, ftp, whisper_model=None):

    mailbox_emails = load_mailbox_emails()

    for mailbox, file_infos in new_files_found.items():
        print(f"Found {len(file_infos)} new file(s) in mailbox {mailbox}.")

        recipients = mailbox_emails.get(mailbox, [])
        
        if not recipients:
            print(f"Warning: No recipients configured for mailbox {mailbox}. Skipping.")
            continue


        for file_info in file_infos:
            file_path = file_info['path']
            modified_time = file_info['modified']
            TEMP_DIR.mkdir(parents=True, exist_ok=True)
            local_path = TEMP_DIR / os.path.basename(file_path)  # This syntax is funny but yeah I suppose it works

            try:
                with open(local_path, 'wb') as f:
                    ftp.retrbinary(f"RETR {file_path}", f.write)
            except ftplib.all_errors as e:
                print(f"Failed to download {file_path}: {e}")
                continue

            mp3_path = TEMP_DIR / f"Mailbox {mailbox} on {modified_time.strftime('%Y-%m-%d at %H-%M-%S')}.mp3"
            if convert_ulaw_to_mp3(local_path, mp3_path):

                # Transcribe audio
                transcription = ""
                if whisper_model:
                    transcription = transcribe_audio_whisper(whisper_model, str(mp3_path), timeout=300)  # 5 minutes timeout

                for recipient in recipients:
                    if not config['O365']['sender_address']:
                        print("Sender address is blank! Cannot send emails.")
                        break
                    timestamp = modified_time.strftime("%B %d, %Y at %I:%M %p")
                    send_voicemail_email(access_token, config['O365']['sender_address'], recipient, mailbox, timestamp, str(mp3_path), transcription=transcription)

            os.remove(local_path)
            if os.path.exists(mp3_path):
                os.remove(mp3_path)

            # Mark file as processed
            prev_scanned_files.add(file_path)
            # Update the scanned files list after each file is processed, so if the script is interrupted we don't reprocess files
            write_scanned_files(prev_scanned_files)

    
def remove_temp_dir():
    if TEMP_DIR.exists() and TEMP_DIR.is_dir():
        print("Cleaning up temporary files...")
        shutil.rmtree(TEMP_DIR)


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
    # 1) Load configuration
    # 2) Connect to FTP and scan for new files
    # 3) Authenticate to Microsoft Graph
    # 4) Load Whisper model
    # 5) For each new file:
    #    a) Download file
    #    b) Convert to MP3 (ffmpeg)
    #    c) Transcribe with Whisper
    #    d) Send email with attachment and transcription
    #    e) Clean up local files
    #    f) Mark file as processed
    # 6) Save updated scanned files list


    print("Loading configuration...")

    if not os.path.exists('config.ini'):
        print("Error: config.ini file not found. The contents of config_template.ini have been copied to config.ini.")
        print("Please edit config.ini to add your configuration settings, then re-run the script.")

        template_path = 'config_template.ini'
        if os.path.exists(template_path):
            shutil.copyfile(template_path, 'config.ini')
        else:
            print("Error: config_template.ini file not found. Please ensure it exists in the script directory.")
        return
    
    config = load_config()
   
    print(f"""
    Welcome to the Madison Children's Museum Voicemail Emailer!
          
        Current configuration status:
            Sending from {config['O365']['sender_address']}
            Scanning FTP server {config['FTP']['host']} under path {config['FTP']['base_path']}
            Using Whisper model: {WHISPER_MODEL}
""")  
    
    remove_temp_dir()
    
    print("Checking for new files...")

    # FTP connection
    print(f"Connecting to FTP server {config['FTP']['host']}...")

    if config['FTP']['host'] == '':
        print("No FTP host set! Exiting...")
        return

    try:
        ftp = ftplib.FTP(config['FTP']['host'])
        ftp.login(user=config['FTP']['user'], passwd=config['FTP']['password'])
        print("Connected to FTP server.")
    except ftplib.all_errors as e:
        print(f"Failed to connect to FTP server: {e}")
        return

    print("Reading previously scanned files...")
    previously_scanned_files_set = set()
    if os.path.exists(SCANNED_FILES_JSON_PATH):
        previously_scanned_files_set = read_scanned_files()
        print(f"Loaded {len(previously_scanned_files_set)} previously scanned files.")

    else:
        print("No previously scanned files found. Initializing assuming all current files have been processed.")
        # On first run, assume all current files are already processed
        _, current_files_on_ftp = scan_ftp_folder(ftp, config['FTP']['base_path'], previously_scanned_files_set)
        previously_scanned_files_set = current_files_on_ftp
        write_scanned_files(previously_scanned_files_set)
        print(f"Recorded {len(previously_scanned_files_set)} existing files as processed.")
        ftp.quit()
        print("FTP connection closed.")
        print("Scan complete.")
        return

    # Find new files since last scan, and collect current files on FTP
    new_files_found, current_files_on_ftp = scan_ftp_folder(ftp, config['FTP']['base_path'], previously_scanned_files_set)

    new_file_count = sum(len(files) for files in new_files_found.values())
    new_mailbox_count = len(new_files_found)

    print(f"Scanned {len(current_files_on_ftp)} total files on FTP server.")
    print(f"Found {new_mailbox_count} mailbox{'' if new_mailbox_count == 1 else 'es'} with {new_file_count} new file{'' if new_file_count == 1 else 's'}.")

    if not new_files_found:
        print("No new files found.")
        ftp.quit()
        print("FTP connection closed.")
        print("Scan complete.")
        return


    # Use MSAL client credentials flow (application authentication)
    # This requires the app registration to have Microsoft Graph -> Application permissions -> Mail.Send
    client_id = config['O365']['client_id']
    tenant = config['O365']['tenant_id']
    client_secret = config['O365']['client_secret']

    if not client_secret or not client_id or not tenant:
        print("Client secret, client id, and tenant id must be configured!")
        return

    # For client credentials you must request the .default scope
    scopes = ["https://graph.microsoft.com/.default"]

    authority = f"https://login.microsoftonline.com/{tenant}"

    print("Signing in to Microsoft Graph...")

    app = msal.ConfidentialClientApplication(client_id=client_id, client_credential=client_secret, authority=authority)
    result = app.acquire_token_for_client(scopes=scopes)

    if not result or 'access_token' not in result:
        print("Failed to acquire app-only token. Result:", result)
        return
    else:
        print("Acquired Microsoft authentication token.")

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

    

    # Load Whisper model
    whisper_model = None

    if torch.cuda.is_available():
        torch.cuda.init()
        print(f"CUDA is available. Using device: {torch.cuda.get_device_name(0)}")

    try:
        print("Loading Whisper model...")
        whisper_model = whisper.load_model(WHISPER_MODEL)
        print("Whisper model loaded.")
    except Exception as e:
        print(f"Failed to load Whisper model: {e}")
        print("Continuing without transcription.")

    # Process each new file found
    print("Processing new files...")
    process_files(new_files_found, previously_scanned_files_set, config, access_token, ftp, whisper_model=whisper_model)

    # Close FTP connection
    ftp.quit()
    print("FTP connection closed.")
    print("Scan complete.")

    # Save updated scanned files list
    write_scanned_files(current_files_on_ftp)

    remove_temp_dir()

if __name__ == "__main__":
    main()