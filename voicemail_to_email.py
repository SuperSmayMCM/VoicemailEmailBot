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
import threading
import atexit
import tempfile
import torch
import whisper
import concurrent.futures
from string import Template
from typing import cast

SCANNED_FILES_JSON_PATH = 'scanned_files.json'
WHISPER_MODEL = 'medium'  # Change to desired model size: tiny, base, small, medium, large
FTP_TIME_OFFSET = timedelta(days=30)
TEMP_DIR = Path('temp')
STATISTICS_PATH = 'statistics.json'

# In-memory stats cache to avoid frequent disk I/O. Flushes at exit.
statistics_cache: dict | None = None
stats_cache_lock = threading.Lock()

# --- File Management ---
def load_config(config_path='config.ini') -> configparser.ConfigParser:
    """Loads configuration from the config.ini file."""
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

def load_statistics() -> dict:
    """Loads statistics from statistics.json into the in-memory cache and returns a copy.

    If the in-memory cache is already initialized, return a copy of it. Otherwise, read
    from disk (if present) and populate the cache.
    """
    global statistics_cache
    # Return copy if cache already populated
    if statistics_cache is not None:
        # return a shallow copy
        return cast(dict, statistics_cache).copy()

    # Initialize cache from disk
    if os.path.exists(STATISTICS_PATH):
        try:
            with open(STATISTICS_PATH, 'r') as f:
                statistics_cache = json.load(f)
        except Exception:
            statistics_cache = {}
    else:
        statistics_cache = {}

    assert statistics_cache is not None
    return cast(dict, statistics_cache).copy()

def write_statistics(stats: dict) -> None:
    """Writes statistics to statistics.json atomically and updates the in-memory cache."""
    global statistics_cache
    with stats_cache_lock:
        statistics_cache = stats.copy() if stats is not None else {}

        # Atomic write to avoid corruption
        dir_name = os.path.dirname(os.path.abspath(STATISTICS_PATH)) or '.'
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix='statistics-', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(statistics_cache, f, indent=4)
            os.replace(tmp_path, STATISTICS_PATH)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

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

def get_git_commit_id() -> str:
    """Gets the current git commit ID, or 'unknown' if it cannot be determined."""
    try:
        commit_id = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('utf-8').strip()
        return commit_id
    except Exception:
        return "unknown"

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

def remove_temp_dir():
    if TEMP_DIR.exists() and TEMP_DIR.is_dir():
        print("Cleaning up temporary files...")
        shutil.rmtree(TEMP_DIR)


# --- Statistics Module ---
# Periodic flush: flush the stats cache every STATS_FLUSH_INTERVAL seconds
STATS_FLUSH_INTERVAL = 60  # seconds
stats_flush_thread: threading.Thread | None = None
stats_flush_stop = threading.Event()

def flush_statistics_cache() -> None:
    """Flush the in-memory statistics cache to disk (atomic replace)."""
    global statistics_cache
    with stats_cache_lock:
        if statistics_cache is None:
            return
        # reuse write logic by dumping directly
        dir_name = os.path.dirname(os.path.abspath(STATISTICS_PATH)) or '.'
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix='statistics-', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(statistics_cache, f, indent=4)
            os.replace(tmp_path, STATISTICS_PATH)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

def _periodic_flush_loop() -> None:
    """Background loop that flushes the statistics cache periodically.

    Uses STATS_FLUSH_STOP.wait(timeout) so it can be stopped quickly.
    """
    while not stats_flush_stop.wait(STATS_FLUSH_INTERVAL):
        try:
            flush_statistics_cache()
        except Exception:
            # swallow exceptions; periodic flusher should not crash the program
            pass

def start_periodic_stats_flush() -> None:
    """Start the background thread that periodically flushes stats.

    Safe to call multiple times; subsequent calls are a no-op.
    """
    global stats_flush_thread
    if stats_flush_thread is not None and stats_flush_thread.is_alive():
        return
    stats_flush_stop.clear()
    t = threading.Thread(target=_periodic_flush_loop, name='stats-flush-thread', daemon=True)
    stats_flush_thread = t
    t.start()

def stop_periodic_stats_flush() -> None:
    """Signal the periodic flusher to stop and flush once more."""
    stats_flush_stop.set()
    try:
        flush_statistics_cache()
    except Exception:
        pass

def add_to_statistics(category: str, action: str, status: str, value: int) -> None:
    """Adds a value to a statistics key in the in-memory cache.

    The cache is flushed to disk at program exit. This reduces disk I/O cost for
    frequent updates. Use `write_statistics` or `flush_statistics_cache` to force
    a flush earlier.
    """
    global statistics_cache
    # Ensure cache is initialized
    if statistics_cache is None:
        load_statistics()

    # Ensure the cache is a dict for static checkers
    try:
        assert statistics_cache is not None
        with stats_cache_lock:
            if category not in statistics_cache:
                statistics_cache[category] = {}
            if action not in statistics_cache[category]:
                statistics_cache[category][action] = {}
            if status in statistics_cache[category][action]:
                statistics_cache[category][action][status] += value
            else:
                statistics_cache[category][action][status] = value
    except Exception as e:
        print(f"Error updating statistics cache: {e}")

def set_statistics(category: str, action: str, status: str, value: int) -> None:
    """Sets a value to a statistics key in the in-memory cache.

    The cache is flushed to disk at program exit. This reduces disk I/O cost for
    frequent updates. Use `write_statistics` or `flush_statistics_cache` to force
    a flush earlier.
    """
    global statistics_cache
    # Ensure cache is initialized
    if statistics_cache is None:
        load_statistics()

    # Ensure the cache is a dict for static checkers
    try:
        assert statistics_cache is not None
        with stats_cache_lock:
            if category not in statistics_cache:
                statistics_cache[category] = {}
            if action not in statistics_cache[category]:
                statistics_cache[category][action] = {}
            statistics_cache[category][action][status] = value
    except Exception as e:
        print(f"Error updating statistics cache: {e}")

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
    add_to_statistics('ftp', 'ftp_scan', 'attempts', 1)
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
                                print(f"Failed to retrieve modification time for {full_path}")
                                add_to_statistics('ftp', 'ftp_file_modtime', 'fails', 1)
                                ftp_mod_time = datetime.now()

                            # Ensure dict entry exists
                            if mailbox_number not in new_files:
                                new_files[mailbox_number] = []

                            new_files[mailbox_number].append({'path': full_path, 'modified': ftp_mod_time})
                except ftplib.error_perm:
                    continue
        add_to_statistics('ftp', 'ftp_scan', 'successes', 1)
    except ftplib.all_errors as e:
        add_to_statistics('ftp', 'ftp_scan', 'fails', 1)
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
    add_to_statistics('audio_conversion', 'ffmpeg_conversion', 'attempts', 1)
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
                add_to_statistics('audio_conversion', 'ffmpeg_conversion', 'successes', 1)
                print(f"Successfully converted {ulaw_path} to {output_path} using ffmpeg")
                return True
            else:
                add_to_statistics('audio_conversion', 'ffmpeg_conversion', 'fails', 1)
                print(f"ffmpeg conversion failed (code {proc.returncode}). stderr:\n{proc.stderr}")
                return False
        else:
            print("ffmpeg not found in PATH. Please install ffmpeg to enable audio conversion.")
            return False

    except Exception as e:
        add_to_statistics('audio_conversion', 'ffmpeg_conversion', 'fails', 1)
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
        add_to_statistics('transcription', 'whisper_transcription', 'attempts', 1)
        return model.transcribe(audio_path)

    start_ts = datetime.now()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(transcribe)
        try:
            result = future.result(timeout=timeout)
            elapsed = datetime.now() - start_ts
            # record elapsed time in milliseconds for better precision
            add_to_statistics('transcription', 'whisper_transcription_time_seconds', 'total', int(elapsed.total_seconds()))
            add_to_statistics('transcription', 'whisper_transcription', 'successes', 1)
            print("Transcription successful.")
            return str(result['text'])
        except concurrent.futures.TimeoutError:
            elapsed = datetime.now() - start_ts
            add_to_statistics('transcription', 'whisper_transcription_time_seconds', 'total', int(elapsed.total_seconds()))
            add_to_statistics('transcription', 'whisper_transcription', 'timeouts', 1)
            print(f"Whisper transcription timed out after {timeout} seconds.")
            return ""
        except Exception as e:
            elapsed = datetime.now() - start_ts
            add_to_statistics('transcription', 'whisper_transcription_time_seconds', 'total', int(elapsed.total_seconds()))
            add_to_statistics('transcription', 'whisper_transcription', 'fails', 1)
            print(f"Whisper transcription failed: {e}")
            return ""

# --- Email Sender Module ---
def send_voicemail_email(access_token: str, recipient: str, mailbox: str, timestamp: str, audio_attachment_path: str, transcription: str | None = None):
    """Sends an email with a new voicemail attachment using Microsoft Graph sendMail.
    """

    config = load_config()
    add_to_statistics('email', 'email_send', 'attempts', 1)

    if mailbox == '0':
        mailbox = 'General Mailbox'

    try:
        # Build message
        subject = ''
        if type(mailbox) is int:
            subject = f"New Voicemail from Mailbox {mailbox}!"
        else:
            subject = f"New Voicemail from {mailbox}!"

        # CIDs for the images. This lets us include the image in the email, and reference it in the HTML.
        # Files will be loaded later, and attached with these IDs
        crayon_line_2_cid = 'crayonline2' 
        # crayon_line_3_cid = 'crayonline3'
        chicken_foot_cid = 'chickenfoot'

        # Build HTML Body using the template
        email_data = {
            'mailbox': mailbox,
            'transcription': transcription if transcription else "No transcription provided.",
            'timestamp': timestamp,
            'support_email': config['O365']['support_email'] if config['O365']['support_email'] else 'tech support',
            'crayon_line_2_cid': crayon_line_2_cid,
            # 'crayon_line_3_cid': crayon_line_3_cid,
            'chicken_foot_cid': chicken_foot_cid,
            'git_commit_id': get_git_commit_id(),
        }

        with open('./templates/email_template.html') as template_file:
            email_template = template_file.read()

        template = Template(email_template)

        body_content = template.substitute(email_data)

        # Read and base64-encode audio attachment
        audio_attachment = None

        if audio_attachment_path is None:
            print("Warning! Audio file path is None, so no audio will be included!")
        else:
            with open(audio_attachment_path, 'rb') as f:
                data = f.read()

            b64 = base64.b64encode(data).decode('utf-8')

            content_type, _ = mimetypes.guess_type(audio_attachment_path)
            if content_type is None:
                content_type = 'application/octet-stream'

            audio_attachment = {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": os.path.basename(audio_attachment_path),
                "contentBytes": b64,
                "contentType": content_type,
            }

        crayon_line_2_path = './images/CrayonLines-2orange.png'
        # crayon_line_3_path = './images/CrayonLines-3orange.png'
        chicken_foot_path = './images/chicken_foot.png'

        with open(crayon_line_2_path, 'rb') as f:
            image_data = f.read()
            b64_image = base64.b64encode(image_data).decode('utf-8')
            image_content_type, _ = mimetypes.guess_type(crayon_line_2_path)
            if image_content_type is None:
                image_content_type = 'application/octet-stream'

        crayon_line_2_attachment = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": os.path.basename(crayon_line_2_path),
            "contentBytes": b64_image,
            "contentType": image_content_type,
            "isInline": True,        # Mark as inline
            "contentId": crayon_line_2_cid   # Assign the Content-ID
        }

        # with open(crayon_line_3_path, 'rb') as f:
        #     image_data = f.read()
        #     b64_image = base64.b64encode(image_data).decode('utf-8')
        #     image_content_type, _ = mimetypes.guess_type(crayon_line_3_path)
        #     if image_content_type is None:
        #         image_content_type = 'application/octet-stream'

        # crayon_line_3_attachment = {
        #     "@odata.type": "#microsoft.graph.fileAttachment",
        #     "name": os.path.basename(crayon_line_3_path),
        #     "contentBytes": b64_image,
        #     "contentType": image_content_type,
        #     "isInline": True,        # Mark as inline
        #     "contentId": crayon_line_3_cid   # Assign the Content-ID
        # }

        with open(chicken_foot_path, 'rb') as f:
            image_data = f.read()
            b64_image = base64.b64encode(image_data).decode('utf-8')
            image_content_type, _ = mimetypes.guess_type(chicken_foot_path)
            if image_content_type is None:
                image_content_type = 'application/octet-stream'

        chicken_foot_attachment = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": os.path.basename(chicken_foot_path),
            "contentBytes": b64_image,
            "contentType": image_content_type,
            "isInline": True,        # Mark as inline
            "contentId": chicken_foot_cid   # Assign the Content-ID
        }


        # 3. Build the final message with BOTH attachments
        attachments = []
        if audio_attachment:
            attachments.append(audio_attachment)

        if crayon_line_2_attachment:
            attachments.append(crayon_line_2_attachment)

        # if crayon_line_3_attachment:
        #     attachments.append(crayon_line_3_attachment)

        if chicken_foot_attachment:
            attachments.append(chicken_foot_attachment)

        message = {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body_content},
            "toRecipients": [{"emailAddress": {"address": recipient}}],
            "attachments": attachments
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # attempt to send as specified sender
        url = f'https://graph.microsoft.com/v1.0/users/{config["O365"]["sender_address"]}/sendMail'

        payload = {"message": message, "saveToSentItems": "true"}

        resp = requests.post(url, headers=headers, json=payload)
        if resp.status_code in (200, 202):
            add_to_statistics('email', 'email_send', 'successes', 1)
            try:
                # measure the full JSON payload size (UTF-8 bytes) including base64 attachment content
                json_payload = json.dumps(payload)
                payload_size = len(json_payload.encode('utf-8'))
                add_to_statistics('email', 'email_payload_bytes', 'total', payload_size)
            except Exception:
                # if for some reason measuring fails, don't block the success path
                pass
            return True
        else:
            add_to_statistics('email', 'email_send', 'fails', 1)
            print(f"Failed to send email to {recipient}. Status: {resp.status_code} Response: {resp.text}")
            return False

    except Exception as e:
        add_to_statistics('email', 'email_send', 'fails', 1)
        print(f"An error occurred while sending email: {e}")
        return False

def process_files(new_files_found, prev_scanned_files, config, access_token, ftp, whisper_model=None):

    add_to_statistics('general', 'file_processing_runs', 'total', 1)

    mailbox_emails = load_mailbox_emails()

    for mailbox, file_infos in new_files_found.items():
        print(f"Found {len(file_infos)} new file(s) in mailbox {mailbox}.")

        recipients = mailbox_emails.get(mailbox, [])
        
        if not recipients:
            print(f"Warning: No recipients configured for mailbox {mailbox}. Skipping.")
            continue


        for file_info in file_infos:
            add_to_statistics('general', 'files_processed', 'total', 1)
            file_path = file_info['path']
            modified_time = file_info['modified']
            TEMP_DIR.mkdir(parents=True, exist_ok=True)
            local_path = TEMP_DIR / os.path.basename(file_path)  # This syntax is funny but yeah I suppose it works

            try:
                with open(local_path, 'wb') as f:
                    add_to_statistics('ftp', 'ftp_file_download', 'attempts', 1)
                    ftp.retrbinary(f"RETR {file_path}", f.write)
                add_to_statistics('ftp', 'ftp_file_download', 'successes', 1)
            except ftplib.all_errors as e:
                print(f"Failed to download {file_path}: {e}")
                add_to_statistics('ftp', 'ftp_file_download', 'fails', 1)
                continue

            mp3_path = TEMP_DIR / f"Mailbox {mailbox} on {modified_time.strftime('%Y-%m-%d at %H-%M-%S')}.mp3"
            if convert_ulaw_to_mp3(local_path, mp3_path):

                # Transcribe audio
                transcription = ""
                if whisper_model:
                    transcription = transcribe_audio_whisper(whisper_model, str(mp3_path), timeout=300)  # 5 minutes timeout
                else:
                    add_to_statistics('transcription', 'whisper_transcription', 'skips', 1)
                    print("No Whisper model loaded; skipping transcription.")

                for recipient in recipients:
                    if not config['O365']['sender_address']:
                        print("Sender address is blank! Cannot send emails.")
                        break
                    timestamp = modified_time.strftime("%B %d, %Y at %I:%M %p")
                    send_voicemail_email(access_token, recipient, mailbox, timestamp, str(mp3_path), transcription=transcription)

            os.remove(local_path)
            if os.path.exists(mp3_path):
                os.remove(mp3_path)

            # Mark file as processed
            prev_scanned_files.add(file_path)
            # Update the scanned files list after each file is processed, so if the script is interrupted we don't reprocess files
            write_scanned_files(prev_scanned_files)

def acquire_token(client_id: str, client_secret: str, tenant: str) -> str | None:

    add_to_statistics('O365', 'token_acquisition', 'attempts', 1)

    access_token = None

    try:
        # For client credentials you must request the .default scope
        scopes = ["https://graph.microsoft.com/.default"]

        authority = f"https://login.microsoftonline.com/{tenant}"

        app = msal.ConfidentialClientApplication(client_id=client_id, client_credential=client_secret, authority=authority)
        result = app.acquire_token_for_client(scopes=scopes)

        if not result or 'access_token' not in result:
            add_to_statistics('O365', 'token_acquisition', 'fails', 1)
            print("Failed to acquire app-only token. Result:", result)
            return
        else:
            add_to_statistics('O365', 'token_acquisition', 'successes', 1)
            print("Acquired Microsoft authentication token.")

        access_token = result['access_token'] if 'access_token' in result else None
        

    except Exception as e:
        print(f"An error occurred while acquiring token: {e}")
    
    if not access_token:
        add_to_statistics('O365', 'token_acquisition', 'fails', 1)
    else:
        add_to_statistics('O365', 'token_acquisition', 'successes', 1)

    return access_token

    


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

    # Ensure we flush the in-memory cache at program exit
    atexit.register(flush_statistics_cache)
    
    # Ensure the periodic flusher is stopped at exit (stop then final flush is already registered)
    atexit.register(stop_periodic_stats_flush)

    def cleanup():
        # Close FTP connection
        ftp.quit()
        print("FTP connection closed.")
        print("Scan complete.")

        # Save updated scanned files list
        write_scanned_files(current_files_on_ftp)

        remove_temp_dir()

        script_end_time = datetime.now()
        total_elapsed = script_end_time - script_start_time
        add_to_statistics('general', 'script_run_time_seconds', 'total', int(total_elapsed.total_seconds()))
        set_statistics('general', 'last_run_time', 'end', int(script_end_time.timestamp()))


    script_start_time = datetime.now()
    set_statistics('general', 'last_run_time', 'start', int(script_start_time.timestamp()))


    print("Loading configuration...")

    add_to_statistics('general', 'script_runs', 'total', 1)

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

    print("Starting periodic statistics flush thread...")
    start_periodic_stats_flush()

    remove_temp_dir()

    ffmpeg_path = shutil.which('ffmpeg')
    if not ffmpeg_path:
        print("Error: ffmpeg not found in PATH. Please install ffmpeg to enable audio conversion.")
        return
    
    print("Checking for new files...")

    # FTP connection
    print(f"Connecting to FTP server {config['FTP']['host']}...")

    if config['FTP']['host'] == '':
        print("No FTP host set! Exiting...")
        return

    try:
        add_to_statistics('ftp', 'ftp_connection', 'attempts', 1)
        ftp = ftplib.FTP(config['FTP']['host'])
        ftp.login(user=config['FTP']['user'], passwd=config['FTP']['password'])
        add_to_statistics('ftp', 'ftp_connection', 'successes', 1)
        print("Connected to FTP server.")
    except ftplib.all_errors as e:
        print(f"Failed to connect to FTP server: {e}")
        add_to_statistics('ftp', 'ftp_connection', 'fails', 1)
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
        cleanup()
        return

    # Find new files since last scan, and collect current files on FTP
    new_files_found, current_files_on_ftp = scan_ftp_folder(ftp, config['FTP']['base_path'], previously_scanned_files_set)

    new_file_count = sum(len(files) for files in new_files_found.values())
    new_mailbox_count = len(new_files_found)

    print(f"Scanned {len(current_files_on_ftp)} total files on FTP server.")
    print(f"Found {new_mailbox_count} mailbox{'' if new_mailbox_count == 1 else 'es'} with {new_file_count} new file{'' if new_file_count == 1 else 's'}.")

    if not new_files_found:
        print("No new files found.")
        cleanup()
        return


    # Use MSAL client credentials flow (application authentication)
    # This requires the app registration to have Microsoft Graph -> Application permissions -> Mail.Send
    client_id = config['O365']['client_id']
    tenant = config['O365']['tenant_id']
    client_secret = config['O365']['client_secret']

    if not client_secret or not client_id or not tenant:
        print("Client secret, client id, and tenant id must be configured!")
        return

    

    print("Signing in to Microsoft Graph...")

    access_token = acquire_token(client_id, client_secret, tenant)

    if not access_token:
        print("Failed to acquire Microsoft authentication token.")
        return

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

    cleanup()

if __name__ == "__main__":
    main()