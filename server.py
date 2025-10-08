import shutil
from flask import Flask, render_template, request, redirect, url_for, flash, session
import configparser
import json
import os
import threading
import time
import subprocess
import sys
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

CONFIG_PATH = 'config.ini'
MAILBOX_EMAILS_PATH = 'mailbox_emails.json'
MAIN_SCRIPT = 'voicemail_to_email.py'

# --- Globals for Scheduler ---
last_run_log = "Scheduler has not run yet."
scheduler_thread_instance = None
stop_scheduler_flag = threading.Event()
log_lock = threading.Lock() # To safely update the log from the thread
script_execution_lock = threading.Lock() # To prevent concurrent script runs

def run_main_script():
    """Runs the main.py script and captures its output in real-time."""
    global last_run_log
    if not script_execution_lock.acquire(blocking=False):
        print("[Scheduler] Attempted to run script while it was already running.")
        # Log this attempt to the user-visible log
        with log_lock:
            # Use a temporary variable to build the string to avoid repeated lock acquisitions
            current_log = last_run_log
            current_log += f"\n--- Manual run request denied: Script is already running. ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---\n"
            last_run_log = current_log
        return

    try:
        print(f"[Scheduler] Running {MAIN_SCRIPT} script with timeout...")
        
        # Reset log for the new run
        log_output = f"--- Log from {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n"
        with log_lock:
            last_run_log = log_output
        
        try:
            python_executable = sys.executable
            process = subprocess.Popen(
                [python_executable, 'run_with_timeout.py', '900', python_executable, MAIN_SCRIPT], # 15 minutes timeout
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1, # Line-buffered
                universal_newlines=True
            )

            prepend_line = f"[{MAIN_SCRIPT}]"

            # Stream stdout
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    
                    with log_lock:
                        last_run_log += line
                    print(f"{prepend_line} {line}", end='') # Also print to server console with a prefix
            
            process.wait() # Wait for the process to complete

            # Capture any remaining stderr
            stderr_output = process.stderr.read() if process.stderr else ""
            if stderr_output:
                with log_lock:
                    last_run_log += "\n--- STDERR ---\n"
                    last_run_log += stderr_output
                for line in stderr_output.split('\n'):
                    print(f"{prepend_line} {line}")
            
            with log_lock:
                last_run_log += f"\n--- Process finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---"
            print(f"[Scheduler] {MAIN_SCRIPT} finished.")

        except Exception as e:
            error_message = f"--- Scheduler failed to execute {MAIN_SCRIPT} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n{e}"
            with log_lock:
                last_run_log = error_message
            print(f"[Scheduler] Failed to run {MAIN_SCRIPT}: {e}")
    finally:
        script_execution_lock.release()

def scheduler_loop():
    """The background thread that runs the script periodically."""
    print("[Server] Scheduler thread started.")
    while not stop_scheduler_flag.is_set():
        config = load_config()
        interval_minutes = config.getint('SCHEDULER', 'interval_minutes', fallback=15)
        
        run_main_script()
        
        # Wait for the interval, but check for stop signal every second
        for _ in range(interval_minutes * 60):
            if stop_scheduler_flag.is_set():
                break
            time.sleep(1)
    print("[Server] Scheduler thread stopped.")

def start_scheduler():
    global scheduler_thread_instance
    if scheduler_thread_instance is None or not scheduler_thread_instance.is_alive():
        stop_scheduler_flag.clear()
        scheduler_thread_instance = threading.Thread(target=scheduler_loop, daemon=True)
        scheduler_thread_instance.start()
        print("[Server] Scheduler started.")

def stop_scheduler():
    global scheduler_thread_instance
    if scheduler_thread_instance and scheduler_thread_instance.is_alive():
        stop_scheduler_flag.set()
        scheduler_thread_instance.join()
        print("[Server] Scheduler stopped.")
        scheduler_thread_instance = None

# --- Flask Routes ---
def load_config():
    """Loads configuration from the config.ini file."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    return config

def save_config(config):
    """Saves configuration to the config.ini file."""
    with open(CONFIG_PATH, 'w') as config_file:
        config.write(config_file)

def load_mailbox_emails():
    """Loads mailbox to email mappings from mailbox_emails.json."""
    if os.path.exists(MAILBOX_EMAILS_PATH):
        with open(MAILBOX_EMAILS_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_mailbox_emails(data):
    """Saves mailbox to email mappings to mailbox_emails.json."""
    with open(MAILBOX_EMAILS_PATH, 'w') as f:
        json.dump(data, f, indent=4)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        config = load_config()
        if 'WEB' not in config:
            config['WEB'] = {}
            save_config(config)

        default_user = 'admin'
        default_password = 'password'

        web_user = config.get('WEB', 'user', fallback=default_user)
        web_pass = config.get('WEB', 'password', fallback=default_password)

        if not web_user:
            web_user = default_user
        if not web_pass:
            web_pass = default_password

        if request.form.get('username') == web_user and request.form.get('password') == web_pass:
            session['logged_in'] = True
            if web_user == default_user and web_pass == default_password:
                flash("Please update the password to something more secure!", 'danger')
            else:
                flash('You were successfully logged in', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    config = load_config()
    mailbox_emails = load_mailbox_emails()
    scheduler_running = scheduler_thread_instance is not None and scheduler_thread_instance.is_alive()
    return render_template('index.html', config=config, mailbox_emails=mailbox_emails, scheduler_running=scheduler_running)

@app.route('/logs')
def logs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    # The initial content is now just a placeholder, JS will fetch the real log.
    return render_template('logs.html', log_content="Loading logs...")

@app.route('/get_log_data')
def get_log_data():
    if not session.get('logged_in'):
        return "Not authorized", 401
    with log_lock:
        return last_run_log

@app.route('/save', methods=['POST'])
def save_settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    config = load_config()
    
    # Scheduler Settings
    if 'SCHEDULER' not in config:
        config['SCHEDULER'] = {}
    config['SCHEDULER']['interval_minutes'] = request.form.get('scheduler_interval', '15')
    config['SCHEDULER']['scheduler_enabled_at_startup'] = 'True' if request.form.get('scheduler_enabled_at_startup') == 'on' else 'False'
    
    # Web Auth Settings
    if 'WEB' not in config:
        config['WEB'] = {}
    config['WEB']['user'] = request.form.get('web_user', 'admin')
    
    new_password = request.form.get('web_password')
    confirm_password = request.form.get('web_password_confirm')

    if new_password:
        if new_password == confirm_password:
            config['WEB']['password'] = new_password
        else:
            flash('New web passwords do not match.', 'danger')
            return redirect(url_for('index'))

    # FTP Settings
    if 'FTP' not in config:
        config['FTP'] = {}
    config['FTP']['host'] = request.form.get('ftp_host', '')
    config['FTP']['user'] = request.form.get('ftp_user', '')
    if request.form.get('ftp_password'):
        config['FTP']['password'] = request.form.get('ftp_password', '')
    config['FTP']['base_path'] = request.form.get('ftp_base_path', '')

    # O365 Settings
    if 'O365' not in config:
        config['O365'] = {}
    config['O365']['sender_address'] = request.form.get('o365_sender_address', '')
    config['O365']['recipient_domain'] = request.form.get('o365_recipient_domain', '')
    config['O365']['client_id'] = request.form.get('o365_client_id', '')
    config['O365']['tenant_id'] = request.form.get('o365_tenant_id', '')
    if request.form.get('o365_client_secret'):
        config['O365']['client_secret'] = request.form.get('o365_client_secret', '')

    save_config(config)

    # Save mailbox_emails.json
    mailbox_emails = {}
    i = 0
    while f'original_mailbox_id_{i}' in request.form:
        new_id = request.form.get(f'mailbox_id_{i}')
        emails_str = request.form.get(f'emails_{i}')
        
        if new_id and emails_str:
            emails = [email.strip() for email in emails_str.split(',')]
            mailbox_emails[new_id] = emails
        i += 1
    
    new_mailbox_id = request.form.get('new_mailbox_id')
    new_mailbox_emails = request.form.get('new_mailbox_emails')
    if new_mailbox_id and new_mailbox_emails:
        emails = [email.strip() for email in new_mailbox_emails.split(',')]
        mailbox_emails[new_mailbox_id] = emails

    save_mailbox_emails(mailbox_emails)

    flash('Settings saved successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/run_now', methods=['POST'])
def run_now():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Run in a separate thread to avoid blocking the UI
    threading.Thread(target=run_main_script).start()
    flash('The script is running in the background. Check the logs page for output shortly.', 'info')
    return redirect(url_for('index'))

@app.route('/toggle_scheduler', methods=['POST'])
def toggle_scheduler():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    action = request.form.get('action')
    if action == 'start':
        start_scheduler()
        flash('Scheduler started.', 'success')
    elif action == 'stop':
        stop_scheduler()
        flash('Scheduler stopped.', 'warning')
    return redirect(url_for('index'))

print("[Server] Loading configuration...")

if not os.path.exists('config.ini'):
    print("[Server] Error: config.ini file not found. The contents of config_template.ini have been copied to config.ini.")
    print("[Server] Please edit config.ini to add your configuration settings, then re-run the script.")

    template_path = 'config_template.ini'
    if os.path.exists(template_path):
        shutil.copyfile(template_path, 'config.ini')
    else:
        print("[Server] Error: config_template.ini file not found. Please ensure it exists in the script directory.")
    
    exit(1)

config = load_config()
scheduler_enabled_at_startup = False
try:
    config.getboolean('SCHEDULER', 'scheduler_enabled_at_startup', fallback=False)
except ValueError:
    pass

if scheduler_enabled_at_startup:
    start_scheduler()  # Start the scheduler when the app starts

if __name__ == '__main__':  
    app.run(port=5001, use_reloader=False, debug=True) # use_reloader=False is important for scheduler

