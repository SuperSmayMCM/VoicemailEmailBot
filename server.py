from flask import Flask, render_template, request, redirect, url_for, flash, session
import configparser
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

CONFIG_PATH = 'config.ini'
MAILBOX_EMAILS_PATH = 'mailbox_emails.json'

def load_config():
    """Loads configuration from the config.ini file."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    return config

def save_config(config):
    """Saves configuration to the config.ini file."""
    with open(CONFIG_PATH, 'w') as configfile:
        config.write(configfile)

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
        web_user = config.get('WEB', 'user', fallback='admin')
        web_pass = config.get('WEB', 'password', fallback='password')

        if request.form.get('username') == web_user and request.form.get('password') == web_pass:
            session['logged_in'] = True
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
    return render_template('index.html', config=config, mailbox_emails=mailbox_emails)

@app.route('/save', methods=['POST'])
def save_settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    # Save config.ini settings
    config = load_config()
    
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
            # Don't save other settings if passwords don't match
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
    
    # Handle new mailbox entry
    new_mailbox_id = request.form.get('new_mailbox_id')
    new_mailbox_emails = request.form.get('new_mailbox_emails')
    if new_mailbox_id and new_mailbox_emails:
        emails = [email.strip() for email in new_mailbox_emails.split(',')]
        mailbox_emails[new_mailbox_id] = emails

    save_mailbox_emails(mailbox_emails)

    flash('Settings saved successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)

