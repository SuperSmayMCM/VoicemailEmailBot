# Madison Children's Museum Voicemail to Email Server

This program is a simple(ish) Python script with an accompanying web server that is designed to scrape a Mitel 5000 PBX running an internal voicemail server, and send emails to Microsoft 365 users when they receive a voicemail. 

The rest of this readme is rough explanation of how it works, in case anyone needs to mess with it in the future.

---

## Setup:
### Prerequisites:
Firstly, if you are not using a Mitel 5000 PBX (or maybe some other very similar models) with an internal voicemail server, this script will not work. It may be possible to adapt for other systems, but that hasn't been done yet.

You will need a Microsoft Entra application with permissions to send emails as an application. Although we aren't using the O365 library, the guide [here](https://o365.github.io/python-o365/latest/getting_started.html#oauth-setup-prerequisite) documents the process. Note that you will be using *application* permissions and not delegated permissions. For more info on how to limit the permission scope to only send as certain addresses, see [security](#security).

You will also need an email address you're allowed to send emails from in your 365 domain. The permissions granted above will let you send emails as *any* address in your domain, so get permission from your boss or make a new address before you start sending emails.

### Running the script:
You will first need to set up the environment. The environment.yaml file contains the Conda environment for the script. Install conda, then simply `conda env create -f environment.yaml`, then `conda activate VoicemailToEmail`.

After your first run, the script will create a configuration file from the template. The configuration file can be edited directly, or edited from the web page. Most of the config fields are pretty straightforward. For a full description, see [configuration](#configuration).

The script can be run standalone as `python voicemail_to_email.py`. This will execute the script once, then exit. 
There is also a web server, with a configuration page and a scheduler that runs the script every few minutes. This web server can be started with `gunicorn --bind 0.0.0.0:5000 wsgi:app`. 
</br><small>If you are developing/debugging, a simple web server with better debug support can also be started with `python server.py`, but this is not recommended for production use.</small> 

Once the server is running, the configuration page can be accessed via http://127.0.0.1:5000. 

Note: The default username and password are `admin` and `password`. Please change these, either on the webpage or in the config file.


## Configuration
### FTP
- host: The address of your FTP server (eg. 10.100.1.2)
- user: Your FTP username
- password: Your FTP password
- base_path: The path to search for voicemail mailbox folders in. For a Mitel 5000 PBX, this should be `/vmail/d/vm/grp`. 

### O365
- client_id: The client ID of your Microsoft Entra application
- client_secret: The client secret of your Microsoft Entra application
- tenant_id: The ID of your Microsoft 365 tenant
- sender_address: The address to send your emails from
- recipient_domain: The default domain to send emails to if a configured address doesn't have a domain

### WEB
- user: The username of the configuration webpage
- password: The password for the configuration webpage

### SCHEDULER
- interval_minutes: How often to run the script
- scheduler_enabled_at_startup: If true, the server will start running the script on an interval automatically at startup. Otherwise, the start button in the web UI must be used.

## Security
This script comes with no security guarantees of any kind. The web page is probably vulnerable to a competent attacker, but should be enough to prevent abuse or tinkering by random users. Probably don't expose it to the open internet.

With that out of the way, you can make it safer by limiting which addresses are valid for the 365 credentials you create to send from. This takes some tinkering in Exchange, but is possible. Basically, [this guide](https://cloudkreise.de/?p=270) has all the most important info. The process is weird and annoying, but it does work.

## Today, on How It's Made™
This part is going to ramble, be incomplete, and generally just be a bit of a mess. It's purpose is to aid any poor future souls that have to tinker with this for whatever reason.

Now, first of all it is important to note that the majority of the base code was written by Gemini. The original code has since been extensively modified, both by hand and by AI tools. The largest remaining AI code is that for the web server. I did not know anything about Flask before this project, and I still know very little. As such, most of the Flask code was generated, along with the HTML. Both have been tinkered with in small ways, but the larger scope remains AI. The program is functional, and seems to be written in a sensible form. The rest of it was initially Gemini, but has been modified quite a bit since then. Functions have been rearranged, tweaked, replaced, etc. 

The primary structure of the whole thing is pretty straightforward:
- `wsgi.py` contains the entry point for gunicorn to start the proper web server (see [this](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-18-04) for more info).
- `server.py` contains the Flask server. This generates the HTML and responds to other http requests for making the whole page work. It also handles the task scheduler (maybe that should be split out into its own thing, but oh well).
- `run_with_timeout.py` is a very simple script who's whole purpose is to run the main scanning script while adding a timeout. This could have been inside of the server code directly, but this was a little easier.
- `voicemail_to_email.py` is part that actually Does the Thing™. It contains a `main` that handles scanning for files, converting those into mp3 audio, transcribing them with Whisper, and sending the final emails. Each of those steps is broken into distinct parts, and often into distinct functions. 

The code itself contains some (though maybe not enough) comments to figure out how it all works. Good luck with any adjustments!