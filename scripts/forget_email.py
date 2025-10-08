# Removes a random mailbox 0 voicemail from the found scanned files
import json
import random 

scanned_files_path = 'scanned_files.json'
mailbox_number = '0'

with open(scanned_files_path, 'r') as f:
    scanned_files = json.load(f)
    mailbox_0_indexes = []
    for i in range(len(scanned_files)):
        line = scanned_files[i]
        if '/0/' in line:
            mailbox_0_indexes.append(i)

if len(mailbox_0_indexes) > 0:
    random_index = random.choice(mailbox_0_indexes)
    del scanned_files[random_index]
    with open(scanned_files_path, 'w') as f:
        json.dump(scanned_files, f, indent=4)
    print(f"Removed a voicemail from mailbox {mailbox_number}.")
else:
    print(f"No voicemails found for mailbox {mailbox_number}.")