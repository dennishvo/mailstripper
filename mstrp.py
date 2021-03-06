#
# mail stripper -- eliminates email messages and attachments
# that contain specific email addresses and content. 
# author: Dennis Kornbluh
# Created: 9/17/2016
# Updated: 9/19/2016
#
ReplaceString1 = """
********************************************************
Stripped because: %(stripClue)s
Received: %(received)s
From: %(emailFrom)s
To: %(emailTo)s
Subject: %(subject)s
********************************************************
"""

ReplaceString2 = """
********************************************************
Stripped because: Illegible data 
The original type was: %(content_type)s
The filename was: %(filename)s, 
It had additional parameters of:
%(params)s
********************************************************
"""

import re, sys, email, json
EMAIL_START = re.compile('From \d*@xxx')
BAD_APP_CONTENT_RE = re.compile('application/(msword|msexcel)', re.I)
BAD_IMG_CONTENT_RE = re.compile('image/(jpeg|png|gif)', re.I)
BAD_FILEEXT_RE = re.compile(r'(\.exe|\.zip|\.pif|\.scr|\.ps)$')
BAD_ENC_CONTENT_RE = re.compile('base64', re.I)
logfile = None

#
# read the email archive, separate into individual messages, save in a list
#
def readMessages(file):
    mailbox = []
    msg = ''
    while True:
        line = file.readline()
        if line == '':
            mailbox.append(msg)
            break
        if EMAIL_START.search(line):
            mailbox.append(msg)
            msg = ''
            msg += line
        else:
            msg += line
    return mailbox

#
# search for the presence of specific email addresses, subject line phrases,
# or strings in the body of the message
# return true if the message should be eliminated from the archive
#
def filterEmail(msg):
    matchFound = False

    #
    # search from/to/cc/bcc headers for email addresses
    #
    items = []
    items.append(msg.get("From"))
    items.append(msg.get("To"))
    items.append(msg.get("Cc"))
    items.append(msg.get("Bcc"))
    blockEmail = config['settings']['blockEmail']
    for item in items:
        if blockEmail:
            for email in blockEmail:
                if email and item and (item.find(email['address']) > -1):
                    matchFound = True;
                    break

    #
    # search subject for strings
    #
    if not matchFound:
        subj = msg.get("Subject")
        blockSubjects = config['settings']['blockSubject']
        if blockSubjects:
            for blockSubject in blockSubjects:
                if subj and blockSubject and subj.find(blockSubject['text']) > -1:
                    matchFound = True
                    break

    #
    # search the body of messages for strings
    #
    if not msg.is_multipart() and not matchFound:
        body = msg.get_payload()
        blockBodyList = config['settings']['blockBody']
        if blockBodyList:
            for blockText in blockBodyList:
                if body and blockText:
                    # case-insensitive search
                    if body.lower().find(blockText['text'].lower()) > -1:
                        matchFound = True
                        break

    return matchFound

#
# save the emails that we're stripping
#
def logEmail(msg):
    if msg != None and msg._unixfrom != None:
        logfile.write(msg._unixfrom + '\n')
        logfile.write(str(msg) + '\n')

#
# sanitize the given message, return the clean version
#
def sanitize(msg):
    # If true, spit out a message to indicate what we removed and why.
    leaveClues = config['settings']['stealthMode']['leaveClues'].lower() == "true"
    # Strip out all payloads of a particular type
    ct = msg.get_content_type()
    # We also want to check for bad filename extensions
    # get_filename() returns None if there's no filename
    fn = msg.get_filename()
    # We also want to check for anything base64
    enc = msg['Content-Transfer-Encoding']

    if filterEmail(msg):
        #
        # store all the email we're filtering out in the log file
        #
        if logfile:
            logEmail(msg)

        # leave a message about what was blocked (or not)
        if leaveClues:
            replace = ReplaceString1 % dict(stripClue=config['settings']['stripClue']['text'], 
                                           received=msg['Received'],
                                           emailFrom=msg['From'], 
                                           emailTo=msg['To'],
                                           subject=msg['Subject'])
        else:
            replace = ''

        #
        # get headers from config and delete from msg
        #
        headers = config['settings']['deleteHeader']
        for header in headers:
            del msg[header['header']]

        msg.set_payload(replace)
        msg.set_type('text/plain')

        
    elif BAD_APP_CONTENT_RE.search(ct) or \
        BAD_IMG_CONTENT_RE.search(ct) or \
        (enc and BAD_ENC_CONTENT_RE.search(enc)) or \
        (fn and BAD_FILEEXT_RE.search(fn)):
        # This part of the message is bad, and we're going to eliminate
        # it. If we're leaving clues, retrieve the data we're about to eliminate so we can tell 
        # the reader about it.
        if leaveClues:
            # Fetch the parameters associated with the content-type. Skip 'content-type:',
            # which is the first entry.
            params = msg.get_params()[1:] 
            # The parameters are a list of (key, value) pairs - join the
            # key-value with '=', and the parameter list with ', '
            params = ', '.join([ '='.join(p) for p in params ])
            # Format the replacement text, tell the reader what has been removed.
            replace = ReplaceString2 % dict(content_type=ct, 
                                           filename=fn, 
                                           params=params)
        else:
            replace = ''

        # Install the text body as the new payload.
        msg.set_payload(replace)
        # Now we manually strip away any paramaters to the content-type 
        # header. Again, we skip the first parameter, as it's the 
        # content-type itself, and we'll stomp that next.
        for k, v in msg.get_params()[1:]:
            msg.del_param(k)
        # And set the content-type appropriately.
        msg.set_type('text/plain')
        # Since we've just stomped the content-type, we also kill these
        # headers - they make no sense otherwise.
        del msg['Content-Transfer-Encoding']
        del msg['Content-Disposition']
    else:
        # Now we check for any sub-parts to the message
        if msg.is_multipart():
            # Call the sanitize routine on any subparts
            payload = [ sanitize(x) for x in msg.get_payload() ]
            # We replace the payload with our list of sanitized parts
            msg.set_payload(payload)
    # Return the sanitized message
    return msg

#
# load settings to configure execution
#
def loadConfig(fileName):
    f = open(fileName)
    configstring = f.read()
    return json.loads(configstring)

#
# main logic
#
CONFIG_FILE = "config.json"
global config
try:
    config = loadConfig(CONFIG_FILE)
except:
    print("Unable to load configuration file from '" + CONFIG_FILE + "'.")
    exit(-1)

fl = config['settings']['filterLog']['file']
if len(fl) > 0:
    logfile = open(fl, "w")

f = open(sys.argv[1])
mailbox = readMessages(f)
for msg in mailbox:
    em = email.message_from_string(msg)
    cleanMsg = sanitize(em)
    print(cleanMsg)
