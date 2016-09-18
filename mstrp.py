#
# mail stripper -- eliminates attachments, eliminates email content
# that contains specific email addresses
# author: Dennis Kornbluh
# Date: 9/17/2016
#
ReplaceString = """
************************************************************
This message contained illegible data that was stripped out. 
The original type was: %(content_type)s
The filename was: %(filename)s, 
It had additional parameters of:
%(params)s
************************************************************
"""

import re, sys, email
import pdb
EMAIL_START = re.compile('From \d*@xxx')
BAD_APP_CONTENT_RE = re.compile('application/(msword|msexcel)', re.I)
BAD_IMG_CONTENT_RE = re.compile('image/(jpeg|png|gif)', re.I)
BAD_FILEEXT_RE = re.compile(r'(\.exe|\.zip|\.pif|\.scr|\.ps)$')
BAD_ENC_CONTENT_RE = re.compile('base64', re.I)
PRIV_EMAIL1 = "@suiter.com"
PRIV_EMAIL2 = "heenlaw@aol.com"

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

def attorney_client_privilege(msg):
    isPrivileged = False
    items = []
    items.append(msg.get("From"))
    items.append(msg.get("To"))
    items.append(msg.get("Cc"))
    items.append(msg.get("Bcc"))
    for item in items:
        if item and ((item.find(PRIV_EMAIL1) > -1) or (item.find(PRIV_EMAIL2) > -1)):
            isPrivileged = True;
            break

    return isPrivileged

def sanitize(msg):
    #pdb.set_trace()
    # Strip out all payloads of a particular type
    ct = msg.get_content_type()
    # We also want to check for bad filename extensions
    # get_filename() returns None if there's no filename
    fn = msg.get_filename()
    # We also want to check for anything base64
    enc = msg['Content-Transfer-Encoding']
    #pdb.set_trace()
    if attorney_client_privilege(msg):
        del msg['Subject']
        del msg['From']
        del msg['To']
        del msg['Cc']
        del msg['Bcc']
        del msg['Delivered-To']
        del msg['Date']
        del msg['Message-ID']
        del msg['Received']
        del msg['X-Originating-IP']
        del msg['Return-Path']
        del msg['Authentication-Results']
        del msg['Received-SPF']
        del msg['DKIM-Signature']
        del msg['authentication-results']
        del msg['In-Reply-To']
        del msg['Thread-Index']
        del msg['Thread-Topic']
        del msg['X-MS-Has-Attach']
        del msg['X-OriginatorOrg']
        del msg['X-GM-THRID']
        del msg['X-Received']
        del msg['x-microsoft-antispam-prvs']
        del msg['x-forefront-antispam-report']
        del msg['X-MS-TNEF-Correlator']
        del msg['References']
        del msg['X-Gmail-Labels']
        del msg['X-MS-Exchange-CrossTenant-originalarrivaltime']
        del msg['x-microsoft-exchange-diagnostics']
        del msg['X-MS-Exchange-CrossTenant-id']
        del msg['x-ms-office365-filtering-correlation-id']
        del msg['x-microsoft-antispam']
        del msg['x-exchange-antispam-report-cfa-test']
        del msg['Content-Transfer-Encoding']
        del msg['Content-Disposition']
        
        replace = "---+++\n"
        msg.set_payload(replace)
        msg.set_type('text/plain')
        
    elif BAD_APP_CONTENT_RE.search(ct) or \
        BAD_IMG_CONTENT_RE.search(ct) or \
        (enc and BAD_ENC_CONTENT_RE.search(enc)) or \
        (fn and BAD_FILEEXT_RE.search(fn)):
        #(emfrm and CONF_EMAIL.search(emfrm)) or \
        # Ok. This part of the message is bad, and we're going to stomp
        # on it. First, though, we pull out the information we're about to
        # destroy so we can tell the user about it.

        # This returns the parameters to the content-type. The first entry
        # is the content-type itself, which we already have.
        params = msg.get_params()[1:] 
        # The parameters are a list of (key, value) pairs - join the
        # key-value with '=', and the parameter list with ', '
        params = ', '.join([ '='.join(p) for p in params ])
        # Format up the replacement text, telling the user we ate their
        # email attachment.
        #pdb.set_trace()
        replace = ReplaceString % dict(content_type=ct, 
                                       filename=fn, 
                                       params=params)
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
            # Call the sanitise routine on any subparts
            payload = [ sanitize(x) for x in msg.get_payload() ]
            # We replace the payload with our list of sanitised parts
            msg.set_payload(payload)
    # Return the sanitised message
    return msg

messages_remain = True
f = open(sys.argv[1])
mailbox = readMessages(f)
#pdb.set_trace()
for msg in mailbox:
    em = email.message_from_string(msg)
    cleanMsg = sanitize(em)
    print(cleanMsg)
