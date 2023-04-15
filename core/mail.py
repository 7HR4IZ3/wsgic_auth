from ..exceptions import *

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from logging import getLogger
from smtplib import SMTP, SMTP_SSL
from threading import Thread
import re

log = getLogger("wsgic_auth.mail")

class Mailer(object):
	
    def __init__(self, sender, smtp_url, join_timeout=5, use_threads=True):
        """Send emails asyncronously

        :param sender: Sender email address
        :type sender: str.
        :param smtp_server: SMTP server
        :type smtp_server: str.
        """
        self.sender = sender
        self.join_timeout = join_timeout
        self.use_threads = use_threads
        self._threads = []
        self._conf = self._parse_smtp_url(smtp_url)

    def _parse_smtp_url(self, url):
        """Parse SMTP URL"""
        match = re.match(r"""
            (                                   # Optional protocol
                (?P<proto>smtp|starttls|ssl)    # Protocol name
                ://
            )?
            (                                   # Optional user:pass@
                (?P<user>[^:]*)                 # Match every char except ':'
                (: (?P<pass>.*) )? @            # Optional :pass
            )?
            (?P<fqdn>                           # Required FQDN on IP address
                ()|                             # Empty string
                (                               # FQDN
                    [a-zA-Z_\-]                 # First character cannot be a number
                    [a-zA-Z0-9_\-\.]{,254}
                )
                |(                              # IPv4
                    ([0-9]{1,3}\.){3}
                    [0-9]{1,3}
                 )
                |(                              # IPv6
                    \[                          # Square brackets
                        ([0-9a-f]{,4}:){1,8}
                        [0-9a-f]{,4}
                    \]
                )
            )
            (                                   # Optional :port
                :
                (?P<port>[0-9]{,5})             # Up to 5-digits port
            )?
            [/]?
            $
        """, url, re.VERBOSE)

        if not match:
            raise RuntimeError("SMTP URL seems incorrect")

        d = match.groupdict()
        if d['proto'] is None:
            d['proto'] = 'smtp'

        if d['port'] is None:
            d['port'] = 25
        else:
            d['port'] = int(d['port'])

        if not 0 < d['port'] < 65536:
            raise RuntimeError("Incorrect SMTP port")

        return d

    def send_email(self, email_addr, subject, email_text):
        """Send an email

        :param email_addr: email address
        :type email_addr: str.
        :param subject: subject
        :type subject: str.
        :param email_text: email text
        :type email_text: str.
        :raises: AAAException if smtp_server and/or sender are not set
        """
        if not (self._conf['fqdn'] and self.sender):
            raise AAAException("SMTP server or sender not set")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.sender
        msg['To'] = email_addr
        if isinstance(email_text, bytes):
            email_text = email_text.encode('utf-8')

        part = MIMEText(email_text, 'html')
        msg.attach(part)
        msg = msg.as_string()

        log.debug("Sending email using %s" % self._conf['fqdn'])

        if self.use_threads:
            thread = Thread(target=self._send, args=(email_addr, msg))
            thread.start()
            self._threads.append(thread)

        else:
            self._send(email_addr, msg)

    def _send(self, email_addr, msg):
        """Deliver an email using SMTP

        :param email_addr: recipient
        :type email_addr: str.
        :param msg: email text
        :type msg: str.
        """
        proto = self._conf['proto']
        assert proto in ('smtp', 'starttls', 'ssl'), \
            "Incorrect protocol: %s" % proto

        try:
            if proto == 'ssl':
                log.debug("Setting up SSL")
                session = SMTP_SSL(self._conf['fqdn'], self._conf['port'])
            else:
                session = SMTP(self._conf['fqdn'], self._conf['port'])

            if proto == 'starttls':
                log.debug('Sending EHLO and STARTTLS')
                session.ehlo()
                session.starttls()
                session.ehlo()

            if self._conf['user'] is not None:
                log.debug('Performing login')
                session.login(self._conf['user'], self._conf['pass'])

            log.debug('Sending')
            session.sendmail(self.sender, email_addr, msg)
            session.quit()
            log.info('Email sent')

        except Exception as e:  # pragma: no cover
            log.error("Error sending email: %s" % e, exc_info=True)

    def join(self):
        """Flush email queue by waiting the completion of the existing threads

        :returns: None
        """
        return [t.join(self.join_timeout) for t in self._threads]

    def __del__(self):
        """Class destructor: wait for threads to terminate within a timeout"""
        try:
            self.join()
        except TypeError:
            pass
