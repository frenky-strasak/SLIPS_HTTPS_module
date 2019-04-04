# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder. 
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import time
import maxminddb

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'GeoIP'
    description = 'Module to find the Country and geolocaiton information of an IP address'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Open the maminddb offline db
        try:
            self.reader = maxminddb.open_database('GeoLite2-Country_20190402/GeoLite2-Country.mmdb')
        except:
            self.print('Error opening the geolite2 db in ./GeoLite2-Country_20190402/GeoLite2-Country.mmdb. Please download it from https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz. Please note it must be the MaxMind DB version.')
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('new_ip')

    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')
        
        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + text)

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=None)
                if message['channel'] == 'new_ip':
                    # Not all the ips!! only the new one coming in the data
                    ip = message['data']
                    # The first message comes with data=1
                    if type(ip) == str:
                        data = __database__.getIPData(ip)
                        # If we alredy have the country for this ip, do not ask the file
                        if not data:
                            geoinfo = self.reader.get(ip)
                            if geoinfo:
                                try:
                                    countrydata = geoinfo['country']
                                    countryname = countrydata['names']['en']
                                    data = {}
                                    data['geocountry'] = countryname
                                except KeyError:
                                    data = {}
                                    data['geocountry'] = 'Unknown'
                            else:
                                data = {}
                                data['geocountry'] = 'Unknown'
                            __database__.setInfoForIPs(ip, data)
                            #self.print('Found country of IP {}: {}'.format(ip, countryname), 1, 0)

        except KeyboardInterrupt:
            if self.reader:
                self.reader.close()
            return True
        except Exception as inst:
            if self.reader:
                self.reader.close()
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True