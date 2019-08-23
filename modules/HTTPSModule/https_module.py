"""
HTTPS module check if there is any malicious behavior in the traffic.
Each minute go through all timewindows and find out if there is some new flow.
"""

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import time
from modules.HTTPSModule.tf_model import TFModel
from modules.HTTPSModule.data_manager import DataManager
from typing import List
import json
import traceback


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'https_module'
    description = 'Module created from Deep Https research in July 2019'
    authors = ['Frantisek Strasak']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # self.c1 = __database__.subscribe('tw_modified')
        self.c1 = __database__.subscribe('new_flow')
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = -1
        else:
            #??
            self.timeout = None

        self.path_to_model = 'modules/HTTPSModule/model.085-0.19624-0.94158.hdf5'
        self.TIME_WINDOW = 1 * 60 * 60

        self.model = TFModel(self.path_to_model)
        self.data_manager = DataManager(__database__)

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
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def send_evidence(self, profileid: str, tw_id: str, predicted_y: int, flow: dict) -> None:
        # 1 is malware label
        if predicted_y == 1:
            description = 'HTTPS detection module found some malicious behaviour.'
            threat_level = 49
            confidence = 1
            key = flow['saddr'] + ':' + flow['daddr'] + ':' + str(flow['dport']) + ':' + flow['proto']
            __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=tw_id)

    def run(self):
        try:
            # if __database__.get_input_type() is 'zeek':
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                if message['type'] != 'message':
                    # We do want subscribe message at the beginning.
                    continue
                data: dict = json.loads(message['data'])
                flow_uid: dict = json.loads(data['flow'])

                for uid, flow in flow_uid.items():
                    flow: dict = json.loads(flow)
                    should_run_detection: bool = self.data_manager.add_next_flow_info(data['profileid'], data['twid'], flow)
                    if should_run_detection:
                        if self.model.model is None:
                            # We have to load trained model here, because tensorflow need some time to load.
                            self.model.load_model()
                        self.data_manager.ask_database_for_time_windows()
                        sample_list: list = self.data_manager.prepare_flows_from_time_windows()
                        for sample in sample_list:
                            _y: int = self.model.predict_sample(sample)
                            self.send_evidence(data['profileid'], data['twid'], _y, flow)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print((traceback.format_exc()))
            return True
