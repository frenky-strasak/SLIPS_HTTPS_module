from typing import Dict, List
import slips.core.database as DB
from sortedcontainers import SortedDict
import json
import numpy as np
from datetime import datetime


def check_validity_of_value(flow: dict, key: str) -> float:
    try:
        value = flow[key]
    except KeyError:
        return 0.0
    try:
        value = float(value)
    except ValueError:
        value = 0.0
    return value


def compute_state_of_conn(conn_state: str) -> float:
    if 'S0' in conn_state:
        return 1
    elif 'S1' in conn_state:
        return 2
    elif 'SF' in conn_state:
        return 3
    elif 'REJ' in conn_state:
        return 4
    elif 'S2' in conn_state:
        return 5
    elif 'S3' in conn_state:
        return 6
    elif 'RSTO' in conn_state:
        return 7
    elif 'RSTR' in conn_state:
        return 8
    elif 'RSTOS0' in conn_state:
        return 9
    elif 'RSTRH' in conn_state:
        return 10
    elif 'SH' in conn_state:
        return 11
    elif 'SHR' in conn_state:
        return 12
    elif 'OTH' in conn_state:
        return 13
    else:
        return 0


class DataManager:

    def __init__(self, database: DB):
        self.UPDATE_THRESHOLD = 10
        self.database: DB = database
        self.tuple_time_window_dict = {}
        self.time_windows_to_check_list: List[tuple] = []
        self.sample_dict: Dict[str, SortedDict[float, list]] = {}
        self.features_names = ['duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'orig_pkts', 'resp_pkts',
                               'second_time_level_diff_list']
        self.max_values = [1467357.072299, 4294967295.0, 12532399119.0, 13.0, 2666605.0, 8426288.0, 1.0]
        # for computing second level time diff.
        self.last_last_timestamp = None
        self.last_timestamp = None
        self.first_timestamp = datetime.timestamp(datetime.now())

    def add_next_flow_info(self, profileid: str, tw_id: str, flow: dict) -> bool:
        """
        This function cares about changes for each 4-tuple for each TW for each profile ID.
        The number of flows are stored here and if we have next new 10 flows for some 4-tuple, we can chack this
        4-tuple by model to detect malicious behaviour.
        """
        if self.tuple_time_window_dict.get(profileid, None) is None:
            self.tuple_time_window_dict[profileid] = {}
        if self.tuple_time_window_dict[profileid].get(tw_id, None) is None:
            self.tuple_time_window_dict[profileid][tw_id] = {}
        # 4-tuple key
        tuple_name = flow['saddr'] + '_' + flow['daddr'] + '_' + str(flow['dport']) + '_' + flow['proto']
        if self.tuple_time_window_dict[profileid][tw_id].get(tuple_name, None) is None:
            self.tuple_time_window_dict[profileid][tw_id][tuple_name] = 0
        # Add +1, because of new flow.
        self.tuple_time_window_dict[profileid][tw_id][tuple_name] += 1
        if self.tuple_time_window_dict[profileid][tw_id][tuple_name] % self.UPDATE_THRESHOLD == 0:
            self.time_windows_to_check_list.append((profileid, tw_id, tuple_name))
            return True
        return False

    def ask_database_for_time_windows(self) -> None:
        """
        Take all flows from given profileID and TW and sort them by timestamp.
        """
        self.sample_dict: Dict[str, SortedDict[float, list]] = {}
        while self.time_windows_to_check_list:
            profile_id, tw_id, tuple_name = self.time_windows_to_check_list.pop()
            data: dict = self.database.get_all_flows_in_profileid_twid(profile_id, tw_id)
            flow_timewindow_dict: SortedDict[float, list] = SortedDict()
            for uid, flow in data.items():
                flow = json.loads(flow)
                _tuple_name = flow['saddr'] + '_' + flow['daddr'] + '_' + str(flow['dport']) + '_' + flow['proto']
                if _tuple_name == tuple_name:
                    timestamp = float(flow['ts'])
                    if flow_timewindow_dict.get(timestamp, None) is None:
                        flow_timewindow_dict[timestamp] = []
                    flow_timewindow_dict[timestamp].append(flow)
            self.sample_dict[profile_id + tw_id + tuple_name] = flow_timewindow_dict

    def __compute_second_time_level_diff(self, ts: float) -> float:
        if self.last_last_timestamp is None or self.last_timestamp is None:
            return 0
        d1 = self.last_timestamp - self.last_last_timestamp
        d2 = ts - self.last_last_timestamp
        try:
            return d1 / float(d2)
        except ZeroDivisionError:
            return 0

    def __normalize(self, feature_vector: list) -> list:
        normalize_values = []
        for value, max_number in zip(feature_vector, self.max_values):
            result = value / float(max_number)
            normalize_values.append(result)
        return normalize_values

    def prepare_flows_from_time_windows(self) -> list:
        sample_list = []
        for profile_id_tw_id_tuple_name, sorted_dict in self.sample_dict.items():
            sample = []
            for ts, flow_list in sorted_dict.items():
                for flow in flow_list:
                    ts = float(ts)
                    duration = check_validity_of_value(flow, 'dur')
                    orig_bytes = check_validity_of_value(flow, 'sbytes')
                    resp_bytes = check_validity_of_value(flow, 'sbytes')
                    conn_state = compute_state_of_conn(flow['origstate'])
                    orig_packets = check_validity_of_value(flow, 'spkts')
                    resp_packets = check_validity_of_value(flow, 'dpkts')
                    second_time_level_diff_list = self.__compute_second_time_level_diff(ts)

                    feature_vector = [duration, orig_bytes, resp_bytes, conn_state, orig_packets, resp_packets, second_time_level_diff_list]
                    normalized_feature_vector = self.__normalize(feature_vector)
                    sample.append(normalized_feature_vector)

            if len(sample) < 250:
                for i in range(250 - len(sample)):
                    vector = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
                    sample.append(vector)
            sample_list.append(sample)
        # Delete all checked 4-tuples.
        self.sample_dict = None
        return [sample_list]


