from secrets import token_bytes
from hashlib import md5
from typing import List
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from dataclass_wizard import fromdict, asdict

server_address = ''
server_port = 443

# Create a WebAPI user in your metatrader app
auth_login = 12345
auth_password = ""
auth_build = 12345
auth_agent = "WebManager"

# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# session = requests.Session()
# adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1)
# session.mount('https://', adapter)

class MetaTraderAPI():

    def __init__(self) -> None:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.session = self.create_session()

    def create_session(self):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1)
        session.mount('https://', adapter)
        return session


    def get_request_raw(self, url: str, params={}):

        complete_url = f'https://{server_address}{url}'
        res = self.session.get(complete_url, params=params,
                          headers={'Connection': 'keep-alive'},
                          verify=False)
        return res


    def authenticate(self):
        auth_url = '/api/auth/start'
        params = {
            'version': auth_build,
            'agent': auth_agent,
            'login': auth_login,
            'type': 'manager'
        }
        auth_first_response_dict = self.get_request_raw(auth_url, params).json()
        auth_digest = self.process_auth(auth_first_response_dict, auth_password)

        random_bytes = token_bytes(16)
        random_bytes_hex_string = random_bytes.hex()

        second_auth_url = '/api/auth/answer'

        second_auth_params = {
            'srv_rand_answer': auth_digest,
            'cli_rand': random_bytes_hex_string
        }
        auth_second_response_dict = self.get_request_raw(
            second_auth_url, second_auth_params).json()


    # THis works
    def process_auth(self, answer, password: str):
        # transcoded = password.encode('utf-8').decode('utf_16_le')
        pass_md5 = md5(password.encode('utf_16_le'))
        pass_md5_digest = pass_md5.digest()

        pass_md5_md5 = md5(pass_md5_digest)
        pass_md5_md5.update('WebAPI'.encode('ascii'))
        pass_md5_md5_digest = pass_md5_md5.digest()

        answer_md5 = md5(pass_md5_md5_digest)
        srv_rand_hex_number = int(answer['srv_rand'], base=16)

        byte_length = (srv_rand_hex_number.bit_length() + 7) // 8
        answer_buf = srv_rand_hex_number.to_bytes(length=byte_length)
        answer_md5.update(answer_buf)

        result = answer_md5.hexdigest()
        return result


    def get_user_ids(self):
        res = self.get_request_raw('/api/user/logins').json()
        return [int(user) for user in res['answer']]


    def get_user_deals_dict(self, uid: int, start_ms: int, end_ms: int):
        user_deals_dict = self.get_request_raw(
            f'/api/deal/get_page',
            params={
                'login': uid,
                'from': start_ms,
                'to': end_ms,
                'offset': 0
            }
        ).json()['answer']

        return user_deals_dict

    def get_user_deals_dict_batch(self, uids: List[int], start_ms: int, end_ms: int):
        user_deals_dict = self.get_request_raw(
            f'/api/deal/get_batch',
            params={
                'login': ','.join([str(uid) for uid in uids]),
                'from': start_ms,
                'to': end_ms,
                'offset': 0
            }
        ).json()['answer']

        return user_deals_dict


    def get_user_orders_dict(self, uid: int, start_ms: int, end_ms: int):
        user_orders_dict = self.get_request_raw(
            f'/api/history/get_page',
            params={
                'login': uid,
                'from': start_ms,
                'to': end_ms,
                'offset': 0
            }
        ).json()['answer']

        return user_orders_dict

    def get_user_orders_dict_batch(self, uids: List[int], start_ms: int, end_ms: int):
        user_orders_dict = self.get_request_raw(
            f'/api/history/get_batch',
            params={
                'login': ','.join([str(uid) for uid in uids]),
                'from': start_ms,
                'to': end_ms,
                'offset': 0
            }
        ).json()['answer']

        return user_orders_dict

    def get_user_positions_dict(self, uid: int, start_ms: int, end_ms: int):
        user_positions_dict = self.get_request_raw(
            f'/api/position/get_page',
            params={
                'login': uid,
                'from': start_ms,
                'to': end_ms,
                'offset': 0
            }
        ).json()['answer']

        return user_positions_dict

    def get_user_positions_dict_batch(self, uids: List[int], start_ms: int, end_ms: int):
            user_positions_dict = self.get_request_raw(
                f'/api/position/get_batch',
                params={
                    'login': ','.join([str(uid) for uid in uids]),
                    'from': start_ms,
                    'to': end_ms,
                    'offset': 0
                }
            ).json()['answer']

            return user_positions_dict

if __name__ == '__main__':
    api = MetaTraderAPI()
    api.authenticate()
