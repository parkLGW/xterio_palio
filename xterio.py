import asyncio
import random
import time
import requests
import json
from web3 import Web3
from web3.middleware import geth_poa_middleware
from loguru import logger
from eth_account.messages import encode_defunct
from fake_useragent import UserAgent


class WenXin:
    def __init__(self, API_KEY, SECRET_KEY):
        self.API_KEY = API_KEY
        self.SECRET_KEY = SECRET_KEY
        self.model_url = {
            "ErnieBot-turbo": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/eb-instant?",
            "ErnieBot": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions?",
            "BLOOMZ-7B": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/bloomz_7b1?",
            "Yi-34B": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/yi_34b_chat",
        }
        self.headers = {'Content-Type': 'application/json'}

    def get_access_token(self):
        url = "https://aip.baidubce.com/oauth/2.0/token"
        params = {"grant_type": "client_credentials", "client_id": self.API_KEY, "client_secret": self.SECRET_KEY}
        return str(requests.post(url, params=params).json().get("access_token"))

    def get_response(self, content, model_type='ErnieBot-turbo'):
        url = self.model_url.get(model_type)
        if url is None:
            raise Exception("未知的模型类型")
        access_token = self.get_access_token()
        # url = url + "access_token=" + access_token
        payload = json.dumps({
            "messages": [
                {
                    "role": "user",
                    "content": content,
                },
            ]
        })

        response = requests.request("POST", url, headers=self.headers, data=payload,
                                    params={"access_token": access_token})
        result = json.loads(response.text)['result']

        sentences = result.split('.')
        max_len = 0
        final_sentence = ''
        for sent in sentences:
            max_len += len(sent) + 1
            if max_len >= 300:
                break
            final_sentence += sent + '.'

        return final_sentence


class Xterio:
    def __init__(self, address, private_key, user_agent, proxies_conf=None):
        self.headers = {
            'authority': 'api.xter.io',
            'accept': '*/*',
            'accept-language': 'zh-HK,zh-TW;q=0.9,zh;q=0.8',
            'authorization': '',
            'content-type': 'application/json',
            'origin': 'https://xter.io',
            'referer': 'https://xter.io/',
            'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': user_agent,
        }
        self.address = address
        self.private_key = private_key
        self.proxies = proxies_conf
        self.req_proxies = proxies_conf['proxies'] if self.proxies is not None else None
        self.xter_rpc = "https://xterio.alt.technology"
        self.bsc_rpc = "https://bsc-pokt.nodies.app"

    def check_balance(self):
        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        balance = w3.eth.get_balance(self.address)

        return balance

    def deposit2xter(self, amount):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['deposit']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.bsc_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        amount = w3.to_wei(amount, 'ether')

        gas = contract.functions.depositETH(200000, '0x').estimate_gas(
            {
                'from': self.address,
                'value': amount,
                'nonce': w3.eth.get_transaction_count(account=self.address)
            }
        )
        transaction = contract.functions.depositETH(200000, '0x').build_transaction({
            'from': self.address,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account=self.address),
            'gas': gas,
            'value': amount,
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"存款hash:{tx_hash.hex()}")

        logger.info(f"deposit pending……")

    def get_challenge(self):
        response = requests.get(
            f'https://api.xter.io/account/v1/login/wallet/{self.address.upper()}',
            headers=self.headers,
            proxies=self.req_proxies
        )

        res = response.json()
        assert res['err_code'] == 0, "获取challenge 错误❗"

        return res['data']['message']

    def get_signature(self):
        message = self.get_challenge()

        encoded_msg = encode_defunct(text=message)
        signed_msg = Web3().eth.account.sign_message(encoded_msg, private_key=self.private_key)
        signature = signed_msg.signature.hex()

        return signature

    def sign_in(self):
        signature = self.get_signature()
        json_data = {
            'address': self.address.upper(),
            'type': 'eth',
            'sign': signature,
            'provider': 'METAMASK',
            'invite_code': '',
        }

        response = requests.post('https://api.xter.io/account/v1/login/wallet', headers=self.headers, json=json_data,
                                 proxies=self.req_proxies)
        res = response.json()

        assert res['err_code'] == 0, "登录出错！"

        id_token = res['data']['id_token']
        self.headers['authorization'] = id_token
        logger.info("登录成功✔")

    def claim_egg(self):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['palio_incubator']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        gas = contract.functions.claimEgg().estimate_gas(
            {
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(account=self.address)
            }
        )
        transaction = contract.functions.claimEgg().build_transaction({
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account=self.address),
            'gas': gas
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"claim egg 成功✔ hash:{tx_hash.hex()}")

    def apply_invite(self, invite_code):
        json_data = {
            'code': invite_code,
        }

        response = requests.post(
            f'https://api.xter.io/palio/v1/user/{self.address}/invite/apply',
            headers=self.headers,
            json=json_data,
            proxies=self.req_proxies
        )

        res = response.json()
        assert res['err_code'] == 0, "填写邀请码出错！"

        logger.info("填写邀请码成功✔")

    def trigger(self, tx_hash):
        json_data = {
            'eventType': 'PalioIncubator::*',
            'network': 'XTERIO',
            'txHash': tx_hash,
        }

        response = requests.post('https://api.xter.io/baas/v1/event/trigger', headers=self.headers, json=json_data,
                                 proxies=self.req_proxies)

        res = response.json()
        assert res['err_code'] == 0, "claim 失败❗"

    def claim_utility(self, type_num):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['palio_incubator']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        gas = contract.functions.claimUtility(type_num).estimate_gas(
            {
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(account=self.address)
            }
        )
        transaction = contract.functions.claimUtility(type_num).build_transaction({
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account=self.address),
            'gas': gas
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        # logs = receipt['logs']

        self.trigger(tx_hash.hex())
        logger.info(f"type {type_num} claim 成功✔ hash:{tx_hash.hex()}")

    def prop(self, type_num):
        json_data = {
            'prop_id': type_num,
        }

        response = requests.post(
            f'https://api.xter.io/palio/v1/user/{self.address}/prop',
            headers=self.headers,
            json=json_data,
            proxies=self.req_proxies
        )

        res = response.json()
        assert res['err_code'] == 0, f'prop type{type_num} 失败❗'

        logger.info(f"喂蛋成功（{type_num}/3）✔")

    def get_task_list(self):
        response = requests.get(f'https://api.xter.io/palio/v1/user/{self.address}/task',
                                headers=self.headers, proxies=self.req_proxies)

        res = response.json()

        assert res['err_code'] == 0, "获取任务id失败❗"

        task_list = res['data']['list']

        return task_list

    def report(self, task_id):
        json_data = {
            'task_id': task_id,
        }

        response = requests.post(
            f'https://api.xter.io/palio/v1/user/{self.address}/task/report',
            headers=self.headers,
            json=json_data,
            proxies=self.req_proxies
        )

        res = response.json()
        assert res['err_code'] == 0, f"三连 {task_id} 报错！"
        logger.info(f"三连 {task_id} 成功✔")

    def task(self, task_id):
        json_data = {
            'task_id': task_id,
        }

        response = requests.post(
            f'https://api.xter.io/palio/v1/user/{self.address}/task',
            headers=self.headers,
            json=json_data,
            proxies=self.req_proxies
        )

        res = response.json()
        assert res['err_code'] == 0, f'get point 报错！ task id：{task_id}'

        logger.info(f"task[{task_id}] get point成功✔")

    def get_ticket(self):
        response = requests.get(
            f'https://api.xter.io/palio/v1/user/{self.address}/ticket',
            headers=self.headers,
            proxies=self.req_proxies
        )

        res = response.json()

        assert res['err_code'] == 0, f'获取票数 报错！'
        logger.info(f"获取票数成功✔  当前总票数：{res['data']['total_ticket']}")

        return res['data']['total_ticket'] - self.get_voted_amt()

    def get_voted_amt(self):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['palio_voter']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        res = contract.functions.userVotedAmt(w3.to_checksum_address(self.address)).call()

        return res

    def vote_onchain(self, vote_param):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['palio_voter']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        gas = contract.functions.vote(vote_param['index'], vote_param['num'], vote_param['total_num'],
                                      vote_param['expire_time'], vote_param['sign']).estimate_gas(
            {
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(account=self.address)
            }
        )
        transaction = contract.functions.vote(vote_param['index'], vote_param['num'], vote_param['total_num'],
                                              vote_param['expire_time'], vote_param['sign']).build_transaction({
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account=self.address),
            'gas': gas
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        logger.info(f"投票成功✔ hash:{tx_hash.hex()}")

    def vote(self, ticket_num, index=0):
        '''
        :param ticket_num: 票数
        :param index: 投第几个，默认第一个
        :return:
        '''

        json_data = {
            'index': index,
            'num': ticket_num,
        }

        response = requests.post(
            f'https://api.xter.io/palio/v1/user/{self.address}/vote',
            headers=self.headers,
            json=json_data,
            proxies=self.req_proxies
        )

        res = response.json()

        assert res['err_code'] == 0, '获取投票参数报错！'
        logger.info("获取投票参数成功✔")

        self.vote_onchain(res['data'])

    def boost(self):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['palio_incubator']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        gas = contract.functions.boost().estimate_gas(
            {
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(account=self.address),
                'value': w3.to_wei(0.01, 'ether'),
            }
        )
        transaction = contract.functions.boost().build_transaction({
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account=self.address),
            'gas': gas,
            'value': w3.to_wei(0.01, 'ether'),
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        self.trigger(tx_hash.hex())
        logger.info(f"boost 成功✔ hash:{tx_hash.hex()}")

    def send_story(self):
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-HK,zh-TW;q=0.9,zh;q=0.8',
            'Authorization': self.headers['authorization'],
            'Connection': 'keep-alive',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Origin': 'https://xter.io',
            'Referer': 'https://xter.io/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'User-Agent': self.headers['user-agent'],
            'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        params = {
            'address': self.address,
        }

        wx = WenXin(API_KEY='', SECRET_KEY='')
        content = "I've got a teeny-tiny question, can you tell me, what is ”SADNESS“? Is sadness like when the sun goes away in the sky and the whole world gets really quiet?\nYou need to control the number of response characters to not exceed 300."
        sentence = wx.get_response(content, "Yi-34B")

        # sentence = "你复制的内容"

        j_data = {
            "answer": sentence
        }

        response = requests.post(
            'https://3656kxpioifv7aumlcwe6zcqaa0eeiab.lambda-url.eu-central-1.on.aws/',
            params=params,
            headers=headers,
            data=json.dumps(j_data),
            proxies=self.req_proxies
        )

        score = 0
        for line in response.iter_lines():
            if line:
                data = json.loads(line)
                if data.get('score'):
                    score = data['score']

        logger.info(f"最终得分：{score}")

    def claim_chat_nft(self):
        f = open('abi.json', 'r', encoding='utf-8')
        contract_palio = json.load(f)['palio_incubator']
        abi = contract_palio['abi']
        contract_address = Web3.to_checksum_address(contract_palio['contract'])

        w3 = Web3(Web3.HTTPProvider(self.xter_rpc, request_kwargs=self.proxies))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        contract = w3.eth.contract(address=contract_address, abi=abi)

        gas = contract.functions.claimChatNFT().estimate_gas(
            {
                'from': self.address,
                'nonce': w3.eth.get_transaction_count(account=self.address)
            }
        )
        transaction = contract.functions.claimChatNFT().build_transaction({
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account=self.address),
            'gas': gas
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        self.trigger(tx_hash.hex())
        logger.info(f"chat nft claim 成功✔ hash:{tx_hash.hex()}")


async def new_account_start(semaphore, invite_code, address, private_key, proxies_conf):
    async with semaphore:
        try:
            xter_obj = Xterio(address, private_key, UserAgent().random, proxies_conf)

            balance = xter_obj.check_balance()
            if balance == 0:
                # 0.01-0.02之间随机bnb
                random_amount = round(random.uniform(0.015, 0.02), 3)
                xter_obj.deposit2xter(random_amount)

                loop_times = 20
                while balance == 0 and loop_times > 0:
                    time.sleep(6)
                    balance = xter_obj.check_balance()
                    loop_times -= 1

                if balance == 0:
                    logger.error(f"{address} deposit BNB 失败")
                    return

                logger.info(f"deposit {random_amount}BNB 成功")

            xter_obj.sign_in()
            time.sleep(3)

            xter_obj.claim_egg()
            time.sleep(3)

            xter_obj.apply_invite(invite_code)

            # 社交任务 ids=[13,14,17]
            social_task_ids = [13, 14, 17]
            for social_task_id in social_task_ids:
                xter_obj.report(social_task_id)
                time.sleep(3)

        except Exception as e:
            logger.error(f"{address} 执行失败 msg:{e}")


async def daily_start(semaphore, address, private_key, proxies_conf):
    async with semaphore:
        try:
            xter_obj = Xterio(address, private_key, UserAgent().random, proxies_conf)

            xter_obj.sign_in()
            time.sleep(3)

            for type_num in [1, 2, 3]:
                xter_obj.claim_utility(type_num)
                time.sleep(3)

            time.sleep(5)
            for type_num in [1, 2, 3]:
                xter_obj.prop(type_num)
                time.sleep(3)

            task_list = xter_obj.get_task_list()
            for task in task_list:
                task_id = task['ID']
                for user_task in task['user_task']:
                    if user_task['status'] == 1:
                        xter_obj.task(task_id)
                        time.sleep(3)

            # 投票，可以先注释掉，统一投
            # ticket_num = xter_obj.get_ticket()
            # if ticket_num > 0:
            #     xter_obj.vote(ticket_num, 0)
        except Exception as e:
            logger.error(f"{address} 执行失败 msg:{e}")


async def boost_purchase(semaphore, address, private_key, proxies_conf):
    async with semaphore:
        try:
            xter_obj = Xterio(address, private_key, UserAgent().random, proxies_conf)
            xter_obj.sign_in()
            xter_obj.boost()
        except Exception as e:
            logger.error(f"{address} 执行失败 msg:{e}")


async def main(run_type, invite_code):
    f = open('account.txt', 'r', encoding='utf-8')
    accounts = f.readlines()
    f.close()

    f = open('proxies.txt', 'r', encoding='utf-8')
    proxies = f.readlines()
    f.close()

    # 并发数，默认10
    semaphore = asyncio.Semaphore(int(10))
    missions = []
    for idx, account in enumerate(accounts):
        account_parts = account.split(',')
        address = Web3.to_checksum_address(account_parts[0].strip())
        private_key = account_parts[1].strip()

        proxies_conf = None
        if len(proxies) != 0:
            proxy = proxies[idx].strip()
            proxies_conf = {
                "proxies": {
                    "http": f"socks5://{proxy}",
                    "https": f"socks5://{proxy}"
                }
            }

        if run_type == 1:
            missions.append(
                asyncio.create_task(new_account_start(semaphore, invite_code, address, private_key, proxies_conf)))
        elif run_type == 2:
            missions.append(asyncio.create_task(daily_start(semaphore, address, private_key, proxies_conf)))
        elif run_type == 3:
            missions.append(asyncio.create_task(boost_purchase(semaphore, address, private_key, proxies_conf)))
        elif run_type == 4:
            missions.append(asyncio.create_task(send_chat(semaphore, address, private_key, proxies_conf)))
    await asyncio.gather(*missions)


async def send_chat(semaphore, address, private_key, proxies_conf):
    async with semaphore:
        try:
            xter_obj = Xterio(address, private_key, UserAgent().random, proxies_conf)

            xter_obj.sign_in()
            time.sleep(3)

            xter_obj.send_story()
            xter_obj.claim_chat_nft()
            time.sleep(3)
            xter_obj.report(18)

            task_list = xter_obj.get_task_list()
            for task in task_list:
                task_id = task['ID']
                for user_task in task['user_task']:
                    if user_task['status'] == 1:
                        try:
                            xter_obj.task(task_id)
                            time.sleep(3)
                        except Exception as e1:
                            logger.error(e1)

        except Exception as e:
            logger.error(f"{address} 执行失败 msg:{e}")


if __name__ == '__main__':
    invite_code = "f076f883fd1503fb614731a1a20bb1c4"
    run_type = input("选择:\n 1. 新注册帐号 \n 2. 日常签到 \n 3. 购买boost \n 4. chat 任务 \n输入:")
    asyncio.run(main(int(run_type), invite_code))
