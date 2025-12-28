import socket
import json
import struct
import threading
import time
import logging
from flask import Flask, request, jsonify

#日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('server_debug.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('GameServer')

app = Flask(__name__)

@app.before_request
def log_request_info():
    logger.info(f"HTTP REQ: {request.method} {request.url}")
    if request.args:
        logger.info(f"HTTP ARGS: {dict(request.args)}")

@app.route('/common/loginCheck.php', methods=['GET'])
def login_check():
    resp = {"accountId": 10001, "sdk_userID": "sdk_manus", "errorId": 0}
    logger.info(f"HTTP RESP (loginCheck): {resp}")
    return jsonify(resp)

#下发服务器列表以及公告数据，这个是必要的
@app.route('/common/serverList.php', methods=['GET'])
def server_list():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1'
    finally:
        s.close()

	#以下为公告格式，可以参考此格式写
    game_notice = {
        "1": {
            "title": "欢迎来到本地模拟服",
            "image": "",
            "content": {
                "1": {
                    "subTitle": "服务器状态",
                    "subContent": {"1": "豪啊！赶紧修数据包吧！还有一堆TCP数据等着你呢！"},
                    "titleColor": [255, 255, 255],
                    "contentColor": [200, 200, 200]
                }
            }
        },
        "2": {
            "title": "给杜的话",
            "image": "",
            "content": {
                "1": {
                    "subTitle": "你画  *  *  的饼",
                    "subContent": {"1": "*  *  *  ，能不能有点实际进度？！"},
                    "titleColor": [255, 255, 255],
                    "contentColor": [200, 200, 200]
                }
            }
        }
    }

    response = {
        "updateAddr": f"http://{local_ip}:8080/update",
        "downloadAddr": f"http://{local_ip}:8080/download",
        "gameNotice": game_notice,
        "1": {
            "id": "114",
            "serverName": "私服测试",
            "ip": local_ip,
            "port": "9997",
            "state": "open",
            "closeTips": "服务器维护中"
        }
    }
    return jsonify(response)

@app.route('/common/checkAccount.php', methods=['GET'])
def check_account():
    resp = {
        "error": 0,
        "accountId": 10001,
        "recentLoginList": [{"serverIndex": 1}],
        "haveCharServerList": {"1": {"level": 50, "name": "ManusTester", "roleId": 123456}}
    }
    logger.info(f"HTTP RESP (checkAccount): {resp}")
    return jsonify(resp)

@app.route('/common/reportLogin.php', methods=['GET'])
def report_login():
    logger.info("HTTP RESP (reportLogin): SUCCESS")
    return "SUCCESS"

#版本号校验，这个说必要的
@app.route('/common/version.php', methods=['GET'])
def get_version():
    return "1.0.2"

#角色数据传输

class GameGateway:
    def __init__(self, host='0.0.0.0', port=9997):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"TCP Gateway started on {self.host}:{self.port}")
        while True:
            client, addr = self.server_socket.accept()
            logger.info(f"New TCP connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client, addr)).start()

    def send_packet(self, client, method, data_dict, addr):

        #修正的加密逻辑，匹配客户端 PacketBuffer.lua (fmt = 'HS')
        json_str = json.dumps(data_dict, ensure_ascii=False)
        json_bytes = json_str.encode('utf-8')
        
        # 1. 构造 Body (fmt = "HS")
        # H: packetId (2字节) 到 客户端解密: bit.bxor(readUShort(), method)
        packet_id_xor = method ^ method # 结果为 0
        body = struct.pack('<H', packet_id_xor)
        
        # S: packetData (String)
        # S 的长度部分 (4字节): bit.bxor(len, method)
        content_len = len(json_bytes)
        len_xor = content_len ^ method
        body += struct.pack('<I', len_xor)
        
        # S 的内容部分: bit.bxor(byte, content_len)
        xor_content = bytes([(b ^ content_len) & 0xFF for b in json_bytes])
        body += xor_content
        
        # 2. 构造 Header: ackNum(4), method(2), bodyLen(4)
        header = struct.pack('<iHi', 0, method, len(body))
        
        client.sendall(header + body)
        logger.info(f"[{addr}] SEND TCP: method={method}, data={json_str}")

    def handle_client(self, client, addr):
        try:
            while True:
                header = client.recv(10)
                if not header: break
                ack_num, method, body_len = struct.unpack('<iHi', header)
                
                logger.info(f"[{addr}] RECV TCP: method={method}, bodyLen={body_len}")
                
                body = b""
                if body_len > 0:
                    while len(body) < body_len:
                        chunk = client.recv(body_len - len(body))
                        if not chunk: break
                        body += chunk
                
                # 尝试解析客户端发送的 HS 格式数据
                if body_len >= 6:
                    try:
                        p_id = struct.unpack('<H', body[0:2])[0] ^ method
                        s_len_xor = struct.unpack('<I', body[2:6])[0]
                        s_len = s_len_xor ^ method
                        if len(body) >= 6 + s_len:
                            s_content_raw = body[6:6+s_len]
                            s_content = "".join([chr(b ^ s_len) for b in s_content_raw])
                            logger.info(f"[{addr}] RECV DATA: packetId={p_id}, content={s_content}")
                    except Exception as pe:
                        logger.warning(f"[{addr}] Failed to parse body: {pe}")

                if method == 2005: # GameCheckPlayerReq
                    self.send_packet(client, 2006, {"errorId": 0, "playeruid": 123456, "accountId": 10001}, addr)
                elif method == 2001: # GameLoginReq
                    self.handle_game_login(client, addr)
                elif method == 1002: # SYNC_TIME_REQ
                    self.send_packet(client, 1003, {"mServerTime": int(time.time())}, addr)
                    
        except Exception as e:
            logger.error(f"[{addr}] TCP Error: {e}")
        finally:
            logger.info(f"[{addr}] TCP connection closed")
            client.close()

    def handle_game_login(self, client, addr):
        self.send_packet(client, 2002, {"result": 0, "logintoken": "token", "loginMainKey": "key", "playerGuid": 123456}, addr)
        
        now_ts = int(time.time())
        
        # 依据msg网络模块列表推测的需要下发的数据，在msg模块列表里面有些数据有对应的示例，可以用来作为参考
        packets = [
            (3004, {"uuid": 123456, "uid": 1, "name": "Manus", "mood": "", "exp": 3400, "level": 50, "vipLevel": 5, "vipexp": 0, "gold": 1000, "coin": 10000, "fame": 0, "strength": 100, "sweepItemNum": [0, 0, 0], "climbTowerTimes": 0, "TowerReliveTimes": 0, "power": 1000, "arenaCountData": 0, "amphitheaterData": {"enter_count": 0, "win_count": 0, "lose_count": 0}, "twelvePalaceUnlockCount": 0, "twelvePalaceBuyTimes": 0, "dailyMultipleCopyCount": 0, "chaimiyouyanCountData": [0, 0, 0, 0], "twelvepalaceCount": 0, "twelvepalaceInfo": "", "couragetrial_daily_point": 0, "couragetrialInfo": "", "oldname": "", "activepoint": {"totalNum": 0}, "fishEatTimes": 0, "guidstr": "0"}),
            (5002, {}),
            (23002, {"disablebegintime": 0, "disableTimeLong": 0, "nowtime": now_ts, "chatplayers": []}),
            (7081, {"result": 0, "reqType": 0, "gold": 1000, "id": 0, "maxChallengeTimes": 5, "maxFreeRefreshTimes": 5, "leftChallengeTimes": 5, "needTime": 0, "nextRefreshCost": 0, "recoverTime": 0, "nextBuyCost": 0, "buyTimes": 0, "lightOfLife": 0, "maxBuyTimes": 5, "monsterID1": 0, "monsterID2": 0, "monsterID3": 0, "coinGroup": [], "refreshTimes": 0, "luckyValues1": 0, "luckyValues2": 0, "luckyValues3": 0, "catCoins": []}),
            (27002, []),
            (8002, {"otherPlayerID": 123456, "haveBuyList": [], "equiped": 0}),
            (26002, []),
            (9002, {"consortid": 1, "consortname": "Manus", "consortlv": 1, "curcontribut": 0, "totalcontribut": 0, "consortjob": 1, "leavetime": 0, "consortcount": 0, "consortpower": 0, "consortrank": 0, "consortdesc": "", "consortres": 0, "leaderid": 0, "leadermodel": 0, "leadername": "", "viceleaderid1": 0, "viceleaderid2": 0, "consortcheck": 0, "consortpowerlimit": 0, "consortexp": 0, "consortlist": [], "consortlist_gettime": 0, "consortlist_expiretime": 600, "checklist": [], "appications": [], "kitchentimes": 0, "eyetimes": 0, "businesscattype": 0, "businesscat_refreshtime": 0, "businesscattimes": 0, "businesscatlv": 0, "businesscat_buylist": [], "act_data_gettime": 0, "act_data_expiretime": 60, "act_data": {}, "act_played_times": 0, "act_can_reward": 0, "act_ticket_award_count": 0, "act_open_state": False, "act_left_time": 0, "eloquence_times": 0, "wooden_cat_gettime": 0, "wooden_cat_expiretime": 5, "wooden_cat_people": {}, "wooden_cat_blood": 0, "wooden_cat_times": 0, "wooden_cat_close_time": 0, "wooden_cat_buff": {}, "wooden_cat_award_get": 0, "wooden_cat_layer_open": False, "wooden_cat_layer_need_reolad": False, "consortactive": 0, "signlv": 0, "signawards": [], "sign": 0, "ticketaward": 0, "taskdata": [{"taskid": 0, "gettime": 0, "remaintime": 0} for _ in range(4)], "taskrefresh": 0}),
            (16002, {"base": [{"level": 1, "piece": 0, "star": 0, "equip": [0]*6} for _ in range(12)], "equip": {}}),
            (22002, {"servantswitch": 1, "food1": 0, "food2": 0, "food3": 0, "food4": 0, "food5": 0, "mainbattle": [0, 0, 0, 0, 0], "assistbattle": [{"equip": 0, "quality": 1} for _ in range(7)], "treasure": [], "servantData": [], "battleStone": 0}),
            (18002, []),
            (20002, {"equipJewelrys": [0,0,0,0,0,0], "jewelryList": {}}),
            (21002, []),
            (7006, {}),
            (14002, {"level": 1, "step": 1, "exp": 0, "soul": 0, "acupointList": []}),
            (29002, [{"modelId": 1, "equipfashion": 0}]),
            (4002, []),
            (7008, {}),
            (30002, {}),
            (31501, {"result": 0, "restChalTimes": 5, "buyTimes": 0, "curRank": 1, "playerScore": 0, "ends": [], "otherRoleInfo": []}),
            (24001, {"result": 0, "reqtype": 1, "highID": 0, "score": 0, "ap": 0, "hp": 0, "times": 0, "buyTimes": 0}),
            (32102, {"monbuytime": 0, "monawardtime": 0, "awardbit": 0, "paybit": 0, "totalpaygold": 0}),
            (3004, {"uuid": 123456, "uid": 1, "name": "Manus", "mood": "", "exp": 3400, "level": 50, "vipLevel": 5, "vipexp": 0, "gold": 1000, "coin": 10000, "fame": 0, "strength": 100, "sweepItemNum": [0, 0, 0], "climbTowerTimes": 0, "TowerReliveTimes": 0, "power": 1000, "arenaCountData": 0, "amphitheaterData": {"enter_count": 0, "win_count": 0, "lose_count": 0}, "twelvePalaceUnlockCount": 0, "twelvePalaceBuyTimes": 0, "dailyMultipleCopyCount": 0, "chaimiyouyanCountData": [0, 0, 0, 0], "twelvepalaceCount": 0, "twelvepalaceInfo": "", "couragetrial_daily_point": 0, "couragetrialInfo": "", "oldname": "", "activepoint": {"totalNum": 0}, "fishEatTimes": 0, "guidstr": "0"}),
            (5002, {}),
            (27002, []),
        ]

        for method, data in packets:
            time.sleep(0.05)
            self.send_packet(client, method, data, addr)
        
        logger.info(f"[{addr}] Login sequence completed for player 123456")

if __name__ == '__main__':
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8080), daemon=True).start()
    GameGateway().start()
