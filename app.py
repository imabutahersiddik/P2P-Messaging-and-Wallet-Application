import threading
import socket
import json
import sys
import time
import hashlib
import base64
import xml.etree.ElementTree as ET
import urllib.request
import urllib.parse
import http.client
import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# Constants
msg_del_time = 30
PORT = 65432
FILE_PORT = 65433
REWARD_AMOUNT = 9999

# NodeConnection Class
class NodeConnection(threading.Thread):
    def __init__(self, main_node, sock, id, host, port):
        super(NodeConnection, self).__init__()
        self.host = host
        self.port = port
        self.main_node = main_node
        self.sock = sock
        self.terminate_flag = threading.Event()
        self.last_ping = time.time()
        self.buffer = ""
        self.public_key = self.main_node.load_key(id)
        self.id = id

        self.main_node.debug_print(
            "NodeConnection.send: Started with client ("
            + self.id
            + ") '"
            + self.host
            + ":"
            + str(self.port)
            + "'"
        )

    def send(self, data):
        try:
            data = data + "-TSN"
            self.sock.sendall(data.encode("utf-8"))
        except Exception as e:
            self.main_node.debug_print(
                "NodeConnection.send: Unexpected error: " + str(e)
            )
            self.terminate_flag.set()

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        self.sock.settimeout(10.0)
        while not self.terminate_flag.is_set():
            if time.time() - self.last_ping > self.main_node.dead_time:
                self.terminate_flag.set()
                print("node" + self.id + " is dead")

            line = ""
            try:
                line = self.sock.recv(4096)
            except socket.timeout:
                pass
            except Exception as e:
                self.terminate_flag.set()
                self.main_node.debug_print(
                    "NodeConnection: Socket has been terminated (%s)" % line
                )
                self.main_node.debug_print(e)

            if line != "":
                try:
                    self.buffer += str(line.decode("utf-8"))
                except Exception as e:
                    print("NodeConnection: Decoding line error | " + str(e))

                index = self.buffer.find("-TSN")
                while index > 0:
                    message = self.buffer[0:index]
                    self.buffer = self.buffer[index + 4 : :]

                    if message == "ping":
                        self.last_ping = time.time()
                    else:
                        self.main_node.node_message(self, message)

                    index = self.buffer.find("-TSN")

            time.sleep(0.01)

        self.main_node.node_disconnected(self)
        self.sock.settimeout(None)
        self.sock.close()
        del self.main_node.nodes_connected[self.main_node.nodes_connected.index(self)]
        time.sleep(1)

# Node Class
class Node(threading.Thread):
    def __init__(self, host="", port=PORT, file_port=FILE_PORT):
        super(Node, self).__init__()
        self.terminate_flag = threading.Event()
        self.pinger = Pinger(self)
        self.debug = True
        self.dead_time = 45
        self.host = host
        self.ip = host
        self.port = port
        self.file_port = file_port
        self.nodes_connected = []
        self.requested = []
        self.msgs = {}
        self.peers = []
        self.publickey, self.private_key = self.generate_keys()
        self.id = self.serialize_key(self.publickey)
        self.max_peers = 10
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.banned = []
        self.wallet = {"balance": 0, "address": self.id}  # Initialize wallet

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.debug_print("Initialization of the Node on port: " + str(self.port))
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(10.0)
        self.sock.listen(1)

    def debug_print(self, msg):
        if self.debug:
            print("[debug] " + str(msg))

    def load_key(self, key):
        key = base64.b64decode(key)
        return RSA.import_key(key)

    def serialize_key(self, key):
        key = base64.b64encode(key.export_key("DER")).decode("utf-8")
        return key

    def generate_keys(self):
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        return public_key, private_key

    def encrypt(self, message, key):
        message = json.dumps(message).encode("utf-8")
        cipher = PKCS1_OAEP.new(key)
        return base64.b64encode(cipher.encrypt(message)).decode("utf-8")

    def decrypt(self, message, key):
        cipher = PKCS1_OAEP.new(key)
        message = cipher.decrypt(base64.b64decode(message))
        return json.loads(message)

    def sign(self, message, private_key):
        digest = SHA256.new()
        digest.update(str(message).encode("utf-8"))
        signer = PKCS1_v1_5.new(private_key)
        sig = signer.sign(digest)
        return base64.b64encode(sig).decode("utf-8")

    def verify(self, message, sig, key):
        digest = SHA256.new()
        digest.update(str(message).encode("utf-8"))
        verifier = PKCS1_v1_5.new(key)
        verified = verifier.verify(digest, base64.b64decode(sig))
        return verified

    def network_send(self, message, exc=[]):
        for i in self.nodes_connected:
            if i.host in exc:
                pass
            else:
                i.send(json.dumps(message))

    def connect_to(self, host, port=PORT):
        if not self.check_ip_to_connect(host):
            self.debug_print("connect_to: Cannot connect!!")
            return False

        if len(self.nodes_connected) >= self.max_peers:
            self.debug_print("Peers limit reached.")
            return True

        for node in self.nodes_connected:
            if node.host == host:
                print("[connect_to]: Already connected with this node.")
                return True

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.debug_print("connecting to %s port %s" % (host, port))
            sock.connect((host, port))

            sock.send(self.id.encode("utf-8"))
            connected_node_id = sock.recv(1024).decode("utf-8")

            if self.id == connected_node_id:
                self.debug_print("Possible own ip: " + host)
                if socket.inet_aton(host):
                    self.local_ip = host
                else:
                    self.ip = host
                self.banned.append(host)
                sock.close()
                return False

            thread_client = NodeConnection(self, sock, connected_node_id, host, port)
            thread_client.start()
            self.nodes_connected.append(thread_client)
            self.node_connected(thread_client)

        except Exception as e:
            self.debug_print("connect_to: Could not connect with node. (" + str(e) + ")")

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        self.pinger.start()
        while not self.terminate_flag.is_set():
            try:
                connection, client_address = self.sock.accept()
                connected_node_id = connection.recv(2048).decode("utf-8")
                connection.send(self.id.encode("utf-8"))

                if self.id != connected_node_id:
                    thread_client = NodeConnection(self, connection, connected_node_id, client_address[0], client_address[1])
                    thread_client.start()
                    self.nodes_connected.append(thread_client)
                    self.node_connected(thread_client)
                else:
                    connection.close()

            except socket.timeout:
                pass
            except Exception as e:
                raise e

            time.sleep(0.01)

        self.pinger.stop()
        for t in self.nodes_connected:
            t.stop()

        self.sock.close()
        print("Node stopped")

    def send_message(self, data, receiver=None):
        if receiver:
            data = self.encrypt(data, self.load_key(receiver))
        self.message("msg", data, {"rnid": receiver})
        self.wallet["balance"] += REWARD_AMOUNT  # Reward for sending message
        self.debug_print(f"Rewarded {REWARD_AMOUNT} coins for sending a message.")

    def message(self, type, data, overrides={}, ex=[]):
        dict = {"type": type, "data": data}
        if "time" not in dict:
            dict["time"] = str(time.time())

        if "snid" not in dict:
            dict["snid"] = str(self.id)

        if "rnid" not in dict:
            dict["rnid"] = None

        if "sig" not in dict:
            dict["sig"] = self.sign(data, self.private_key)

        dict = {**dict, **overrides}
        self.network_send(dict, ex)

    def check_ip_to_connect(self, ip):
        if (
            ip not in self.peers
            and ip != ""
            and ip != self.ip
            and ip != self.local_ip
            and ip not in self.banned
        ):
            return True
        else:
            return False

    def node_connected(self, node):
        self.debug_print("node_connected: " + node.id)
        if node.host not in self.peers:
            self.peers.append(node.host)
        self.send_peers()

    def node_disconnected(self, node):
        self.debug_print("node_disconnected: " + node.id)
        if node.host in self.peers:
            self.peers.remove(node.host)

    def node_message(self, node, data):
        try:
            json.loads(data)
        except json.decoder.JSONDecodeError:
            self.debug_print(f"Error loading message from {node.id}")
            return
        self.data_handler(json.loads(data), [node.host, self.ip])

    def data_handler(self, dta, n):
        if not self.check_validity(dta):
            return False

        dta = self.encryption_handler(dta)
        if not dta:
            return False

        type = dta["type"]
        data = dta["data"]

        if type == "msg":
            self.on_message(data, dta["snid"], bool(dta["rnid"]))
            self.wallet["balance"] += REWARD_AMOUNT  # Reward for receiving message
            self.debug_print(f"Rewarded {REWARD_AMOUNT} coins for receiving a message.")

    def check_validity(self, msg):
        if not ("time" in msg and "type" in msg and "snid" in msg and "sig" in msg and "rnid" in msg):
            return False

        if not self.verify(msg["data"], msg["sig"], self.load_key(msg["snid"])):
            self.debug_print(f"Error validating signature of message from {msg['snid']}")
            return False

        return True

# Pinger Class
class Pinger(threading.Thread):
    def __init__(self, parent):
        self.terminate_flag = threading.Event()
        super(Pinger, self).__init__()
        self.parent = parent

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        print("Pinger Started")
        while not self.terminate_flag.is_set():
            for i in self.parent.nodes_connected:
                i.send("ping")
                time.sleep(20)
        print("Pinger stopped")

# Streamlit Frontend
def main():
    st.title("P2P Messaging and Wallet Application")

    # Initialize Node
    node = Node()
    node.start()

    # Wallet Section
    st.header("Wallet Management")
    st.write(f"Wallet Address: {node.wallet['address']}")
    st.write(f"Balance: {node.wallet['balance']} coins")

    # Send Coins
    receiver_address = st.text_input("Receiver Address")
    amount_to_send = st.number_input("Amount to Send", min_value=0)
    if st.button("Send Coins"):
        if amount_to_send <= node.wallet["balance"]:
            node.wallet["balance"] -= amount_to_send
            st.success(f"Sent {amount_to_send} coins to {receiver_address}.")
        else:
            st.error("Insufficient balance!")

    # Messaging Section
    st.header("Messaging")
    message = st.text_input("Enter your message:")
    if st.button("Send Message"):
        node.send_message(message)
        st.success("Message sent!")

    # File Upload
    uploaded_file = st.file_uploader("Upload a file", type=["txt", "pdf", "jpg", "png"])
    if uploaded_file is not None:
        file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
        node.message("file", {"filename": uploaded_file.name, "hash": file_hash})
        st.success("File sent!")

    # Recent Activity
    st.header("Recent Activity")
    st.write("Recent messages and files will be displayed here.")

    # Connected Nodes
    st.header("Connected Nodes")
    st.write(f"Currently connected nodes: {len(node.nodes_connected)}")

if __name__ == "__main__":
    main()
