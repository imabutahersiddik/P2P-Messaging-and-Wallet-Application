import streamlit as st
import hashlib
import json
import socket
import os
from time import time

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def create_genesis_block():
    return Block(0, "0", time(), "Genesis Block", calculate_hash(0, "0", time(), "Genesis Block"))

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + previous_hash + str(timestamp) + json.dumps(data)
    return hashlib.sha256(value.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [create_genesis_block()]
        self.current_transactions = []

    def add_block(self, block):
        self.chain.append(block)

    def create_block(self, data):
        previous_block = self.chain[-1]
        index = previous_block.index + 1
        timestamp = time()
        hash = calculate_hash(index, previous_block.hash, timestamp, data)
        block = Block(index, previous_block.hash, timestamp, data, hash)
        self.add_block(block)
        return block

class Wallet:
    def __init__(self):
        self.wallets = {}

    def create_wallet(self, wallet_name):
        private_key = os.urandom(32).hex()
        public_key = hashlib.sha256(private_key.encode()).hexdigest()  # Simple public key generation
        self.wallets[wallet_name] = private_key
        return public_key

    def export_wallet(self, wallet_name):
        return json.dumps(self.wallets[wallet_name])

    def import_wallet(self, wallet_name, private_key):
        self.wallets[wallet_name] = private_key

class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

def send_coins(sender_wallet, receiver_wallet, amount):
    transaction = Transaction(sender_wallet, receiver_wallet, amount)
    # Add transaction logic here
    return transaction

def send_message(sender, message):
    blockchain.create_block({"sender": sender, "message": message})
    reward_sender(sender)

def send_file(sender, file_data):
    blockchain.create_block({"sender": sender, "file": file_data})
    reward_sender(sender)

def reward_sender(sender):
    # Logic to reward the sender with 9999 coins
    print(f"{sender} has been rewarded with 9999 coins!")

def main():
    st.title("Blockchain Wallet and Messaging System")

    global blockchain
    blockchain = Blockchain()
    wallet = Wallet()

    st.sidebar.header("Wallet Management")
    wallet_name = st.sidebar.text_input("Wallet Name")

    if st.sidebar.button("Create Wallet"):
        public_key = wallet.create_wallet(wallet_name)
        st.sidebar.success(f"Wallet created! Public Key: {public_key}")

    if st.sidebar.button("Export Wallet"):
        try:
            private_key = wallet.export_wallet(wallet_name)
            st.sidebar.success(f"Exported Wallet: {private_key}")
        except KeyError:
            st.sidebar.error("Wallet not found!")

    if st.sidebar.button("Import Wallet"):
        private_key = st.sidebar.text_input("Private Key to Import")
        wallet.import_wallet(wallet_name, private_key)
        st.sidebar.success("Wallet imported!")

    st.sidebar.header("Send Coins")
    sender_wallet = st.sidebar.text_input("Sender Wallet Name")
    receiver_wallet = st.sidebar.text_input("Receiver Wallet Name")
    amount = st.sidebar.number_input("Amount", min_value=1)

    if st.sidebar.button("Send Coins"):
        send_coins(sender_wallet, receiver_wallet, amount)
        st.sidebar.success(f"Sent {amount} coins from {sender_wallet} to {receiver_wallet}!")

    st.header("Messaging and File Sharing")
    sender = st.text_input("Sender Wallet Name")

    if st.button("Send Message"):
        message = st.text_input("Message")
        send_message(sender, message)
        st.success("Message sent and block created!")

    if st.button("Send File"):
        file_data = st.file_uploader("Choose a file", type=['txt', 'pdf', 'png', 'jpg'])
        if file_data is not None:
            send_file(sender, file_data.read())
            st.success("File sent and block created!")

    st.subheader("Recent Messages and Files")
    for block in blockchain.chain:
        if "message" in block.data:
            st.write(f"Sender: {block.data['sender']}, Message: {block.data['message']}")
        elif "file" in block.data:
            st.write(f"Sender: {block.data['sender']}, File: {block.data['file']}")

    st.subheader("Connected Nodes")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    st.write(f"Current Node: {ip_address}")
    # Add logic to display connected nodes

if __name__ == "__main__":
    main()
