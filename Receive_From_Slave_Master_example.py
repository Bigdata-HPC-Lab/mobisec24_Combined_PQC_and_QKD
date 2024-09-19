import socket
import ctypes
import os
import base64
import oqs
import threading


from qiskit import QuantumCircuit
from qiskit_aer import Aer
from qiskit import transpile


# Function to save the QKD key to a specified directory
def save_key_to_directory(node_id, key, directory="/root/keys/"):
    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            print(f"Directory {directory} created.")
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")
            return

    # Set the key file path
    key_file_path = os.path.join(directory, f"{node_id}_qkd_key.txt")

    # Save the key to the file
    try:
        with open(key_file_path, 'w') as f:
            f.write(",".join(str(k) for k in key))  # Save the key in text format
        print(f"Master {node_id}: QKD key saved to {key_file_path}")
    except Exception as e:
        print(f"Error saving key to {key_file_path}: {e}")

# Function to save the private key to a file
def save_private_key_to_file(private_key, file_path="/root/keys/private_key.bin"):
    try:
        with open(file_path, 'wb') as f:
            f.write(private_key)
        print(f"Private key saved to {file_path}")
    except Exception as e:
        print(f"Error saving private key: {e}")


# Function to decrypt the private key using the QKD key (using XOR operation)
def decrypt_with_qkd_key(encrypted_private_key, qkd_key):
    qkd_key_str = ''.join(str(bit) for bit in qkd_key)
    # Extend the qkd_key to match the length of the encrypted_private_key
    extended_qkd_key = (qkd_key_str * (len(encrypted_private_key) // len(qkd_key_str) + 1))[:len(encrypted_private_key)]
    decrypted_key = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(encrypted_private_key, extended_qkd_key))
    return decrypted_key.encode()


# Function to decrypt the data
def decrypt_data(encrypted_data, private_key_path):
    try:
        # Read the private key from the file
        with open(private_key_path, 'rb') as f:
            private_key = f.read()

        # Convert the private key to a ctypes format
        secret_key_ctypes = ctypes.create_string_buffer(private_key)

        # Decrypt using the private key
        with oqs.KeyEncapsulation("Kyber512") as kem:
            kem.secret_key = secret_key_ctypes  # Set the ctypes object directly

            # Perform decryption
            shared_secret_dec = kem.decap_secret(encrypted_data)

            print(f"Data decrypted successfully using QKD key: {shared_secret_dec}")
            return shared_secret_dec
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

# Function to receive QKD key from the slave node over the Quantum channel
def receive_qkd_key_from_slave(master_id, host, quantum_port, shared_data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, quantum_port))
        s.listen()
        print(f"Master {master_id}: Listening for QKD key on {host}:{quantum_port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Master {master_id}: Connected by {addr} for QKD key")
                qkd_key_str = conn.recv(4096).decode()
                if not qkd_key_str:
                    continue

                qkd_key = list(map(int, qkd_key_str.split(',')))
                print(f"Master {master_id}: Received QKD key: {qkd_key}")

                save_key_to_directory(master_id, qkd_key)
                shared_data['qkd_key'] = qkd_key



# Function for the master node to receive and process data from the slave node
def receive_data_from_slave(master_id, host, classical_port, shared_data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, classical_port))
            s.listen()
            print(f"Master {master_id}: Listening for encrypted data on {host}:{classical_port}")

            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Master {master_id}: Connected by {addr} for encrypted data")

                    data = conn.recv(4096).decode()
                    if not data:
                        continue

                    encoded_encrypted_private_key, encoded_data = data.split(":", 1)
                    encrypted_data = base64.b64decode(encoded_data)
                    encrypted_private_key = base64.b64decode(encoded_encrypted_private_key)

                    print(f"Master {master_id}: Received encrypted data.")
                    shared_data['encrypted_data'] = encrypted_data
                    shared_data['encrypted_private_key'] = encrypted_private_key

                    if 'qkd_key' in shared_data:
                        process_received_data(master_id, shared_data)


# Function to process the received data
def process_received_data(master_id, shared_data):
    qkd_key = shared_data['qkd_key']
    encrypted_private_key = shared_data['encrypted_private_key']
    encrypted_data = shared_data['encrypted_data']

    decrypted_private_key = decrypt_with_qkd_key(encrypted_private_key, qkd_key)
    private_key_path = "/root/keys/private_key.bin"
    save_private_key_to_file(decrypted_private_key, private_key_path)

    decrypted_data = decrypt_data(encrypted_data, private_key_path)
    if decrypted_data:
        print(f"Master {master_id}: Data decrypted successfully.")
    else:
        print(f"Master {master_id}: Decryption failed.")
                

if __name__ == "__main__":
    # Master ID and port configuration
    master_id = "Master1"
    host = "0.0.0.0"  # Listen to connections from all IPs
    #port = 65431  # Port configuration for the master node
    quantum_port = 65431  # Quantum channel port
    classical_port = 65432  # Classical channel port


    shared_data = {}

    quantum_thread = threading.Thread(target=receive_qkd_key_from_slave, args=(master_id, host, quantum_port, shared_data))
    quantum_thread.start()

    classical_thread = threading.Thread(target=receive_data_from_slave, args=(master_id, host, classical_port, shared_data))
    classical_thread.start()
