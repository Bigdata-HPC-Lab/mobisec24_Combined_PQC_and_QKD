import socket
import threading
import oqs
import numpy as np
import base64
import time
import ctypes

from qiskit import QuantumCircuit
from qiskit_aer import Aer
from qiskit import transpile

# Quantum Key Distribution (QKD) Simulation using BB84 Protocol
def run_bb84_protocol(num_bits):
    # Generate random bits and bases for Alice
    alice_bits = np.random.randint(2, size=num_bits)
    alice_bases = np.random.randint(2, size=num_bits)

    # Generate random bases for Bob
    bob_bases = np.random.randint(2, size=num_bits)

    # Quantum state preparation and measurement
    results = []
    for bit, alice_base, bob_base in zip(alice_bits, alice_bases, bob_bases):
        qc = QuantumCircuit(1, 1)

        # Prepare Alice's bit
        if alice_base == 0:  # Z basis (standard)
            if bit == 1:
                qc.x(0)
        else:  # X basis (+/-)
            if bit == 1:
                qc.x(0)
            qc.h(0)

        # Bob's measurement
        if bob_base == 1:  # Measure in X basis
            qc.h(0)

        qc.measure(0, 0)

        # Transpile and run quantum circuit
        simulator = Aer.get_backend('qasm_simulator')
        transpiled_circuit = transpile(qc, simulator)
        result = simulator.run(transpiled_circuit, shots=1).result()
        measurement = int(list(result.get_counts().keys())[0])
        results.append(measurement)

    # Compare and verify keys between Alice and Bob
    key = [alice_bits[i] for i in range(num_bits) if alice_bases[i] == bob_bases[i]]
    print(f"Generated QKD key: {key}")

    return key


# Function to encrypt a private key using the QKD key (using XOR operation)
def encrypt_with_qkd_key(private_key, qkd_key):
    qkd_key_str = ''.join(str(bit) for bit in qkd_key)
    # Extend the qkd_key to match the length of the private_key
    extended_qkd_key = (qkd_key_str * (len(private_key) // len(qkd_key_str) + 1))[:len(private_key)]
    encrypted_key = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(private_key, extended_qkd_key))
    return encrypted_key.encode()  # Return as bytes


# Quantum Channel function to send QKD key
def send_qkd_key(master_host, quantum_port, qkd_key):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((master_host, quantum_port))
        # Send QKD key (separated by commas)
        s.sendall(f"{','.join(map(str, qkd_key))}".encode())
        print(f"Sent QKD key to {master_host}:{quantum_port} over Quantum Channel.")


# Classical Channel function to send data
def send_data_to_master(master_host, classical_port, shared_secret_enc, encrypted_private_key):
    start_time = time.time()

    # Encode binary data using Base64
    encoded_data = base64.b64encode(shared_secret_enc).decode()
    encoded_encrypted_private_key = base64.b64encode(encrypted_private_key).decode()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((master_host, classical_port))
        # Send encrypted private key and encrypted data (QKD key is sent separately over Quantum Channel)
        s.sendall(f"{encoded_encrypted_private_key}:{encoded_data}".encode())
        print(f"Sent encrypted data to {master_host}:{classical_port} over Classical Channel.")
    end_time = time.time()
    print(f"Data Transmission Runtime for {master_host}:{classical_port}: {end_time - start_time:.4f} seconds")


# Slave node function to perform Kyber encryption, QKD generation, and data transmission to the master node
def slave_node(file_paths, master_nodes):
    for file_path, (master_host, quantum_port, classical_port) in zip(file_paths, master_nodes):
        # Read the file in binary mode (file to be encrypted)
        with open(file_path, 'rb') as f:
            binary_data = f.read()

        print(f"Slave: Read binary data from {file_path}, size: {len(binary_data)} bytes.")

        start_time = time.time()
        # Generate encryption key for the file using Kyber
        encrypted_file_path = f"{file_path}.enc"
        with oqs.KeyEncapsulation("Kyber512") as kem:
            # Generate public/private key pair
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

            # Generate encryption key using public key
            # Perform file encryption using shared symmetric key
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)

            # Encrypt the file data using the symmetric key and save it
            with open(encrypted_file_path, 'wb') as f:
                f.write(shared_secret_enc)  # Save the file data encrypted with the symmetric key

            # Generate QKD key
            qkd_key = run_bb84_protocol(128)  # Generate 128-bit key

            # Encrypt private key using QKD key
            encrypted_private_key = encrypt_with_qkd_key(private_key, qkd_key)

        end_time = time.time()
        print(f"Kyber Encryption Runtime for {file_path}: {end_time - start_time:.4f} seconds")

        # Send QKD key (Quantum Channel)
        threading.Thread(target=send_qkd_key, args=(master_host, quantum_port, qkd_key)).start()

        # Send encrypted data (Classical Channel)
        send_data_to_master(master_host, classical_port, shared_secret_enc, encrypted_private_key)

if __name__ == "__main__":
    # File paths to be tested (files to be sent from slave node)
    file_paths = [
        '/root/expanded_datasets/ECU-IoHT-Dataset_1000MB_part_1.csv'  # File to be encrypted
    ]
    # Master node's IP and Quantum/Classical Port configuration
    master_nodes = [("192.168.140.132", 65431, 65432)]  # Quantum Port: 65431, Classical Port: 65432
    # Execute test function on the slave node
    slave_node(file_paths, master_nodes)
