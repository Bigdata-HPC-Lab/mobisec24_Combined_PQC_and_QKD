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

# BB84 프로토콜을 사용하여 양자 키 분배 시뮬레이션
def run_bb84_protocol(num_bits):
    # Alice가 송신할 무작위 비트와 기저 선택
    alice_bits = np.random.randint(2, size=num_bits)
    alice_bases = np.random.randint(2, size=num_bits)

    # Bob의 무작위 기저 선택
    bob_bases = np.random.randint(2, size=num_bits)

    # 양자 상태 생성 및 측정
    results = []
    for bit, alice_base, bob_base in zip(alice_bits, alice_bases, bob_bases):
        qc = QuantumCircuit(1, 1)

        # Alice의 비트를 준비
        if alice_base == 0:  # Z 기저 (표준)
            if bit == 1:
                qc.x(0)
        else:  # X 기저 (+/-)
            if bit == 1:
                qc.x(0)
            qc.h(0)

        # Bob의 측정
        if bob_base == 1:  # X 기저에서 측정
            qc.h(0)

        qc.measure(0, 0)

        # 양자 회로 컴파일 (Transpile) 및 실행
        simulator = Aer.get_backend('qasm_simulator')
        transpiled_circuit = transpile(qc, simulator)
        result = simulator.run(transpiled_circuit, shots=1).result()
        measurement = int(list(result.get_counts().keys())[0])
        results.append(measurement)

    # Alice와 Bob의 키 비교 및 확인
    key = [alice_bits[i] for i in range(num_bits) if alice_bases[i] == bob_bases[i]]
    print(f"Generated QKD key: {key}")

    return key



# QKD 키를 사용하여 개인 키를 암호화하는 함수 (XOR 연산 사용)
def encrypt_with_qkd_key(private_key, qkd_key):
    qkd_key_str = ''.join(str(bit) for bit in qkd_key)
    # qkd_key와 private_key의 길이를 맞추기 위해 qkd_key를 반복하여 확장
    extended_qkd_key = (qkd_key_str * (len(private_key) // len(qkd_key_str) + 1))[:len(private_key)]
    encrypted_key = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(private_key, extended_qkd_key))
    return encrypted_key.encode()  # 바이트로 반환



# QKD 키를 전송하는 Quantum Channel 함수
def send_qkd_key(master_host, quantum_port, qkd_key):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((master_host, quantum_port))
        # QKD 키를 전송 (키를 쉼표로 구분하여 전송)
        s.sendall(f"{','.join(map(str, qkd_key))}".encode())
        print(f"Sent QKD key to {master_host}:{quantum_port} over Quantum Channel.")



# 데이터를 전송하는 Classical Channel 함수
def send_data_to_master(master_host, classical_port, shared_secret_enc, encrypted_private_key):
    start_time = time.time()

    # Base64로 바이너리 데이터를 인코딩
    encoded_data = base64.b64encode(shared_secret_enc).decode()
    encoded_encrypted_private_key = base64.b64encode(encrypted_private_key).decode()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((master_host, classical_port))
        # 암호화된 개인 키 및 암호화된 데이터를 전송 (QKD 키는 Quantum Channel을 통해 별도로 전송)
        s.sendall(f"{encoded_encrypted_private_key}:{encoded_data}".encode())
        print(f"Sent encrypted data to {master_host}:{classical_port} over Classical Channel.")
    end_time = time.time()
    print(f"Data Transmission Runtime for {master_host}:{classical_port}: {end_time - start_time:.4f} seconds")



# Slave 노드에서 Kyber 암호화와 QKD 생성 및 Master 노드로 데이터 전송
def slave_node(file_paths, master_nodes):
    for file_path, (master_host, quantum_port, classical_port) in zip(file_paths, master_nodes):
        # 파일을 바이너리 모드로 읽기 (암호화 대상 파일)
        with open(file_path, 'rb') as f:
            binary_data = f.read()

        print(f"Slave: Read binary data from {file_path}, size: {len(binary_data)} bytes.")

        start_time = time.time()
        # Kyber로 파일 데이터의 암호화 키 생성
        encrypted_file_path = f"{file_path}.enc"
        with oqs.KeyEncapsulation("Kyber512") as kem:
            # 공개키/개인키 쌍 생성
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

            # 공개키를 사용한 암호화 키 생성 
            # 공유 대칭키를 이용한 파일 암호화만 진행. 
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)

            # 파일 데이터 암호화 
            with open(encrypted_file_path, 'wb') as f:
                f.write(shared_secret_enc)  # 파일 데이터를 대칭키로 암호화하고 저장

            # QKD 키 생성
            qkd_key = run_bb84_protocol(128)  # 128 비트 키 생성

            # 개인 키를 QKD 키로 암호화
            encrypted_private_key = encrypt_with_qkd_key(private_key, qkd_key)

        end_time = time.time()
        print(f"Kyber Encryption Runtime for {file_path}: {end_time - start_time:.4f} seconds")

        # QKD 키 전송 (Quantum Channel)
        threading.Thread(target=send_qkd_key, args=(master_host, quantum_port, qkd_key)).start()

        # 암호화된 데이터 전송 (Classical Channel) # master host, classical port, data, key
        send_data_to_master(master_host, classical_port, shared_secret_enc, encrypted_private_key)

if __name__ == "__main__":
    # 테스트할 파일 경로 (Slave에서 보낼 파일 경로)
    file_paths = [
        '/root/expanded_datasets/ECU-IoHT-Dataset_1000MB_part_1.csv'  # 암호화 대상 파일
    ]
    # Master 노드의 IP와 Quantum/Classic Port 설정
    master_nodes = [("192.168.140.132", 65431, 65432)]  # Quantum Port: 65431, Classical Port: 65432
    # Slave 노드에서 테스트 함수 실행
    slave_node(file_paths, master_nodes)
