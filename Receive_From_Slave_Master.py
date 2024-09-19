import socket
import ctypes
import os
import base64
import oqs

# QKD 키를 지정한 디렉터리에 저장하는 함수
def save_key_to_directory(node_id, key, directory="/root/keys/"):
    # 디렉터리가 존재하지 않으면 생성
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            print(f"Directory {directory} created.")
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")
            return

    # 키 파일 경로 설정
    key_file_path = os.path.join(directory, f"{node_id}_qkd_key.txt")

    # 키를 파일에 저장
    try:
        with open(key_file_path, 'w') as f:
            f.write(",".join(str(k) for k in key))  # 키를 텍스트 형식으로 저장
        print(f"Master {node_id}: QKD key saved to {key_file_path}")
    except Exception as e:
        print(f"Error saving key to {key_file_path}: {e}")

# 비밀 키를 파일에 저장하는 함수
def save_private_key_to_file(private_key, file_path="/root/keys/private_key.bin"):
    try:
        with open(file_path, 'wb') as f:
            f.write(private_key)
        print(f"Private key saved to {file_path}")
    except Exception as e:
        print(f"Error saving private key: {e}")


# QKD 키를 사용하여 개인 키를 복호화하는 함수 (XOR 연산 사용)
def decrypt_with_qkd_key(encrypted_private_key, qkd_key):
    qkd_key_str = ''.join(str(bit) for bit in qkd_key)
    # qkd_key와 encrypted_private_key의 길이를 맞추기 위해 qkd_key를 반복하여 확장
    extended_qkd_key = (qkd_key_str * (len(encrypted_private_key) // len(qkd_key_str) + 1))[:len(encrypted_private_key)]
    decrypted_key = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(encrypted_private_key, extended_qkd_key))
    return decrypted_key.encode()


# 데이터를 복호화하는 함수
def decrypt_data(encrypted_data, private_key_path):
    try:
        # 비밀 키를 파일에서 읽기
        with open(private_key_path, 'rb') as f:
            private_key = f.read()

        # 비밀 키를 ctypes 형식으로 변환
        secret_key_ctypes = ctypes.create_string_buffer(private_key)

        # 비밀 키를 사용하여 복호화
        with oqs.KeyEncapsulation("Kyber512") as kem:
            kem.secret_key = secret_key_ctypes  # ctypes 객체를 직접 설정

            # 복호화 수행
            shared_secret_dec = kem.decap_secret(encrypted_data)

            print(f"Data decrypted successfully using QKD key: {shared_secret_dec}")
            return shared_secret_dec
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

# Quantum 채널에서 QKD 키를 수신하는 함수
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



# Master 노드가 데이터를 수신하고 처리하는 함수
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


# 수신한 데이터를 처리하는 함수
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
    # Master ID 및 포트 설정
    master_id = "Master1"
    host = "0.0.0.0"  # 모든 IP로부터의 연결을 수신
    #port = 65431  # Master 노드의 포트 설정
    quantum_port = 65431  # Quantum 채널 포트
    classical_port = 65432  # Classical 채널 포트


    shared_data = {}

    quantum_thread = threading.Thread(target=receive_qkd_key_from_slave, args=(master_id, host, quantum_port, shared_data))
    quantum_thread.start()

    classical_thread = threading.Thread(target=receive_data_from_slave, args=(master_id, host, classical_port, shared_data))
    classical_thread.start()
