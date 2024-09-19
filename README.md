# Enhancing Cloud Security for IoHT: A Dual-Layer Scheme Combining Quantum Key Distribution and Post-Quantum Cryptography. 
Summited in mobisec'24


## Overview
This paper proposes an effective dual-layer encryption scheme for securing Internet of Health Things (IoHT) data in cloud environments. It combines Post-Quantum Cryptography (PQC) with Quantum Key Distribution (QKD) to provide robust security against classical and quantum computing threats.

## Key Features

### Dual-Layer Encryption
1) First Layer: Uses the Kyber algorithm for post-quantum encryption, ensuring data protection against quantum attacks.
2) Second Layer: Employs the BB84 protocol for QKD, adding an additional layer of protection by securely distributing encryption keys.

## Implementation
The implementation is based on:
- Kyber Algorithm from the Open Quantum Safe (OQS) project for post-quantum cryptography.
- Qiskit Quantum Simulator to simulate the BB84 protocol for QKD.

