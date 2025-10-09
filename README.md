# RealTime-FinTech-Fraud-Anomaly-Detection-Engine

A Data Structures & Algorithms (DSA) Approach to High-Throughput Fraud Mitigation

## Project Overview

This repository features a conceptual, high-performance FinTech Fraud Detection Engine designed to analyze financial transactions in real-time. The project is an explicit demonstration of how leveraging advanced Data Structures and Algorithms (DSA) provides the necessary efficiency and complexity for critical operations, ensuring minimal latency and high throughput.

The core goal is to accurately detect anomalous user behavior and known fraud patterns to generate a precise risk score, thereby achieving low false positives—a necessity for any modern financial system.

## Architectural Philosophy: The DSA Toolkit

The system's efficiency and real-time capability are achieved through the strategic, multi-layered deployment of optimized data structures. Key components and their algorithmic rationale are listed below:

| Data Structure | Function in Fraud Detection | Time Complexity |
|----------------|----------------------------|-----------------|
| **Hash Table** (`user_profiles`) | O(1) lookup for user history and profile data | O(1) |
| **Deque** (Sliding Window) | O(1) management of recent transaction activity for velocity analysis | O(1) |
| **Bloom Filter** | Highly efficient, probabilistic pre-screening for known fraud patterns | O(k) |
| **Trie** (Prefix Tree) | O(m) precise pattern matching against sequences of known fraudulent transactions | O(m) |
| **Max-Heap** (`high_risk_heap`) | O(log n) maintenance of the global Top N riskiest users, enabling priority review | O(log n) |
| **Binary Search/bisect** | O(log n) calculation of a transaction's risk percentile against a user's history | O(log n) |
| **Graph** (Adjacency List) | O(1) insertion to map the transaction network, aiding in "money mule" ring detection | O(V + E) for full traversal |
| **Queue** (`review_queue`) | O(1) FIFO management of flagged cases for manual review workflow | O(1) |

## Key Detection Algorithms

1. **Velocity Check (Sliding Window)**: Analyzes the volume of recent transactions (Deque) to identify sudden, high-frequency activity typical of account takeover (ATO) attempts.

2. **Statistical Deviation**: Calculates the statistical outlier status (Z-score) of the transaction amount compared to the user's running average, flagging transactions far outside the norm.

3. **Pattern Recognition**: Combines the Bloom Filter (fast exclusion) and Trie (precise inclusion) to rapidly match transaction codes against known fraudulent sequences.

4. **Composite Risk Scoring**: Generates the final risk score based on a weighted combination of velocity, deviation, pattern match, and account tenure factors.

## Getting Started

This project is a standalone Python application intended for demonstration and educational purposes.

### Prerequisites

- Python 3.6+

### Execution

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/RealTime-FinTech-Fraud-Anomaly-Detection-Engine.git
   cd RealTime-FinTech-Fraud-Anomaly-Detection-Engine
   ```

2. Run the interactive script:
   ```bash
   python Fraud_detection_system_v2.py
   ```

The console menu will allow you to create new users, process transactions, and view the results from the various DSA components (e.g., Top Risky Users from the Heap, Transaction Network Graph).

## Contribution & License

This project is intended as a demonstration of computer science principles applied to FinTech. Contributions, issues, and feature requests are welcome.

**License**: Apache 2.0
