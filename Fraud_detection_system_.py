#---------------------------------------------------Fraud_detection_system_v2.py--------------------------------------------------------------------#
'''This project demonstrates the importance of DATA STRUCTURES & ALGORITHMS
in designing efficient, real-world fraud detection systems.
Data Structures Used:
----------------------
1. Bloom Filter → For Fast fraud pattern checking and screening O(k)
2. Trie (Suffix Tree) → For Pattern detection O(m)
3. Hash Table → For Fast user and transaction lookups O(1)
4. Deque → Sliding window for recent transactions O(1)
5. Heap → Top risky user management (O(log n))
6. Graph (Adjacency List) → Transaction network mapping (O(1) insert)
7. Binary Search → Fraud percentile ranking (O(log n))
8. Queue → Fraud review workflow O(1)
Algorithms Used:
-----------------
1. Hashing → Unique transaction signatures (O(1))
2. Pattern Matching → Fraud pattern recognition (O(m))
3. Sliding Window → Recent activity tracking (O(1) amortized-Analyzing the Average time per operation)
4. Risk Scoring → Composite fraud risk calculation (O(1))
5. Binary Search → Percentile rank calculation (O(log n))
-------------------------------------------------'''
import hashlib
import heapq
import bisect
import time
from collections import deque, defaultdict

# --- BLOOM FILTER (Probabilistic Membership Testing) ---
class BloomFilter:
    '''Used to quickly check if a transaction pattern that may have appeared before.
    Time Complexity: add() = O(k), check() = O(k)'''
    def _init_(self, size=1000, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0]*size
        self.items_added = 0

    def _hashes(self, item):
        return [int(hashlib.md5((str(item)+str(i)).encode()).hexdigest(), 16) % self.size for i in range(self.hash_count)]

    def add(self, item):
        for h in self._hashes(item):
            self.bit_array[h] = 1
        self.items_added += 1

    def check(self, item):
        return all(self.bit_array[h] for h in self._hashes(item))

# --- TRIE (Prefix Tree for Fraud Patterns) ---
class TrieNode:
    def _init_(self):
        self.children = {}
        self.is_end = False

class Trie:
    '''Stores known fraud patterns as prefixes for quick search.
    Time Complexity: insert() = O(m), search() = O(m)'''
    def _init_(self):
        self.root = TrieNode()

    def insert(self, sequence):
        node = self.root
        for char in sequence:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True

    def search(self, sequence):
        node = self.root
        for char in sequence:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.is_end

# --- USER PROFILE (Hash Table Entry) ---
class UserProfile:
    '''Represents a user and their transaction history.
    Uses deque for recent activity (O(1) append/pop) and binary search for percentile calculation.'''
    def _init_(self, user_id, name="", email="", phone="", address="", age=0):
        self.user_id = user_id
        self.name = name
        self.email = email
        self.phone = phone
        self.address = address
        self.age = age
        self.transaction_count = 0
        self.total_amount = 0.0
        self.avg_transaction_amount = 0.0

        # --- Deques for Sliding Windows (O(1) amortized operations) ---
        self.transaction_times = deque(maxlen=100)
        self.transaction_amounts = deque(maxlen=100)
        self.transaction_locations = deque(maxlen=50)
        self.transaction_types = deque(maxlen=100)

        # --- Risk Tracking ---
        self.creation_time = time.time()
        self.account_age_days = 0
        self.fraud_score = 0.0
        self.is_flagged = False
        self.flag_reason = ""
        self.risk_history = []  # Maintained sorted for percentile (O(log n) insert)

    def add_transaction(self, amount, location, transaction_type, timestamp=None):
        '''Adds a new transaction record.
        Updates rolling averages and sliding window.
        Time Complexity: O(1)'''
        if timestamp is None:
            timestamp = time.time()
        self.transaction_count += 1
        self.total_amount += amount
        self.avg_transaction_amount = self.total_amount / self.transaction_count
        self.transaction_times.append(timestamp)
        self.transaction_amounts.append(amount)
        self.transaction_locations.append(location)
        self.transaction_types.append(transaction_type)
        self.account_age_days = (timestamp - self.creation_time) / (24 * 3600)

    def get_velocity_score(self):
        '''Measures how frequently the user transacts.
        High velocity = risky.
        Time Complexity: O(1)'''
        if len(self.transaction_times) < 2:
            return 0
        recent = list(self.transaction_times)[-10:]
        if len(recent) < 2:
            return 0
        hours = (recent[-1] - recent[0]) / 3600
        return len(recent) / hours if hours > 0 else float('inf')

    def get_amount_deviation_score(self):
        
        '''Measures how much the latest transaction deviates statistically.
        Time Complexity: O(n)'''
        if len(self.transaction_amounts) < 5:
            return 0
        amounts = list(self.transaction_amounts)
        avg = sum(amounts) / len(amounts)
        variance = sum((x - avg) ** 2 for x in amounts) / len(amounts)
        std = variance ** 0.5
        return abs(amounts[-1] - avg) / std if std else 0

    def record_risk(self, score):
        '''
        Inserts risk score in sorted order for percentile ranking.
        Time Complexity: O(log n) '''
        bisect.insort(self.risk_history, score)

    def get_percentile_rank(self, score):
        
        '''Finds percentile rank of a score using binary search.
        Time Complexity: O(log n)'''
        if not self.risk_history:
            return 0
        pos = bisect.bisect_left(self.risk_history, score)
        return (pos / len(self.risk_history)) * 100

# --- MAIN SYSTEM (Integrating All DSA Components) ---
class InteractiveFraudDetectionSystem:
    '''
    The core fraud detection engine demonstrating:
    - Hash Tables for user lookup
    - Trie + Bloom Filter for pattern detection
    - Heap for high-risk tracking
    - Graph for transaction network
    - Queue for review management'''
    def _init_(self, window_size=5, bloom_size=1000):
        # --- Core DSA Structures ---
        self.user_profiles = {}                     # Hash Table (O(1))
        self.recent_transactions = deque(maxlen=window_size)
        self.fraud_trie = Trie()
        self.fraud_bloom = BloomFilter(size=bloom_size)
        self.transaction_log = defaultdict(list)     # For duplicate detection (O(1))
        self.high_risk_heap = []                     # Max-Heap for risky users (O(log n))
        self.transaction_graph = defaultdict(list)   # Graph adjacency list (O(1))
        self.review_queue = deque()                  # Queue for fraud cases (O(1))

        # --- Fraud Patterns ---
        self.fraud_patterns = ["p5p5p5", "w10w10", "p1p1p1p1", "p3p3p3p3", "w5w5w5", "t1t1t1"]
        for pattern in self.fraud_patterns:
            self.fraud_trie.insert(pattern)
            self.fraud_bloom.add(pattern)

        # --- Risk Thresholds ---
        self.VELOCITY_THRESHOLD = 10
        self.AMOUNT_DEVIATION_THRESHOLD = 3
        self.FRAUD_SCORE_THRESHOLD = 0.7

    # -------------------------- Utility Methods --------------------------

    def log_transaction(self, user_id, amount, location, tx_type):
        '''
        Hash-based duplicate transaction check.
        Time Complexity: O(1)'''
        tx_hash = hashlib.sha256(f"{amount}{location}{tx_type}".encode()).hexdigest()
        if tx_hash in self.transaction_log[user_id]:
            print(" Duplicate transaction detected!")
        else:
            self.transaction_log[user_id].append(tx_hash)

    def record_transfer(self, sender_id, receiver_id):
        '''
        Records money transfer as directed graph edge.
        Time Complexity: O(1)'''
        self.transaction_graph[sender_id].append(receiver_id)

    def update_risk_heap(self, user):
        '''
        Push user into max-heap by fraud score.
        Time Complexity: O(log n)'''
        heapq.heappush(self.high_risk_heap, (-user.fraud_score, user.user_id))
        if len(self.high_risk_heap) > 10:
            heapq.heappop(self.high_risk_heap)

    def add_to_review_queue(self, user):
        '''
        Adds flagged user to review queue (FIFO).
        Time Complexity: O(1)'''
        if user.is_flagged:
            self.review_queue.append(user.user_id)
            print(f"🕵 Added {user.user_id} to review queue.")
    # -------------------------- Fraud Detection Logic --------------------------
    def create_user(self):
        '''
        Creates new user profile (Hash Table Insert)
        Time Complexity: O(1)'''
        print("\n--- Enter User Details ---")

        # User ID input with validation
        while True:
            user_id = input("User ID: ").strip()
            if user_id:
                break
            print("User ID cannot be empty. Please enter a valid User ID.")

        # Name input with validation
        while True:
            name = input("Full Name: ").strip()
            if name:
                break
            print("Full Name cannot be empty. Please enter a valid name.")

        # Email input with validation
        while True:
            email = input("Email: ").strip()
            if email:
                break
            print("Email cannot be empty. Please enter a valid email.")

        # Address input with validation
        while True:
            address = input("Address: ").strip()
            if address:
                break
            print("Address cannot be empty. Please enter a valid address.")

        # Age input with validation
        while True:
            age_input = input("Age: ").strip()
            try:
                age = int(age_input)
                break
            except ValueError:
                print("Please enter a valid integer for age.")
        
        # Phone input with validation
        while True:
            phone_input = input("Enter phone number: ").strip()
            if phone_input.isdigit() and len(phone_input) == 10:
                phone = phone_input
                break
            else:
                print("Please enter a valid 10-digit phone number.")

        if user_id in self.user_profiles:
            print("User already exists.")
            return user_id

        self.user_profiles[user_id] = UserProfile(user_id, name, email, phone, address, age)
        print(f"Created profile for {name} ({user_id})")
        return user_id

    def process_transaction(self, user_id):
        '''Accepts and analyzes a transaction using multiple data structures.
        Time Complexity: O(n) overall (due to deviation check)'''
        user = self.user_profiles[user_id]
        print("\n--- Enter Transaction Details ---")
        amount = float(input("Transaction Amount: "))
        location = input("Location: ").strip()
        print("Type: [1] Purchase [2] Withdrawal [3] Transfer [4] Deposit")
        tx_type_input = input("Transaction Type (1-4): ").strip()
        tx_types = { '1': 'purchase', '2': 'withdrawal', '3': 'transfer', '4': 'deposit' }
        tx_type = tx_types.get(tx_type_input, 'purchase')

        user.add_transaction(amount, location, tx_type)
        self.log_transaction(user_id, amount, location, tx_type)
        code = f"{tx_type[0]}{int(amount // 1000)}"
        self.recent_transactions.append(code)
        result = self.check_fraud(user, code)

        print("\n=== FRAUD ANALYSIS ===")
        print(f"User: {user.name}")
        print(f"Transaction: ${amount} in {location} [{tx_type}]")
        print(f"Result: {' FRAUD' if result['is_fraud'] else ' SAFE'}")
        print(f"Risk Score: {result['risk_score']:.3f}")
        print(f"Velocity: {result['velocity_score']:.2f}, Deviation: {result['amount_deviation']:.2f}")

        self.update_risk_heap(user)
        self.add_to_review_queue(user)
        user.record_risk(user.fraud_score)

    def check_fraud(self, user, new_code):
        '''Core fraud detection algorithm using Bloom Filter, Trie, and scoring.
        Time Complexity: O(k + m + n) → hash checks + pattern match + deviation calc'''
        is_pattern_fraud = False
        flag_reason = " "

        # Pattern analysis
        if len(self.recent_transactions) >= 3:
            pattern_seq = "".join(list(self.recent_transactions)[-3:])
            if self.fraud_bloom.check(pattern_seq) and self.fraud_trie.search(pattern_seq):
                is_pattern_fraud = True
                flag_reason = f"Known fraud pattern: {pattern_seq}"

        velocity = user.get_velocity_score()
        deviation = user.get_amount_deviation_score()

        age_risk = 0.8 if user.account_age_days < 1 else 0.3
        large_tx = 0.7 if user.transaction_amounts[-1] > 10000 else 0.2

        v_risk = min(velocity / self.VELOCITY_THRESHOLD, 1.0)
        d_risk = min(deviation / self.AMOUNT_DEVIATION_THRESHOLD, 1.0)

        risk_score = 0.25*v_risk + 0.2*d_risk + 0.25*age_risk + 0.3*large_tx
        is_fraud = is_pattern_fraud or risk_score > self.FRAUD_SCORE_THRESHOLD

        user.is_flagged = is_fraud
        user.fraud_score = risk_score
        user.flag_reason = flag_reason or f"High risk score: {risk_score:.2f}"
        return {
            'is_fraud': is_fraud,
            'risk_score': risk_score,
            'velocity_score': velocity,
            'amount_deviation': deviation
        }

    # -------------------------- Visualization & Review --------------------------
    def show_top_risky_users(self):
        '''
        Displays top risky users from heap.
        Time Complexity: O(n log n)
        '''
        print("\n=== Top Risky Users ===")
        for score, uid in sorted(self.high_risk_heap, reverse=True):
            print(f"User ID: {uid}, Fraud Score: {-score:.3f}")

    def show_transaction_network(self):
        '''
        Displays user-to-user transaction graph.
        Time Complexity: O(V + E)
        '''
        print("\n=== Transaction Network Graph ===")
        for user, connections in self.transaction_graph.items():
            print(f"{user} → {connections}")

    def process_review_queue(self):
        '''
        FIFO fraud case processing using queue.
        Time Complexity: O(n)
        '''
        print("\n=== Review Queue ===")
        while self.review_queue:
            uid = self.review_queue.popleft()
            print(f"🔎 Reviewing {uid}... done ")
# -------------------------- Main Menu --------------------------
def main():
    print("\n=== FRAUD DETECTION SYSTEM (DSA Edition) ===")
    system = InteractiveFraudDetectionSystem()
    while True:
        print("\nMenu:")
        print("1. Create new user")
        print("2. Process transaction")
        print("3. Show top risky users")
        print("4. Show transaction network")
        print("5. Review fraud queue")
        print("6. Exit")
        choice = input("Select (1-6): ").strip()
        if choice == "1":
            system.create_user()
        elif choice == "2":
            if not system.user_profiles:
                print(" No users found. Create one first!")
                continue
            uid = input("Enter User ID: ").strip()
            if uid not in system.user_profiles:
                print("Invalid User ID!")
                continue
            system.process_transaction(uid)
        elif choice == "3":
            system.show_top_risky_users()
        elif choice == "4":
            system.show_transaction_network()
        elif choice == "5":
            system.process_review_queue()
        elif choice == "6":
            print(" Exiting system.")
            break
        else:
            print("Invalid option.")
if __name__ == "_main_":
    main()