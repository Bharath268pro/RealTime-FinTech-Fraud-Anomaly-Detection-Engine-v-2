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
    def __init__(self, size=1000, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0] * size
        self.items_added = 0

    def _hashes(self, item):
        # Generate multiple hash values for the item
        hash_values = []
        for i in range(self.hash_count):
            # Combine item with index i to create unique hash
            combined_string = str(item) + str(i)
            encoded_string = combined_string.encode()
            
            # Generate MD5 hash
            hash_object = hashlib.md5(encoded_string)
            hex_digest = hash_object.hexdigest()
            
            # Convert hex to integer and get position in bit array
            hash_int = int(hex_digest, 16)
            position = hash_int % self.size
            hash_values.append(position)
        
        return hash_values

    def add(self, item):
        hash_positions = self._hashes(item)
        for position in hash_positions:
            self.bit_array[position] = 1
        self.items_added += 1

    def check(self, item):
        hash_positions = self._hashes(item)
        for position in hash_positions:
            if self.bit_array[position] == 0:
                return False
        return True

# --- TRIE (Prefix Tree for Fraud Patterns) ---
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class Trie:
    '''Stores known fraud patterns as prefixes for quick search.
    Time Complexity: insert() = O(m), search() = O(m)'''
    def __init__(self):
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
    def __init__(self, user_id, name="", email="", phone="", address="", age=0):
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
        
        # Get last 10 transactions
        recent = list(self.transaction_times)[-10:]
        if len(recent) < 2:
            return 0
        
        # Calculate time span in hours
        time_difference = recent[-1] - recent[0]
        hours = time_difference / 3600
        
        if hours > 0:
            return len(recent) / hours
        else:
            return float('inf')

    def get_amount_deviation_score(self):
        '''Measures how much the latest transaction deviates statistically.
        Time Complexity: O(n)'''
        if len(self.transaction_amounts) < 5:
            return 0
        
        amounts = list(self.transaction_amounts)
        
        # Calculate average
        total = 0
        for amount in amounts:
            total += amount
        avg = total / len(amounts)
        
        # Calculate variance
        variance_sum = 0
        for amount in amounts:
            difference = amount - avg
            squared_difference = difference ** 2
            variance_sum += squared_difference
        variance = variance_sum / len(amounts)
        
        # Calculate standard deviation
        std = variance ** 0.5
        
        # Calculate deviation of latest transaction
        latest_amount = amounts[-1]
        deviation = abs(latest_amount - avg)
        
        if std > 0:
            return deviation / std
        else:
            return 0

    def record_risk(self, score):
        '''Inserts risk score in sorted order for percentile ranking.
        Time Complexity: O(log n)'''
        bisect.insort(self.risk_history, score)

    def get_percentile_rank(self, score):
        '''Finds percentile rank of a score using binary search.
        Time Complexity: O(log n)'''
        if not self.risk_history:
            return 0
        
        position = bisect.bisect_left(self.risk_history, score)
        percentile = (position / len(self.risk_history)) * 100
        return percentile

# --- MAIN SYSTEM (Integrating All DSA Components) ---
class InteractiveFraudDetectionSystem:
    '''The core fraud detection engine demonstrating:
    - Hash Tables for user lookup
    - Trie + Bloom Filter for pattern detection
    - Heap for high-risk tracking
    - Graph for transaction network
    - Queue for review management'''
    def __init__(self, window_size=5, bloom_size=1000):
        # --- Core DSA Structures ---
        self.user_profiles = {}                       # Hash Table (O(1))
        self.recent_transactions = deque(maxlen=window_size)
        self.fraud_trie = Trie()
        self.fraud_bloom = BloomFilter(size=bloom_size)
        self.transaction_log = defaultdict(list)      # For duplicate detection (O(1))
        self.high_risk_heap = []                      # Max-Heap for risky users (O(log n))
        self.transaction_graph = defaultdict(list)    # Graph adjacency list (O(1))
        self.review_queue = deque()                   # Queue for fraud cases (O(1))

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
        '''Hash-based duplicate transaction check.
        Time Complexity: O(1)'''
        # Create unique hash for transaction
        transaction_string = f"{amount}{location}{tx_type}"
        encoded_transaction = transaction_string.encode()
        hash_object = hashlib.sha256(encoded_transaction)
        tx_hash = hash_object.hexdigest()
        
        # Check if this transaction hash exists for this user
        if tx_hash in self.transaction_log[user_id]:
            print("Duplicate transaction detected!")
        else:
            self.transaction_log[user_id].append(tx_hash)

    def record_transfer(self, sender_id, receiver_id):
        '''Records money transfer as directed graph edge.
        Time Complexity: O(1)'''
        # Check if edge already exists to prevent excessive graph growth
        if receiver_id not in self.transaction_graph[sender_id]:
            self.transaction_graph[sender_id].append(receiver_id)
            print(f" Recorded transfer: {sender_id} -> {receiver_id}")
        else:
            print(f" Edge already exists: {sender_id} -> {receiver_id}")

    def update_risk_heap(self, user):
        '''Push user into max-heap by fraud score.
        Time Complexity: O(log n)'''
        # Use negative score for max-heap behavior
        heap_entry = (-user.fraud_score, user.user_id)
        # NOTE: A more robust system would re-sort or remove stale entries, 
        # but for demonstration, we only push and trim.
        heapq.heappush(self.high_risk_heap, heap_entry)
        
        # Keep only top 10 risky users
        if len(self.high_risk_heap) > 10:
            heapq.heappop(self.high_risk_heap)

    def add_to_review_queue(self, user):
        '''Adds flagged user to review queue (FIFO).
        Time Complexity: O(1)'''
        if user.is_flagged and user.user_id not in self.review_queue: # Check if already in queue
            self.review_queue.append(user.user_id)
            print(f" Added {user.user_id} to review queue. Reason: {user.flag_reason}")
    
    # -------------------------- Fraud Detection Logic --------------------------
    def create_user(self):
        '''Creates new user profile (Hash Table Insert)
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
            print(" User already exists.")
            return user_id

        self.user_profiles[user_id] = UserProfile(user_id, name, email, phone, address, age)
        print(f" Created profile for {name} ({user_id})")
        return user_id

    def process_transaction(self, user_id):
        '''Accepts and analyzes a transaction using multiple data structures.
        Time Complexity: O(n) overall (due to deviation check)'''
        user = self.user_profiles[user_id]
        print("\n--- Enter Transaction Details ---")
        
        # Amount input with validation
        while True:
            try:
                amount = float(input("Transaction Amount: "))
                if amount > 0:
                    break
                else:
                    print("Amount must be positive.")
            except ValueError:
                print("Invalid amount. Please enter a number.")
                
        location = input("Location: ").strip()
        print("Type: [1] Purchase [2] Withdrawal [3] Transfer [4] Deposit")
        tx_type_input = input("Transaction Type (1-4): ").strip()
        tx_types = { '1': 'purchase', '2': 'withdrawal', '3': 'transfer', '4': 'deposit' }
        tx_type = tx_types.get(tx_type_input, 'purchase')

        # Record the transaction for the user
        user.add_transaction(amount, location, tx_type)
        self.log_transaction(user_id, amount, location, tx_type)
        
        # --- FIX FOR GRAPH: Record transfer and potential deposit ---
        if tx_type == 'transfer':
            while True:
                receiver_id = input(f"Enter Receiver User ID for {user_id}'s transfer: ").strip()
                if receiver_id and receiver_id != user_id:
                    break
                print("Invalid or same User ID. Please enter a valid receiver ID.")
                
            # Populate the Graph (Adjacency List)
            self.record_transfer(user_id, receiver_id) 
            
            # Record the other side of the transaction (deposit) for the receiver
            if receiver_id in self.user_profiles:
                receiver_user = self.user_profiles[receiver_id]
                receiver_user.add_transaction(amount, location, 'deposit')
            else:
                print(f"Warning: Receiver ID {receiver_id} not found in system. Deposit not recorded.")
        # -------------------------------------------------------------
        
        # Create transaction code (first letter + amount in thousands)
        amount_in_thousands = int(amount // 1000)
        code = f"{tx_type[0]}{amount_in_thousands}"
        self.recent_transactions.append(code)
        
        result = self.check_fraud(user, code)

        print("\n=== FRAUD ANALYSIS ===")
        print(f"User: {user.name}")
        print(f"Transaction: ${amount} in {location} [{tx_type}]")
        
        if result['is_fraud']:
            print(f" Result: HIGH-RISK FRAUD ALERT")
        else:
            print(f" Result: SAFE")
        
        print(f"Risk Score: {result['risk_score']:.3f} (Percentile: {user.get_percentile_rank(user.fraud_score):.2f}%)")
        print(f"Velocity: {result['velocity_score']:.2f}, Deviation: {result['amount_deviation']:.2f} $\sigma$")

        self.update_risk_heap(user)
        self.add_to_review_queue(user)
        user.record_risk(user.fraud_score)

    def check_fraud(self, user, new_code):
        '''Core fraud detection algorithm using Bloom Filter, Trie, and scoring.
        Time Complexity: O(k + m + n) → hash checks + pattern match + deviation calc'''
        is_pattern_fraud = False
        flag_reason = ""

        # Pattern analysis - check last 3 transactions (Sliding Window)
        if len(self.recent_transactions) >= 3:
            # Get last 3 transaction codes
            last_three = list(self.recent_transactions)[-3:]
            pattern_seq = "".join(last_three)
            
            # Check if pattern is fraudulent using Bloom Filter (O(k)) and Trie (O(m))
            bloom_check = self.fraud_bloom.check(pattern_seq)
            trie_check = self.fraud_trie.search(pattern_seq)
            
            if bloom_check and trie_check:
                is_pattern_fraud = True
                flag_reason = f"Known fraud pattern: {pattern_seq}"

        # Calculate risk scores
        velocity = user.get_velocity_score()
        deviation = user.get_amount_deviation_score()

        # Age-based risk
        if user.account_age_days < 1:
            age_risk = 0.8 # New accounts are riskier
        else:
            age_risk = 0.3

        # Large transaction risk
        latest_amount = user.transaction_amounts[-1]
        if latest_amount > 10000:
            large_tx = 0.7
        else:
            large_tx = 0.2

        # Normalize velocity and deviation risks
        v_risk = velocity / self.VELOCITY_THRESHOLD
        if v_risk > 1.0:
            v_risk = 1.0
        
        d_risk = deviation / self.AMOUNT_DEVIATION_THRESHOLD
        if d_risk > 1.0:
            d_risk = 1.0

        # Calculate composite risk score (weighted average)
        risk_score = (0.25 * v_risk) + (0.2 * d_risk) + (0.25 * age_risk) + (0.3 * large_tx)
        
        # Determine if transaction is fraudulent
        is_fraud = is_pattern_fraud or (risk_score > self.FRAUD_SCORE_THRESHOLD)

        # Update user fraud status
        user.is_flagged = is_fraud
        user.fraud_score = risk_score
        
        if flag_reason:
            user.flag_reason = flag_reason
        elif is_fraud:
            user.flag_reason = f"High risk score: {risk_score:.2f} (V:{v_risk:.2f}, D:{d_risk:.2f})"
        else:
            user.flag_reason = ""
        
        return {
            'is_fraud': is_fraud,
            'risk_score': risk_score,
            'velocity_score': velocity,
            'amount_deviation': deviation
        }

    # -------------------------- Visualization & Review --------------------------
    def show_top_risky_users(self):
        '''Displays top risky users from heap.
        Time Complexity: O(n log n)'''
        print("\n=== Top Risky Users (Max-Heap) ===")
        
        # Create a temporary sorted list (O(n log n) or O(k log n) if only top k are needed)
        # Using a shallow copy for sorting without modifying the original heap
        sorted_users = sorted(self.high_risk_heap, reverse=True)
        
        if not sorted_users:
            print("No high-risk users in the heap.")
            return

        for score, uid in sorted_users:
            actual_score = -score  # Convert back from negative
            user = self.user_profiles.get(uid)
            if user:
                print(f" User ID: {uid} | Score: {actual_score:.3f} | Flagged: {user.is_flagged} | Reason: {user.flag_reason}")
            else:
                print(f" User ID: {uid} | Score: {actual_score:.3f} | [User Profile Not Found]")

    def show_transaction_network(self):
        '''Displays user-to-user transaction graph.
        Time Complexity: O(V + E)'''
        print("\n=== Transaction Network Graph (Transfers) ===")
        if not self.transaction_graph:
            print("No transfers recorded yet.")
            return
            
        for sender, receivers in self.transaction_graph.items():
            if receivers:
                # V is the sender, E is the list of receivers (Adjacency List structure)
                print(f"💰 {sender} → {', '.join(receivers)}")

    def process_review_queue(self):
        '''FIFO fraud case processing using queue.
        Time Complexity: O(n)'''
        print("\n=== Review Queue (Processing FIFO) ===")
        if not self.review_queue:
            print("Queue is empty. No cases for review.")
            return
            
        # FIX: Process one item at a time for interactive feel, or loop as intended
        while self.review_queue:
            uid = self.review_queue.popleft()
            
            user = self.user_profiles.get(uid)
            if user:
                print(f"🔍 Reviewing Case ID: {uid}")
                print(f"  Risk Score: {user.fraud_score:.3f}, Reason: {user.flag_reason}")
                
                action = input("  [A]pproved (Clear Flag) or [D]eclined (Keep Flag)? [A/D]: ").lower().strip()
                
                if action == 'a':
                    user.is_flagged = False
                    user.flag_reason = "Reviewed and Approved/Cleared."
                    print(f"  User {uid}'s flag **CLEARED**.")
                elif action == 'd':
                    print(f"  User {uid}'s flag **KEPT** for further action.")
                else:
                    print("  Invalid action. Flag remains for next review cycle.")
            else:
                print(f"Reviewing {uid}... User not found. Skipped.")

# -------------------------- Main Menu --------------------------
def main():
    print("\n=== FRAUD DETECTION SYSTEM (DSA Edition) ===")
    system = InteractiveFraudDetectionSystem()
    
    # Pre-create a couple of users for easier testing
    system.user_profiles['U101'] = UserProfile('U101', 'Alice', age=30)
    system.user_profiles['U102'] = UserProfile('U102', 'Bob', age=45)
    system.user_profiles['U103'] = UserProfile('U103', 'Charlie', age=22)
    print("Pre-created users: U101 (Alice), U102 (Bob), U103 (Charlie)")
    
    while True:
        print("\nMenu:")
        print("1. Create new user")
        print("2. Process transaction (Test Fraud Rules)")
        print("3. Show top risky users (Heap)")
        print("4. Show transaction network (Graph)")
        print("5. Review fraud queue (Queue)")
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
                print(" Invalid User ID!")
                continue
            system.process_transaction(uid)
        elif choice == "3":
            system.show_top_risky_users()
        elif choice == "4":
            system.show_transaction_network()
        elif choice == "5":
            system.process_review_queue()
        elif choice == "6":
            print("Exiting system.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()