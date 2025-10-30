import hashlib
import random
import string
import time

# Hashes a list of strings with a given algorithm and measures the time taken.
def hash_dataset(algo, dataset):
    # Record the start time.
    start = time.time()
    
    # Use a list comprehension to efficiently hash every string in the dataset.
    # getattr(hashlib, algo) dynamically calls the correct function (e.g., hashlib.md5).
    # .hexdigest() returns the hash as a readable hexadecimal string.
    hashes = [getattr(hashlib, algo)(s.encode()).hexdigest() for s in dataset]
    
    # Calculate the total elapsed time.
    end = time.time() - start
    return hashes, end

# Detects if there are any duplicate hashes (collisions) in a list of hashes.
def detect_collisions(hashes):
    # Use a set for very fast checking of previously seen items.
    seen = set()
    collisions = []
    
    # Iterate through all the computed hashes.
    for h in hashes:
        # If the hash has been seen before, it's a collision.
        if h in seen:
            collisions.append(h)
        # Otherwise, add it to the set of seen hashes.
        else:
            seen.add(h)
    return collisions

# --- EXPERIMENT SETUP AND EXECUTION ---
# Generate a dataset of 50 to 100 random strings.
size = random.randint(50, 100)
# Each string has a random length and contains letters and digits.
dataset = [''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15))) for _ in range(size)]

print(f"Analyzing {len(dataset)} random strings...")
print("-" * 50)

# Iterate through the list of hashing algorithms to be tested.
for algo in ("md5", "sha1", "sha256"):
    # Run the hashing and timing function.
    hashes, total_time = hash_dataset(algo, dataset)
    
    # Run the collision detection function.
    collisions = detect_collisions(hashes)
    
    # Print a formatted summary of the results for the current algorithm.
    print(f"{algo.upper():6} | Time: {total_time:.6f}s | Collisions found: {len(collisions)}")