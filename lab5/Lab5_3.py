import hashlib, random, string, time

def hash(algo, dataset):
    start = time.time()
    hashes = [getattr(hashlib, algo)(s.encode()).hexdigest() for s in dataset]
    end = time.time()-start
    return hashes, end

def detect_collisions(hashes):
    seen, collisions = set(), []
    for h in hashes:
        if h in seen: collisions.append(h)
        else: seen.add(h)
    return collisions
size=random.randint(50,100)
dataset = [''.join(random.choices(string.ascii_letters+string.digits, k=random.randint(5,15)))for _ in range(size)]

for algo in ("md5", "sha1", "sha256"):
    hashes, total_time = hash(algo, dataset)
    collisions = detect_collisions(hashes)
    print(f"{algo.upper():6} time: {total_time:.6f}s | collisions: {len(collisions)}")
