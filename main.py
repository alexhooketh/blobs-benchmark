import random, ckzg
from time import time

setup = ckzg.load_trusted_setup("trusted_setup.txt")

# the blob is in fact an array of 4096 elements 32 bytes each, but each element can't
# be more than BLS_MODULUS which is technically 254.857... bits
BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513

def generate_blob():
    return b"".join([random.randint(0, BLS_MODULUS).to_bytes(32) for _ in range(4096)])

def cycle():
    blob = generate_blob()

    commitment = ckzg.blob_to_kzg_commitment(blob, setup)
    proof = ckzg.compute_blob_kzg_proof(blob, commitment, setup)
    assert ckzg.verify_blob_kzg_proof(blob, commitment, proof, setup)

    return

    point = random.randint(0, 4096)
    element = blob[point*32:(point+1)*32]
    proof = ckzg.compute_kzg_proof(blob, element, setup)
    assert ckzg.verify_kzg_proof(commitment, element, proof[1], proof[0], setup) # lmao no idea why the proof tuple is in inverse order

s = time()
for i in range(100):
    cycle()
    print(i)
e = round(time() - s, 2)
print("generated 100 eip-4844 blobs in {} seconds or avg {}s/blob".format(e, e/100))