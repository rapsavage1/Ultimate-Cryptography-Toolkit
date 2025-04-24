# import hashlib
# import itertools

# hashes = [
#     bytes.fromhex("F7002A5259567B1F993E743D3128B6A97B153EACFC7BB914802DCFB43D23FA2E"),
#     bytes.fromhex("6E2B86DC5982F533C3A896E66B97D377D09E7988B7E27E9BE5DDBA9F34C325FC"),
#     bytes.fromhex("83AAB3327FFF40207AEB5919BD7FB06BAE953324FC71EE35816076CD6480334A"),
#     bytes.fromhex("0B794C734A46D75BE2EEE543F714E8D7E2D41D0549D4D8E1167B77B63080DE83"),
#     bytes.fromhex("EC40BD8242061EF401305485800CA5D63A9AB6DA659221A27C7BFAD3A9694E6C")
# ]

# expected_final = "254D0EFBF65B24BAA1F29CD09ED0D3F97810A11D044137953DD5FDF4C69B346D"

# for perm in itertools.permutations(hashes):
#     chain = hashlib.sha256()
#     for h in perm:
#         chain.update(h)
#     result = chain.hexdigest().upper()
    
#     if result == expected_final:
#         print("\n✅ MATCH FOUND!")
#         print("Permutation that works:")
#         for i, h in enumerate(perm, start=1):
#             print(f"Hash{i}: {h.hex().upper()}")
#         break
# else:
#     print("❌ No matching permutation found.")

import hashlib
import itertools

hashes = [
    bytes.fromhex("F7002A5259567B1F993E743D3128B6A97B153EACFC7BB914802DCFB43D23FA2E"),
    bytes.fromhex("6E2B86DC5982F533C3A896E66B97D377D09E7988B7E27E9BE5DDBA9F34C325FC"),
    bytes.fromhex("83AAB3327FFF40207AEB5919BD7FB06BAE953324FC71EE35816076CD6480334A"),
    bytes.fromhex("0B794C734A46D75BE2EEE543F714E8D7E2D41D0549D4D8E1167B77B63080DE83"),
    bytes.fromhex("EC40BD8242061EF401305485800CA5D63A9AB6DA659221A27C7BFAD3A9694E6C")
]

expected_final = "254D0EFBF65B24BAA1F29CD09ED0D3F97810A11D044137953DD5FDF4C69B346D"

count = 0  # Count how many permutations we've checked

for perm in itertools.permutations(hashes):
    count += 1
    chain = hashlib.sha256()
    for h in perm:
        chain.update(h)
    result = chain.hexdigest().upper()
    
    if result == expected_final:
        print(f"\n✅ MATCH FOUND after {count} permutations!")
        print("Permutation that works:")
        for i, h in enumerate(perm, start=1):
            print(f"Hash{i}: {h.hex().upper()}")
        break
else:
    print(f"\n❌ No matching permutation found after {count} total permutations.")
