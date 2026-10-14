
const SAMPLE_A=`sub_401000:
  mov [rbp-8], rdi
  mov [rbp-16], rsi
  mov rax, [rbp-8]
  add rax, [rbp-16]
  mov [rbp-24], rax
  cmp qword [rbp-24], 100
  jle .L1
  mov rax, 100
  jmp .L2
.L1:
  mov rax, [rbp-24]
.L2:
  ret
sub_401100:
  mov [rbp-8], rdi
  mov [rbp-16], rsi
  mov [rbp-24], rdx
  mov rdx, [rbp-24]
  mov rsi, [rbp-16]
  mov rdi, [rbp-8]
  call memcpy
  mov rax, 0
  ret
sub_401200:
  mov rax, rdi
  imul rax, 8
  add rax, 1
  mov rdi, rax
  call send_packet
  ret
sub_401300:
  call debug_dump
  ret`;
const SAMPLE_B=`sub_402b40:
  cmp rdx, 256
  ja .bad
  call memcpy
  xor rax, rax
  ret
.bad:
  mov rax, -1
  ret
sub_402a10:
  lea rax, [rdi+rsi]
  mov rcx, 100
  cmp rax, rcx
  cmovg rax, rcx
  ret
sub_403000:
  call system
  ret
sub_402f80:
  mov rax, rdi
  shl rax, 3
  add rax, 2
  mov rdi, rax
  call send_packet
  ret`;
