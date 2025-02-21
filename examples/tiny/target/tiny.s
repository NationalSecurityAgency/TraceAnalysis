bits 64
extern _start
_start:
mov rdi, bar
mov rsi, foo
mov rcx, 5
rep movsb

mov rax,[baz]
add rax,rax
mov [baz+8],rax

mov rbx, 5
mov rax,60
syscall

section .data
foo:
db "hello world",0
bar:
times 100 db 0xaa
baz:
times 40 db 0x55
