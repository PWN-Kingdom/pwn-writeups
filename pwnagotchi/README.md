# HSCTF 7

##  pwnagotchi


> 116
>
> Have fun with your new pwnagotchi!
>
> Connect to view your `\ (•-•) /` at `nc pwn.hsctf.com 5005`
>
> Author: meow
>
> [`pwnagotchi `](pwnagotchi)

## Анализ бинарного файла
### file pwnagotchi
```
    pwnagotchi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, 
                interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
                BuildID[sha1]=f8c34ef43ba5a8fbce8b89987797d88f7adbb31f, not stripped
```
### checksec pwnagotchi
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Итак, что мы имеем: 64-битный исполняемый ELF файл, отсутствует стековая канарейка и сегмент текста программы в памяти расположен по статическому адресу. 

##  Как работает программа
### ./pwnagotchi
```
    Enter your pwnagotchi's name: 
    admin

    \ (•-•) /
    
    admin is not happy!
```
Админ несчастлив. Программа принимаем наш ввод и печатает его. Посмотрим глубже.
### Декомпилирование с Ghidra





