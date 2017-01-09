## Introduction

```
[!] Couldn't find relocations against PLT to get symbols
[*] '/root/ctf/edu_ctf/pwn/Silver_Bullet/Silver_Bullet'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

This binary is really NX!!XDD

It have 4 features
```
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :
```

1. Create a Silver Bullet
    * if not create can do 2 and 3
    * read(0, description, 48)
    * power is 3
2. Power up Silver Bullet
    * power up
    * read(0, another_description, 45)
3. Beat the Werewolf 
    * Warewolf hp is 2147483647
4. quit()

## Vulnerbility

in description when you power up another_description is 24

three times ago,you can overwrite return address

and then beat() * 2，you can trigger your payload

First need to leak libc base and return to start

ans just do exploit again

[payload](exp.rb)
