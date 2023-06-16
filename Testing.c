#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include "Structs.h"
#include "Macros.h"

extern PVOID NTAPI Spoof(PVOID a, ...);
PVOID FindGadget(LPBYTE Module, ULONG Size)
{
    for (int x = 0; x < Size; x++)
    {
        if (memcmp(Module + x, "\xFF\x23", 2) == 0)
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}

/* Credit to VulcanRaven project for the original implementation of these two*/
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;
        default:
            printf("[-] Error: Unsupported Unwind Op Code\n");
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
Cleanup:
    return status;
}
ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = RtlLookupFunctionEntry(
        (DWORD64)ReturnAddress,
        &ImageBase,
        pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return status;
}

int bruh(int a, int b, int c, int d, int* e, int* f, int* g)
{
    *e = 7;
    *f = 8;
    *g = 9;
}
int main() {

    PVOID ReturnAddress = NULL;
    PRM p = { 0 };
    PRM ogp = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    PVOID pPrintf = GetProcAddress(LoadLibraryA("msvcrt.dll"), "printf");

    p.trampoline = FindGadget((LPBYTE)GetModuleHandle(L"kernel32.dll"), 0x200000);
    printf("[+] Gadget is at 0x%llx\n", p.trampoline);

    ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk")) + 0x14; // Would walk export table but am lazy
    p.BTIT_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.BTIT_retaddr = ReturnAddress;

    ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
    p.RUTS_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.RUTS_retaddr = ReturnAddress;

    p.Gadget_ss = CalculateFunctionStackSizeWrapper(p.trampoline);
    
    // 0 stack args
    for (int i = 0; i < 2; i++)
    {
        p.Function = Sleep;
        printf("[+] Iteration %d\n", i);
        Spoof(4000, NULL, NULL, NULL, &p, (PVOID)0);
        printf("[+] Returning to 0x%llx\n", _ReturnAddress());
    }
    
    // 1 stack arg
    
    for (int i = 0; i < 500; i++)
    {
        p.Function = VirtualAllocEx;
        PVOID alloc = Spoof((PVOID)(-1), 0, 1024, MEM_COMMIT | MEM_RESERVE, &p, (PVOID)1, (PVOID)PAGE_EXECUTE_READWRITE);
        
        p.Function = pPrintf;
        Spoof("[+] Allocated to 0x%llx\n", alloc, NULL, NULL, &p, (PVOID)0);
    }

    // 2 stack arg
    
    for (int i = 0; i < 500; i++)
    {
        p.Function = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtAllocateVirtualMemory");
        PVOID alloc = NULL;
        SIZE_T size = 1024;
        PVOID base = NULL;
        Spoof((PVOID)(-1), &alloc, NULL, &size, &p, (PVOID)2, (PVOID)(MEM_COMMIT | MEM_RESERVE), (PVOID)PAGE_EXECUTE_READWRITE);

        p.Function = pPrintf;
        Spoof("[+] NtAllocated to 0x%llx\n", alloc, NULL, NULL, &p, (PVOID)0);
    }
    
    // indirect syscall
    p.ssn = 0x18;
    for (int i = 0; i < 500; i++)
    {
        p.Function = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtAllocateVirtualMemory");
        p.Function = (PBYTE)p.Function + 0x12;
        PVOID alloc = NULL;
        SIZE_T size = 1024;
        PVOID base = NULL;
        Spoof((PVOID)(-1), &alloc, NULL, &size, &p, (PVOID)2, (PVOID) (MEM_COMMIT | MEM_RESERVE), (PVOID) PAGE_EXECUTE_READWRITE);

        p.Function = pPrintf;
        Spoof("[+] Indirectly Allocated to 0x%llx\n", alloc, NULL, NULL, &p, (PVOID)0);
    }
    p.Function = gets_s;
    char* buffer = malloc(50);
    size_t size = 50;
    Spoof(buffer, size, NULL, NULL, &p, (PVOID) 0);
    
    int e = 0;
    int f = 0;
    int g = 0;
    
    /* Testing if stack args get modified */
    p.Function = bruh;
    Spoof((PVOID)0, (PVOID)0, (PVOID)0, (PVOID)0, &p, (PVOID)3, &e, &f, &g);
    printf("e: %d\n", e);
    printf("f: %d\n", f);
    printf("g: %d\n", g);
    
    printf("Cya\n");
    return 0; 
}