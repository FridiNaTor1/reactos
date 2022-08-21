
#include <asm.inc>
#include <ksamd64.inc>

.code64

EXTERN RtlCaptureContext:PROC
EXTERN check:PROC

PUBLIC continuePoint
.PROC continuePoint

    // Allocate space for a CONTEXT structure
    .ALLOCSTACK CONTEXT_FRAME_LENGTH + 8
    .ENDPROLOG

    // Capture the current CONTEXT
    mov rcx, rsp
    call RtlCaptureContext

//    mov rax, dr0
//    mov [rsp + CxDr0], rax

    // Call the function that will compare the current context with the expected one
    cld
    mov rcx, rsp
    call check

    // check() must not return
    int 3

.ENDP

// EOF
END
