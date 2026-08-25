	.file	"spectre_stage_auto.c"
	.text
	.globl	array1_size
	.data
	.align 4
	.type	array1_size, @object
	.size	array1_size, 4
array1_size:
	.long	16
	.comm	unused1,64,32
	.globl	array1
	.align 32
	.type	array1, @object
	.size	array1, 160
array1:
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	16
	.zero	144
	.comm	unused2,64,32
	.comm	array2,131072,32
	.globl	secret
	.section	.rodata
.LC0:
	.string	"Y"
	.section	.data.rel.local,"aw",@progbits
	.align 8
	.type	secret, @object
	.size	secret, 8
secret:
	.quad	.LC0
	.globl	temp
	.bss
	.type	temp, @object
	.size	temp, 1
temp:
	.zero	1
	.section	.rodata
.LC1:
	.string	"spectre_function: x=%zu\n"
	.text
	.globl	spectre_function
	.type	spectre_function, @function
spectre_function:
.LFB3923:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC1(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	.globl STAGE1_BEGIN
STAGE1_BEGIN:
	call pmu_stage1_before
	nop
.L2:
	.globl STAGE1_END
STAGE1_END:
	call pmu_stage1_after
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3923:
	.size	spectre_function, .-spectre_function
	.globl	stage1_mistrain_trigger
	.type	stage1_mistrain_trigger, @function
stage1_mistrain_trigger:
.LFB3924:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movq	%rdi, -40(%rbp)
	movl	$59, -28(%rbp)
	jmp	.L4
.L7:
	movl	-28(%rbp), %eax
	movl	array1_size(%rip), %ecx
	movl	$0, %edx
	divl	%ecx
	movl	%edx, %eax
	movl	%eax, %eax
	movq	%rax, -24(%rbp)
	leaq	array1_size(%rip), %rax
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	clflush	(%rax)
	movl	$0, -32(%rbp)
	jmp	.L5
.L6:
	movl	-32(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -32(%rbp)
.L5:
	movl	-32(%rbp), %eax
	cmpl	$99, %eax
	jle	.L6
	movl	-28(%rbp), %ecx
	movl	$1717986919, %edx
	movl	%ecx, %eax
	imull	%edx
	sarl	$2, %edx
	movl	%ecx, %eax
	sarl	$31, %eax
	subl	%eax, %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	subl	%eax, %ecx
	movl	%ecx, %edx
	leal	-1(%rdx), %eax
	movw	$0, %ax
	cltq
	movq	%rax, -16(%rbp)
	movq	-16(%rbp), %rax
	shrq	$16, %rax
	orq	%rax, -16(%rbp)
	movq	-40(%rbp), %rax
	xorq	-24(%rbp), %rax
	andq	-16(%rbp), %rax
	xorq	-24(%rbp), %rax
	movq	%rax, -16(%rbp)
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	spectre_function
	subl	$1, -28(%rbp)
.L4:
	cmpl	$0, -28(%rbp)
	jns	.L7
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3924:
	.size	stage1_mistrain_trigger, .-stage1_mistrain_trigger
	.section	.rodata
	.align 8
.LC2:
	.string	"STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB3925:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movl	%edi, -36(%rbp)
	movq	%rsi, -48(%rbp)
	movq	secret(%rip), %rax
	movq	%rax, %rdx
	leaq	array1(%rip), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	movq	%rax, -8(%rbp)
	movl	$0, -20(%rbp)
	jmp	.L9
.L10:
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	leaq	array2(%rip), %rax
	movb	$1, (%rdx,%rax)
	addl	$1, -20(%rbp)
.L9:
	cmpl	$131071, -20(%rbp)
	jle	.L10
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movq	%rax, %rdi
	call	stage1_mistrain_trigger
	call	pmu_stage1_get_count@PLT
	movl	%eax, -12(%rbp)
	movl	$0, -16(%rbp)
	jmp	.L11
.L12:
	movl	-16(%rbp), %eax
	movl	%eax, %edi
	call	pmu_stage1_get_delta@PLT
	movq	%rax, %rdx
	movl	-16(%rbp), %eax
	movl	%eax, %esi
	leaq	.LC2(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	addl	$1, -16(%rbp)
.L11:
	movl	-16(%rbp), %eax
	cmpl	-12(%rbp), %eax
	jl	.L12
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3925:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
