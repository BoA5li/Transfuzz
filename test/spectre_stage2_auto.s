	.file	"spectre_stage2_auto.c"
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
	.local	stage2_cycles_array
	.comm	stage2_cycles_array,2400,32
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
	pushq	%rbx
	subq	$56, %rsp
	.cfi_offset 3, -24
	movq	%rdi, -56(%rbp)
	movl	$0, -36(%rbp)
	movq	-56(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC1(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
#APP
# 60 "spectre_stage2_auto.c" 1
	.globl STAGE2_BEGIN
STAGE2_BEGIN:
# 0 "" 2
# 61 "spectre_stage2_auto.c" 1
	rdtscp
	shl $32, %rdx
	or  %rdx, %rax
	mov %rax, %rsi
	cpuid
	
# 0 "" 2
#NO_APP
	movq	%rsi, -32(%rbp)
	movl	array1_size(%rip), %eax
	movl	%eax, %eax
	cmpq	%rax, -56(%rbp)
	jnb	.L2
.L2:
#APP
# 72 "spectre_stage2_auto.c" 1
	rdtscp
	shl $32, %rdx
	or  %rdx, %rax
	mov %rax, %rsi
	cpuid
	
# 0 "" 2
#NO_APP
	movq	%rsi, -24(%rbp)
#APP
# 80 "spectre_stage2_auto.c" 1
	.globl STAGE2_END
STAGE2_END:
# 0 "" 2
#NO_APP
	movq	-24(%rbp), %rax
	subq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	record_stage2_cycle
	nop
	addq	$56, %rsp
	popq	%rbx
	popq	%rbp
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
	movl	$299, -28(%rbp)
	jmp	.L4
.L7:
	movl	-28(%rbp), %eax
	cltd
	shrl	$31, %edx
	addl	%edx, %eax
	andl	$1, %eax
	subl	%edx, %eax
	cltq
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
	cmpl	$199, %eax
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
	.globl	cycle_i
	.bss
	.align 4
	.type	cycle_i, @object
	.size	cycle_i, 4
cycle_i:
	.zero	4
	.text
	.globl	record_stage2_cycle
	.type	record_stage2_cycle, @function
record_stage2_cycle:
.LFB3925:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movl	cycle_i(%rip), %eax
	leal	1(%rax), %edx
	movl	%edx, cycle_i(%rip)
	cltq
	leaq	0(,%rax,8), %rcx
	leaq	stage2_cycles_array(%rip), %rax
	movq	-8(%rbp), %rdx
	movq	%rdx, (%rcx,%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3925:
	.size	record_stage2_cycle, .-record_stage2_cycle
	.section	.rodata
	.align 8
.LC2:
	.string	"STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n"
	.align 8
.LC3:
	.string	"STAGE2_DELTA_CACGE_MISS_COND[%d]=%llu\n"
.LC4:
	.string	"STAGE2_DELTA_CYCLE_[%d]=%llu\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB3926:
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
	movl	$0, -32(%rbp)
	jmp	.L10
.L11:
	movl	-32(%rbp), %eax
	movslq	%eax, %rdx
	leaq	array2(%rip), %rax
	movb	$1, (%rdx,%rax)
	addl	$1, -32(%rbp)
.L10:
	cmpl	$131071, -32(%rbp)
	jle	.L11
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	stage1_mistrain_trigger
	call	pmu_stage1_get_count@PLT
	movl	%eax, -16(%rbp)
	movl	$0, -28(%rbp)
	jmp	.L12
.L13:
	movl	-28(%rbp), %eax
	movl	%eax, %edi
	call	pmu_stage1_get_delta@PLT
	movq	%rax, %rdx
	movl	-28(%rbp), %eax
	movl	%eax, %esi
	leaq	.LC2(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	addl	$1, -28(%rbp)
.L12:
	movl	-28(%rbp), %eax
	cmpl	-16(%rbp), %eax
	jl	.L13
	call	pmu_stage2_get_count@PLT
	movl	%eax, -12(%rbp)
	movl	$0, -24(%rbp)
	jmp	.L14
.L15:
	movl	-24(%rbp), %eax
	movl	%eax, %edi
	call	pmu_stage2_get_delta@PLT
	movq	%rax, %rdx
	movl	-24(%rbp), %eax
	movl	%eax, %esi
	leaq	.LC3(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	addl	$1, -24(%rbp)
.L14:
	movl	-24(%rbp), %eax
	cmpl	-12(%rbp), %eax
	jl	.L15
	movl	$0, -20(%rbp)
	jmp	.L16
.L17:
	movl	-20(%rbp), %eax
	cltq
	leaq	0(,%rax,8), %rdx
	leaq	stage2_cycles_array(%rip), %rax
	movq	(%rdx,%rax), %rdx
	movl	-20(%rbp), %eax
	movl	%eax, %esi
	leaq	.LC4(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	addl	$1, -20(%rbp)
.L16:
	cmpl	$299, -20(%rbp)
	jle	.L17
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3926:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
