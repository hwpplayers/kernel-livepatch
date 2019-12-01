#ifdef CONFIG_X86_64

.section .rodata

.global klp_xen_int3_stub_templ_begin
.global klp_xen_int3_stub_templ_end
.global klp_xen_int3_stub_templ_jmp_reloc

klp_xen_int3_stub_templ_begin:
	/* See xen_pv_trap macro from the Linux kernel */
	pop  %rcx
	pop %r11

	/* jmp insn, the address will be relocated */
	.byte 0xe9
klp_xen_int3_stub_templ_jmp_reloc:
	.int 0xdecafbad
klp_xen_int3_stub_templ_end:

#endif
