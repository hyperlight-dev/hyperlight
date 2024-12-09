.global floorl
floorl:
	fldt 8(%rsp)
1:	mov $0x7,%al
1:	fstcw 8(%rsp)
	mov 9(%rsp),%ah
	mov %al,9(%rsp)
	fldcw 8(%rsp)
	frndint
	mov %ah,9(%rsp)
	fldcw 8(%rsp)
	ret

.global ceill
ceill:
	fldt 8(%rsp)
	mov $0xb,%al
	jmp 1b

.global truncl
truncl:
	fldt 8(%rsp)
	mov $0xf,%al
	jmp 1b
