.global atanl
atanl:
	fldt 8(%rsp)
	fld1
	fpatan
	ret
