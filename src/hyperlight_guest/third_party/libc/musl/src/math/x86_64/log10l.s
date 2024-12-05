.global log10l
log10l:
	fldlg2
	fldt 8(%rsp)
	fyl2x
	ret
