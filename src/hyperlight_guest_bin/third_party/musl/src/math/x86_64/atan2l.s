.global atan2l
atan2l:
	fldt 8(%rsp)
	fldt 24(%rsp)
	fpatan
	ret
