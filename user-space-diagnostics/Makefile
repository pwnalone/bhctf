shell: shell.c
	gcc -Os -static -o $@ $<

small: shell
	upx -9 -o $@ $<
