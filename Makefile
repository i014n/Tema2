build: so_stdio.dll

so_stdio.dll: so_stdio.obj
	link /dll /out:so_stdio.dll /implib:so_stdio.obj so_stdio.obj
so_stdio.obj:
	cl /c so_stdio.c