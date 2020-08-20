all:	galaxy_dll_inject_privesc.exe galaxy_dll_inject_privesc.dll

galaxy_dll_inject_privesc.dll:	galaxy_dll_inject_privesc_dll.c
	i686-w64-mingw32-gcc -Wall -s -shared -o galaxy_dll_inject_privesc.dll galaxy_dll_inject_privesc_dll.c -lws2_32 -lbcrypt

galaxy_dll_inject_privesc.exe:	galaxy_dll_inject_privesc.c
	i686-w64-mingw32-gcc -Wall -s -o galaxy_dll_inject_privesc.exe galaxy_dll_inject_privesc.c -lpsapi

zip:	all
	rm -f gog_galaxy_updated_poc.zip gog_galaxy_updated_poc_v2.zip
	zip gog_galaxy_updated_poc_v2.zip galaxy_dll_inject_privesc.c galaxy_dll_inject_privesc_dll.c galaxy_dll_inject_privesc.exe galaxy_dll_inject_privesc.dll Makefile README.txt

clean:
	rm -f *~ *.exe *.dll gog_galaxy_updated_poc.zip gog_galaxy_updated_poc_v2.zip
