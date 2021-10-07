all:
	gcc -o gtp_method_1 gtp_method_1.c -lm -lssl -lcrypto `mysql_config --cflags --libs`
	gcc -o gtp_method_2 gtp_method_2.c -lm -lssl -lcrypto `mysql_config --cflags --libs`
	gcc -o gtp_method_3 gtp_method_3.c -lm -lssl -lcrypto `mysql_config --cflags --libs`
clean:
	rm gtp_method_1 gtp_method_2 gtp_method_3
 
