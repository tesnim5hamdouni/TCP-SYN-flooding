all : synking 

synking : synking.c
	gcc synking.c -o synking -pthread

clean :
	rm -f synking
	
