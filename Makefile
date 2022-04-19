all: client server

client:
	gcc client.c -o client -pthread
server:
	gcc server.c -o server -pthread
clean:
	rm -f hala
