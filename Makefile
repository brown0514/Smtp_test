all:
	gcc hala.c -o hala -pthread
clean:
	rm -f hala
