.PHONY: main clean run all

all: main

main: main.cpp
	g++ main.cpp -o main -g

clean:
	rm main

run: main
	./main
