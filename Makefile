src_dir = src
build_dir = build
target_dir = $(build_dir)/main
target = main

obj_files = \
	$(src_dir)/main.c
	
CC = gcc
CFLAGS =
LIBS = -lSDL2 -lSDL2_net -lsodium

all: build run

build: $(obj_files)
	mkdir -p $(target_dir)
	$(CC) $(obj_files) -o $(target_dir)/$(target) $(CFLAGS) $(LIBS)
	
run:
	cd $(target_dir); ./$(target)

clean:
	rm $(obj_files)
