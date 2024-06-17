#include<stdlib.h>
#include <stdio.h>
#include <unistd.h>

char *chunk_list[0x100];

void menu() {
    puts("1. add chunk");
    puts("2. delete chunk");
    puts("3. edit chunk");
    puts("4. show chunk");
    puts("5. exit");
    puts("choice:");
}

int get_num() {
    char buf[0x10];
    read(0, buf, sizeof(buf));
    return atoi(buf);
}

void add_chunk() {
    puts("index:");
    int index = get_num();
    puts("size:");
    int size = get_num();
    chunk_list[index] = malloc(size);
}

void delete_chunk() {
    puts("index:");
    int index = get_num();
    free(chunk_list[index]);
}

void edit_chunk() {
    puts("index:");
    int index = get_num();
    puts("length:");
    int length = get_num();
    puts("content:");
    read(0, chunk_list[index], length);
}

void show_chunk() {
    puts("index:");
    int index = get_num();
    puts(chunk_list[index]);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        menu();
        switch (get_num()) {
            case 1:
                add_chunk();
                break;
            case 2:
                delete_chunk();
                break;
            case 3:
                edit_chunk();
                break;
            case 4:
                show_chunk();
                break;
            case 5:
                exit(0);
            default:
                puts("invalid choice.");
        }
    }
}
