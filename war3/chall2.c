#include <stdio.h>

int main(int argc, char *argv[]) {
    int i = 0;
    while (i <= 9) {
        if (i % 2 != 0) {
            printf("%d\n", i); //guessed format string
        } 
        i += 1;
    }
    return 1;
}