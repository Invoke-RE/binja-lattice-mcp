#include <stdio.h>

int global_var = 42;

int add(int a, int b) {
    int result = a + b;
    return result;
}

void print_message(const char* message) {
    printf("%s\n", message);
}

int main() {
    int local_var = 10;
    int sum = add(local_var, global_var);
    print_message("Hello, World!");
    return sum;
} 