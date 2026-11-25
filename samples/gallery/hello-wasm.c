__attribute__((import_module("env"), import_name("log_message")))
extern void log_message(const char *message, unsigned length);

void greet(void) {
    static const char message[] = "Hello, world!";
    log_message(message, sizeof(message) - 1);
}
