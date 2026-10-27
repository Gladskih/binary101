extern volatile int ehCounter;

void ehMayThrow() { ++ehCounter; }
