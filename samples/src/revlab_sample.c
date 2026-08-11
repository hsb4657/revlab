#include <windows.h>
#include <stdio.h>
#include <string.h>

/* REVLab 自研合规测试样本:展示典型的 PE 特征 */
static int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

static void make_request(void) {
    /* 模拟网络初始化(仅触发导入,不实际外联) */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    WSACleanup();
}

int main(void) {
    char buf[128];
    int sum = 0;
    for (int i = 0; i < 10; i++) sum += fibonacci(i);
    snprintf(buf, sizeof(buf), "REVLab test sample: fib sum=%d", sum);
    MessageBoxA(NULL, buf, "REVLab", MB_OK | MB_ICONINFORMATION);
    make_request();
    return 0;
}
