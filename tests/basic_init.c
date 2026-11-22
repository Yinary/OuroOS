/* 自有集成启动器：程序列表由官方 run-all.sh 生成，不修改官方测例。 */
#include "unistd.h"
#include "stdio.h"
#include "basic_cases.h"
int main(void) {
    if (chdir("/basic") != 0) return 1;
    int failed = 0;
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        int pid = fork();
        if (pid == 0) {
            char *args[] = {(char *)cases[i], 0};
            char *env[] = {"PATH=/basic:/bin", 0};
            execve(cases[i], args, env);
            exit(127);
        }
        int status = -1;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || status != 0) {
            printf("BASIC CASE FAILED: %s status=%d\n", cases[i], status);
            failed++;
        }
    }
    printf("BASIC GROUP RESULT: %d failed\n", failed);
    return failed != 0;
}