#include <stdio.h>

extern int re_this(int arg1,int arg2);

int main() {
	int ans = re_this(5, 6);
	printf("%d\n", ans);
	return 0;
}