#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
	for (;;) {
		int fd = open("./ready", O_WRONLY);
		if (fd < 0) {
			return 1;
		}
		close(fd);
	}
	return 0;
}
