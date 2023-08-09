#include <fcntl.h>
#include <unistd.h>
int main(int argc, char *argv[]){
	int fd = open("./ready", O_RDONLY);
	return fd < 0 ? 1 : 0;
}
