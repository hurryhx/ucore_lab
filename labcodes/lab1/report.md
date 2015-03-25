#Lab1 Report
-----
## Ex1
1. 操作系统镜像文件ucore.img是如何一步一步生成的？（需要比较详细地解释Makefile中每一条相关命令和命令参数的含义，以及说明命令导致的结果）
	```
	前言：各指令各参数意义在最后，正文注重逻辑梳理。

	生成ucore.img的直接指令如下
	$(UCOREIMG): $(kernel) $(bootblock)
		$(V)dd if=/dev/zero of=$@ count=10000
		$(V)dd if=$(bootblock) of=$@ conv=notrunc
		$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc
	可看出两个依赖为bootblock和kernel。

	生成bootblock
		$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
			@echo + ld $@
			$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
			@$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
			@$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
			@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
		其中bootfiles为/boot下的三个文件，sign为tools/sign.c的目标文件。

		生成obj/boot/bootasm.o和obj/boot/bootmain.o
			bootfiles = $(call listf_cc,boot)
			$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
			生成bootasm.o
				gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o
				需要boot/bootasm.S
			生成bootmain.o
				gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
				需要bootmain.c

		生成sign
			gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
			gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
			需要tools/sign.c

		ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
		连接生成bootblock.o。
		objdump -S obj/bootblock.o > obj/bootblock.asm
		反汇编bootblock.o到bootblock.asm。
		objcopy -S -O binary obj/bootblock.o obj/bootblock.out
		拷贝二进制代码到bootblock.out。
		bin/sign obj/bootblock.out bin/bootblock
		使用刚生成的sign，构建硬盘主引导扇区。

	生成kernel
		$(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,$(KCFLAGS))
		$(call add_files_cc,$(call listf_cc,$(LIBDIR)),libs,)
		KOBJS	= $(call read_packet,kernel libs)
		$(kernel): tools/kernel.ld
		$(kernel): $(KOBJS)
			@echo + ld $@
			$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
			@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
			@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

		KOBJS为kern和lib下各.c文件编译出来的.o文件
			init.o readline.o stdio.o kdebug.o kmonitor.o panic.o clock.o console.o intr.o picirq.o trap.o trapentry.o vectors.o pmm.o  printfmt.o string.o
		生成命令举例
			gcc -Ikern/init/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/init/init.c -o obj/kern/init/init.o
		然后通过ld连接各文件得到kernel.o

	生成含10000个0填充512bytes大小的块文件
	dd if=/dev/zero of=bin/ucore.img count=10000
	不截断把bootblock写入第一个块
	dd if=bin/bootblock of=bin/ucore.img conv=notrunc
	不截断把kernel写入第二个块
	dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
	最后得到ucore.img

	gcc各参数意义
		-I<dir>  添加搜索头文件的路径
		-m32  生成适用于32位环境的代码
		-ggdb 生成gdb调试信息
		-gstabs 生成stabs调试信息
		-fno-builtin  除非用__builtin_前缀，否则不进行builtin函数的优化
		-nostdinc 不使用标准库
		-fno-stack-protector 不检测缓冲区溢出
		-Os 控制代码大小
	ld各参数意义
		-m elf_i385 模拟i386连接器
		-nostdlib 不使用标准库
		-N 代码段和数据段均可读写
		-e 指定入口
		-Ttext 指定代码段开始位置
	objdump各参数意义
		-S 输出C源代码和反汇编出来的指令对照的格式
	objcopy各参数意义
		-S  移除所有符号和重定位信息
		-O <bfdname>  指定输出格式
	```

1. 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？

	> * 观察sign.c，要求读入文件长度为510字节，写入0x55和0xAA后变为512字节。
	> * 长度为512字节
	> * 倒数第二字节为0x55
	> * 最后一个字节为0xAA

## Ex2
1. 从CPU加电后执行的第一条指令开始，单步跟踪BIOS的执行。

	> * 删去tools/gdbinit最后一行，避免qemu在gdb连接后马上启动。
	> * 修改makefile。不希望X11来捣乱，qemu启动时置后台，gdb结束即kill掉进程。
	```
	debug-nox: $(UCOREIMG)
		$(V)$(QEMU) -S -s -d in_asm -D $(BINDIR)/q.log -serial mon:stdio -hda $< -nographic &
		$(V)sleep 2
		$(V)$(TERMINAL) -e "gdb -q -x tools/gdbinit"
		$(V)$(TERMINAL) -e "pkill qemu-system-i38"
	```
	> * 运行如下命令，si即可单步调试。
	```
		make debug-nox
	```

2. 在初始化位置0x7c00设置实地址断点,测试断点正常。

	> * 在tools/gdbinit最后加入一行
	```
		b *0x7c00
	```
	> * 运行以下指令可见汇编指令
	```
		make debug-nox
		c
		x /5i $pc
	```

3. 从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与bootasm.S和 bootblock.asm进行比较。

	> * 运行以下指令
	```
		make debug-nox
		c
		c
	```
	> * 可得bin/q.log部分内容如下
	```
		IN:
		0x00007c00:  cli
		0x00007c01:  cld
		0x00007c02:  xor    %ax,%ax
		0x00007c04:  mov    %ax,%ds
		0x00007c06:  mov    %ax,%es
		0x00007c08:  mov    %ax,%ss
		IN:
		0x00007c0a:  in     $0x64,%al
	```
	> * 比较得与bootasm.S和bootblock.asm一致。

4. 自己找一个bootloader或内核中的代码位置，设置断点并进行测试。

	> * 运行以下指令
	```
		make debug-nox
		b init.c:30
		c
	```

## Ex3
### 分析bootloader 进入保护模式的过程。

* 观察bootasm.S，从start开始。
* 首先初始化寄存器为0

	```
		cli                                             # Disable interrupts
		cld                                             # String operations increment
		# Set up the important data segment registers (DS, ES, SS).
		xorw %ax, %ax                                   # Segment number zero
		movw %ax, %ds                                   # -> Data Segment
		movw %ax, %es                                   # -> Extra Segment
		movw %ax, %ss                                   # -> Stack Segment
	```
* 然后使能A20，使32位地址线可用。
  先等待8042键盘控制器输入缓存为空，然后写入0x64表示要向P2端口写入数据。
  继续等待输入缓存为空，然后将0x60端口赋值为0xdf。
  这样A20位就赋值为1。

	```
			# Enable A20:
			#  For backwards compatibility with the earliest PCs, physical
			#  address line 20 is tied low, so that addresses higher than
			#  1MB wrap around to zero by default. This code undoes this.
		seta20.1:
			inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
			testb $0x2, %al
			jnz seta20.1

			movb $0xd1, %al                                 # 0xd1 -> port 0x64
			outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port

		seta20.2:
			inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
			testb $0x2, %al
			jnz seta20.2

			movb $0xdf, %al                                 # 0xdf -> port 0x60
			outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1

			# Switch from real to protected mode, using a bootstrap GDT
			# and segment translation that makes virtual addresses
			# identical to physical addresses, so that the
			# effective memory map does not change during the switch.
	```
* 初始化gdt表，使能cr0寄存器的PE位，从实模式进入保护模式

	```
		lgdt gdtdesc
		movl %cr0, %eax
		orl $CR0_PE_ON, %eax
		movl %eax, %cr0
	```
* 长跳转更新cs基地址

	```
		ljmp $PROT_MODE_CSEG, $protcseg
	```
* 设置段寄存器，并建立堆栈

	```
		.code32                                             # Assemble for 32-bit mode
		protcseg:
			# Set up the protected-mode data segment registers
			movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
			movw %ax, %ds                                   # -> DS: Data Segment
			movw %ax, %es                                   # -> ES: Extra Segment
			movw %ax, %fs                                   # -> FS
			movw %ax, %gs                                   # -> GS
			movw %ax, %ss                                   # -> SS: Stack Segment
			# Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
			movl $0x0, %ebp
			movl $start, %esp
	```
* 进入保护模式完成，进入bootmain

	```
		call bootmain
	```

## Ex 4
1. bootloader如何读取硬盘扇区的？

	> * 观察bootmain.c中的readsect
	> * 等待磁盘
	```
		waitdisk();
	```
	> * 读取数量设为1，32位磁盘号secno均分成四段，最高段强制为1110，写入0x20表示读扇区
	```
		outb(0x1F2, 1);                         // count = 1
		outb(0x1F3, secno & 0xFF);
		outb(0x1F4, (secno >> 8) & 0xFF);
		outb(0x1F5, (secno >> 16) & 0xFF);
		outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
		outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors
	```
	> * 等待磁盘
	```
		waitdisk();
	```
	> * 从0x1F0把扇区读取到dst指向的内存
	```
		insl(0x1F0, dst, SECTSIZE / 4);
	```

1. bootloader是如何加载ELF格式的OS？

	> * readseg函数根据offset算出扇区号与偏移，并利用readsect读取count字节内容到va。
	> * bootmain首先把磁盘第一页通过readseg读进，即ELF头部信息，并检查合法性
	```
		readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);
		// is this a valid ELF?
		if (ELFHDR->e_magic != ELF_MAGIC) {
			goto bad;
		}
	```
	> * 从每一段中找到被加载位置并通过readseg读进
	```
		ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
		eph = ph + ELFHDR->e_phnum;
		for (; ph < eph; ph ++) {
			readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
		}
	```
	> * 调用入口函数
	```
		((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
	```

## Ex5
* 根据提示补全代码即可，详见代码。
* 输出时发现不一定有STACKFRAME_DEPTH这么多的调用，应判断ebp是否为0。
* 本机输出如下
```
ebp:0x00007b18 eip:0x00100a18 args:0x00010094 0x00000000 0x00007b48 0x0010007f
    kern/debug/kdebug.c:306: print_stackframe+21
ebp:0x00007b28 eip:0x00100d15 args:0x00000000 0x00000000 0x00000000 0x00007b98
    kern/debug/kmonitor.c:125: mon_backtrace+10
ebp:0x00007b48 eip:0x0010007f args:0x00000000 0x00007b70 0xffff0000 0x00007b74
    kern/init/init.c:48: grade_backtrace2+19
ebp:0x00007b68 eip:0x001000a0 args:0x00000000 0xffff0000 0x00007b94 0x00000029
    kern/init/init.c:53: grade_backtrace1+27
ebp:0x00007b88 eip:0x001000bc args:0x00000000 0x00100000 0xffff0000 0x00100043
    kern/init/init.c:58: grade_backtrace0+19
ebp:0x00007ba8 eip:0x001000dc args:0x00000000 0x00000000 0x00000000 0x00103240
    kern/init/init.c:63: grade_backtrace+26
ebp:0x00007bc8 eip:0x00100050 args:0x00000000 0x00000000 0x00010094 0x00000000
    kern/init/init.c:28: kern_init+79
ebp:0x00007bf8 eip:0x00007d66 args:0xc031fcfa 0xc08ed88e 0x64e4d08e 0xfa7502a8
    <unknow>: -- 0x00007d65 --
```
* 最后一行，各数字意义
	* ebp表示bootmain栈底，bootloader设置堆栈起始地址为0x7c00，call bootmain后即为0x7bf8
	* eip表示返回地址
	* 其后四个为传入bootmain的参数，也可能并没有传入如此多的参数

## Ex6
1. 中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

	> * 观察kern/mm/mmu.h，gatedesc共占8字节大小
	> * 16~31位表示段描述符，0~15以及48~63位拼接表示偏移量，二者共同描述代码入口

2. 代码完善详见代码，根据提示完成即可
