# Lab1 Report

## 练习1
#### 生成kernel：

通过add_files_cc调用function.mk里定义的一些函数查找并编译/kern和/libs目录下的源代码，生成.o文件
```
$(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,$(KCFLAGS))
```

设定make target
```
KOBJS	= $(call read_packet,kernel libs)

kernel = $(call totarget,kernel)

$(kernel): tools/kernel.ld
```

待所有.o都编译完成后，使用-T指定tools/kernel.ld脚本连接所有.o文件、生成kernel
```
$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

$(call create_target,kernel)
```


#### 生成bootblock

通过listf_cc调用function.mk里面定义的一些函数查找并编译/boot下的源文件，生成.o。此处使用了-0s选项以减小bootblock大小。
```
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
```

设定make target
```
bootblock = $(call totarget,bootblock)
```


此段首先由于`$(call totarget,sign)`通过
```
$(call add_files_host,tools/sign.c,sign,sign)
$(call create_target_host,sign,sign)
```
生成sign工具

然后连接.o生成bootblock并通过调用sign打上签名。-N指定数据段和代码段均可读写，且关闭数据段页对齐；-e start指定入口；-Ttext 0x7c00指定代码段位置。
```
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
	@$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
	@$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
	@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)

$(call create_target,bootblock)
```

#### 生成ucore.img

设定make target
```
UCOREIMG	:= $(call totarget,ucore.img)
```

在kernel和bootblock生成后，这段生成ucore.img
首先生成一个10000个block的全0文件
然后把bootblock写到第一个block
然后从第二个block开始写kernel
```
$(UCOREIMG): $(kernel) $(bootblock)
	$(V)dd if=/dev/zero of=$@ count=10000
	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

$(call create_target,ucore.img)
```

## 练习2
#### 1.从CPU加电后执行的第一条指令开始，单步跟踪BIOS的执行。
#### 2.在初始化位置0x7c00设置实地址断点,测试断点正常。

只要修改/tools/gdbinit把`break kern_init`改为`break *0x7c00`即可通过`make debug`开始单步跟踪

可以得到类似一下的结果
```
0x0000fff0 in ?? ()
Breakpoint 1 at 0x7c00

Breakpoint 1, 0x00007c00 in ?? ()
(gdb) x/24i $pc  
=> 0x7c00:      cli    
   0x7c01:      cld    
   0x7c02:      xor    %eax,%eax
   0x7c04:      mov    %eax,%ds
   0x7c06:      mov    %eax,%es
   0x7c08:      mov    %eax,%ss
   0x7c0a:      in     $0x64,%al
   0x7c0c:      test   $0x2,%al
   0x7c0e:      jne    0x7c0a
   0x7c10:      mov    $0xd1,%al
   0x7c12:      out    %al,$0x64
   0x7c14:      in     $0x64,%al
   0x7c16:      test   $0x2,%al
   0x7c18:      jne    0x7c14
   0x7c1a:      mov    $0xdf,%al
   0x7c1c:      out    %al,$0x60
   0x7c1e:      lgdtl  (%esi)
   0x7c21:      insb   (%dx),%es:(%edi)
   0x7c22:      jl     0x7c33
   0x7c24:      and    %al,%al
   0x7c26:      or     $0x1,%ax
   0x7c2a:      mov    %eax,%cr0
   0x7c2d:      ljmp   $0xb866,$0x87c32
   0x7c34:      adc    %al,(%eax)
```

#### 3.从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与bootasm.S和 bootblock.asm进行比较。

由上面的输出结果可以看到反汇编结果基本和原来的汇编代码一样，但在`movl %cr0, %eax`处，变成了
```
   0x7c21:      insb   (%dx),%es:(%edi)
   0x7c22:      jl     0x7c33
   0x7c24:      and    %al,%al
```
原因不明

#### 4.自己找一个bootloader或内核中的代码位置，设置断点并进行测试。
只要修改/tools/gdbinit中的`break **breakpoint**`即可


## 练习3

首先关中断并将段寄存器清零
```
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
```

然后开A20，关闭4M地址回绕。
```
seta20.1:
    inb $0x64, %al
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al
    outb %al, $0x64

seta20.2:
    inb $0x64, %al
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al
    outb %al, $0x60
```

载入GDT
```
    lgdt gdtdesc
```

通过设置cr0进入保护模式
```
    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0
```

通过长跳转更新CS
```
    ljmp $PROT_MODE_CSEG, $protcseg
```

更新段寄存器
```
    movw $PROT_MODE_DSEG, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movl $0x0, %ebp
    movl $start, %esp
```

进入boot process
```
    call bootmain
```

## 练习4

首先读入硬盘第一扇区
```
readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);
```

readseg中调用了readsect进行实际的读取操作，具体过程如下
```
    waitdisk();                             // 等待磁盘空闲

    outb(0x1F2, 1);
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    // 上面五条指令指定了读取扇区数量和扇区号
    outb(0x1F7, 0x20);                      // 指定操作为读扇区

    waitdisk();

    insl(0x1F0, dst, SECTSIZE / 4);         // 把数据读取到内存dst位置
```

判断是否为合法的ELF格式
```
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }
```

依次载入ELF的各个段
```
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }
```

根据ELF头找到代码段，跳入kernel
```
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
```

## 练习5

主要利用了进行函数调用时会将主调函数的栈指针ebp压栈至栈顶，由此可以回溯调用栈。

输出如下
```
ebp:0x00007b18 eip:0x00100a36 args:0x00010094 0x00000000 0x00007b48 0x00100084 
    kern/debug/kdebug.c:306: print_stackframe+21
ebp:0x00007b28 eip:0x00100d33 args:0x00000000 0x00000000 0x00000000 0x00007b98 
    kern/debug/kmonitor.c:125: mon_backtrace+10
ebp:0x00007b48 eip:0x00100084 args:0x00000000 0x00007b70 0xffff0000 0x00007b74 
    kern/init/init.c:48: grade_backtrace2+19
ebp:0x00007b68 eip:0x001000a5 args:0x00000000 0xffff0000 0x00007b94 0x00000029 
    kern/init/init.c:53: grade_backtrace1+27
ebp:0x00007b88 eip:0x001000c1 args:0x00000000 0x00100000 0xffff0000 0x00100043 
    kern/init/init.c:58: grade_backtrace0+19
ebp:0x00007ba8 eip:0x001000e1 args:0x00000000 0x00000000 0x00000000 0x00103540 
    kern/init/init.c:63: grade_backtrace+26
ebp:0x00007bc8 eip:0x00100050 args:0x00000000 0x00000000 0x00010094 0x00000000 
    kern/init/init.c:28: kern_init+79
ebp:0x00007bf8 eip:0x00007d66 args:0xc031fcfa 0xc08ed88e 0x64e4d08e 0xfa7502a8 
    <unknow>: -- 0x00007d65 --
```

最后一行就是bootloader中的函数bootmain，ebp就是入口0x7c00前一个byte，且eip就在入口0x7c00后不远处。

## 练习6

#### 1.中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

一个表项有8个bytes，3~4字节是段选择子，1~2和7~8字节是offset，合并可得中断处理程序入口。

## 扩展练习 Challenge1

通过中断T_SWITCH_TOU和T_SWITCH_TOK来切换特权级。

首先是switch_to_user函数，预留了4bytes切换特权级的栈空间并压入esp后触发中断
```
movl %esp %eax
subl $0x4 %esp
pushl %eax
int T_SWITCH_TOU
```

在中断处理程序中修改栈的内容，填入发生了特权级转换时会压入栈的栈寄存器并修改已有栈寄存器为用户段。同时给予用户态IO权限
```
		tf->tf_cs = USER_CS;
		tf->tf_ds = tf->tf_es = tf->tf_fs = tf->tf_gs = tf->tf_ss = USER_DS;
		tf->tf_eflags |= 3 << 12;

```

switch_to_kernel也类似，不过因为从用户态触发中断本身就要切换特权级，所以不用预留空间了。
而在中断处理程序中，同样把段寄存器修改为内核段并关闭用户态IO权限即可。

## 与参考答案的比较

基本练习的实现与参考答案的思路是完全一样的。
扩展实验1中，我的实现是直接修改现有的栈数据，而参考答案似乎是新建了一个栈帧，然后在中断处理结束的时候再恢复栈指针。

## 知识点

本实验中，需要知道：
1. 实模式和保护模式的区别，保护模式的GDT等，及如何进入保护模式；
2. C风格函数调用栈的结构；
3. ELF格式；
4. 中断向量表及中断处理程序，特权级的转换；