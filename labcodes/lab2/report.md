#Lab2 Report
-----
## Ex1
1. 实现first-fit连续物理内存分配算法。

	> * 阅读memlayout.h了解Page结构体的各类成员变量及使用方法
	> * default_init_memap
		* 初始化从base开始的n页
		* 第一页特殊处理，并最后并入free_list
	> * default_alloc_pages
		* 找第一个满足大小的块分配空间
		* free_list从头开始遍历，第一个大小>n的块即为所求
		* 若最后仍有剩余空间，新建块并维护free_list
	> * default_free_pages
		* 从base开始释放n页
		* 先遍历n页释放空间
		* 再寻找free_list中应插入的位置
		* 插入free_list，并在可以的时候合并前驱后继
	> * 具体实现见代码

1. 你的first fit算法是否有进一步的改进空间？

	> * 使用平衡树维护free_list
	> * 则查询、插入、删除均可做到O(logn)的复杂度

## Ex2
1. 实现寻找虚拟地址对应的页表项。

	> * 根据页目录基地址和一级索引找到页目录项
		* 如果发生缺失，那新建对应页表
	> * 根据页目录项得到耳机页表基地址，结合二级索引得到二级页表项
	> * 具体实现见代码

1. 请描述页目录项（Pag Director Entry）和页表项（Page Table Entry）中每个组成部分的含义和以及对ucore而言的潜在用处。

	> * PDE共32位，前20位对应页表物理地址前20位，后12位包含该页目录项的访问位、可写位等，详见mmu.h。
	> * PTE共32位，前20位对应页帧物理地址前20位，后12位包含该页表项的访问位、可写位等，详见mmu.h。
	> * 了解他们的区别与相似之处，有助于我们在编写ucore代码时保持清晰思路，计算正确的地址以及判断合法性等。

1. 如果ucore执行过程中访问内存，出现了页访问异常，请问硬件要做哪些事情？

	> * 执行中断，权限交由操作系统，在内存与硬盘间交换数据。

## Ex3
1. 释放某虚地址所在的页并取消对应二级页表项的映射。

	> * 根据提示完成代码即可
	> * 先转换页目录项到Page结构体，再减少引用，并在零引用时释放该结构体，最后标记上不合法即可
	> * 具体实现见代码

1. 数据结构Page的全局变量（其实是一个数组）的每一项与页表中的页目录项和页表项有无对应关系？如果有，其对应关系是啥？

	> * 若该页没有被分配，则没有对应关系
	> * 若该页已被分配，则有。
		* Page是物理页，与逻辑地址一一对应，数值上相差恒定的偏移值。

1. 如果希望虚拟地址与物理地址相等，则需要如何修改lab2，完成此事？

	> * 在alloc_page中传入虚拟地址，使其分配或替换相等物理地址的页。

## 与标准答案的差异
* Ex1中实现思路与标准答案差不多，实现稍有不同。
* Ex2和Ex3基本相同。

## 本实验中重要的知识点
* 使用了最先分配的空闲内存分配算法。
* 页结构的原理和实现，并更为具体地阐释了页目录项、页表项等的关系。

## OS原理中很重要但在实验中没有对应上的知识点
* 没有涉及段机制

