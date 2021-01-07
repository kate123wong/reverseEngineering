## 目的：改变notepad++的字体颜色/字体等。

## 第一步：查看导入表，初步筛选可改变字体颜色的函数

1、找到notepad++程序的位置，查看[导入表](./notepad++_imports.txt)。

```
1、notepad++程序的位置：
C:\Windows\System32\notepad.exe

2、查看导入表：
vs powershell 执行：
cd C:\Windows\System32\
dumpbin /imports .\notepad++.exe > D:\notepad_imports.txt
```

![image-20210103174545122](images/image-20210103174545122.png)

2、找到导入表中与颜色有关的API。

```
 GDI32.dll!2A6 SetTextColor
 USER32.dll!17E GetSysColorBrush
 USER32.dll!17E GetSysColor
```

依次对三个与图像相关的函数进行查阅文档:

+ [SetTextColor](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-settextcolor)：SetTextColor是对 [TextOut](https://docs.microsoft.com/en-us/windows/desktop/api/wingdi/nf-wingdi-textouta) and [ExtTextOut](https://docs.microsoft.com/en-us/windows/desktop/api/wingdi/nf-wingdi-exttextouta) 两个函数所写的字符进行渲染！！（需要验证notepad++页面渲染的时候是否是由这个函数）

```
COLORREF SetTextColor(
  HDC      hdc,
  COLORREF color
);
```

+ [GetSysColorBrush](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsyscolorbrush) ：检索指定颜色对应的全局逻辑刷的句柄

```
HBRUSH GetSysColorBrush(
  int nIndex
);
```

+ [GetSysColor](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsyscolor)：检索指定显示元素的当前颜色。显示元素是窗口和显示在系统显示屏上的部分。

```
DWORD GetSysColor(
  int nIndex
);
```

## 第二步：使用Windbg调试SetTextColor函数

1、学习Windbg相关内容，见附1。

2、对函数SetTextColor下断点调试，看是否可以改变字体颜色。

+ 所使用的命令：

  ```
  bp gdi32!SetTextColor  "r rdx = DC143C;g"  # 在x64框架下，rdx存放函数的第二个参数。
  ```

+ 效果如下：

  ![image-20210107164457721](images/image-20210107164457721.png)

+ 该过程中遇到如下错误：尝试使用`eb`写入寄存器值时出错。

  ![image-20210107120754784](images/image-20210107120754784.png)

  + `mov qword ptr [rsp+8],rbx` : 该命令的意思是将寄存器`rbx`里面的值写入`rsp+8`。（其原因是：[在 Win64 下，会为每个参数保留一份用来传递的 stack 空间，以便**回写** caller 的 stack](https://blog.csdn.net/a1875566250/article/details/11619637)）
  + 最后采用`r`指令代替`eb`指令。

## 第三步  



## 附录

###  附1 Windbg学习

+ `lm` :查看所有的模块，以及模块信息。

  如图，

  ![image-20210107104945587](images/image-20210107104945587.png)

+ `r`： 查看当前的寄存器信息。

  ![image-20210107105418143](images/image-20210107105418143.png)

###  命令表达式

+ 两种可用的表达式
  + c++表达式：@@c++()
  + MASM(宏汇编表达式)：@@masm()

+ `.expr` :  可以查看当前的表达式类型

  ![image-20210107111018057](images/image-20210107111018057.png)

+ MASM 表达式
  + 运算符： `+、-、*、/、>>、<<、>>>、>=、<=、==、=、!=、^（或xor）、按位与&(或and)、按位或|(或or)、正负号`。
  + 特殊运算符：`poi(取地址)、lo、hi、by、wo、dwo、qwo`。
  + 类函数运算符：`$scmp()、 $sicmp()、 $spat()`
  + bp `[模块名!]Filename[:LineNumber]`

+ 数字

  + 宏汇编表达式默认是十六进制；c++表达式默认是十进制。

    下图中，`?`表示使用宏汇编表达式，43是十六进制，windbg将其转成10进制是67。

    ![image-20210107112448374](images/image-20210107112448374.png)

    下图的`??`表示c++表达式，22即为十进制22。

    ![image-20210107112607060](images/image-20210107112607060.png)

    