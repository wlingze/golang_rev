# golang rev

一个ida的golang逆向插件。

## 功能

主要功能：

- 快速解析`.gopclntab`段恢复函数名， 并自动跳转到`mian_main`函数
- 通过指针头和长度快速设置字符串
- 快速进行指针重命名

## 使用

将golang_rev.py放到`/ida/plugins`目录下。

重新启动ida， 载入去符号的golang二进制文件，分析中多使用右键菜单中的功能。

开始享受快捷吧。:wink:

## 注意

在设置字符串时，调用`MakeStr`字符串， 在某些版本可能出现的问题， 通过修改对应python文件解决：

```python
# /ida/python/idc_bc695.py
# 原
def MakeStr(ea, endea): return create_strlit(ea, 0 if (endea) == ida_idaapi.BADADDR else endea-ea)
# 修改后
def MakeStr(ea, endea): return create_strlit(ea, endea)
```

## 声明：

此插件的uihook部分编写仿照[lazyida插件](https://github.com/L4ys/LazyIDA)。

## 演示

* 快速设置函数

![](https://i.loli.net/2020/07/22/mwXqKR8fHZcpbgT.gif)

* 设置字符串

![](https://i.loli.net/2020/07/22/nGMKN3Yxs5mgQC2.gif)

* 设置指针

![](https://i.loli.net/2020/07/22/WA9rXTsfoRmSCYv.gif)