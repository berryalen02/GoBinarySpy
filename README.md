目前比较完整的实现了自动化的项目，可以看@yj94的BinarySpy，他写的比我快，下次一定比他快🤯
我这个开个坑，目前实现了稳定的指定FA patch有机会慢慢研究与优化自动化的实现。
# 用法

```
go run .\BinarySpy.go -h                                                                      
   _____       ____  _                         _____             
  / ____|     |  _ \(_)                       / ____|
 | |  __  ___ | |_) |_ _ __   __ _ _ __ _   _| (___  _ __  _   _
 | | |_ |/ _ \|  _ <| | '_ \ / _` | '__| | | |\___ \| '_ \| | | |
 | |__| | (_) | |_) | | | | | (_| | |  | |_| |____) | |_) | |_| |
  \_____|\___/|____/|_|_| |_|\__,_|_|   \__, |_____/| .__/ \__, |
                                         __/ |      | |     __/ |
                                        |___/       |_|    |___/
by https://github.com/berryalen02/BinarySpy
Usage: patcher -file <file_path> -patch <new_content|bin_file> [-fa <fa>] [-symbol <symbol>] [-bin] [-author <author>]

Options:
  -bin
        是否为bin文件
  -fa string
        文件偏移FA
  -file string
        目标PE文件
  -h    help
  -patch string
        shellcode
  -symbol string
        PE的导出函数
```
# 示例
文件夹example中提供了白文件和calc.bin，执行以下命令即可成功patch源文件（64位）
```BASH
go run .\BinarySpy.go -fa 0xAF3B0 -file .\example\bugreport.exe -patch .\example\calc.bin -bin
```
