# 用法

```
go run .\BinarySpy.go -h                                                                      
  ____  _                        ____              
 | __ )(_)_ __   __ _ _ __ _   _/ ___| _ __  _   _
 |  _ \| | '_ \ / _` | '__| | | \___ \| '_ \| | | |
 | |_) | | | | | (_| | |  | |_| |___) | |_) | |_| |
 |____/|_|_| |_|\__,_|_|   \__, |____/| .__/ \__, |
                           |___/      |_|    |___/

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
文件夹example中提供了白文件和calc.bin，执行以下命令即可成功patch源文件
```BASH
go run .\BinarySpy.go -fa 0xAF3B0 -file .\example\bugreport.exe -patch .\example\calc.bin -bin
```