package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Function struct {
	Name    string
	Address uint64
	Size    uint64
}

func main() {
	exePath := ".\\WeMeetCrashHandler.exe"
	outputFilePath := "objdump_output.txt"

	// 运行 objdump 并将输出重定向到文件
	cmd := exec.Command("objdump", "-d", exePath)
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	cmd.Stdout = outputFile
	if err := cmd.Run(); err != nil {
		panic(err)
	}

	// 解析 objdump 输出文件
	functions, err := parseObjdumpOutput(outputFilePath)
	if err != nil {
		panic(err)
	}

	// 查找 main 或 WinMain 函数并解析其调用的函数
	mainFunc := findFunctionByName(functions, "main")
	if mainFunc == nil {
		mainFunc = findFunctionByName(functions, "WinMain")
	}
	if mainFunc == nil {
		panic("main or WinMain function not found")
	}

	calledFunctions := findCalledFunctions(mainFunc, functions)

	// 输出 main 或 WinMain 函数调用的函数信息
	for _, function := range calledFunctions {
		fmt.Printf("Called Function: %s\n", function.Name)
		fmt.Printf("Address: 0x%x\n", function.Address)
		fmt.Printf("Size: %d\n", function.Size)
	}
}

func parseObjdumpOutput(filePath string) ([]Function, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var functions []Function
	var currentFunction *Function

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Disassembly of section") {
			continue
		}

		if strings.HasPrefix(line, "0000") {
			if currentFunction != nil {
				functions = append(functions, *currentFunction)
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				address, _ := strconv.ParseUint(parts[0], 16, 64)
				name := parts[1]
				currentFunction = &Function{Name: name, Address: address}
			}
		} else if currentFunction != nil {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				size, _ := strconv.ParseUint(parts[0], 16, 64)
				currentFunction.Size += size
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if currentFunction != nil {
		functions = append(functions, *currentFunction)
	}

	return functions, nil
}

func findFunctionByName(functions []Function, name string) *Function {
	for _, function := range functions {
		if function.Name == name {
			return &function
		}
	}
	return nil
}

func findCalledFunctions(mainFunc *Function, functions []Function) []Function {
	var calledFunctions []Function
	for _, function := range functions {
		if function.Address > mainFunc.Address && function.Address < mainFunc.Address+mainFunc.Size {
			calledFunctions = append(calledFunctions, function)
		}
	}
	return calledFunctions
}
