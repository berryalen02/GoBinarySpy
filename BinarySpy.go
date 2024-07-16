package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	peparser "github.com/saferwall/pe"
)

type PEHeader struct {
	Signature      uint32
	FileHeader     peparser.ImageFileHeader
	OptionalHeader peparser.ImageOptionalHeader64
}

type SectionHeader struct {
	Name                 [8]byte
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
	StartFA uint32
	EndFA   uint32
	Size    uint32
}

func ParsePEFile(filePath string) (PEHeader, []SectionHeader, error) {
	// 读取文件内容
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to read file: %v", err)
	}

	// 创建PE对象
	pe, err := peparser.NewBytes(data, &peparser.Options{})
	if err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to create PE object: %v", err)
	}

	// 解析PE文件
	err = pe.Parse()
	if err != nil {
		return PEHeader{}, nil, fmt.Errorf("failed to parse PE file: %v", err)
	}

	// 获取节区数量
	numSections := pe.NtHeader.FileHeader.NumberOfSections
	fmt.Printf("Number of Sections: %d\n", numSections)

	// 计算节区表的文件偏移量
	const sizeOfFileHeader = 20
	optionalHeaderSize := pe.NtHeader.FileHeader.SizeOfOptionalHeader
	sectionHeadersOffset := int64(pe.DOSHeader.AddressOfNewEXEHeader) + 4 + int64(sizeOfFileHeader) + int64(optionalHeaderSize)
	fmt.Printf("Section Headers Offset: %d\n", sectionHeadersOffset)

	// 这里是和后面的根据导出函数
	/*	// 类型断言 OptionalHeader
		var optionalHeader peparser.ImageOptionalHeader64
		switch oh := pe.NtHeader.OptionalHeader.(type) {
		case *peparser.ImageOptionalHeader64:
			optionalHeader = *oh
		case *peparser.ImageOptionalHeader32:
			return PEHeader{}, nil, fmt.Errorf("32-bit PE files are not supported")
		default:
			return PEHeader{}, nil, fmt.Errorf("unexpected optional header type")
		}*/

	// 构造返回值
	peHeader := PEHeader{
		Signature:  pe.NtHeader.Signature,
		FileHeader: pe.NtHeader.FileHeader,
		// OptionalHeader: optionalHeader,
	}

	sectionHeaders := make([]SectionHeader, numSections)
	for i := 0; i < int(numSections); i++ {
		section := pe.Sections[i]
		sectionHeaders[i] = SectionHeader{
			Name:                 section.Header.Name,
			VirtualSize:          section.Header.VirtualSize,
			VirtualAddress:       section.Header.VirtualAddress,
			SizeOfRawData:        section.Header.SizeOfRawData,
			PointerToRawData:     section.Header.PointerToRawData,
			PointerToRelocations: section.Header.PointerToRelocations,
			PointerToLinenumbers: section.Header.PointerToLineNumbers,
			NumberOfRelocations:  section.Header.NumberOfRelocations,
			NumberOfLinenumbers:  section.Header.NumberOfLineNumbers,
			Characteristics:      section.Header.Characteristics,
		}
	}

	return peHeader, sectionHeaders, nil
}

/*// FindFunctions 遍历所有函数，并把他们记录在册
func FindFunctions(data []byte, peHeader PEHeader, sectionHeaders []SectionHeader) ([]Function, error) {
	var functions []Function

	// 寻找 call 和 ret 两条命令
	for _, section := range sectionHeaders {
		sectionData := data[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]
		reader := bytes.NewReader(sectionData)
		var startFA, endFA uint32
		for {
			// 读取此刻opcode
			var opcode byte
			if err := binary.Read(reader, binary.LittleEndian, &opcode); err != nil {
				break
			}
			offset, err := reader.Seek(0, os.SEEK_CUR)
			if err != nil {
				break
			}
			// 此时opcode为call，再读取下四个字节就是相对偏移
			// 小端序，所以减一
			offset -= 1
			if opcode == 0xE8 { // call指令
				var relAddr int32
				if err := binary.Read(reader, binary.LittleEndian, &relAddr); err != nil {
					break
				}
				// 计算绝对地址，call+相对地址（1+4 bytes）
				callAddr := uint32(offset + 5 + int64(relAddr))
				// 将VA转化为FA
				startFA, _ = VAtoFileOffset(peHeader, sectionHeaders, uint64(callAddr))
			} else if opcode == 0xC3 { // ret 指令
				endFA = section.PointerToRawData + uint32(offset)
				if startFA != 0 && endFA != 0 {
					functions = append(functions, Function{
						StartFA: startFA,
						EndFA:   endFA,
						Size:    endFA - startFA,
					})
					startFA, endFA = 0, 0
				}
			}
		}
	}

	return functions, nil
}*/

// 找所有匹配的函数片段
func FindFunctions(data []byte, peHeader PEHeader, sectionHeaders []SectionHeader) ([]Function, error) {
	var functions []Function

	for _, section := range sectionHeaders {
		// 检查是否为 .text 段
		if string(section.Name[:5]) != ".text" {
			continue
		}

		if section.PointerToRawData+section.SizeOfRawData > uint32(len(data)) {
			return nil, fmt.Errorf("section size exceeds file size")
		}

		sectionData := data[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]
		reader := bytes.NewReader(sectionData)
		var startFA, endFA uint32
		flag := false
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
			// 小端序，往后四字节，即call xxxxxxxx相对偏移地址
			offset -= 1
			if opcode == 0xE8 && flag == false {
				flag = true
				var relAddr int32
				if err := binary.Read(reader, binary.LittleEndian, &relAddr); err != nil {
					return nil, err
				}
				callAddr := uint32(offset + 5 + int64(relAddr))
				startFA, _ = VAtoFileOffset(peHeader, sectionHeaders, uint64(callAddr))
			} else if opcode == 0xE8 && flag == true {
				// 遇到嵌套call，略过嵌套，先找最近的ret
				continue
			} else if opcode == 0xC3 && flag == true {
				// 遇到最近的ret就刷新call状态，开始寻找下一个call
				flag = false
				endFA = section.PointerToRawData + uint32(offset)
				if startFA != 0 && endFA != 0 {
					functions = append(functions, Function{
						StartFA: startFA,
						EndFA:   endFA,
						Size:    startFA - endFA,
					})
					startFA, endFA = 0, 0
				}
			}
		}
	}

	return functions, nil
}

// FindSuitableFunction 找到合适的函数存放shellcode。
// 这里就是找到空间比shellcode大的函数，可以做一个map，随机用一个空间
func FindSuitableFunction(functions []Function, binSize uint32) *Function {
	for _, function := range functions {
		if function.Size >= binSize {
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

// PatchExportSymbol patch PE 导出符号
/*func PatchExportSymbol(filePath, symbolName string, patchData []byte) error {
	// Read the PE file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var peHeader PEHeader
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &peHeader); err != nil {
		return fmt.Errorf("failed to parse PE header: %v", err)
	}

	numSections := peHeader.FileHeader.NumberOfSections
	sectionHeaders := make([]SectionHeader, numSections)
	reader.Seek(int64(peHeader.FileHeader.NumberOfSymbols), 0)
	if err := binary.Read(reader, binary.LittleEndian, &sectionHeaders); err != nil {
		return fmt.Errorf("failed to parse section headers: %v", err)
	}

	// 导出目录RVA为第0条记录
	exportDirectoryRVA := peHeader.OptionalHeader.DataDirectory[peparser.ImageDirectoryEntryExport].VirtualAddress
	exportDirectoryOffset := exportDirectoryRVA - peHeader.OptionalHeader.SectionAlignment + peHeader.OptionalHeader.FileAlignment

	var exportDirectory ExportDirectory
	reader = bytes.NewReader(data[exportDirectoryOffset:])
	if err := binary.Read(reader, binary.LittleEndian, &exportDirectory); err != nil {
		return fmt.Errorf("failed to parse export directory: %v", err)
	}

	nameRVA := exportDirectory.AddressOfNames
	nameOffset := nameRVA - peHeader.OptionalHeader.SectionAlignment + peHeader.OptionalHeader.FileAlignment
	for i := uint32(0); i < exportDirectory.NumberOfNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(data[nameOffset+4*i:])
		nameOffset := nameRVA - peHeader.OptionalHeader.SectionAlignment + peHeader.OptionalHeader.FileAlignment
		name := string(data[nameOffset:bytes.IndexByte(data[nameOffset:], 0)])
		if name == symbolName {
			ordinal := binary.LittleEndian.Uint16(data[exportDirectory.AddressOfNameOrdinals+2*i:])
			functionRVA := binary.LittleEndian.Uint32(data[exportDirectory.AddressOfFunctions+4*uint32(ordinal):])
			functionOffset := functionRVA - peHeader.OptionalHeader.SectionAlignment + peHeader.OptionalHeader.FileAlignment
			copy(data[functionOffset:], patchData)
			break
		}
	}

	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}
*/
// SplitBinData splits the bin data into chunks that fit into the given functions
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
	// symbol := flag.String("symbol", "", "PE的导出函数")
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

		// shellcode分块
		chunks, _ := SplitBinData(patchData, functions)
		if len(chunks) == 0 {
			fmt.Println("No suitable functions found to patch")
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
		} else {
			fmt.Println("Usage: patcher -file <file_path> -patch <new_content|bin_file> [-fa <fa>] [-symbol <symbol>] [-bin] [-author <author>]")
			return
		}
		/*} else if *symbol != "" {
			if err := PatchExportSymbol(*filePath, *symbol, patchData); err != nil {
				fmt.Printf("Failed to patch export symbol: %v\n", err)
			}
		}*/
		fmt.Printf("Shellcode Inject Completed!")
	}
}
