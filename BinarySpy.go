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

func main() {
	fmt.Println("   _____       ____  _                         _____             \n  / ____|     |  _ \\(_)                       / ____|            \n | |  __  ___ | |_) |_ _ __   __ _ _ __ _   _| (___  _ __  _   _ \n | | |_ |/ _ \\|  _ <| | '_ \\ / _` | '__| | | |\\___ \\| '_ \\| | | |\n | |__| | (_) | |_) | | | | | (_| | |  | |_| |____) | |_) | |_| |\n  \\_____|\\___/|____/|_|_| |_|\\__,_|_|   \\__, |_____/| .__/ \\__, |\n                                         __/ |      | |     __/ |\n                                        |___/       |_|    |___/ ")
	fmt.Printf("by https://github.com/berryalen02/GoBinarySpy\n")

	fa := flag.String("fa", "", "文件偏移FA")
	symbol := flag.String("symbol", "", "PE的导出函数")
	filePath := flag.String("file", "", "目标PE文件")
	patchSource := flag.String("patch", "", "shellcode")
	help := flag.Bool("h", false, "help")

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

	// 读取shellcode
	patchData, err := ioutil.ReadFile(*patchSource)
	if err != nil {
		fmt.Printf("Failed to read bin file: %v\n", err)
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
