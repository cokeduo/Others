# coding=utf-8

import os
import re
import sys


# 功能： 从 mach-o 文件解析出无用类
# 使用： python unusedClassChecker.py  mach-o文件路径
# 思路： 获取所有类和所有已经使用的类，两者取差即得出未使用的类


# mach-o 文件路径
# macho_path = '/Users/wangduo/Desktop/Maco-o/Mach-O2/OCMachODemo'


# 读取类的地址
def pointers_from_binary(line,binary_file_arch):
	line = line[16:].strip().split(' ')
	pointers = set()
	if binary_file_arch == 'x86_64':
		if len(line) == 16:
			pointers.add(''.join(line[4:8][::-1] + line[0:4][::-1]))
			pointers.add(''.join(line[12:16][::-1] + line[8:12][::-1]))
		if len(line) == 8:
			pointers.add(''.join(line[4:8][::-1] + line[0:4][::-1]))
		return pointers
			
	if binary_file_arch.startswith('arm'):
		if len(line) == 4:
			pointers.add(line[1] + line[0])
			pointers.add(line[3] + line[2])
		if len(line) == 2:
			pointers.add(line[1] + line[0])
		return pointers
	return None
		

# 获取使用到类的地址
def class_ref_pointers(path, binary_file_arch):
	ref_pointers = set()
	lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classrefs %s' % path).readlines()
	for line in lines:
		pointers = pointers_from_binary(line, binary_file_arch)
		if pointers != None:
			ref_pointers = ref_pointers.union(pointers)
	return ref_pointers


# 获取所有类的地址
def class_list_pointers(path, binary_file_arch):
	list_pointers = set()
	lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classlist %s' % path).readlines()
	for line in lines:
		pointers = pointers_from_binary(line,binary_file_arch)
		if pointers != None:
			list_pointers = list_pointers.union(pointers)
	return list_pointers


# 符号化，获取地址和类名字映射
def class_symbols(path):
	symbols = {}
	#0000000100005968 (__DATA,__objc_data) external _OBJC_CLASS_$_Person
	re_class_name = re.compile('(\w{16}) .* _OBJC_CLASS_\$_(.+)')
	lines = os.popen('nm -nm %s' % path).readlines()
	for line in lines:
		result = re_class_name.findall(line)
		if result:
			(address, symbol) = result[0]
			symbols[address] = symbol
	return symbols



# 根据value从map中取出key
def get_class_ptr_with_clsname(clsname, classpointers):
	for key in classpointers.keys():
		if classpointers[key] == clsname:
			return key
	return None

# 未使用类中过滤掉父类
def filter_super_class(macho_path, classMaping, unref_pointers):
	re_subclass_name = re.compile('\w{16} 0x\w{9} _OBJC_CLASS_\$_(.+)')
	re_superclass_name = re.compile('\s*superclass 0x\w+ _OBJC_CLASS_\$_(.+)')

	lines = os.popen('/usr/bin/otool -oV %s' % macho_path).readlines()
	subclass_name = ''
	superclass_name = ''

	for line in lines:

		subclass_match_result = re_subclass_name.findall(line)
		if subclass_match_result:
			subclass_name = subclass_match_result[0]

		superclass_match_result = re_superclass_name.findall(line)
		if superclass_match_result:
			superclass_name = superclass_match_result[0]


		superclass_name_ptr = get_class_ptr_with_clsname(superclass_name,classMaping)
		subclass_name_ptr = get_class_ptr_with_clsname(subclass_name,classMaping)

		if superclass_name_ptr != None and subclass_name_ptr != None:
			if superclass_name_ptr in unref_pointers and subclass_name_ptr not in unref_pointers:
				unref_pointers.remove(superclass_name_ptr)




def find_all_class_list(macho_path):
	# 获取mach-o文件的架构类型
	binary_file_arch = os.popen('file -b ' + macho_path).read().split(' ')[-1].strip()

	all_class_list = class_list_pointers(macho_path,binary_file_arch)
	ref_class_list = class_ref_pointers(macho_path,binary_file_arch)

	# 取差集得到未使用的类地址
	unref_pointers = all_class_list - ref_class_list

	# 符号化
	classMaping = class_symbols(macho_path)

	# 过滤父类
	filter_super_class(macho_path, classMaping, unref_pointers)


	# 过滤掉无效value
	unused_class_results = []
	for cls_symbol in unref_pointers:
		class_name = classMaping.get(cls_symbol, 'no_class_default')
		if class_name != 'no_class_default':
			unused_class_results.append(class_name)

	# 记录无用class
	oupput_string = ''
	for cls in unused_class_results:
		oupput_string = oupput_string + cls + '\n'

	# 写文件
	current_path = sys.path[0].strip() + '/unused_class_result.txt'
	file = open(current_path, 'w')
	file.write('ununsed class number: %d\n\n' % len(unused_class_results))
	file.write(oupput_string)
	file.close()

	print '\n************* Done! ***************\n'


if __name__ == '__main__':
	macho_path = sys.argv[1]
	find_all_class_list(macho_path)






	