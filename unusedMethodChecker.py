# coding=utf-8

import sys
import os
import re


# 功能： 从 mach-o 文件解析出无用方法
# 使用： python unusedMethodChecker.py  mach-o文件路径
# 思路: 获取到所有方法和所有已使用的方法，做差集，然后过滤掉系统方法即为未使用的方法


# 以xxx开头的方法过滤掉
filter_pre_sels = {'application', 'performSelector:', '.cxx_', 'conformsToProtocol:'}

# 相同方法过滤掉
filter_same_sels = {'class', 'superclass', 'isProxy', 'zone', 'self', 'retainCount', 'hash', 'description', 'isEqual:', 'isKindOfClass:', 'isMemberOfClass:', 'debugDescription', 'release', 'retain','autorelease','respondsToSelector:'}


# 获取使用到的方法
def ref_selectors(macho_path):

	re_selrefs = re.compile('__TEXT:__objc_methname:(.+)')

	ref_sels = set()
	lines = os.popen('/usr/bin/otool -v -s __DATA __objc_selrefs %s' % macho_path).readlines()
	for line in lines:
		results = re_selrefs.findall(line)
		if results:
			ref_sels.add(results[0])
	return ref_sels


# 取出所有 set,get 方法
def get_all_setter_getters(macho_path):

    # 获取类信息
    cls_lines = os.popen('/usr/bin/otool -oV %s' % macho_path).readlines()
    all_setter_getters_re = re.compile('\simp 0x\w{9} -\[.+ (set.+)\]')

    all_setter_getters = set()

    for line in cls_lines:
    	results = all_setter_getters_re.findall(line)
    	if results:
    		sel_setter_name = results[0]
    		sel_getter_name = sel_setter_name[3:]
    		sel_getter_name = sel_getter_name[:1].lower() + sel_getter_name[1:]
    		sel_getter_name = sel_getter_name[:-1]
    		all_setter_getters.add(sel_getter_name)
    		all_setter_getters.add(sel_setter_name)
    return all_setter_getters


# 过滤系统方法
def will_filter(sel_name):
	for filter_pre in filter_pre_sels:
		if sel_name.startswith(filter_pre):
			return True

	for filter_same in filter_same_sels:
		if sel_name == filter_same:
			return True
	return False

def all_selectors(macho_path):
 			
	all_setter_getters = get_all_setter_getters(macho_path)

	all_sels = set()
	lines = os.popen('/usr/bin/otool -v -s __TEXT __objc_methname %s' % macho_path).readlines()


	# 取出所有方法名字
	all_sels_re = re.compile('\w{16}(.+)')	


	all_selector_results = set()
	
	for line in lines:
		results = all_sels_re.findall(line)
		if results:
			sel_name = results[0].strip()

			# 过滤成员变量
			if sel_name.startswith('_'):
				continue

			# 过滤 get set 方法
			if sel_name in all_setter_getters:
				continue

			# other
			if will_filter(sel_name):
				continue

			all_selector_results.add(sel_name)
			
	return all_selector_results


def unref_selectors(macho_path):

	all_sels = all_selectors(macho_path)

	ref_sels = ref_selectors(macho_path)

	unused_sels = all_sels - ref_sels

	# 记录无用方法
	oupput_string = ''
	for sel in unused_sels:
		oupput_string = oupput_string + sel + '\n'

	# 写文件
	current_path = sys.path[0].strip() + '/unused_method_result.txt'
	file = open(current_path, 'w')
	file.write('ununsed method number: %d\n\n' % len(unused_sels))
	file.write(oupput_string)
	file.close()



if __name__ == '__main__':
	macho_path = sys.argv[1]
	unref_selectors(macho_path)