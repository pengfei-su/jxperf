#!/usr/bin/env python2

import os, sys
from pylib import *
import multiprocessing as mp
#from functools import partial

##global variables
isDataCentric = False
isNuma = False
isGeneric = False
isHeap = False


def get_all_files(directory):
	files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory,f))]
	ret_dict = dict()
	for f in files:
		if f.startswith("agent-trace-") and f.find(".run") >= 0:
			start_index = len("agent-trace-")
			end_index = f.find(".run")
			tid = f[start_index:end_index]
			if tid not in ret_dict:
				ret_dict[tid] = []
			ret_dict[tid].append(os.path.join(directory,f))
	return ret_dict

def parse_input_file(file_path, level_one_node_tag):
	print "parsing", file_path
	with open(file_path) as f:
		contents = f.read()
		#print contents
	parser = special_xml.HomoXMLParser(level_one_node_tag, contents)
	return parser.getVirtualRoot()

def remove_all_files(directory):
	files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory,f))]
	for f in files:
		if f.startswith("agent-trace-") and f.find(".run") >= 0:
			os.remove(f)
		elif f.startswith("agent-statistics") and f.find(".run"):
			os.remove(f)

def load_method(method_root):
	method_manager = code_cache.MethodManager()
	for m_xml in method_root.getChildren():
		m = code_cache.Method(m_xml.getAttr("id"),m_xml.getAttr("version"))
		## set fields
		m.file = m_xml.getAttr("file")
		m.start_addr = m_xml.getAttr("start_addr")
		m.code_size = m_xml.getAttr("code_size")
		m.method_name = m_xml.getAttr("name")
		m.class_name = m_xml.getAttr("class")

		## add children; currently addr2line mapping and bci2line mapping
		addr2line_xml = None
		bci2line_xml = None
		for c_xml in m_xml.getChildren():
			if c_xml.name() == "addr2line":
				assert(not addr2line_xml)
				addr2line_xml = c_xml
			elif c_xml.name() == "bci2line":
				assert(not bci2line_xml)
				bci2line_xml = c_xml
		if addr2line_xml:
			for range_xml in addr2line_xml.getChildren():
				assert(range_xml.name() == "range")
				start = range_xml.getAttr("start")
				end = range_xml.getAttr("end")
				lineno = range_xml.getAttr("data")

				m.addAddr2Line((start,end),lineno)

		if bci2line_xml:
			for range_xml in bci2line_xml.getChildren():
				assert(range_xml.name() == "range")
				start = range_xml.getAttr("start")
				end = range_xml.getAttr("end")
				lineno = range_xml.getAttr("data")

				m.addBCI2Line((start,end),lineno)

		method_manager.addMethod(m)
	return method_manager

def load_context(context_root):
	context_manager = context.ContextManager()
	print "It has ", len(context_root.getChildren()), " contexts"
	for ctxt_xml in context_root.getChildren():

		ctxt = context.Context(ctxt_xml.getAttr("id"))
		# set fields
		ctxt.method_version = ctxt_xml.getAttr("method_version")
		ctxt.binary_addr = ctxt_xml.getAttr("binary_addr")
		ctxt.method_id = ctxt_xml.getAttr("method_id")
		ctxt.bci = ctxt_xml.getAttr("bci")
		ctxt.setParentID(ctxt_xml.getAttr("parent_id"))

		metrics_xml = None
		for c_xml in ctxt_xml.getChildren():
			if c_xml.name() == "metrics":
				assert(not metrics_xml)
				metrics_xml = c_xml
		if metrics_xml:
			for c_xml in metrics_xml.getChildren():
				attr_dict = c_xml.getAttrDict()
				if not(attr_dict.has_key("value")):
					break
				
				if attr_dict["event"] == "BR_INST_RETIRED.NEAR_CALL" and attr_dict["value"] == "1":
					break
				ctxt.metrics_dict[attr_dict["event"]+":"+attr_dict["measure"]] = float(attr_dict["value"])
			ctxt.metrics_type = "BR_INST_RETIRED.NEAR_CALL"

		## add it to context manager
		context_manager.addContext(ctxt)
	roots = context_manager.getRoots()
	print "remaining roots: ", str([r.id for r in roots])
	assert(len(roots) == 1)
	#context_manager.populateMetrics()
	return context_manager

def output_to_file(method_manager, context_manager, dump_data):
	intpr = interpreter.Interpreter(method_manager, context_manager)
	accessed = dict()
	ip = dict()
	for ctxt_list in context_manager.getAllPaths("0", "root-leaf"):#"root-subnode"):
	 	i = 0
		while i < len(ctxt_list):
			if ctxt_list[i].metrics_dict:
				#print ctxt_list[i].metrics_dict
				key = "\n".join(intpr.getSrcPosition(c) for c in ctxt_list[:(i+1)])
				if not(accessed.has_key(key)):
					accessed[key] = True
					assert(not(dump_data.has_key(key)))
					dump_data[key] = ctxt_list[i].metrics_dict
			i += 1

def parallel1(tid, tid_file_dict):
	root = xml.XMLObj("root")
	if tid == "method":
		level_one_node_tag = "method"
	else:
		level_one_node_tag = "context"

	for f in tid_file_dict[tid]:
		new_root = parse_input_file(f, level_one_node_tag)
		root.addChildren(new_root.getChildren())
	if len(root.getChildren()) > 0:
		#xml_root_dict[tid] = root
		return tid, root

def parallel2(tid, xml_root_dict, method_manager):
	if tid == "method":
		return
	print("Reconstructing contexts from TID " + tid)
	xml_root = xml_root_dict[tid]
	print("Dumping contexts from TID "+tid)
	dump_data = dict()
	output_to_file(method_manager, load_context(xml_root), dump_data)

	file = open("agent-data-" + tid + ".out", "w")
	rows = sorted(dump_data.items(), key=lambda x: (x[1]['BR_INST_RETIRED.NEAR_CALL:COUNT']), reverse = True)
	for row in rows:
		file.write(row[0] + "\n")
		for col in row[1]:
			file.write(col + " = " + str(row[1][col]) + " ")
		file.write("\n\n")

	file.close()


def main():
	### read all agent trace files
	tid_file_dict = get_all_files(".")
	#print tid_file_dict
	### each file may have two kinds of information
	# 1. context; 2. code
	# the code information should be shared global while the context information is on a per-thread basis.
	pool = mp.Pool(mp.cpu_count())
	tmp = [pool.apply(parallel1, args=(tid, tid_file_dict)) for tid in tid_file_dict]
	tmp = list(filter(None, tmp))
	xml_root_dict = dict(tmp)
	#print xml_root_dict	
	
	### reconstruct method
	print("start to load methods")
	method_root = xml_root_dict["method"]
	method_manager = load_method(method_root)
	print("Finished loading methods")

	print("Start to output")

	[pool.apply(parallel2, args=(tid, xml_root_dict, method_manager)) for tid in xml_root_dict]
	pool.close()

	print("Final dumping")

	#remove_all_files(".")

main()
