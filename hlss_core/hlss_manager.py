#!/usr/bin/python
#from hlss import *
# send the key chunks
# chain the key chunks
# register it as session

import os
import sys
import time

try:
	import thread
except:
	import _thread as thread

# extending support from hlss
from hlss import *


# key fragments to process
RECVD_KEY_FRAG = []


class HLSS_CACHECHAIN_FS:
	def __init__(self, batch_id=""):
		# list all files associated with batch_id
		# retreived from cachechains.py: [[batch_id, start, end, fixed len, len],]
		self.batch_id = batch_id
		self.file_lst_inproc = [mdata for mdata in metadata_send if mdata[0]==self.batch_id]
		self.file_lst_merged = [mdata for mdata in metadata_done if mdata[0]==self.batch_id]
	
	def joined_fname(mdata):
		return " ".join(mdata[0], mdata[1], mdata[2], mdata[3], mdata[4])
	
	def merged_fname(item):
		return self.joined_fname([item[0], "INIT", "FINL", item[3], item[3]])
	
	def save_fragment(mdata, fragment):
		# register 'mdata' to 'metadata' list
		metadata.append(mdata)
		
		# save fragment to `cache/inprocess/` path
		filedir = os.path.join("cache", "inprocess", " ".join([str(mdat) for mdat in mdata]))
		with open(filedir, "wb") as frag_data:
			frag_data.write(fragment.encode())
	
	def extract(self, item, mode): # mode: "inprocess" / "merged"
		# filename by mode
		fname_mod = self.merged_fname(item) if mode=="merged" else self.joined_fname(item)
		
		# read fragment data
		filedir = os.path.join("cache", mode, self.joined_fname(item))
		
		if os.path.exists(filedir):
			with open(filedir, "rb") as frag_data:
				return frag_data.read().decode("utf-8") 
	
	def remove(self, item, mode): # mode: "inprocess" / "merged"
		# delete from `cache/<mode>/` and to all metadata list
		if mode == "inprocess":
			del self.file_lst_inproc[ self.file_lst_inproc.index(item) ]
			del metadata_send[ metadata_send.index(item) ]
		elif mode == "merged":
			del self.file_lst_merged[self.file_lst_merged.index(item)]
			del metadata_done[ metadata_done.index(item) ]
		
		# filename by mode
		fname_mod = self.merged_fname(item) if mode=="merged" else self.joined_fname(item)
		
		# delete from cache
		filedir = os.path.join("cache", mode, fname_mod)
		if os.path.exists(filedir):
			os.remove(filedir)
	
	def update_list(self):
		self.file_lst_inproc = [mdata for mdata in metadata_send if mdata[0]==self.batch_id]
		self.file_lst_merged = [mdata for mdata in metadata_done if mdata[0]==self.batch_id]


def HLSS_register_to_send(data):
	global RECVD_KEY_FRAG
	# generate session key
	security_key = md5(os.urandom(64)).hexdigest()
	# data encryption
	data = AESCryptography(key=security_key).encrypt(data=data)
	# split the payload
	batch_id = SPLITTING().slash(data=data)
	# split session key
	key_meta_data = split_key(batch_id, security_key) # output: [[batch_id, n, data_key_chunk],..]
	# return `batch id` and `splitted key`
	return batch_id, key_meta_data


def HLSS_retrieve_from_cachechain(batch_id, item):
	# file object to access fragmented stream
	stream_FSobj = HLSS_CACHECHAIN_FS(batch_id=batch_id)
	# now, the fragment is presumably completed, the thread from hlss_manager will build it
	frag_data = stream_FSobj.extract(item=item, mode="merged")
	# get security key
	security_key = security_keys[batch_id]
	# data decryption
	raw_data = AESCryptography(key=security_key).decrypt(data=frag_data)
	# return decryped (raw) data
	return raw_data


def get_fragment(batch_id, request_callback, req_head, req_bd, service):
	# file object to access fragmented stream
	stream_FSobj = HLSS_CACHECHAIN_FS(batch_id=Batch_ANNN)
	# get metadata of merged data
	merged_list = stream_FSobj.file_lst_merged
	
	if bool(merged_list):
		# extract merged request message
		merged_data = stream_FSobj.extract(item=merged_list[0], mode="merged")
		# get security key
		security_key = security_keys[batch_id]
		# request data decryption
		msg_data = AESCryptography(key=security_key).decrypt(data=merged_data)
		# send modified http request msg to the assigned service at localhost ; get response message
		response_data = request_callback(url=service, proxies={}, headers=req_head, data=req_bd, dump=True)
		# response message encryption
		data = AESCryptography(key=security_key).encrypt(data=response_data)
		# split and save to `cache/inprocess` and 'metadata_send'
		dummy_batch_id = SPLITTING().slash(data=data)
		
		# hacking the 'metadata_send' to prevent reverse retrieval
		# [might encounter anomaly in synchronisation]
		for i in range(len(metadata_send)):
			# if list item associated with 'dummy_batch_id'
			if metadata_send[i][0] == dummy_batch_id:
				# replace 'dummy_batch_id' with 'batch_id'
				metadata_send[i][0] = batch_id
	
	# update cache list
	stream_FSobj.update_list()
	
	# if response message fragment exists
	if bool(stream_FSobj.file_lst_inproc):
		# response fragment metadata
		frag_resp_mdat = metadata_send.pop( metadata_send.index(stream_FSobj.file_lst_inproc[0]) )
		
		# extract response fragment data
		frag_resp = stream_FSobj.extract(item=frag_resp_mdat, mode="inprocess")
		
		# delete the metadata ; delete the cache data
		stream_FSobj.remove(item=frag_resp_mdat, mode="inprocess")
		
		# return extract response fragment data
		return frag_resp


def HLSS_buildkey():
	while 1:
		# (this block is in thread-assisted loop)
		# *** harvesting and build keys ***
		for key_metadata in RECVD_KEY_FRAG:
			build_status = build_key(batch_id=key_metadata[0], part=key_metadata[1], content=key_metadata[2])
			
			# del * key fragments from `RECVD_KEY_FRAG` associated with `batch_id` when done
			if build_status:
				i = 0
				while i <= len(RECVD_KEY_FRAG)-1:
					if RECVD_KEY_FRAG[i][0] == key_metadata[0]:
						del RECVD_KEY_FRAG[i]
				break
		
		time.sleep(1)



##########################
#[thread] RECEIVER THREADS
##########################
# receive data chunks then merge
thread.start_new_thread(cachechains_loop,())
# session timeout for key/data build
thread.start_new_thread(session_timeout,())
# build received key fragments
thread.start_new_thread(HLSS_buildkey, ())



if __name__ == "__main__":
	data = """Somebody once told me the world is gonna roll me\nI ain't the sharpest tool in the shed\nShe was looking kind of dumb with her finger and her thumb\nIn the shape of an "L" on her forehead"""
	
	# register to cacechain as "to send" fragments
	batch_id, key_meta_data = HLSS_register_to_send(data=data)
	
	while 1:
		time.sleep(1)




