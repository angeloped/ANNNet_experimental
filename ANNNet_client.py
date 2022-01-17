#!/usr/bin/python
import io
import cgi
import sys
import urllib
import requests
try:
	import SocketServer
	import SimpleHTTPServer
except:
	import socketserver as SocketServer
	import http.server as SimpleHTTPServer

sys.path.append("hlss_core")
import hlss_core.hlss_manager

sys.path.append("assets")
import assets.requests_toolbelt_dump

################################################################################
# title: ANNNet Proxy Client
# author: Bryan Angelo Pedrosa
# date: 12/15/2021
################################################################################

# RESPONSE STATUS CODE:
# 0x00 - Error
# 0x01 - Okay
# 0x02 - No result

PORT = 9102
SERVICE = "http://localhost:2021/"

proxies = {"http":"socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
headers = {"User-Agent":"ANNNet/1.0"}

ANNNet_METAWEB_Nonce = [] # For ANNNet Guard's nonce verification

ANNNet_METAWEB_dbms_callbacks = {} # Assigned function callback from submodule ANNNet_METAWEB.py (Guard); this is important for connecting the reverse proxy handler and ANNNet Guard.


def get_session(url="", headers=headers, proxies=proxies, data={}, dump=False):
	response = requests.get(url, headers=headers, data=data, proxies=proxies, allow_redirects=True, stream=True) #, timeout=3)
	return assets.requests_toolbelt_dump.dump_response(response) if dump else response # return dump or response obj


def HTTP_MSG_Modifier(http_message):
	# split header and body message
	header_body = http_reply.split("\r\n\r\n")
	
	# parse header
	headers = [_ln.split(": ") for _ln in headers[0].split("\r\n")]
	headers[0] = [headers[0][0], ""] # modify method: ["GET / HTTP/1.1", ""]
	
	# assign `headers` contents to `_headers`
	_headers = {"Connection":None, "Accept":None, "User-Agent":None, "Accept-Encoding:":None, }
	for ln in headers:
		_headers[ _ln[0].title() ] = header_feeds[ _ln[1] ]
	
	# return parsed headers and body
	return _headers, head_body[1]


class MyProxy(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		#self.send_header("Content-type", "text/html")
		self.end_headers()
	
	def do_GET(self):
		self._REQSTS()
	
	def do_POST(self):
		self._REQSTS()
	
	def _REQSTS(self):
		# set headers
		self._set_headers()
		
		# reading the msg body from a file-like object
		http_body = self.rfile.read( int(self.headers.get('Content-Length')) )
		
		# <http_message> to join status line and headers
		http_message = "{0}\r\n{1}\r\n\r\n{2}".format(self.requestline, self.headers, http_body)
		
		# parameters from request form
		form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
		
		# command variable
		XMD = form.getvalue("XMD_ANNNet")
		
		if XMD != None:
			if XMD == "ping": # ping w/ nonce
				# Nonce-DESTINATION variables
				Nonce_ANNN = form.getvalue("Nonce_ANNNet")
				Dest_ANNN = form.getvalue("Dest_ANNNet")
				
				if bool(Nonce_ANNN) and bool(Dest_ANNN):
					nonce_response = get_session(url=Dest_ANNN, data={"XMD_ANNNet":"recvping", "Nonce_ANNNet":Nonce_ANNN})
					self.wfile.write(nonce_response.content)
			elif XMD == "recvping": # pingback the pinger w/ nonce
				# register Nonce variable to 'ANNNet_METAWEB_Nonce'
				Nonce_ANNN = form.getvalue("Nonce_ANNNet")
				ANNNet_METAWEB_Nonce.append(Nonce_ANNN)
				self.wfile.write(0x01)
			elif XMD == "relay":
				# KEY or METADATA-FRAGMENT variable
				Key_ANNN = form.getvalue("KEY_ANNNet")       # "<batch_id> <n> <data_key_chunk>"
				MData_ANNN = form.getvalue("MDAT_ANNNet")    # "<batch_id> <start> <end> <fixed> <len> <len>"
				Fragment_ANNN = form.getvalue("FRAG_ANNNet") # "<fragment data>"
				Dest_ANNN = form.getvalue("Dest_ANNNet")     # "<IP addr>"
				
				if bool(Key_ANNN) and bool(MData_ANNN) and bool(Fragment_ANNN) and bool(Dest_ANNN): # ANNNet forwarder
					data = {"KEY_ANNNet":Key_ANNN, "MDAT_ANNNet":MData_ANNN, "FRAG_ANNNet":Fragment_ANNN}
					self.copyfile( io.BytesIO(get_session(url=Dest_ANNN, data=data).content) , self.wfile )
				else:
					self.wfile.write(0x00)
			elif XMD == "send":
				# set destination variable
				url = self.path[0:]
				
				# register 'http_message' to cacechain as "to send" fragments
				# output: 'batch_id' and '[[batch_id, n, data_key_chunk],..]'
				batch_id, key_meta_data = HLSS_register_to_send(data=http_message)
				
				# file object to access fragmented stream
				stream_FSobj = hlss_core.hlss_manager.HLSS_CACHECHAIN_FS(batch_id=batch_id)
				
				# send decryption key fragments
				# key data: "<batch_id> <n> <data_key_chunk>"
				for key in key_meta_data:
					get_session(url=url, data={"XMD_ANNNet":"recv", "KEY_ANNNet":" ".join(key)})
				
				# send fragments by acessing 'metadata_send' & cache `path/inprocess/`
				for frag_item_mdata in stream_FSobj.file_lst_inproc:
					# extract fragment contents. output: [[batch_id, start, end, fixed len, len],]
					frag_data = stream_FSobj.extract(item=frag_item_mdata, mode="inprocess")
					
					# send fragments
					get_session(url=url, data={"XMD_ANNNet":"recv", "MDAT_ANNNet":stream_FSobj.joined_fname(frag_item_mdata), "FRAG_ANNNet":frag_data})
					
					# delete fragment from `cache/inprocess/` path & 'metadata_send' variable
					if get_session(url, headers).content == "1": # [sent successfully]
						stream_FSobj.remove(item=frag_item_mdata, mode="inprocess")
				
				# receive response fragments from the service
				while 1:
					# request for fragmented responses
					# output: "<batch_id> <start> <end> <fixed len> <len>\r\n<fragment>"
					response = get_session(url=url, data={"XMD_ANNNet":"getfrag", "SESSN_ANNNet":batch_id})
					
					# loop all reply until 0x02 (not found)
					if response == 0x02:
						break
					
					# split response between metadata & fragment ('\r\n' delimiter)
					response = response.split("\r\n") # [metadata, fragment]
					
					# file object to access fragmented stream
					stream_FSobj = hlss_core.hlss_manager.HLSS_CACHECHAIN_FS()
					
					# save fragment to `cache/inprocess/`
					stream_FSobj.save_fragment(mdata=response[0], fragment=response[1])
					
					# add metadata to `metadata` variable for merging process
					metadata.append(response[0].split(" "))
				
				# append key fragments to RECVD_KEY_FRAG (hlss_manager)
				# auto key building for later decryption
				for key_mdata in key_meta_data:
					RECVD_KEY_FRAG.append(key_mdata)
				
				# now, the fragment is presumably completed, the thread from hlss_manager will build it
				# this line will only retrieve the entire response (auto decrypt, auto unsession)
				raw_data = HLSS_retrieve_from_cachechain(batch_id=batch_id, item=frag_item_mdata)
				
				# send the entire `data` 
				self.wfile.write(raw_data)
			elif XMD == "recv":
				# KEY or METADATA-FRAGMENT variable
				Key_ANNN = form.getvalue("KEY_ANNNet")       # "<batch_id> <n> <data_key_chunk>"
				MData_ANNN = form.getvalue("MDAT_ANNNet")    # "<batch_id> <start> <end> <fixed> <len> <len>"
				Fragment_ANNN = form.getvalue("FRAG_ANNNet") # "<fragment data>"
				
				if Key_ANNN != None:
					# Key_ANNN: [batch_id, n, data_key_chunk]
					Key_ANNN = Key_ANNN.split(" ")
					
					# append the key fragment (auto-build)
					if len(Key_ANNN) == 3:
						# convert number in str to int
						if Key_ANNN[1].isint():
							Key_ANNN[1] = int(Key_ANNN[1])
						
						# allocate new key if none
						if not Key_ANNN[0] in keys_metadata:  
							keys_metadata[Key_ANNN[0]] = []
						
						# save key to keys_metadata
						keys_metadata[Key_ANNN[0]].append([Key_ANNN[1], Key_ANNN[2]])
						
						self.wfile.write(0x01)
						return
					
					self.wfile.write(0x00)
				elif MData_ANNN != None and Fragment_ANNN != None:
					# MData_ANNN: [batch_id, start, end, fixed len, len]
					MData_ANNN = MData_ANNN.split(" ")
					
					if len(MData_ANNN) == 5 and len(Fragment_ANNN) > 0:
						# convert number in str to int
						if Key_ANNN[3].isint() and MData_ANNN[4].isint():
							MData_ANNN[3] = int(MData_ANNN[3])
							MData_ANNN[4] = int(MData_ANNN[4])
						
						# if batch_id is available in 'security_keys'
						if MData_ANNN[0] in security_keys:
							# file object to access fragmented stream
							stream_FSobj = hlss_core.hlss_manager.HLSS_CACHECHAIN_FS()
							
							# save fragment to `cache/inprocess/`
							stream_FSobj.save_fragment(mdata=MData_ANNN, fragment=Fragment_ANNN)
							
							self.wfile.write(0x01)
							return
					
					self.wfile.write(0x00)
				else:
					self.wfile.write(0x02)
			elif XMD == "getfrag":
				Batch_ANNN = form.getvalue("Batch_ANNNet")
				
				if Batch_ANNN != None:
					# parsed http request message
					request_headers, request_body = HTTP_MSG_Modifier(http_message)
					
					# get response http message
					request_msg = hlss_core.hlss_manager.get_fragment(batch_id=Batch_ANNN, request_callback=get_session, req_head=request_headers, req_bd=request_body, service=SERVICE)
					
					# if not empty, reply `response`
					if response != None:
						self.wfile.write(response)
						return
				
				self.wfile.write(0x00)
			elif XMD == "guard":
				# if this client reverse proxy server isn't acting as People's Guard; no callbacks were registered
				# to 'ANNNet_METAWEB_dbms_callbacks' dict; this block is exclusive only for running as ANNNet_METAWEB.py
				# simply known as Guard who manages database of relays of the entire ANNNetwork.
				if bool(ANNNet_METAWEB_dbms_callbacks):
					# func command
					func_ANNN = form.getvalue("func_ANNNet") # [get_hsl, dump_relay, register]
					
					# parameters
					ANNNURL_ANNN = form.getvalue("ANNNURL_ANNNet")
					Regstr_ANNN = form.getvalue("Regstr_ANNNet")
					HSURL_ANNN = form.getvalue("HSURL_ANNNet")
					Key_ANNN = form.getvalue("Key_ANNNet")
					RID_ANNN = form.getvalue("RID_ANNNet")
					
					if bool(func_ANNN): # if function is triggered
						if func_ANNN == "get_hsl" and bool(ANNNURL_ANNN):
							# get hidden service link (param: annnurl)
							self.wfile.write( ANNNet_METAWEB_dbms_callbacks["get_hidden_service"](annnurl=ANNNURL_ANNN) )
						elif func_ANNN == "dump_relay":
							# request random relay (no param)
							self.wfile.write( ANNNet_METAWEB_dbms_callbacks["dump_relays_services"]() )
						elif func_ANNN == "register":
							# register/update hidden service
							if bool(HSURL_ANNN) and bool(Key_ANNN):
								self.wfile.write( ANNNet_METAWEB_dbms_callbacks["register_service"](hsurl=HSURL_ANNN, key=Key_ANNN) ) # register
							elif bool(RID_ANNN) and bool(ANNNURL_ANNN):
								self.wfile.write( ANNNet_METAWEB_dbms_callbacks["register_service"](rid=RID_ANNN, set_annnurl=ANNNURL_ANNN) ) # re-register
				
				self.wfile.write(0x00)
			else:
				self.wfile.write(0x00)
		else:
			self.wfile.write(0x00)



def LAUNCH_ANNNet_reverse_proxy():
	httpd = SocketServer.ForkingTCPServer(('', PORT), MyProxy)
	print("Now serving at port {0} ...".format(str(PORT)))
	httpd.serve_forever()


if __name__ == "__main__":
	while 1: # auto set port when cannot access the existing one
		try:
			# launch reverse proxy of ANNNetwork
			LAUNCH_ANNNet_reverse_proxy()
		except KeyboardInterrupt:
			break
		except:
			PORT += 1



