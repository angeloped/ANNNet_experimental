#!/usr/bin/python

# title: ANNNet Communication Proof-of-Concept Infrastructure
# type: PEOPLE'S GUARDS
# description: The future of the inter-communication privacy, security, and anonymity.
#              A system without leaks or direct surveillance.
# author: Bryan Angelo Opina Pedrosa
# begin date: 2021/2/23

import os
import re
import time
import hashlib
import sqlite3

import ANNNet_client

try:
	import thread
except:
	import _thread as thread



# relay identification
# authentication hash
# hidden service link
# .annn address linker
# salt (anti-bruteforce)
intergateway_sql = """
CREATE TABLE INTERGATEWAY_REDIR(
	AUTH CHAR(128) NOT NULL,
	RID_ CHAR(32) NOT NULL,
	HSL_ CHAR(64) NOT NULL,
	LNK_ CHAR(40) NOT NULL,
	SALT CHAR(32) NOT NULL,
	UNIQUE(AUTH, LNK_)
);
"""


whereami = "my_host_on_tor.onion" # .onion host of ANNNet guard
guards = [] # unused object; for future use of guard synchronisation



class ANNNet_Utils:
	def determn_NET(self, url): #[ok] determine url network type [Tor/I2p/Unknown]
		if re.match(r"(^[a-zA-Z0-9_]*)\.onion", url) is not None:
			return "Tor"
		elif re.match(r"(^[a-zA-Z0-9_]*)\.i2p", url) is not None:
			return "I2p"
		else:
			return "Err"
	
	def checkifup(self, url): # ping to check if service/relay is up
		net_type = self.determn_NET(url)
		nonce = hashlib.md5(os.urandom(128)).hexdigest()
		
		# ping services via relay by sending nonce as verification
		nonce_status = ANNNet_client.get_session(url=url, data={"XMD_ANNNet":"ping", "Nonce_ANNNet":nonce, "Dest_ANNNet":whereami})
		
		# if nonce is sucessfully sent
		if bool(nonce_status):
			# a service relay handler will redirect the nonce back to ours
			# we will receive the nonce we sent to relay and automatically appends to 'ANNNet_client.ANNNet_METAWEB_Nonce' 
			# access nonce from 'ANNNet_client.ANNNet_METAWEB_Nonce'
			# if nonce is found, then authenticity of a relay is validated
			if nonce in ANNNet_client.ANNNet_METAWEB_Nonce:
				# clean up the garbage
				nonc_index = ANNNet_client.ANNNet_METAWEB_Nonce.index(nonce)
				del ANNNet_client.ANNNet_METAWEB_Nonce[nonc_index]
				
				# return verification status
				return True
		
		# otherwise, there's anomaly between us and the relay
		return False
	
	def annn_url_calc(self, hsl_, auth, bday): # calculate .annn linker (44 chars)
		return "{0}.annn".format(hashlib.sha1((hsl_ + auth + bday).encode()).hexdigest())


class INTERGATEWAY_REDIR(ANNNet_Utils):
	def __init__(self):
		self.relay_count = 23
	
	def get_hidden_service(self, annnurl=""): # get hidden service link
		cur = conn.cursor()
		hs_link = cur.execute("SELECT HSL_ FROM INTERGATEWAY_REDIR WHERE LNK_=?", (annnurl,))
		return cur.fetchone()[0]
	
	def dump_relays_services(self): # request random relay
		cur = conn.cursor()
		relays_db = cur.execute("SELECT HSL_ FROM INTERGATEWAY_REDIR ORDER BY RANDOM() LIMIT ?", (self.relay_count,))
		return "\n".join([relay[0] for relay in relays_db])
	
	def register_service(self, hsurl="", key="", rid="", set_annnurl=""): # register/update
		if bool(hsurl) and bool(key):
			new_auth = hashlib.sha512(key.encode()).hexdigest()
			new_rid  = hashlib.md5(os.urandom(128)).hexdigest()
			new_salt = hashlib.md5(os.urandom(128)).hexdigest()
			new_link = self.annn_url_calc(hsurl, new_auth)
			
			try: # register service
				cur = conn.cursor()
				cur.execute("INSERT INTO INTERGATEWAY_REDIR(AUTH, RID_, HSL_, LNK_, SALT) VALUES(?, ?, ?, ?, ?)", (new_auth, new_rid, hsurl, new_link, new_salt,))
				conn.commit()
				return 0x01
			except:
				try: # update service
					cur = conn.cursor()
					cur.execute("UPDATE INTERGATEWAY_REDIR SET HSL_=? WHERE SALT=?", (hsurl, new_salt))
					conn.commit()
					return 0x01
				except:
					pass
		elif bool(set_annnurl) and bool(rid):
			# change service's .annn linker [warning: administrative use only]
			cur = conn.cursor()
			cur.execute("UPDATE INTERGATEWAY_REDIR SET LNK_=? WHERE RID_=?", (set_annnurl, rid))
			conn.commit()
			return 0x01
		
		return 0x00
	
	def refresh_relay(self): # [a thread] remove inactive relays
		cur = conn.cursor()
		while 1:
			relays_db = cur.execute("SELECT HSL_ FROM INTERGATEWAY_REDIR")
			for relay in relays_db:
				if not self.checkifup(relay[0]): # if down
					cur.execute("DELETE FROM INTERGATEWAY_REDIR WHERE HSL_=?", (relay[0],))
					conn.commit()
			time.sleep(30)
		
	def thread_loop(self):
		thread.start_new_thread(self.refresh_relay, ())



if __name__ == "__main__":
	try:
		# sqlite3 create database conn
		# create db if db not found; else, open existing
		if not os.path.exists("system.db"):
			conn = sqlite3.connect("system.db", check_same_thread=False)
			conn.executescript(intergateway_sql)
		else:
			conn = sqlite3.connect("system.db", check_same_thread=False)
		
		# ANNNet's Meta-Internet Gateway DBMS
		intrgt_obj = INTERGATEWAY_REDIR()
		
		
		# initiate a threaded loop for relay checker
		intrgt_obj.thread_loop()
		
		
		# interfacing ANNNet_METAWEB to ANNNet_client.py and act as a Guard
		# this could be done by making relay manager functions accessible to
		# the submodule ANNNet_client.py
		#
		# get hidden service link (param: annnurl)
		ANNNet_client.ANNNet_METAWEB_dbms_callbacks["get_hidden_service"] = intrgt_obj.get_hidden_service
		# request random relay (no param)
		ANNNet_client.ANNNet_METAWEB_dbms_callbacks["dump_relays_services"] = intrgt_obj.dump_relays_services
		# register/update hidden service
		# register params: hsurl, key
		# update params:   rid, set_annnurl
		ANNNet_client.ANNNet_METAWEB_dbms_callbacks["register_service"] = intrgt_obj.register_service
		
		
		# launch reverse proxy of ANNNetwork
		ANNNet_client.LAUNCH_ANNNet_reverse_proxy()
	
	except Exception as excp:
		pass #[wip] catch
	finally:
		conn.close()



