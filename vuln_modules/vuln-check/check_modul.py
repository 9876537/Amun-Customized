"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import struct
import random
import check_shellcodes
import hashlib
import os
import amun_logging

import traceback
import StringIO
import sys

### Module for testing new vulnerability modules / port_watcher
### Simulate Windows Telnet without password

class vuln:

	def __init__(self):
		try:
			self.vuln_name = "CHECK Vulnerability"
			self.stage = "CHECK_STAGE1"
			self.shellcode = []
			self.randomNumber_dir = random.randint(255,5100)
			self.randomNumber_net = random.randint(255,5100)
			self.computerName = "DESKTOP-%i" % (random.randint(255,5100))
			os_id = random.randint(0, 1)
			if os_id == 0:
				self.welcome_message = "Microsoft Windows XP [Version 5.1.2600]\n(C) Copyright 1985-2001 Microsoft Corp.\n\nC:\\WINNT\\System32>"
				self.prompt = "C:\\WINNT\\System32>"
			else:
				self.welcome_message = "Microsoft Windows 2000 [Version 5.00.2195]\n(C) Copyright 1985-2000 Microsoft Corp.\n\nC:\\WINDOWS\\System32>"
				self.prompt = "C:\\WINDOWS\\System32>"
		except KeyboardInterrupt:
			raise

        def write_hexdump(self, shellcode=None, extension=None):
                if not shellcode:
                        hash = hashlib.sha("".join(self.shellcode))
                else:
                        hash = hashlib.sha("".join(shellcode))
                if extension!=None:
                        filename = "hexdumps/%s-%s.bin" % (extension, hash.hexdigest())
                else:
                        filename = "hexdumps/%s.bin" % (hash.hexdigest())
                if not os.path.exists(filename):
                        fp = open(filename, 'a+')
                        if not shellcode:
                                fp.write("".join(self.shellcode))
                        else:
                                fp.write("".join(shellcode))
                        fp.close()
                        print ".::[Amun - CHECK] no match found, writing hexdump ::."
                return

	def print_message(self, data):
		print "\n"
		counter = 1
		for byte in data:
			if counter==16:
				ausg = hex(struct.unpack('B',byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split('x')
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg
				else:
					print ausg
				counter = 0
			else:
				ausg = hex(struct.unpack('B',byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split('x')
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg,
				else:
					print ausg,
			counter += 1
		print "\n>> Incoming Codesize: %s\n\n" % (len(data))

	def getVulnName(self):
		return self.vuln_name

	def getCurrentStage(self):
		return self.stage

	def getWelcomeMessage(self):
		return self.welcome_message

	def ipconfig(self, data, ownIP):
		""" emulate ipconfig command """
		reply = ""
		try:
			if data=="ipconfig":
				reply = "\nWindows IP Configuration\n\n"
				reply+= "Ethernet adapter Local Area Connection 3:\n\n"
				reply+= "\tConnection-specific DNS Suffix  . :\n"
				reply+= "\tIP Address. . . . . . . . . . . . : %s\n" % (ownIP)
				reply+= "\tSubnet Mask . . . . . . . . . . . : 255.255.255.0\n"
				reply+= "\tDefault Gateway . . . . . . . . . : %s\n\n" % (ownIP[:ownIP.rfind('.')]+".4")
				return reply
		except:
			pass
		return reply

	def dir(self, data):
		""" emulate dir command """
		reply = ""
		try:
			if data=="dir":
				reply = "\nVolume in drive C has no label\n"
				reply+= "Volume Serial Number is %i-FAB8\n\n" % (self.randomNumber_dir)
				reply+= "Directory of %s\n\n" % (self.prompt.strip('>'))
				reply+= "06/11/2007  05:01p    <DIR>\t\t.\n"
				reply+= "06/11/2007  05:01p    <DIR>\t\t..\n"
				reply+= "               0 File(s)\t\t0 bytes\n"
				reply+= "               2 Dir(s)\t1,627,193,344 bytes free\n\n"
				return reply
		except:
			pass
		return reply

	def net(self, data):
		""" emulate the net command """
		reply = ""
		try:
			if data=="net user":
				reply = "\nUser accounts for \\\\%s\n\n" % (self.computerName)
				reply+= "--------------------------------------------------------------------------------\n"
				reply+= "admin\t\t\tAdministrator\t\t\tGuest\n"
				reply+= "HelpAssistant\t\tSUPPORT_%ia0\n" % (self.randomNumber_net)
				reply+= "The command completed successfully\n\n"
				return reply
		except:
			pass
		return reply

	def changeDirectory(self, data):
		""" emulate directory changing """
		try:
			if data=="cd ..":
				data="cd.."
			if data=="cd.." and self.prompt!="C:\\>":
				position = self.prompt.rfind('\\')
				newPrompt = self.prompt[:position]
				if newPrompt=="C:":
					newPrompt = "C:\\"
				self.prompt = "%s>" % (newPrompt)
			elif data=="cd\\":
				self.prompt = "C:\\>"
			elif data.startswith('cd '):
				position = data.find(' ')
				newdir = data[position+1:]
				newPrompt = self.prompt[:-1]
				if newPrompt[-1] == '\\':
					self.prompt = "%s%s>" % (newPrompt,newdir)
				else:
					self.prompt = "%s\\%s>" % (newPrompt,newdir)
		except:
			pass
		return '\n%s' % self.prompt

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			self.log_obj = amun_logging.amun_logging("vuln_check", vuLogger)

			self.reply = random_reply[:62]
			#for i in range(0,510):
			#	try:
			#		self.reply.append( struct.pack("B", random.randint(0,255)) )
			#	except KeyboardInterrupt:
			#		raise

			resultSet = {}
			resultSet['vulnname'] = self.vuln_name
			resultSet['result'] = False
			resultSet['accept'] = False
			resultSet['shutdown'] = False
			resultSet['reply'] = "None"
			resultSet['stage'] = self.stage
			resultSet['shellcode'] = "None"
			resultSet["isFile"] = False

			#if bytes>0:
				#self.log_obj.log("CHECK Incoming: %s (Bytes: %s)" % (message, bytes), 6, "debug", True, False)
				#self.print_message(message)
		
			message = message.strip()
			if self.stage=="CHECK_STAGE1":
				if message.startswith('ipconfig'):
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "%s%s" % (self.ipconfig(message, ownIP), self.prompt)
					self.stage="CHECK_STAGE1"
					return resultSet
				elif message.startswith('dir'):
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "%s%s" % (self.dir(message), self.prompt)
					self.stage="CHECK_STAGE1"
					return resultSet
				elif message.startswith('net '):
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "%s%s" % (self.net(message), self.prompt)
					self.stage="CHECK_STAGE1"
					return resultSet
				elif message.startswith('cd'):
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "%s" % self.changeDirectory(message)
					self.stage="CHECK_STAGE1"
					return resultSet
				elif message.rfind('exit')!=-1 or message.rfind('EXIT')!=-1:
					resultSet['result'] = True
					resultSet['accept'] = False
					resultSet['reply'] = "\'%s\' is not recognized as an internal or external command, \noperable program or batch file.\n\n%s" % (message, self.prompt)
					self.stage="CHECK_STAGE1"
					return resultSet
				else:
					if bytes>0:
						self.log_obj.log("CHECK (%s) Incoming: %s (Bytes: %s)" % (ip, message, bytes), 6, "debug", True, True)
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "\'%s\' is not recognized as an internal or external command, \noperable program or batch file.\n\n%s" % (message, self.prompt)
					self.stage="CHECK_STAGE1"
					return resultSet
			elif self.stage=="SHELLCODE":
				if bytes>0:
					print "CHECK Collecting Shellcode"
					resultSet['result'] = True
					resultSet['accept'] = True
					#resultSet['reply'] = "".join(self.reply)
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					#resultSet['shellcode'] = "".join(self.shellcode)
					self.stage="SHELLCODE"
					return resultSet
				else:
					print "CHECK finished Shellcode"
					resultSet['result'] = False
					resultSet["accept"] = True
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
			else:
				resultSet["result"] = False
				resultSet["accept"] = False
				resultSet["reply"] = "None"
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			print e
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(1)