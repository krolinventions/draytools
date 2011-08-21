#!/usr/bin/env python
#
# DrayTek V2xxx config file and firmware decryption/decompression tools
#
# draytools Copyright (C) AMMOnium <ammonium at mail dot ru>
# 
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#

import sys
import os
from pydelzo import pydelzo, LZO_ERROR
from struct import pack, unpack

class draytools:
	CFG_RAW = 0
	CFG_LZO = 1
	CFG_ENC = 2

	class fs:
		def __init__(self, data, test=False, echo=False):
			self.cdata = data			
			self.test = test
			self.echo = echo

		def get_fname(self,i):
			addr = 0x10+i*44
			return str(self.cdata[ addr : addr + 0x20 ].strip('\x00'))

		def get_offset(self,i):
			addr = 0x10+i*44 + 0x24
			return unpack("<L", str(self.cdata[ addr : addr + 4 ]))[0] + self.datastart

		def get_fsize(self,i):	
			addr = 0x10+i*44 + 0x28
			return unpack("<L", str(self.cdata[ addr : addr + 4 ]))[0]

		def save_file(self,i):
			fname = self.get_fname(i)
			ds = self.get_offset(i)
			fs = self.get_fsize(i)
			fdata = self.cdata[ds : ds+fs]
			pp = fname.split('\\')
			pp = [self.path] + pp
			ppp = os.sep.join(pp[:-1])
			if len(pp) > 1:
				if not os.path.exists(ppp) and not self.test:
					os.makedirs(ppp)
			nfname = os.sep.join(pp)
			rawfs = -1
			if not self.test:
				ff = file(nfname,'wb')
			if fs>0:	
				if pp[-1].split('.')[-1].lower() in ['gif','jpg','cgi','cab','txt','jar']:
					rawfdata = fdata
				else:
					try:
						rawfdata = pydelzo.decompress('\xF0'+pack(">L",fs*64)+fdata)
					except LZO_ERROR as lze:						
						print '[ERR]:\tFile "'+ fname + '" is damaged or uncompressed [' + str(lze) + '], RAW DATA WRITTEN'
						rawfdata = fdata
			else:
				rawfdata = ''
			rawfs = len(rawfdata)
			if not self.test:
				ff.write(rawfdata)
				ff.close()
			if self.echo:
				print '%08X' % ds + '\t' + fname + '\t' + '%08X'%fs + '\t' + '%08X'%rawfs
			return (fs, rawfs)

		def save_all(self, path):
			self.path = path
			numfiles = unpack("<H",str(self.cdata[0x0E:0x10]))[0]
			self.datastart = 0x10 + 44 * numfiles	
			for i in xrange(numfiles):
				fs,rawfs = self.save_file(i)
			return numfiles

	@staticmethod
	def decompress_cfg(data):
		modelid = data[0x0C:0x0E]
		rawcfgsize = 0x00100000
		lzocfgsize = unpack(">L", data[0x24:0x28])[0]
		raw = data[:0x100]+pydelzo.decompress('\xF0' + pack(">L",rawcfgsize) + data[0x100:0x100+lzocfgsize])
		return raw

	@staticmethod
	def make_key(modelstr):
		sum = 0
		for c in modelstr:
			sum += ord(c)
		return (0xFF & sum)

	@staticmethod
	def enc(c, key):
		c ^= key
		c -= key
		c = 0xFF & (c >> 5 | c << 3)
		return c

	@staticmethod
	def dec(c, key):
		c = (c << 5 | c >> 3)
		c += key
		c ^= key
		c &= 0xFF
		return c

	@staticmethod
	def decrypt(data, key):
		rdata = ''
		for i in xrange(len(data)):
			rdata += chr(draytools.dec(ord(data[i]), key))
		return rdata

	@staticmethod
	def decrypt_cfg(data):
		modelstr = "V" + format(unpack(">H",data[0x0C:0x0E])[0],"04X")
		ckey = draytools.make_key(modelstr)
		return data[:0x100] + draytools.decrypt(data[0x100:], ckey)

	@staticmethod
	def get_credentials(data):
		login = data[0x100+0x28:0x100+0x40].replace('\x00','')
		password = data[0x100+0x40:0x100+0x58].replace('\x00','')
		return [login, password]

	@staticmethod
	def guess(data):
		if len(data) > 0x30000:
			return draytools.CFG_RAW
		if "Vigor" in data and "draytek" in data:
			return draytools.CFG_LZO
		return draytools.CFG_ENC

	@staticmethod
	def de_cfg(data):
		g = draytools.guess(data) 
		if g == draytools.CFG_RAW:
			return data
		elif g == draytools.CFG_LZO:
			return draytools.decompress_cfg(data)
		elif g == draytools.CFG_ENC:
			return draytools.decompress_cfg(draytools.decrypt_cfg(data))

	@staticmethod
	def decompress_firmware(data):
		flen = len(data)
		sigstart = data.find('\xA5\xA5\xA5\x5A\xA5\x5A')
		if sigstart <= 0:
			sigstart = data.find('\x5A\x5A\xA5\x5A\xA5\x5A')

		if sigstart > 0:
			lzosizestart = sigstart + 6
			lzostart = lzosizestart + 4
			lzosize = unpack('>L', data[lzosizestart:lzostart])[0]
			return data[0x100:sigstart+2]+pydelzo.decompress('\xF0' + pack(">L",0x1000000)+data[lzostart:lzostart+lzosize])
		else:
			print '[ERR]:\tCompressed FW signature not found!'
			return ''

	@staticmethod
	def decompress_fs(data, path, test = False, echo = False):
		lzofsdatalen = unpack('>L', data[4:8])[0]
		fsdatalen = 0x800000
		fs_raw = pydelzo.decompress('\xF0'+pack(">L",fsdatalen) + data[0x08:0x08+lzofsdatalen])
		cfs = draytools.fs(fs_raw,test,echo)
		return (lzofsdatalen, cfs.save_all(path))
	
	@staticmethod
	def decompress_fs_only(data, path, test = False, echo = False):
		fsstart = unpack('>L', data[:4])[0]
		return draytools.decompress_fs(data[fsstart:],path,test,echo)

if __name__=='__main__':
	import optparse

	usage = "usage: %prog [options] file"

	parser = optparse.OptionParser(usage=usage,version="%prog v0.2")

	cfggroup = optparse.OptionGroup(parser, "Config file (*.cfg) options",
                    "To be used on config files only")
	fwgroup = optparse.OptionGroup(parser, "Firmware file (*.all, *.rst, *.bin) options",
                    "To be used on firmware files only")

	parser.add_option('-o', '--output',
		action="store", dest="outfile",
		help="Output file name, %INPUTFILE%.out if omitted", default="")

	parser.add_option('-t', '--test',
		action="store_true", dest="test",
		help="Do not write anything, only try to parse files", default=False)

	parser.add_option('-v', '--verbose',
		action="store_true", dest="verbose",
		help="Verbose output", default=False)


	cfggroup.add_option('-c', '--config',
		action="store_true", dest="config",
		help="Decrypt and decompress config", default=False)

	cfggroup.add_option('-d', '--decompress',
		action="store_true", dest="decompress",
		help="Decompress an unenrypted config file", default=False)

	cfggroup.add_option('-y', '--decrypt',
		action="store_true", dest="decrypt",
		help="Decrypt config file", default=False)

	cfggroup.add_option('-p', '--password',
		action="store_true", dest="password",
		help="Retrieve admin login and password from config file", default=False)


	fwgroup.add_option('-f', '--firmware',
		action="store_true", dest="firmware",
		help="Decompress firmware", default=False)

	fwgroup.add_option('-F', '--firmware-all',
		action="store_true", dest="fw_all",
		help="Decompress firmware and extract filesystem", default=False)

	fwgroup.add_option('-s', '--fs',
		action="store_true", dest="fs",
		help="Extract filesystem", default=False)

	fwgroup.add_option('--out-dir',
		action="store", dest="outdir",
		help="Output directory for filesystem contents", default="fs_out")


	parser.add_option_group(cfggroup)
	parser.add_option_group(fwgroup)

	
	options, args = parser.parse_args()				

	infile = None
	data = None

	if len(args) > 1:
		print 'Too much arguments, only input file name expected'
		sys.exit(1)
	elif len(args) < 1:
		print 'Input file name expected'
		sys.exit(1)

	infile = file(args[0],'rb')
	indata = infile.read()

	outfname = options.outfile is not None and options.outfile or args[0]+'.out'
	outdir = options.outdir

	if options.config:
		outdata = draytools.de_cfg(indata)
		ol = len(outdata)
		if not options.test:
			outfile = file(outfname, 'wb')
			outfile.write(outdata)
			print outfname + ' written, %d [0x%08X] bytes'%(ol,ol)
			outfile.close()
		else:
			print 'CFG decryption/decompression test OK, output size %d [0x%08X] bytes'%(ol,ol)
			
	elif options.decrypt:
		outdata = draytools.decrypt_cfg(indata)
		ol = len(outdata)
		if not options.test:
			outfile = file(outfname, 'wb')
			outfile.write(outdata)
			outfile.close()
			print outfname + ' written, %d [0x%08X] bytes'%(ol,ol)
		else:
			print 'CFG decryption test OK, output size %d [0x%08X] bytes'%(ol,ol)
			                                   
	elif options.decompress:
		outdata = draytools.decompress_cfg(indata)
		ol = len(outdata)
		if not options.test:
			outfile = file(outfname, 'wb')
			outfile.write(outdata)
			outfile.close()
			print outfname + ' written, %d [0x%08X] bytes'%(ol,ol)
		else:
			print 'CFG decompression test OK, output size %d [0x%08X] bytes'%(ol,ol)

	if options.password and not (True in [options.firmware, options.fw_all, options.fs]):
		creds = draytools.get_credentials(draytools.de_cfg(indata))
		print "Login:\t" + (creds[0] == "" and "admin" or creds[0])
		print "Password:\t" + creds[1]
		sys.exit(0)

	if options.firmware:
		outdata = draytools.decompress_firmware(indata)
		ol = len(outdata)
		if not options.test:
			outfile = file(outfname, 'wb')
			outfile.write(outdata)
			outfile.close()
			print outfname + ' written, %d [0x%08X] bytes'%(ol,ol)
		else:
			print 'FW extraction test OK, output size %d [0x%08X] bytes'%(ol,ol)

	elif options.fw_all:
		outdata = draytools.decompress_firmware(indata)
		ol = len(outdata)
		if not options.test:
			outfile = file(outfname, 'wb')
			outfile.write(outdata)
			outfile.close()
			print outfname + ' written, %d [0x%08X] bytes'%(ol,ol)
		else:
			print 'FW extraction test OK, output size %d [0x%08X] bytes'%(ol,ol)

		fss, nf = draytools.decompress_fs_only(indata,outdir,options.test,options.verbose)
		if not options.test:
			print 'FS extracted to ['+ outdir+'], %d files extracted' % nf
		else:
			print 'FS extraction test OK, %d files extracted' % nf
		

	elif options.fs:
		fss, nf = draytools.decompress_fs_only(indata,outdir,options.test,options.verbose)
		if not options.test:
			print 'FS extracted to ['+ outdir+'], %d files extracted' % nf
		else:
			print 'FS extraction test OK, %d files extracted' % nf
			
