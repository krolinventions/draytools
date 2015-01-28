#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# DrayTek Vigor password recovery, config & firmware tools
#
# https://github.com/ammonium/draytools/
#
# draytools Copyright (C) 2011 AMMOnium <ammonium at mail dot ru>
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
#

import sys
import os
import re
import math

from struct import pack, unpack
from binascii import hexlify, unhexlify
from collections import defaultdict

from pydelzo import pydelzo, LZO_ERROR


class draytools:
    """DrayTek Vigor password recovery, config & firmware tools"""
    __version__ = "v0.41"
    copyright = \
    "draytools Copyright (C) 2011 AMMOnium <ammonium at mail dot ru>"
    
    CFG_RAW = 0
    CFG_LZO = 1
    CFG_ENC = 2

    verbose = False
    modelprint = True
    force_smart_guess = True

    class fs:
        """Draytek filesystem utilities"""
        def __init__(self, data, test=False, echo=False):
            self.cdata = data            
            self.test = test
            self.echo = echo

        def get_fname(self,i):
            """Return full filename of the file #i from FS header"""
            addr = 0x10+i*44
            return str(self.cdata[addr : addr+0x20].strip('\x00'))

        def get_hash(self,i):
            """Return currently unknown hash for the file #i from FS header"""
            addr = 0x10+i*44 + 0x20
            return unpack("<L", str(self.cdata[addr : addr+4]))[0]

        def get_offset(self,i):
            """Return offset of the file #i in FS block"""
            addr = 0x10+i*44 + 0x24
            return unpack("<L", str(self.cdata[addr : addr+4]))[0] \
                + self.datastart

        def get_fsize(self,i):    
            """Return compressed size of the file #i"""
            addr = 0x10+i*44 + 0x28
            return unpack("<L", str(self.cdata[addr : addr+4]))[0]

        def save_file(self,i):
            """Extract file #i from current FS"""            
            fname = self.get_fname(i)
            # compressed file data offset in FS block
            ds = self.get_offset(i)
            # size of compressed file
            fs = self.get_fsize(i)
            # compressed file data
            fdata = self.cdata[ds : ds+fs]
            # create all subdirs along the path if they don't exist
            pp = fname.split('\\')
            pp = [self.path] + pp
            ppp = os.sep.join(pp[:-1])
            if len(pp) > 1:
                if not os.path.exists(ppp) and not self.test:
                    os.makedirs(ppp)
            nfname = os.sep.join(pp)
            # size of uncompressed file
            rawfs = -1
            if not self.test:
                ff = file(nfname,'wb')
            # perform extraction, some file types are not compressed
            if fs>0:    
                if pp[-1].split('.')[-1].lower() \
                in ['gif','jpg','cgi','cab','txt','jar']:
                    rawfdata = fdata
                else:
                    try:
                        rawfdata = pydelzo.decompress('\xF0' \
                            + pack(">L",fs*64)+fdata)
                    except LZO_ERROR as lze:
                        print '[ERR]:\tFile "'+ fname \
                            + '" is damaged or uncompressed [' \
                            + str(lze) \
                            + '], RAW DATA WRITTEN'
                        rawfdata = fdata
            else:
                rawfdata = ''
            rawfs = len(rawfdata)
            if not self.test:
                ff.write(rawfdata)
                ff.close()
            # print some debug info for each file
            if self.echo:
                print '%08X "' % ds + fname + '" %08X' % fs \
                    + ' %08X' % rawfs
            return (fs, rawfs)

        def save_all(self, path):
            """Extract all files from current FS"""
            self.path = path
            numfiles = unpack("<H", str(self.cdata[0x0E:0x10]))[0]
            # All files data block offset in FS
            self.datastart = 0x10 + 44 * numfiles    
            for i in xrange(numfiles):
                fs,rawfs = self.save_file(i)
            return numfiles


    @staticmethod
    def v2k_checksum(data):
        """V2xxx checksum function, 32-bit checksum of a given block"""
        a1 = (len(data) - 4) >> 2
        if len(data) < 4:
            return 0xFFFFFFFF
        if len(data) % 4:
            data += '\x00' * (4 - len(data) % 4)

        pos = 0
        v0 = 0
        a0 = 0
        a2 = 0

        while a1 > 0:
            v0 = unpack(">L", data[pos+a0:pos+a0+4])[0]
            a0 += 4
            a2 += v0
            a1 -= 1

        v0 = unpack(">L",data[pos+a0:pos+a0+4])[0]
        a2 = ~a2
        v0 ^= a2
        return v0 & 0xFFFFFFFF

    @staticmethod
    def get_modelid(data):
        """Extract a model ID from config file header"""
        modelid = data[0x0C:0x0E]
        return modelid

    @staticmethod
    def decompress_cfg(data):
        """Decompress a config file"""
        modelstr = "V" + format(unpack(">H", 
            draytools.get_modelid(data))[0],"04X")
        if draytools.verbose and draytools.modelprint: 
            print 'Model is :\t' + modelstr
        else:
            draytools.modelprint = True
        rawcfgsize = 0x00100000
        lzocfgsize = unpack(">L", data[0x24:0x28])[0]
        raw = data[:0x2D] + '\x00' + data[0x2E:0x100] \
            + pydelzo.decompress('\xF0' + pack(">L",rawcfgsize) \
            + data[0x100:0x100+lzocfgsize])
        return raw

    @staticmethod
    def make_key(modelstr):
        """Construct a key out of a model string (like 'V2710')"""
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
        """Decrypt a block of data using given key"""
        rdata = ''
        for i in xrange(len(data)):
            rdata += chr(draytools.dec(ord(data[i]), key))
        return rdata
#        return ''.join(map(lambda od:chr(draytools.dec(ord(od),key)),data))

    @staticmethod
    def brute_cfg(data):
        """Check all possible keys until data looks like decrypted"""
        rdata = None
        key = 0
        for i in xrange(256):
            rdata = draytools.decrypt(data, i)
            if draytools.smart_guess(rdata) == draytools.CFG_LZO:
                key = i
                break
        if draytools.verbose:
            print 'Found key:\t[0x%02X]' % key
        return rdata

    @staticmethod
    def decrypt_cfg(data):
        """Decrypt config, bruteforce if default key fails"""
        modelstr = "V" + format(unpack(">H", 
            draytools.get_modelid(data))[0],"04X")
        if draytools.verbose:
            print 'Model is :\t' + modelstr
            draytools.modelprint = False
        ckey = draytools.make_key(modelstr)
        rdata = draytools.decrypt(data[0x100:], ckey)
        # if the decrypted data does not look good, bruteforce
        if draytools.smart_guess(rdata) != draytools.CFG_LZO:
            rdata = draytools.brute_cfg(data[0x100:])
        elif draytools.verbose:
            print 'Used key :\t[0x%02X]' % ckey
        return data[:0x2D] + '\x01' + data[0x2E:0x100] + rdata

    @staticmethod
    def get_credentials(data):
        """Extract admin credentials from config"""
        login = data[0x100+0x28:0x100+0x40].split('\x00')[0]
        password = data[0x100+0x40:0x100+0x58].split('\x00')[0]
        return [login, password]

    @staticmethod
    def get_params(data):
        """Extract parameters from config"""
        desc = []
        packstring = ">296s"# ??? do 296
        desc.append("???")

        packstring += "24s"# login do 320 
        desc.append("login")

        packstring += "24s"# password 344
        desc.append("System Maintenance >> Administrator Password Setup >> Administrator Password")

        packstring += "24s"# Router Name 368
        desc.append("System Maintenance >> Management >> Management Setup >> Roouter Name")

        packstring += "160s"# ??? 598
        desc.append("???")

        packstring += 'i'# System Maintenance >> Management >> Management Setup >> Management Port Setup >> Telnet Port
        desc.append("System Maintenance >> Management >> Management Setup >> Management Port Setup >> Telnet Port")

        packstring += 'i'# System Maintenance >> Management >> Management Setup >> Management Port Setup >> HTTP Port
        desc.append("System Maintenance >> Management >> Management Setup >> Management Port Setup >> HTTP Port")

        packstring += 'i'# System Maintenance >> Management >> Management Setup >> Management Port Setup >> FTP Port
        desc.append("System Maintenance >> Management >> Management Setup >> Management Port Setup >> FTP Port")

        packstring += 'i'# System Maintenance >> Management >> Management Setup >> Management Port Setup >> HTTPS Port
        desc.append("System Maintenance >> Management >> Management Setup >> Management Port Setup >> HTTPS Port")

        packstring += "32s"
        desc.append("???")

        for i in range(20):
            packstring += "H" # NAT >> Port Redirection >> Index No. %02d >> Public Port
            desc.append("NAT >> Port Redirection >> Index No. %02d >> Public Port"% (i+1))
            packstring += "2s" # ????
            desc.append("???")
            packstring += "16s"# NAT >> Port Redirection >> Index No. %02d >> Private IP
            desc.append("NAT >> Port Redirection >> Index No. %02d >> Private IP"% (i+1))
            packstring += "H" # NAT >> Port Redirection >> Index No. %02d >> Private Port
            desc.append("NAT >> Port Redirection >> Index No. %02d >> Private Port"% (i+1))
            packstring += "24s"# NAT >> Port Redirection >> Index No. %02d >> Service Name
            desc.append("NAT >> Port Redirection >> Index No. %02d >> Service Name"% (i+1))
            packstring += "4s" # ????
            desc.append("???")

        packstring += "2344s"# ??? 392
        desc.append("???")

        packstring += "24s"# System Maintenance >> Management >> Management Setup >> SNMP Setup >> Trap Community 3944
        desc.append("System Maintenance >> Management >> Management Setup >> SNMP Setup >> Trap Community")

        packstring += "24s"# System Maintenance >> Management >> Management Setup >> SNMP Setup >> Get Community 3968
        desc.append("System Maintenance >> Management >> Management Setup >> SNMP Setup >> Get Community")

        packstring += "24s"# System Maintenance >> Management >> Management Setup >> SNMP Setup >> Set Community 3992
        desc.append("System Maintenance >> Management >> Management Setup >> SNMP Setup >> Set Community")

        packstring += "88s"# ??? 408
        desc.append("???")

        packstring += "32s"# System Maintenance >> Time Date >> Time Setup >> Server IP Address 4112
        desc.append("System Maintenance >> Time Date >> Time Setup >> Server IP Address")

        packstring += "11928s"# ??? 16040
        desc.append("???")

        for i in range(2):
            packstring += "24s"# Interface WAN %d Display Name
            desc.append("Interface WAN %d Display Name"% (i+1))
            packstring += "600s"# ???
            desc.append("???")

        packstring += "19716s"# ??? 37004 
        desc.append("???")

        for i in range(12):
            packstring += "24s"# Filter Set %02d Comment
            desc.append("Filter Set %02d Comment"% (i+1))
            packstring += "32s"# ???
            desc.append("???")
            for j in range(1,8):
                packstring += "24s"# Filter Set %02d Rule %02d Comment
                desc.append("Filter Set %02d Rule %02d Comment"% (i+1,j))
                packstring += "120s"# ???
                desc.append("???") # 49772

        packstring += "200s"# ???
        desc.append("???") # 49972

        for i in range(192):
            packstring += "16s"# Object Setting >> IP Object >> Profile Index : %03d >> Name
            desc.append("Object Setting >> IP Object >> Profile Index : %03d >> Name"% (i+1))
            packstring += "20s"# ??? 
            desc.append("???") # 56884



        for i in range(20):
            packstring += "16s"# Object Setting >> IP Group >> Profile Index : %02d >> Name
            desc.append("Object Setting >> IP Group >> Profile Index : %02d >> Name"% (i+1))
            packstring += "16s"# ??? 
            desc.append("???") # 57524

        packstring += "384s"# ??? 57908
        desc.append("???")

        for i in range(96):
            packstring += "16s"# "Object Setting >> Service Type Object >> Profile Index : %02d >> Name
            desc.append("Object Setting >> Service Type Object >> Profile Index : %02d >> Name"% (i+1))
            packstring += "12s"# ??? 
            desc.append("???") # 60596

        packstring += "23588s"# ??? 84184
        desc.append("???")

        packstring += "256s"# CSM >> URL Content Filter Profile >> Administration Message 84440
        desc.append("CSM >> URL Content Filter Profile >> Administration Message")

        packstring += "12s"# ??? 84452
        desc.append("???")

        for i in range(8):
            packstring += "16s"# FIX: CSM >> URL Content Filter Profile >> Profile Index : %01d >> Profile Name 84580
            desc.append("CSM >> URL Content Filter Profile >> Profile Index : %01d >> Profile Name"% (i+1))
            packstring += "108s"# ??? 
            desc.append("???");

        for i in range(8):
            packstring += "8s"# [FIX] Object Setting >> File Extension Object >> Profile Index : %0d >> Profile Name
            desc.append("Object Setting >> File Extension Object >> Profile Index : %0d >> Profile Name"% (i+1))
            packstring += "160s"# ??? 
            desc.append("???")

        packstring += "4s"
        desc.append("???")

        packstring += "256s"# CSM >> Web Content Filter Profile >> Administration Message 87048
        desc.append("CSM >> Web Content Filter Profile >> Administration Message")

        packstring += "1292s"# ??? 88340
        desc.append("???")

        packstring += "256s"# Bandwidth Management >> Session Limit >> Administration Message 88596  
        desc.append("Bandwidth Management >> Session Limit >> Administration Message")

        packstring += "4s"# ??? 88600
        desc.append("???")

        for i in range(32):
            packstring += "12s"# LAN >> Bind IP to MAC >> IP Bind List >> Index %02d >> Comment 88984
            desc.append("LAN >> Bind IP to MAC >> IP Bind List >> Index %02d >> Commen"% (i+1))
        packstring += "14080s"# ??? 103064 
        desc.append("???")

        for i in range(3):
            packstring += "12s"# Bandwidth Management >> Quality of Service >> Class index #%01d >> Name 
            desc.append("Bandwidth Management >> Quality of Service >> Class index #%01d >> Name"% (i+1))
            packstring += "1040s"# ???
            desc.append("???")

        packstring += "4660s"# ??? 110880
        desc.append("???")

        for i in range(4):
            packstring += "32s"# Wireless LAN >> General Setup >> General Setting (IEEE 802.11) >> %01d >> SSID
            desc.append("Wireless LAN >> General Setup >> General Setting (IEEE 802.11) >> %01d >> SSID"% (i+1))
            packstring += "472s"# ???
            desc.append("???") # 118296
            packstring += "64s"# Wireless LAN >> Security Settings >> SSID %01d >> Pre-Shared Key (PSK)
            desc.append("Wireless LAN >> Security Settings >> SSID %01d >> Pre-Shared Key (PSK)"% (i+1))
            packstring += "1286s"# ???
            desc.append("???") # 118296

        #packstring += "59776s"# ??? 164616
        packstring += "46272s"# ??? 164616
        desc.append("???")

        for i in range(32): 
            packstring += "48s"# VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-In Settings >> Peer ID 
            desc.append("VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-In Settings >> Peer ID"% (i+1))
        
        packstring += "11968s"# ??? 178072
        desc.append("???")

        for i in range(32):
            packstring += "10s"# VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Common Settings >> Profile Name
            desc.append("VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Common Settings >> Profile Name"% (i+1))
            packstring += "10s"# ???
            desc.append("???")
            packstring += "12s"# VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-In Settings >> Username
            desc.append("VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-In Settings >> Username"% (i+1))
            packstring += "60s"# ???
            desc.append("???")
            packstring += "50s"# VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-Out Settings >> Username
            desc.append("VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-Out Settings >> Username"% (i+1))
            packstring += "14s"# ???
            desc.append("???")
            packstring += "16s"# VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-Out Settings >> Password
            desc.append("VPN and Remote Access >> LAN to LAN >> Profile Index : %02d >> Dial-Out Settings >> Password"% (i+1))
            packstring += "44s"# ???
            desc.append("???")

        packstring += "81476s"# ??? 
        desc.append("???")

        for i in range(200):
            packstring += "16s"# Object Setting >> Keyword Object >> Profile Index : %03d >> Name
            desc.append("Object Setting >> Keyword Object >> Profile Index : %03d >> Name"% (i+1))
            packstring += "64s"# Object Setting >> Keyword Object >> Profile Index : %03d >> Contents
            desc.append("Object Setting >> Keyword Object >> Profile Index : %03d >> Contents"% (i+1))
            packstring += "64s"# Object Setting >> Keyword Object >> Profile Index : %03d >> Contents
            desc.append("???")

        for i in range(32):
            packstring += "16s"# Object Setting >> Keyword Group Setup >> Profile Index : %03d >> Name
            desc.append("Object Setting >> Keyword Object >> Profile Index : %03d >> Name"% (i+1))
            packstring += "48s"# ???
            desc.append("???")

        packstring += "1920s"# 299228
        desc.append("???")

        for i in range(32):
            packstring += "16s"# CSM >> APP Enforcement Profile >> Profile Index : %0d >> Profile Name
            desc.append("CSM >> APP Enforcement Profile >> Profile Index : %02d >> Profile Name"% (i+1))
            packstring += "160s"# ???
            desc.append("???") 

        packstring += "27916s"# 332776 
        desc.append("???")

        packstring += "16s"# USB General Settings Workgroup Name 332792
        desc.append("USB General Settings Workgroup Name")

        packstring += "31712s"# ??? 364504 
        desc.append("???")

        packstring += "32s"# "System Maintenance >> Login Page Greeting >> Login Page Title 364536
        desc.append("System Maintenance >> Login Page Greeting >> Login Page Title")

        packstring += "384s"# ??? 364920 
        desc.append("???")

        packstring += "512s"# "System Maintenance >> Login Page Greeting >> Login Page Title 365432
        desc.append("System Maintenance >> Login Page Greeting >> Login Page Title")

        variables = list(unpack(packstring, data[:365432]))
        for i in range(0,len(variables)):
            if type(variables[i]) == type(str()):
                variables[i]=variables[i].split('\x00')[0]
        dict_list = zip (desc, variables) 
        
        return dict(dict_list)

    @staticmethod
    def guess(data):
        """Return CFG type - raw(0), compressed(1), encrypted(2)"""
        return ord(data[0x2D])

    @staticmethod
    def smart_guess(data):
        """Guess is the cfg block compressed or not"""
        # Uncompressed block is large and has low entropy
        if draytools.entropy(data) < 1.0 or len(data) > 0x10000:
             return draytools.CFG_RAW
        # Compressed block still has pieces of cleartext at the beginning
        if "Vigor" in data and ("Series" in data or "draytek" in data):
            return draytools.CFG_LZO
        return draytools.CFG_ENC

    @staticmethod
    def de_cfg(data):
        """Get raw config data from raw /compressed/encrypted & comressed"""
        if draytools.force_smart_guess:
            g = draytools.smart_guess(data)
        else:
            g = draytools.guess(data)
        if g == draytools.CFG_RAW:
            if draytools.verbose:
                print 'File is  :\tnot compressed, not encrypted'
            return g, data
        elif g == draytools.CFG_LZO:
            if draytools.verbose:
                print 'File is  :\tcompressed, not encrypted'
            return g, draytools.decompress_cfg(data)
        elif g == draytools.CFG_ENC:
            if draytools.verbose:
                print 'File is  :\tcompressed, encrypted'
            return g, draytools.decompress_cfg(draytools.decrypt_cfg(data))

    @staticmethod
    def decompress_firmware(data):
        """Decompress firmware"""
        flen = len(data)
        sigstart = data.find('\xA5\xA5\xA5\x5A\xA5\x5A')
        # Try an alternative signature
        if sigstart <= 0:
            sigstart = data.find('\x5A\x5A\xA5\x5A\xA5\x5A')
        # Compressed FW block found, now decompress
        if sigstart > 0:
            if draytools.verbose:
                print 'Signature found at [0x%08X]' % sigstart
            lzosizestart = sigstart + 6
            lzostart = lzosizestart + 4
            lzosize = unpack('>L', data[lzosizestart:lzostart])[0]
            return data[0x100:sigstart+2] \
                + pydelzo.decompress('\xF0' + pack(">L",0x1000000) \
                    + data[lzostart:lzostart+lzosize])
        else:
            print '[ERR]:\tCompressed FW signature not found!'
            raise Exception('Compressed FW signature not found')
            return ''

    @staticmethod
    def decompress_fs(data, path, test = False):
        """Decompress filesystem"""
        lzofsdatalen = unpack('>L', data[4:8])[0]
        if draytools.verbose:
            print 'Compressed FS length: %d [0x%08X]' % (lzofsdatalen, 
                lzofsdatalen)
        # stupid assumption of raw FS length. Seems OK for now
        fsdatalen = 0x800000
        fs_raw = pydelzo.decompress('\xF0' + pack(">L", fsdatalen) \
             + data[0x08:0x08 + lzofsdatalen])
        cfs = draytools.fs(fs_raw, test, draytools.verbose)
        return (lzofsdatalen, cfs.save_all(path))
    
    @staticmethod
    def decompress_fs_only(data, path, test = False):
        """Decompress filesystem"""
        fsstart = unpack('>L', data[:4])[0]
        if draytools.verbose:
            print 'FS block start at: %d [0x%08X]' % (fsstart, fsstart)
        return draytools.decompress_fs(data[fsstart:], path, test)

    @staticmethod
    def entropy(data):
        """Calculate Shannon entropy (in bits per byte)"""
        flist = defaultdict(int)
        dlen = len(data)
        data = map(ord, data)
        # count occurencies
        for byte in data:
            flist[byte] += 1
        ent = 0.0
        # convert count of occurencies into frequency
        for freq in flist.values():
            if freq > 0:
                ffreq = float(freq)/dlen
                # actual entropy calcualtion
                ent -= ffreq * math.log(ffreq, 2)
        return ent

    @staticmethod
    def spkeygen(mac):
        """Generate a master key like 'AbCdEfGh' from MAC address"""
        # stupid translation from MIPS assembly, but works
        atu = 'WAHOBXEZCLPDYTFQMJRVINSUGK'
        atl = 'kgusnivrjmqftydplczexbohaw'
        res = ['\x00'] * 8
        st = [0] * 8
        # compute 31*(31*(31*(31*(31*m0+m1)+m2)+m3)+m4)+m5, sign-extend mac bytes
        a3 = 0
        for i in mac:
            v1 = a3 << 5
            v1 &= 0xFFFFFFFF
            a0 = ord(i)
            if a0 >= 0x80:
                a0 |= 0xFFFFFF00
            v1 -= a3
            v1 &= 0xFFFFFFFF
            a3 = v1 + a0
            a3 &= 0xFFFFFFFF
        # Divide by 13 :) Old assembly trick, I leave it here
        # 0x4EC4EC4F is a multiplicative inverse for 13
        ck = 0x4EC4EC4F * a3
        v1 = (ck & 0xFFFFFFFF00000000) >> 32
        # shift by two
        v1 >>= 3
        v0 = v1 << 1
        v0 &= 0xFFFFFFFF
        # trick ends here and now v0 = a3 / 13
        v0 += v1
        v0 <<= 2
        v0 &= 0xFFFFFFFF
        v0 += v1
        v0 <<= 1
        v0 -= a3
    #    v0 &= 0xFFFFFFFF
        st[0] = a3
        res[0] = atu[abs(v0)]
        
        for i in xrange(1,8):
            v1 = st[i-1]
            a0 = ord(res[0])
            t0 = ord(res[1])
            v0 = (v1 << 5) & 0xFFFFFFFF
            a1 = ord(res[2])
            v0 -= v1
            v0 += a0
            a2 = ord(res[3])
            a3 = ord(res[4])
            v0 += t0
            v0 += a1
            t0 = ord(res[5])
            v1 = ord(res[6])
            v0 += a2
            a0 = ord(res[7])
            v0 += a3
            v0 += t0
            v0 += v1
            # v0 here is a 32-bit sum of currently computed key chars
            v0 &= 0xFFFFFFFF
            a3 = v0 + a0
            # Again divide by 13
            i1 = a3 * 0x4EC4EC4F
            a0 = i & 1
            st[i] = a3
            v1 = (i1 & 0xFFFFFFFF00000000) >> 32
            v1 >>= 3
            v0 = v1 << 1
            # here v0 = a3 / 13
            v0 += v1
            v0 <<= 2
            v0 += v1
            v0 <<= 1
            v0 = a3 - v0
            a1 += v0
            v0 &= 0xFFFFFFFF
            if a0 == 0:
                v1 = atu[abs(v0)]
            else:
                v1 = atl[abs(v0)]
            res[i] = v1
            v0 = 0
        return ''.join(res)
        


if __name__ == '__main__':
    import optparse

    usage = \
"""usage: %prog [options] file
DrayTek Vigor V2xxx/V3xxx password recovery, config & firmware tools"""

# initialize cmdline option parser
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog
    parser = optparse.OptionParser(usage=usage, \
        version="%prog "+draytools.__version__, \
        epilog=
"""
Examples:

To print login&password from the config file:
# python draytools.py -p config.cfg
    Login and password will be displayed

To decrypt & decompress the config file:
# python draytools.py -c config.cfg
    Raw config file "config.cfg.out" will be produced

To extract firmware and filesystem contents
# python draytools.py -F firmware.all
    Uncompressed firmware will be written to file "firmware.all.out"
    Filesystem will be extracted to "fs_out" folder.
""")

    cfggroup = optparse.OptionGroup(parser, "Config file (*.cfg) commands",
        "To be used on config files only")
    fwgroup = optparse.OptionGroup(parser, \
        "Firmware file (*.all, *.rst, *.bin) commands",
        "To be used on firmware files only")
    
    mgroup = optparse.OptionGroup(parser, "Miscellaneous commands",
        "Some other useful stuff")

    parser.add_option('-o', '--output',
        action="store", dest="outfile",
        help="Output file name, %INPUTFILE%.out if omitted", default="")

    parser.add_option('-t', '--test',
        action="store_true", dest="test", help=
"""Test mode, do not write anything to disk, only try to parse files""",
        default=False)

    parser.add_option('-v', '--verbose',
        action="store_true", dest="verbose",
        help="Verbose output", default=False)

# config file option group for cmdline option parser 

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
        help="Retrieve admin login and password from config file", 
        default=False)

    cfggroup.add_option('-e', '--extract',
        action="store_true", dest="text",
        help="Extract text config from config file",
        default=False)


# firmware/fs option group for cmdline option parser 

    fwgroup.add_option('-f', '--firmware',
        action="store_true", dest="firmware",
        help="Decompress firmware", default=False)

    fwgroup.add_option('-F', '--firmware-all',
        action="store_true", dest="fw_all",
        help="Decompress firmware and extract filesystem", default=False)

    fwgroup.add_option('-s', '--fs',
        action="store_true", dest="fs",
        help="Extract filesystem", default=False)

    fwgroup.add_option('-O', '--out-dir',
        action="store", dest="outdir",
        help=
        "Output directory for filesystem contents, \"fs_out\" by default", 
        default="fs_out")

# miscellaneous option group for cmdline option parser 
    mgroup.add_option('-m', '--master-key',
        action="store", dest="mac",
        help="Generate FTP master key for given router MAC address. "
        "To login to FTP enter \"admin\" as username and generated "
        "master key as password", 
        default=None)


    parser.add_option_group(cfggroup)
    parser.add_option_group(fwgroup)
    parser.add_option_group(mgroup)

    
    options, args = parser.parse_args()

    draytools.verbose = options.verbose

# default output filename is input filename + '.out'
    outfname = options.outfile is not None and options.outfile \
        or (len(args) > 0 and args[0]+'.out' or 'file.out')
    outdir = options.outdir


    infile = None
    data = None
    indata = None
    outdata = None

    if len(args) > 1:
        print '[ERR]:\tToo much arguments, only input file name expected'
        print 'Run "draytools --help"'
        sys.exit(1)
    elif len(args) < 1 and not options.mac:
        print '[ERR]:\tInput file name expected'
        print 'Run "draytools --help"'
        sys.exit(1)

# open input file
    if not options.mac:
        try:
            infile = file(args[0],'rb')
            indata = infile.read()
            # if default FS extraction path is used, put it near input file
            if outdir == 'fs_out':
                outdir = os.path.join(os.path.dirname(
                    os.path.abspath(args[0])),'fs_out')

        except IOError:
            print '[ERR]:\tInput file open failed'
            sys.exit(2)

# Command: get raw config file
    if options.config:
        g = -1
        try:
            g, outdata = draytools.de_cfg(indata)
        except LZO_ERROR:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)
        if g == draytools.CFG_RAW:
            print '[ERR]:\tNothing to do. '\
                'Config file is already not encrypted and not compressed.'
            sys.exit(3)
                        
        ol = len(outdata)
        if not options.test:
            outfile = file(outfname, 'wb')
            outfile.write(outdata)
            print outfname + ' written, %d [0x%08X] bytes' % (ol,ol)
            outfile.close()
        else:
            print 'CFG decryption/decompression test OK, ' \
            'output size %d [0x%08X] bytes' % (ol,ol)
            
# Command: decrypt config file
    elif options.decrypt:
        try:
            outdata = draytools.decrypt_cfg(indata)
        except LZO_ERROR:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)

        cksum = draytools.v2k_checksum(str(outdata))
        if options.verbose:
            print 'V2kCheckSum = %08X ' % \
                cksum + ((cksum == 0) and 'OK' or 'FAIL')
        ol = len(outdata)
        if not options.test:
            outfile = file(outfname, 'wb')
            outfile.write(outdata)
            outfile.close()
            print outfname + ' written, %d [0x%08X] bytes' % (ol,ol)
        else:
            print 'CFG decryption test OK, ' \
            'output size %d [0x%08X] bytes' % (ol,ol)

# Command: decompress config file
    elif options.decompress:
        try:
            outdata = draytools.decompress_cfg(indata)
        except LZO_ERROR:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)
        cksum = draytools.v2k_checksum(str(indata))
        if options.verbose:
            print 'V2kCheckSum = %08X ' % \
                cksum + ((cksum == 0) and 'OK' or 'FAIL')
        ol = len(outdata)
        if not options.test:
            outfile = file(outfname, 'wb')
            outfile.write(outdata)
            outfile.close()
            print outfname + ' written, %d [0x%08X] bytes' % (ol,ol)
        else:
            print 'CFG decompression test OK, ' \
            'output size %d [0x%08X] bytes' % (ol,ol)

# Command: extract admin credentials from config file
    if options.password and \
    not (True in [options.firmware, options.fw_all, options.fs]):
        g = -1
        try:
            g, outdata = draytools.de_cfg(indata)
        except LZO_ERROR:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)
        creds = draytools.get_credentials(outdata)
        print "Login    :\t" + (creds[0] == "" and "admin" or creds[0])
        print "Password :\t" + (creds[1] == "" and "admin" or creds[1])
        sys.exit(0)

# Command: extract parameters from config file
    if options.text and \
    not (True in [options.firmware, options.fw_all, options.fs]):
        g = -1
        try:
            g, outdata = draytools.de_cfg(indata)
        except LZO_ERROR:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)
        params = draytools.get_params(outdata)
        for k,v in sorted(params.iteritems()):
            if v:      
                print "%s => %s" % (k, v)

        sys.exit(0)

# Command: extract firmware
    if options.firmware:
        try:
            outdata = draytools.decompress_firmware(indata)
        except:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)

        ol = len(outdata)
        if not options.test:
            outfile = file(outfname, 'wb')
            outfile.write(outdata)
            outfile.close()
            print outfname + ' written, %d [0x%08X] bytes' % (ol,ol)
        else:
            print 'FW extraction test OK, ' \
                'output size %d [0x%08X] bytes' % (ol,ol)

# Command: extract firmware and filesystem
    elif options.fw_all:
        try:
            outdata = draytools.decompress_firmware(indata)
        except:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)

        ol = len(outdata)
        if not options.test:
            outfile = file(outfname, 'wb')
            outfile.write(outdata)
            outfile.close()
            print outfname + ' written, %d [0x%08X] bytes' % (ol,ol)
        else:
            print 'FW extraction test OK, ' \
                'output size %d [0x%08X] bytes' % (ol,ol)

        try:
            fss, nf = draytools.decompress_fs_only(indata, outdir, 
                options.test)
        except:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)
        if not options.test:
            print 'FS extracted to [' + outdir + '], %d files extracted' % nf
        else:
            print 'FS extraction test OK, %d files extracted' % nf
        

# Command: extract filesystem
    elif options.fs:
        try:
            fss, nf = draytools.decompress_fs_only(indata, outdir, 
                options.test)
        except:
            print '[ERR]:\tInput file corrupted or not supported'
            sys.exit(3)

        if not options.test:
            print 'FS extracted to [' + outdir + '], %d files extracted' % nf
        else:
            print 'FS extraction test OK, %d files extracted' % nf

# Command: generate master password
    elif options.mac is not None:
        # validate mac address (hex, delimited by colons, dashes or nothing)
        xr = re.compile(\
            r'^([a-fA-F0-9]{2}([:-]?)[a-fA-F0-9]{2}(\2[a-fA-F0-9]{2}){4})$')
        rr = xr.match(options.mac)
        if rr:
            xmac = unhexlify(re.sub('[:\-]', '', options.mac))
            print 'Username  :\t' + "admin"
            print 'Master key:\t' + draytools.spkeygen(xmac)
        else:
            print '[ERR]:\tPlease enter a valid MAC address, e.g '\
            '00-11-22-33-44-55 or 00:DE:AD:BE:EF:00 or 1337babecafe'
# EOF

