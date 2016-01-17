#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3, sys, glob, shutil, json, time, hashlib
from base64 import b64decode
from os import path, walk,makedirs,remove
from ctypes import (Structure, c_uint, c_void_p, c_ubyte,c_char_p, CDLL, cast,byref,string_at)
from datetime import datetime
from subprocess import call

# Magic Module: https://github.com/ahupp/python-magic

###############################################################################################################

magicpath = 'C:\WINDOWS\system32\magic' # Only in Windows, path to magic file (Read Manual in www.dumpzilla.org)

watchsecond = 4 # --Watch option: Seconds update. (NO Windows)
python3_path = "" # Python 3.x path (NO Windows). Example: /usr/bin/python3.2

##############################################################################################################

def show_info_header():
   if sys.version.startswith('2.') == True and varSession2OK == 1 and varPasswordsOK == 1:
      print ("\n[WARNING]: Python 2.x currently used, Python 3.x and UTF-8 is recommended !")
   elif varSession2OK == 1:
      print ("\nExecution time: %s" % datetime.now())
      print ("Mozilla Profile: %s\n" % varDir)

##############################################################################################################

def show_sha256(filepath):
   sha256 = hashlib.sha256()
   f = open(filepath, 'rb')
   try:
      sha256.update(f.read())
   finally:
       f.close()
   return "[SHA256 hash: "+sha256.hexdigest()+"]"

#############################################################################################################

class SECItem(Structure):
   _fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]
		
class secuPWData(Structure):
   _fields_ = [('source',c_ubyte),('data',c_char_p)]

(SECWouldBlock,SECFailure,SECSuccess)=(-2,-1,0)
(PW_NONE,PW_FROMFILE,PW_PLAINTEXT,PW_EXTERNAL)=(0,1,2,3)

def readsignonDB(varDir):
   show_title("Decode Passwords", 250)	
   count = 0
   if libnss.NSS_Init(varDir)!=0:
      print ("Error Initializing NSS_Init, Probably no useful results")
   conn = sqlite3.connect(varDir+"/signons.sqlite")
   conn.text_factory = str
   c = conn.cursor()
   c.execute("select hostname, encryptedUsername, encryptedPassword from moz_logins")
   for row in c:
      uname.data  = cast(c_char_p(b64decode(row[1])),c_void_p)
      uname.len = len(b64decode(row[1]))
      passwd.data = cast(c_char_p(b64decode(row[2])),c_void_p)
      passwd.len=len(b64decode(row[2]))
      if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
         print ("Error: Master Password used !")
         return
      print ("Web: %s:"%row[0].encode("utf-8"))
      print ("Username: %s" % string_at(dectext.data,dectext.len))
      if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
         print ("Error: Master Password used !")
         return
      print ("Passsword: %s" % string_at(dectext.data,dectext.len))
      print ("\n")
      count = count + 1
   contador['Passwords_decode'] = count
   c.close()
   conn.close()
   libnss.NSS_Shutdown()

##############################################################################################################

def show_session(varDir):
   if sys.platform.startswith('win') == True:
      if path.isfile(varDir+"\\sessionstore.js") == False and  path.isfile(varDir+"\\sessionstore.json") == False:
         return
      else:
         if path.isfile(varDir+"\\sessionstore.js") == True:
            f = open(varDir+"\\sessionstore.js")
            hashsession = show_sha256(varDir+"\\sessionstore.js")
         elif  path.isfile(varDir+"\\sessionstore.json") == True:
            f = open(varDir+"\\sessionstore.json")
            hashsession = show_sha256(varDir+"\\sessionstore.json")
   else:
      if path.isfile(varDir+"/sessionstore.js") == False and path.isfile(varDir+"/sessionstore.json") == False:
         return
      else:
         if path.isfile(varDir+"/sessionstore.js") == True:
            f = open(varDir+"/sessionstore.js")
            hashsession = show_sha256(varDir+"/sessionstore.js")
         elif  path.isfile(varDir+"/sessionstore.json") == True:
            f = open(varDir+"/sessionstore.json")
            hashsession = show_sha256(varDir+"/sessionstore.json")
   filesession = "js"
   jdata = json.loads(f.read())
   f.close()
   extract_data_session(jdata,filesession,hashsession)

   if sys.platform.startswith('win') == True:
      if path.isfile(varDir+"\\sessionstore.bak") == False and  path.isfile(varDir+"\\sessionstore.bak") == False:
         return
      else:
         if path.isfile(varDir+"\\sessionstore.bak") == True:
            f = open(varDir+"\\sessionstore.bak")
            hashsession = show_sha256(varDir+"\\sessionstore.bak")

   else:
      if path.isfile(varDir+"/sessionstore.bak") == False and path.isfile(varDir+"/sessionstore.bak") == False:
         return
      else:
         if path.isfile(varDir+"/sessionstore.bak") == True:
            f = open(varDir+"/sessionstore.bak")
            hashsession = show_sha256(varDir+"/sessionstore.bak")

   filesession = "bak"
   jdata = json.loads(f.read())
   f.close()
   extract_data_session(jdata,filesession,hashsession)

###################################################################################################################

def extract_data_session(jdata,filesession,hashsession):
   if filesession == "js":
      show_title("Session              "+hashsession, 302)
   elif filesession == "bak":
      show_title("Backup session       "+hashsession, 302)

   count = 0
   print ("Last update %s:\n " % time.ctime(jdata["session"]["lastUpdate"]/1000.0))
   for win in jdata.get("windows"):
       for tab in win.get("tabs"):
           if tab.get("index") is not None:
              i = tab.get("index") - 1
           print ("Title: %s" % tab.get("entries")[i].get("title"))
           print ("URL: %s" % tab.get("entries")[i].get("url"))
           if tab.get("entries")[i].get("referrer") is not None:
              print ("Referrer: %s" % tab.get("entries")[i].get("referrer"))
           if tab.get("entries")[i].get("formdata") is not None and str(tab.get("entries")[i].get("formdata")) != "{}" :
              if str(tab.get("entries")[i].get("formdata").get("xpath")) == "{}" and str(tab.get("entries")[i].get("formdata").get("id")) != "{}":
                 print ("Form: %s\n" % tab.get("entries")[i].get("formdata").get("id"))
              elif str(tab.get("entries")[i].get("formdata").get("xpath")) != "{}" and str(tab.get("entries")[i].get("formdata").get("id")) == "{}":
                 print ("Form: %s\n" % tab.get("entries")[i].get("formdata").get("xpath"))
              else:
                 print ("Form: %s\n" % tab.get("entries")[i].get("formdata"))
           print ("\n")
           count = count + 1
   if filesession == "js":
      contador['Session1'] = count
   elif  filesession == "bak":
      contador['Session2'] = count

##############################################################################################################

def extract_data_session_watch (varDir):
   if path.isfile(varDir+"/sessionstore.js") == False and path.isfile(varDir+"/sessionstore.json") == False:
         return
   else:
      if path.isfile(varDir+"/sessionstore.js") == True:
         f = open(varDir+"/sessionstore.js")
   
      elif  path.isfile(varDir+"/sessionstore.json") == True:
         f = open(varDir+"/sessionstore.json")
   
   filesession = "js"
   jdata = json.loads(f.read())
   f.close()
      
   count = 0
   countform = 0
   for win in jdata.get("windows"):
       for tab in win.get("tabs"):
           if tab.get("index") is not None:
              i = tab.get("index") - 1
           print ("Title: %s" % tab.get("entries")[i].get("title"))
           print ("URL: %s" % tab.get("entries")[i].get("url"))
           if tab.get("entries")[i].get("formdata") is not None and str(tab.get("entries")[i].get("formdata")) != "{}" :
              countform = countform + 1
              if str(tab.get("entries")[i].get("formdata").get("xpath")) == "{}" and str(tab.get("entries")[i].get("formdata").get("id")) != "{}":
                 print ("Form: %s\n" % tab.get("entries")[i].get("formdata").get("id"))
              elif str(tab.get("entries")[i].get("formdata").get("xpath")) != "{}" and str(tab.get("entries")[i].get("formdata").get("id")) == "{}":
                 print ("Form: %s\n" % tab.get("entries")[i].get("formdata").get("xpath"))
              else:
                 print ("Form: %s\n" % tab.get("entries")[i].get("formdata"))
           print ("\n")
           count = count + 1
   print ("\n\n\n* Last update: %s " % time.ctime(jdata["session"]["lastUpdate"]/1000.0))
   print ("* Number of windows / tabs in use: %s" % count)
   print ("* Number of webs with forms in use: %s" % countform)
   print ("* Exit: Cntrl + c")

##############################################################################################################

def All_execute(varDir):
   show_cookies_firefox(varDir,varDom = 0)
   show_permissions_firefox(varDir)
   show_preferences_firefox(varDir)
   show_addons_firefox(varDir)
   show_extensions_firefox(varDir)
   show_search_engines(varDir)
   show_info_addons(varDir)
   show_downloads_firefox(varDir)
   show_downloads_history_firefox(varDir)
   show_downloadsdir_firefox(varDir)
   show_forms_firefox(varDir)
   show_history_firefox(varDir)
   show_bookmarks_firefox(varDir)
   show_passwords_firefox(varDir)
   show_cache_offline(varDir)
   show_cert_override(varDir)
   show_thumbnails(varDir)
   show_session(varDir)

###############################################################################################################

def show_cookies_firefox(varDir, varDom = 1, varDomain = "%",varName = "%",varHost = "%", varLastacess = "%", varCreate = "%", varSecure = "%", varHttp = "%", varRangeLast1 = "1991-08-06 00:00:00", varRangeLast2 = "3000-01-01 00:00:00",varRangeCreate1 = "1991-08-06 00:00:00", varRangeCreate2 = "3000-01-01 00:00:00"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\cookies.sqlite"
   else:
      bbdd = varDir+"/cookies.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Cookies database not found !")
      return
   show_title("Cookies              "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str
   cursor = conn.cursor()
   cursor.execute("select baseDomain, name, value, host, path, datetime(expiry, 'unixepoch', 'localtime'), datetime(lastAccessed/1000000,'unixepoch','localtime') as last ,datetime(creationTime/1000000,'unixepoch','localtime') as creat, isSecure, isHttpOnly FROM moz_cookies where baseDomain like ? escape '\\' and name like ? escape '\\' and host like ? escape '\\' and last like ? and creat like ? and isSecure like ? and isHttpOnly like ? and last between ? and ? and creat between ? and ?",[varDomain,varName,varHost,('%'+varLastacess+'%'),('%'+varCreate+'%'),varSecure,varHttp, varRangeLast1, varRangeLast2, varRangeCreate1,varRangeCreate2])

   for row in cursor:
      print('Domain: %s' % row[0])
      print('Host: %s' % row[3])
      print('Name: %s' % row[1])
      print('Value: %s' % row[2])
      print('Path: %s' % row[4])
      print('Expiry: %s' % row[5])
      print('Last acess: %s' % row[6])
      print('Creation Time: %s' % row[7])
      if row[8] == 0:
         print('Secure: No')
      else:
        print('Secure: Yes')
      if row[9] == 0:
         print('HttpOnly: No')
      else:
        print('HttpOnly: Yes')
      print("\n")
      count = count +1
   contador['Cookies'] = count

   contador['DOMshow'] = "WARNING: For show the DOM storage data , use the option -showdom"

   if varDom == 0:
      count = 0
      if sys.platform.startswith('win') == True:
         bbdd = varDir+"\\webappsstore.sqlite"
      else:
         bbdd = varDir+"/webappsstore.sqlite"
      if path.isfile(bbdd) == False:
         print ("[ERROR]: Webappsstore database not found !")
         return
      show_title("DOM Storage          "+show_sha256(bbdd), 302)
      conn = sqlite3.connect(bbdd)
      conn.text_factory = str
      cursor = conn.cursor()
      cursor.execute("select scope,value from webappsstore2")
      for row in cursor:
         if row[0].find("http") == -1:
            print('Domain: %s' % path.split(row[0][::-1])[1][1:])
         if row[0].startswith("/") == False and row[0].find("http") != -1:
            print('Domain: %s' % path.split(row[0][::-1])[1].rsplit(':.', 1)[1])
         print('DOM data: %s' % row[1])
         print ("\n------------------------\n")
         count = count +1
      contador['DOM'] = count

   cursor.close()
   conn.close()

###############################################################################################################

def show_permissions_firefox(varDir,varHostPreferences = "%"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\permissions.sqlite"
   else:
      bbdd = varDir+"/permissions.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Permissions database not found !")
      return
   show_title("Permissions          "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str
   cursor = conn.cursor()
   cursor.execute("select host,type,permission,expireType,datetime(expireTime/1000,'unixepoch','localtime') from moz_hosts where host like ? escape '\\'",[varHostPreferences])
   for row in cursor:
      print('Host: %s' % row[0])
      print('Type: %s' % row[1])
      print('Permission: %s' % row[2])
      if row[3] == 0:
         print('Not expire') 
      else:
         print('Expire Time: %s' % row[4])
      print("\n")
      count = count +1
   contador['Preferences'] = count
   cursor.close()
   conn.close()
   
def show_preferences_firefox(varDir):

   if sys.platform.startswith('win') == True:
      dirprefs = "\\prefs.js"
   else:
      dirprefs = "/prefs.js"

   if path.isfile(varDir+dirprefs) == False:
      print ("[ERROR]: prefs.js not found !")
      return

   show_title("Preferences          "+show_sha256(varDir+dirprefs), 302)

   firefox = 0
   seamonkey = 1
   for line in open(varDir+dirprefs):
      if "extensions.lastAppVersion" in line:
         seamonkey = line.split()[1][:-2].replace("\"", "")
         print ("\nBrowser Version: "+line.split()[1][:-2].replace("\"", ""))
      if "extensions.lastPlatformVersion" in line and seamonkey != line.split()[1][:-2].replace("\"", ""): # Only Seamonkey
         print ("Firefox Version: "+line.split()[1][:-2].replace("\"", ""))
      if "browser.download.dir" in line:
         print ("\nDownload directory: "+line.split()[1][:-2].replace("\"", ""))
      elif "browser.download.lastDir" in line:
         print ("Last Download directory: "+line.split()[1][:-2].replace("\"", ""))
      elif "browser.cache.disk.capacity" in line:
         print ("Browser cache disk capacity: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.backup.ftp_port" in line:
        print ("FTP backup proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.backup.ftp" in line:
         print ("\nFTP backup proxy: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.backup.socks_port" in line:
         print ("Socks backup proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.backup.socks" in line:
         print ("Socks backup proxy: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.backup.ssl_port" in line:
         print ("SSL backup proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.backup.ssl" in line:
         print ("SSL backup proxy: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.ftp_port" in line:
        print ("FTP proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.ftp" in line:
         print ("FTP proxy: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.socks_port" in line:
         print ("Socks proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.socks" in line:
         print ("Socks proxy: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.ssl_port" in line:
         print ("SSL proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.http_port" in line:
         print ("Http proxy port: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.http" in line:
         print ("Http proxy: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.share_proxy_settings" in line:
         print ("Share proxy settings: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.autoconfig_url" in line:
         print ("\nURL proxy autoconfig: "+line.split()[1][:-2].replace("\"", ""))
      elif "network.proxy.type" in line:
         print ("Type Proxy: "+line.split()[1][:-2].replace("\"", "")+" (0: No proxy | 4: Auto detect settings | 1: Manual configuration | 2: URL autoconfig)")

###############################################################################################################

def show_addons_firefox(varDir):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\addons.sqlite"
   else:
      bbdd = varDir+"/addons.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Addons database not found !")
      return
   show_title("Addons               "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str  
   cursor = conn.cursor()
   cursor.execute("select name,version,creatorURL,homepageURL from addon")
   for row in cursor:
      print('Name: %s' % row[0])
      print('Version: %s' % row[3])
      print('Creator URL: %s' % row[1])
      print('Homepage URL: %s' % row[2])
      print("\n")
      count = count +1
   contador['Addons'] = count
   cursor.close()
   conn.close()
   
def show_extensions_firefox(varDir):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\extensions.sqlite"
   else:
      bbdd = varDir+"/extensions.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Extensions database not found !")
      return
   show_title("Extensions           "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str   
   cursor = conn.cursor()
   cursor.execute("select type, descriptor,version,releaseNotesURI,datetime(installDate/1000,'unixepoch','localtime'),datetime(UpdateDate/1000,'unixepoch','localtime'),active from addon")
   for row in cursor:
      print('Type: %s' % row[0])
      print('Descriptor: %s' % row[1])
      print('Version: %s' % row[2])
      print('Release: %s' % row[3])
      print('Install date: %s' % row[4])
      print('Update date: %s' % row[5])
      print('Active: %d' % row[6])
      print("\n")
      count = count +1
   contador['Extensions'] = count
   cursor.close()
   conn.close()


def show_info_addons(varDir):
   if sys.platform.startswith('win') == True:
      filepath = varDir+"\\localstore.rdf"
      if path.isfile(filepath) == False:
         print ("[ERROR]: File localstore.rdf not found !")
         return
      else:
         filead = open(varDir+"\\localstore.rdf")
      
   else:
      filepath = varDir+"/localstore.rdf"
      if path.isfile(filepath) == False:
         print ("[ERROR]: File localstore.rdf not found !")
         return
      else:
         filead = open(varDir+"/localstore.rdf")

   show_title("Addons (URLS/PATHS)  "+show_sha256(filepath), 302)
   lines = filead.readlines()
   i = 3
   y = 0
   while i != len(lines):
      if lines[i].find("tp://") != -1 or lines[i].find('label="/') != -1 or lines[i].find(':\\') != -1:
         y = i - 1
         while lines[y].find("RDF:Description RDF:about=") == -1:
            y = y - 1
         print ("APP: "+lines[y].replace('<RDF:Description RDF:about="', "").replace('"', "").replace(" ","")+"URL/PATH: "+lines[i].replace('" />', "").replace('label="', " ").replace(" ","")+"\n")
      i = i + 1
   if y == 0:
      print ("The file localstore.rdf does not contain URLs or paths !")


def show_search_engines(varDir):

   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\search.sqlite"
   else:
      bbdd = varDir+"/search.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Search engines database not found !")
      return

   show_title("Search Engines       "+show_sha256(bbdd), 302)

   conn = sqlite3.connect(bbdd)
   conn.text_factory = str   
   cursor = conn.cursor()
   cursor.execute("select name, value from engine_data")
   for row in cursor:
      print('Name: %s' % row[0])
      print('Value: %s' % str(row[1]))
      print("\n")
      count = count +1
   contador['SearchEngines'] = count
   cursor.close()
   conn.close()

###############################################################################################################

def show_downloads_firefox(varDir, varDownloadRange1 = "1991-08-06 00:00:00", varDownloadRange2 = "3000-01-01 00:00:00"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\downloads.sqlite"
   else:
      bbdd = varDir+"/downloads.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Downloads database not found !")
      return
   show_title("Downloads            "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str   
   cursor = conn.cursor()
   cursor.execute("select name,mimeType,maxBytes/1024,source,target,referrer,tempPath, datetime(startTime/1000000,'unixepoch','localtime') as start,datetime(endTime/1000000,'unixepoch','localtime') as end,state,preferredApplication,preferredAction from moz_downloads where start between ? and ?",[varDownloadRange1,varDownloadRange2])
   for row in cursor:
      print('Name: %s' % row[0])
      print('Mime: %s' % row[1])
      print('Size (KB): %d' % row[2])
      print('Source: %s' % row[3])
      print('Download directory: %s' % row[4])
      print('Referrer: %s' % row[5])
      print('Path temp: %s' % row[6])
      print('startTime: %s' % row[7])
      print('Endtime: %s' % row[8])
      print('State (4 pause, 3 cancell, 1 completed, 0 downloading): %s' % row[9])
      print('Preferred application: %s' % row[10])
      print('Preferred action: %d' % row[11])
      print ("\n")
      count = count +1
   contador['Downloads'] = count


def show_downloads_history_firefox(varDir, varDownloadRange1 = "1991-08-06 00:00:00", varDownloadRange2 = "3000-01-01 00:00:00"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\places.sqlite"
   else:
      bbdd = varDir+"/places.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: History Downloads database not found !")
      return
   show_title("History Downloads    "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str   
   cursor = conn.cursor()
   cursor.execute('select datetime(ann.lastModified/1000000,"unixepoch","localtime") as modified, moz.url, ann.content from moz_annos ann, moz_places moz where moz.id=ann.place_id and ann.content not like "UTF-%" and ann.content not like "ISO-%"  and ann.content like "file%" and modified between ? and ?',[varDownloadRange1,varDownloadRange2])
   for row in cursor:
      print('Date: %s' % row[0])
      print('URL: %s' % row[1])
      print('Download: %s' % row[2])
      print ("\n") 
      count = count +1
   contador['Downloads_History'] = count

def show_downloadsdir_firefox(varDir):

   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\content-prefs.sqlite"
   else:
      bbdd = varDir+"/content-prefs.sqlite"    
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Download directories database not found !")
      return
   show_title("Directories          "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   conn.text_factory = str   
   cursor = conn.cursor()
   cursor.execute('select distinct value from prefs where value like "/%"')
   for row in cursor:
      print('Downloads directories: %s' % row[0])
   cursor.close()
   conn.close()

###############################################################################################################

def show_forms_firefox(varDir,varFormsValue = '%', varFormRange1 = "1991-08-06 00:00:00",varFormRange2 = "3000-01-01 00:00:00" ):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\formhistory.sqlite"
   else:
      bbdd = varDir+"/formhistory.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Forms database not found !")
      return
   show_title("Forms                "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   cursor = conn.cursor()
   cursor.execute("select fieldname,value,timesUsed,datetime(firstUsed/1000000,'unixepoch','localtime') as last,datetime(lastUsed/1000000,'unixepoch','localtime') from moz_formhistory where value like ? escape '\\' and last between ? and ?",[varFormsValue,varFormRange1,varFormRange2])
   for row in cursor:
      print('Name: %s' % row[0])
      print('Value: %s' % row[1])
      print('Times Used: %d' % row[2])
      print('First Used: %s' % row[3])
      print('LastUsed: %s' % row[4])
      print("\n")
      count = count +1
   contador['Forms'] = count
   
   cursor.close()
   conn.close()

###############################################################################################################

def show_history_firefox(varDir, varURL = '%', varFrequency = 1, varTitle = '%', varDate = '%', varRange1 = "1991-08-06 00:00:00", varRange2 = "3000-01-01 00:00:00"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\places.sqlite"
   else:
      bbdd = varDir+"/places.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: History database not found !")
      return
   show_title("History              "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   cursor = conn.cursor()

   if varFrequency == 1:
      cursor.execute("select datetime(last_visit_date/1000000,'unixepoch','localtime') as last, title, url, visit_count from moz_places where url like ? and title like ? escape '\\' and (last like ? and last is not null) and last between ? and ? ORDER BY last COLLATE NOCASE ",[('%'+varURL+'%'), varTitle,('%'+varDate+'%'),varRange1,varRange2])
   else:
      cursor.execute("select datetime(last_visit_date/1000000,'unixepoch','localtime') as last, title, url, visit_count from moz_places where url like ? title like ? escape '\\' and (last like ?  and last is not null) and last between ? and ? ORDER BY visit_count COLLATE NOCASE DESC",[('%'+varURL+'%'), varTitle,('%'+varDate+'%'),varRange1,varRange2])

   for row in cursor:
      print('Last visit: %s' % row[0])
      print('Title: %s' % row[1])
      print('URL: %s' % row[2])
      print('Frequency: %d' % row[3])
      print("\n")
      count = count +1
   contador['History'] = count
   cursor.close()
   conn.close()

###############################################################################################################

def show_bookmarks_firefox(varDir, varBookmarkRange1 = "1991-08-06 00:00:00", varBookmarkRange2 = "3000-01-01 00:00:00"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\places.sqlite"
   else:
      bbdd = varDir+"/places.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Bookmarks database not found !")
      return
   show_title("Bookmarks            "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   cursor = conn.cursor()
   cursor.execute('select bm.title,pl.url,datetime(bm.dateAdded/1000000,"unixepoch","localtime"),datetime(bm.lastModified/1000000,"unixepoch","localtime") as last from moz_places pl,moz_bookmarks bm where bm.fk=pl.id and last between ? and ?',[varBookmarkRange1,varBookmarkRange2] )
   for row in cursor:
      print('Title: %s' % row[0])
      print('URL: %s' % row[1])
      print('Date add: %s' % row[2])
      print('Last modified: %s' % row[3])
      print("\n")
      count = count +1
   contador['Bookmarks'] = count
   cursor.close()
   conn.close()
  
###############################################################################################################

def show_passwords_firefox(varDir):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\signons.sqlite"
   else:
      bbdd = varDir+"/signons.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Signons database not found !")
      return
   show_title("Exceptions/Passwords "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   cursor = conn.cursor()
   cursor.execute('select hostname from moz_disabledHosts')
   for row in cursor:
      print('Exception Web: %s' % row[0])
   print ("\n")

   cursor.execute('select formSubMitURL,usernameField,passwordField ,encryptedUsername,encryptedPassword,encType,datetime(timeCreated/1000,"unixepoch","localtime"),datetime(timeLastUsed/1000,"unixepoch","localtime"),datetime(timePasswordChanged/1000,"unixepoch","localtime"),timesUsed FROM moz_logins')
   for row in cursor:
      print('Web: %s' % row[0])
      print('User field: %s' % row[1])
      print('Password field: %s' % row[2])
      print('User login (crypted): %s' % row[3])
      print('Password login (crypted): %s' % row[4])
      #print('Encripton type: %s' % row[5])
      print('Created: %s' % row[6])
      print('Last used: %s' % row[7])
      print('Change: %s' % row[8])
      print('Frequency: %s' % row[9])
      print("\n")
      count = count +1
   contador['Passwords'] = count
   if sys.platform.startswith('win') == False and sys.version.startswith('2.') == True and count > 0:
      readsignonDB(varDir)
   elif count == 0:
      print ("Users not found!")
   else:
      print ("WARNING: Decode password only in GNU/Linux with python 2.x\nEXAMPLE: python2.7 dumpzilla.py yle8qt6e.default --Passwords")
   cursor.close()
   conn.close()

###############################################################################################################

def show_cache_offline(varDir,varCacheoffRange1 = "1991-08-06 00:00:00", varCacheoffRange2 = "3000-01-01 00:00:00"):
   count = 0
   if sys.platform.startswith('win') == True:
      bbdd = varDir+"\\OfflineCache\\index.sqlite"
   else:	   
      bbdd = varDir+"/OfflineCache/index.sqlite"
   if path.isfile(bbdd) == False:
      print ("[ERROR]: Cache Offline (HTML5) database not found !")
      return
   show_title("Cache offline Html5  "+show_sha256(bbdd), 302)
   conn = sqlite3.connect(bbdd)
   cursor = conn.cursor()
   cursor.execute("select ClientID,key,DataSize,FetchCount,datetime(LastFetched/1000000,'unixepoch','localtime'),datetime(LastModified/1000000,'unixepoch','localtime') as last,datetime(ExpirationTime/1000000,'unixepoch','localtime') from moz_cache where last between ? and ?",[varCacheoffRange1,varCacheoffRange2])
   for row in cursor:
      print('Url: %s' % row[0])
      print('File: %s' % row[1])
      print('Data Size: %s' % row[2])
      print('FetchCount: %s' % row[3])
      print('Last Fetched: %s' % row[4])
      print('Last Modified: %s' % row[5])
      print('Expiration: %s' % row[6])
      print("\n")
      count = count + 1
   cursor.close()
   conn.close()
   contador['Cacheoffline'] = count

##############################################################################################################

def show_cache_offline_extract(varDir, directory):
   import magic
   count = 0
   if sys.platform.startswith('win') == True:
      dircacheextract = "\\OfflineCache"
   else:
      dircacheextract = "/OfflineCache/"

   if not path.exists(varDir+dircacheextract):
      print ("[ERROR]: OfflineCache not found !")
      return


   if sys.platform.startswith('win') == True: # Windows

      for dirname, dirnames, filenames in walk(varDir+dircacheextract):
         for filename in filenames:
            file = path.join(dirname, filename)
            mime = magic.Magic(magic_file=magicpath)
            
            if not path.exists(directory):
               makedirs(directory)
               
            if mime.from_file(file).decode('unicode-escape').startswith("gzip"):
               if not path.exists(directory+"\\files_gzip"):
                  makedirs(directory+"\\files_gzip")
               shutil.copy2(file, directory+"\\files_gzip\\"+filename+".gz")
               
            elif mime.from_file(file).decode('unicode-escape').find("image") != -1 :
               if not path.exists(directory+"\\images"):
                  makedirs(directory+"\\images")
               if mime.from_file(file).decode('unicode-escape').find("JPEG") != -1 or mime.from_file(file).decode('unicode-escape').find("jpg") != -1:      
                  shutil.copy2(file, directory+"\\images\\"+filename+".jpg")
               elif mime.from_file(file).decode('unicode-escape').find("GIF") != -1:
                  shutil.copy2(file, directory+"\\images\\"+filename+".gif")
               elif mime.from_file(file).decode('unicode-escape').find("BMP") != -1:
                  shutil.copy2(file, directory+"\\images\\"+filename+".bmp")
               elif mime.from_file(file).decode('unicode-escape').find("PNG") != -1:
                  shutil.copy2(file, directory+"\\images\\"+filename+".png")
               elif mime.from_file(file).decode('unicode-escape').find("X-ICON") != -1:
                  shutil.copy2(file, directory+"\\images\\"+filename+".ico")
               else:
                  shutil.copy2(file, directory+"/images/"+filename)

            elif mime.from_file(file).decode('unicode-escape').find("text") != -1:
               if not path.exists(directory+"\\text"):
                  makedirs(directory+"\\text")
               shutil.copy2(file, directory+"\\text\\"+filename+".txt")
            
            else:
               shutil.copy2(file, directory+"\\"+filename)
            count = count + 1
            if filename != "index.sqlite":
               print ("Copying "+filename+": "+mime.from_file(file).decode('unicode-escape'))

      contador['Cacheoffline_extract'] = count -1
      remove(directory+"\\index.sqlite")

   else: # Unix systems

      for dirname, dirnames, filenames in walk(varDir+dircacheextract):
         for filename in filenames:
            file = path.join(dirname, filename)
            mime = magic.Magic(mime=True)
            if not path.exists(directory):
               makedirs(directory)
            if mime.from_file(file).decode('unicode-escape') == "application/x-gzip":
               if not path.exists(directory+"/files_gzip/"):
                  makedirs(directory+"/files_gzip/")
               shutil.copy2(file, directory+"/files_gzip/"+filename+".gz")
            
            elif mime.from_file(file).decode('unicode-escape').startswith("image"):
               if not path.exists(directory+"/images/"):
                  makedirs(directory+"/images/")
               if mime.from_file(file).decode('unicode-escape').find("jpeg") != -1 or mime.from_file(file).decode('unicode-escape').find("jpg") != -1:      
                  shutil.copy2(file, directory+"/images/"+filename+".jpg")
               elif mime.from_file(file).decode('unicode-escape').find("gif") != -1:
                  shutil.copy2(file, directory+"/images/"+filename+".gif")
               elif mime.from_file(file).decode('unicode-escape').find("bmp") != -1:
                  shutil.copy2(file, directory+"/images/"+filename+".bmp")
               elif mime.from_file(file).decode('unicode-escape').find("png") != -1:
                  shutil.copy2(file, directory+"/images/"+filename+".png")
               elif mime.from_file(file).decode('unicode-escape').find("x-icon") != -1:
                  shutil.copy2(file, directory+"/images/"+filename+".ico")
               else:
                  shutil.copy2(file, directory+"/images/"+filename)

            elif mime.from_file(file).decode('unicode-escape').startswith("text"):
               if not path.exists(directory+"/text/"):
                  makedirs(directory+"/text/")
               shutil.copy2(file, directory+"/text/"+filename+".txt")

            else:
               shutil.copy2(file, directory+"/"+filename)
            count = count + 1
      contador['Cacheoffline_extract'] = count -1
      remove(directory+"/index.sqlite")

##############################################################################################################

def show_thumbnails(varDir, directory = "null"):
   count = 0

   if sys.platform.startswith('win') == True:
      dthumbails = "\\thumbnails"
   else:
      dthumbails = "/thumbnails/"
   
   if not path.exists(varDir+dthumbails):
      print ("[ERROR]: Thumbnails not found !")
      return

   show_title("Thumbnails images", 243)
   
   for dirname, dirnames, filenames in walk(varDir+dthumbails):
	   for filename in filenames:
	      if directory == 'null':
                 file = path.join(dirname, filename)
                 print (file)
	      else:
                 file = path.join(dirname, filename)     
                 if not path.exists(directory):
                    makedirs(directory)
                 shutil.copy2(file, directory)
                 print ("Copy "+file+" in "+directory)
	      count = count + 1
   contador['Thumbnails'] = count
   
##############################################################################################################

def show_title(varText,varSize):
        varText = "\n"+varText+"\n"
        print ("\n")
        print (varText.center(varSize, "="))
        print ("\n")

##############################################################################################################

def show_cert_override(varDir):

   if sys.platform.startswith('win') == True:
      if path.isfile(varDir+"\\cert_override.txt"):
         lineas = open(varDir+"\\cert_override.txt").readlines()
         show_title("Cert override        "+show_sha256(varDir+"\\cert_override.txt"), 302)
      else:
         return
   else:
      if path.isfile(varDir+"/cert_override.txt"):
         lineas = open(varDir+"/cert_override.txt").readlines()
         show_title("Cert override        "+show_sha256(varDir+"/cert_override.txt"), 302)
	 
      else:
         return
   contador['Cert'] = len(lineas)-2
   nl = 0
   for certificado in lineas:
      if lineas[nl].split()[0].startswith("#") == False:
         print("Site: %s" % lineas[nl].split()[0])
         print("Hash Algorithm: %s" % lineas[nl].split()[1])
         print(lineas[nl].split()[2])
         print ("\n")
      nl = nl + 1

###############################################################################################################

def show_watch(varDir,watchtext = 1):
   if sys.platform.startswith('win') == True:
      print ("\n--Watch option not supported on Windows!\n")
      return
   elif python3_path == "":
      print ("\n[ERROR]: Edit the header of dumpzilla.py and add the python3 path to the variable 'python3_path'.\nExample: python3_path = '/usr/bin/python3.3'\n")
      sys.exit()

   elif watchtext == 1:
      cmd = ["watch", "-n", "4",python3_path, path.abspath(__file__), varDir, "--Session2"]
      call(cmd)
   else:
      cmd = ["watch", "-n", "4",python3_path, path.abspath(__file__), varDir, "--Session2", "| grep --group-separator '' -A 2 -B 2 -i", "'"+watchtext+"'" ]
      call(cmd)   

###############################################################################################################

def show_help():
   print ("""
Version: 15/03/2013

Usage: python dumpzilla.py browser_profile_directory [Options]

Options:

 --All (Shows everything but the DOM data. Doesn't extract thumbnails or HTML 5 offline)
 --Cookies [-showdom -domain <string> -name <string> -hostcookie <string> -access <date> -create <date> -secure <0/1> -httponly <0/1> -range_last -range_create <start> <end>]
 --Permissions [-host <string>]
 --Downloads [-range <start> <end>]
 --Forms	[-value <string> -range_forms <start> <end>]
 --History [-url <string> -title <string> -date <date> -range_history <start> <end> -frequency]
 --Bookmarks [-range_bookmarks <start> <end>]
 --Cacheoffline [-range_cacheoff <start> <end> -extract <directory>]
 --Thumbnails [-extract_thumb <directory>]
 --Range <start date> <end date>
 --Addons
 --Passwords (Decode only in Unix)
 --Certoverride
 --Session
 --Watch [-text <string>] (Shows in daemon mode the URLs and text form in real time. -text' Option allow filter,  support all grep Wildcards. Exit: Ctrl + C. only Unix).

Wildcards: '%'  Any string of any length (Including zero length)
           '_'  Single character
	   '\\'  Escape character

Date syntax: YYYY-MM-DD HH:MM:SS

Win profile: 'C:\\Documents and Settings\\xx\\Application Data\\Mozilla\\Firefox\\Profiles\\xxxx.default'
Unix profile: '/home/xx/.mozilla/seamonkey/xxxx.default/'\n""")
   sys.exit()

############################################################################################################### Main

if sys.platform.startswith('win') == False:
   libnss = CDLL("libnss3.so")

pwdata = secuPWData()
pwdata.source = PW_NONE
pwdata.data=0

uname = SECItem()
passwd = SECItem()
dectext = SECItem()

showAll = 1
count = 0
contador = {'Cookies': "0", 'Preferences': "0", 'Addons': "0",'Extensions': "0", 'Downloads': "0",'Downloads_History': "0", 'Forms': "0", 'History': "0", 'Bookmarks': "0", 'DOM': "0", 'DOMshow': "0", 'SearchEngines': "0", 'Passwords':"0", 'Passwords_decode': "0", 'Cacheoffline': "0", 'Cacheoffline_extract': "0", 'Cert': "0",'Thumbnails': "0", 'Session1': "0", 'Session2': "0"}

if len(sys.argv) == 1:
      show_help()
else:
   varDir = sys.argv[1]
   if path.isdir(varDir) == True and len(sys.argv) == 2:
      
      show_help()

   elif path.isdir(varDir) == True and len(sys.argv) > 2:
      
      varCookieOK = 1
      varDom = 1
      varDomain = "%"
      varName = "%"
      varHost = "%"
      varLastacess = "%"
      varCreate = "%"
      varSecure = "%"
      varHttp = "%"
      varRangeLast1 = "1991-08-06 00:00:00"
      varRangeLast2 = "3000-01-01 00:00:00"
      varRangeCreate1 = "1991-08-06 00:00:00"
      varRangeCreate2 = "3000-01-01 00:00:00"

      varPermissionsOK = 1
      varHostPreferences = "%"

      varAddonOK = 1

      varDownloadsOK = 1
      varDownloadRange1 = "1991-08-06 00:00:00"
      varDownloadRange2 = "3000-01-01 00:00:00"

      varFormsOK = 1
      varFormsValue = '%'
      varFormRange1 = "1991-08-06 00:00:00"
      varFormRange2 = "3000-01-01 00:00:00"
      
      varHistoryOK = 1
      varFrequency = 1
      varURL = '%'
      varTitle = '%'
      varDate = '%'
      varRange1 = "1991-08-06 00:00:00"
      varRange2 = "3000-01-01 00:00:00"

      varBookmarksOK = 1
      varBookmarkRange1 = "1991-08-06 00:00:00"
      varBookmarkRange2 = "3000-01-01 00:00:00"

      varPasswordsOK = 1

      varCacheoffOK = 1
      varCacheoffRange1 = "1991-08-06 00:00:00"
      varCacheoffRange2 = "3000-01-01 00:00:00"

      varExtract = 1
      varCertOK = 1
      
      varThumbOK = 1
      directory = 'null'

      varSessionOK = 1
      varSession2OK = 1
      watchtext = 1
      varWatchOK = 1

      for arg in sys.argv:

         if arg.startswith("-") == True and count > 1:
            if arg != "--All" and arg != "--Range" and arg != "--Cookies" and  arg != "-showdom" and  arg != "-domain" and arg != "-name" and arg != "-hostcookie" and arg != "-access" and arg != "-create" and arg != "-secure" and  arg != "-httponly" and arg != "-range_last" and arg != "-range_last" and  arg != "-range_create" and  arg != "--Permissions" and  arg != "-host" and arg != "--Addons" and arg != "--Downloads" and  arg != "-range" and arg != "--Forms" and  arg != "-value" and arg != "-range_forms" and  arg != "--History" and arg != "-url" and arg != "-frequency" and arg != "-title" and arg != "-date" and arg != "-range_history" and arg != "--Bookmarks" and arg != "-range_bookmarks" and arg != "--Passwords" and arg != "--Cacheoffline" and arg != "-range_cacheoff" and arg != "-extract" and arg != "--Certoverride" and arg != "--Thumbnails" and arg != "-extract_thumb" and arg != "--Session" and arg != "--Watch" and arg != "-text"  and arg != "--Session2":
               print("\n[ERROR] "+str(arg)+" : Invalid argument !")
               show_help()
               
         if arg == "--All":
            showAll = 0
         if arg == "--Range":
            varCookieOK = 0
            varRangeLast1 = sys.argv[count+1]
            varRangeLast2 = sys.argv[count+2]
            varDownloadsOK = 0
            varDownloadRange1 = sys.argv[count+1]
            varDownloadRange2 = sys.argv[count+2]
            varFormsOK = 0
            varFormRange1 = sys.argv[count+1]
            varFormRange2 = sys.argv[count+2]
            varHistoryOK = 0
            varRange1 = sys.argv[count+1]
            varRange2 = sys.argv[count+2]
            varBookmarksOK = 0
            varBookmarkRange1 = sys.argv[count+1]
            varBookmarkRange2 = sys.argv[count+2]
            varCacheoffOK = 0
            varCacheoffRange1 = sys.argv[count+1]
            varCacheoffRange2 = sys.argv[count+2]
         if arg == "--Cookies":
            varCookieOK = 0
         elif arg == "-showdom" and varCookieOK == 0:
            varDom = 0
         elif arg == "-domain" and varCookieOK == 0:
            varDomain = sys.argv[count+1]
         elif arg == "-name" and varCookieOK == 0:
            varName = sys.argv[count+1]
         elif arg == "-hostcookie" and varCookieOK == 0:
            varHost = sys.argv[count+1]
         elif arg == "-access" and varCookieOK == 0:
            varLastacess = sys.argv[count+1]
         elif arg == "-create" and varCookieOK == 0:
            varCreate = sys.argv[count+1]
         elif arg == "-secure" and varCookieOK == 0:
            varSecure = sys.argv[count+1]
         elif arg == "-httponly" and varCookieOK == 0:
            varHttp = sys.argv[count+1]
         elif arg == "-range_last" and varCookieOK == 0:
            varRangeLast1 = sys.argv[count+1]
            varRangeLast2 = sys.argv[count+2]
         elif arg == "-range_create" and varCookieOK == 0:
            varRangeCreate1 = sys.argv[count+1]
            varRangeCreate2 = sys.argv[count+2]
         elif arg == "--Permissions":
            varPermissionsOK = 0
         elif arg == "-host" and varPermissionsOK == 0:
            varHostPreferences = sys.argv[count+1]
         elif arg == "--Addons":
            varAddonOK = 0
         elif arg == "--Downloads":
            varDownloadsOK = 0
         elif arg == "-range" and varDownloadsOK == 0:
            varDownloadRange1 = sys.argv[count+1]
            varDownloadRange2 = sys.argv[count+2]
         elif arg == "--Forms":
            varFormsOK = 0
         elif arg == "-value" and varFormsOK == 0:
            varFormsValue = sys.argv[count+1]
         elif arg == "-range_forms" and varFormsOK == 0:
            varFormRange1 = sys.argv[count+1]
            varFormRange2 = sys.argv[count+2]
         elif arg == "--History":
            varHistoryOK = 0
         elif arg == "-url" and varHistoryOK == 0:
              varURL =  sys.argv[count+1]
         elif arg == "-frequency" and varHistoryOK == 0:
            varFrequency = 0
         elif arg == "-title" and varHistoryOK == 0:
            varTitle = sys.argv[count+1]
         elif arg == "-date" and varHistoryOK == 0:
            varDate = sys.argv[count+1]
         elif arg == "-range_history" and varHistoryOK == 0:
            varRange1 = sys.argv[count+1]
            varRange2 = sys.argv[count+2]
         elif arg == "--Bookmarks":
            varBookmarksOK = 0
         elif arg == "-range_bookmarks" and varBookmarksOK == 0:
            varBookmarkRange1 = sys.argv[count+1]
            varBookmarkRange2 = sys.argv[count+2]
         elif arg == "--Passwords":
            varPasswordsOK = 0
         elif arg == "--Cacheoffline":
            varCacheoffOK = 0
         elif arg == "-range_cacheoff" and varCacheoffOK == 0:
            varCacheoffRange1 = sys.argv[count+1]
            varCacheoffRange2 = sys.argv[count+2]
         elif arg == "-extract" and varCacheoffOK == 0:
            varExtract = 0
            directory = sys.argv[count+1]
         elif arg == "--Certoverride":
            varCertOK = 0
         elif arg == "--Thumbnails":
            varThumbOK = 0
         elif arg == "-extract_thumb" and varThumbOK == 0:
            directory = sys.argv[count+1]
         elif arg == "--Session":
            varSessionOK = 0
         elif arg == "--Session2":
            varSession2OK = 0
         elif arg == "--Watch":
            varWatchOK = 0
         elif arg == "-text" and varWatchOK == 0:
            watchtext = sys.argv[count+1]
         count = count+1
    
      show_info_header()
      
      if showAll == 0:
         All_execute(varDir)
      if varCookieOK == 0:
         show_cookies_firefox(varDir,varDom,varDomain,varName,varHost,varLastacess,varCreate,varSecure,varHttp,varRangeLast1,varRangeLast2,varRangeCreate1,varRangeCreate2)
      if varPermissionsOK == 0:
         show_permissions_firefox(varDir,varHostPreferences)
         show_preferences_firefox(varDir)
      if varAddonOK == 0:
         show_addons_firefox(varDir)
         show_extensions_firefox(varDir)
         show_search_engines(varDir)
         show_info_addons(varDir)
      if varDownloadsOK == 0:
         show_downloads_firefox(varDir,varDownloadRange1,varDownloadRange2)
         show_downloads_history_firefox(varDir,varDownloadRange1,varDownloadRange2)
         show_downloadsdir_firefox(varDir)
      if varFormsOK == 0:
         show_forms_firefox(varDir,varFormsValue,varFormRange1,varFormRange2)
      if varHistoryOK == 0:
         show_history_firefox(varDir, varURL, varFrequency, varTitle, varDate, varRange1, varRange2)
      if varBookmarksOK == 0:
         show_bookmarks_firefox(varDir,varBookmarkRange1,varBookmarkRange2)
      if varPasswordsOK == 0:
         show_passwords_firefox(varDir)   
      if varCacheoffOK == 0:
         show_cache_offline(varDir,varCacheoffRange1,varCacheoffRange2)
      if varCacheoffOK == 0 and varExtract == 0: 
         show_cache_offline_extract(varDir, directory)
      if varCertOK == 0:
         show_cert_override(varDir)
      if varThumbOK == 0:
         show_thumbnails(varDir, directory)
      if varSessionOK == 0:
         show_session(varDir)
      if varSession2OK == 0:
         extract_data_session_watch(varDir)
      if varWatchOK == 0:
         show_watch(varDir,watchtext)

      if varSession2OK == 1:
          show_title("Total information", 243)

      if varCookieOK == 0 or showAll == 0:
         print ("Total Cookies: "+str(contador['Cookies']))
         print ("Total DOM Data displayed: "+str(contador['DOM']))
         if varDom == 1 and showAll == 1:
            print (contador['DOMshow'])
      if varPermissionsOK == 0 or showAll == 0:
         print ("Total Permissions: "+str(contador['Preferences']))
      if varAddonOK == 0 or showAll == 0:
         print ("Total Addons: "+str(contador['Addons']))
         print ("Total Extensions (Extensions / Themes): "+str(contador['Extensions']))
         print ("Total Search Engines: "+str(contador['SearchEngines']))
      if varDownloadsOK == 0 or showAll == 0:
         print ("Total Downloads: "+str(contador['Downloads']))
         print ("Total History downloads: "+str(contador['Downloads_History']))
      if varFormsOK == 0 or showAll == 0:
         print ("Total Forms: "+str(contador['Forms']))
      if varHistoryOK == 0 or showAll == 0:
         print ("Total urls in History: "+str(contador['History']))
      if varBookmarksOK == 0 or showAll == 0:
         print ("Total urls in Bookmarks: "+str(contador['Bookmarks']))
      if varPasswordsOK == 0  or showAll == 0:
         print ("Total passwords: "+str(contador['Passwords']))
         print ("Total passwords decode: "+str(contador['Passwords_decode']))
      if varCacheoffOK == 0 or showAll == 0:
         print ("Total files in offlineCache: "+str(contador['Cacheoffline']))
      if varCacheoffOK == 0 and showAll == 1:
         print ("Total extract files in offlineCache (-extract): "+str(contador['Cacheoffline_extract']))
      if varCertOK == 0 or showAll == 0:
         print ("Total Certificated override: "+str(contador['Cert']))
      if varThumbOK == 0 or showAll == 0:
         print ("Total Images Thumbnails: "+str(contador['Thumbnails']))
      if varSessionOK == 0 or showAll == 0:
         print ("Total webs in last session: "+str(contador['Session1']))
         print ("Total webs in backup session: "+str(contador['Session2']))

      print ("\n")

   else:
      show_help()
      sys.exit()

# Site: www.dumpzilla.org
# Author: Busindre ( busilezas[@]gmail.com )
# Version: 15/03/2013
