#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3, sys, glob, shutil, json, time, hashlib, re, os
from base64 import b64decode
from os import path,walk,makedirs,remove
from ctypes import (Structure, c_uint, c_void_p, c_ubyte,c_char_p, CDLL, cast,byref,string_at)
from datetime import datetime
from subprocess import call
from collections import OrderedDict

# Magic Module: https://github.com/ahupp/python-magic

########################################### GLOBAL VARIABLES ##################################################

magicpath = 'C:\WINDOWS\system32\magic' # Only in Windows, path to magic file (Read Manual in www.dumpzilla.org)

query_str_f = "" 
query_str_a = ""

output_mode = 0 # Output modes: 0 - Standart output (default)

is_showall_ok = False
count = 0
arg_count = 0

#########################
# TOTAL EXTRACTION DICT
#########################
total_extraction = {} 

#~~~~~~~~~~~~~~#
# ^ Structure  #
#~~~~~~~~~~~~~~#
#
#     {
#        parameter1 : {
#          absolute_file1_path : [ 
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   (...)
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value }
#                                ],
#          absolute_fileN_path : [ 
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   (...)
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value }
#                                ]                
#        },
#
#     (...)
#
#        parameterN : {
#          absolute_file1_path : [ 
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   (...)
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value }
#                                ],
#          absolute_fileN_path : [ 
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value },
#                                   (...)
#                                   { column1_name : value, column2_name : value, (...), columnN_name : value }
#                                ]                
#        }
#     }
#

###############
### DEFAULTS      
###############
      
# Valid parameters
parameters = ["--All", "--Preferences", "--Summary", "--RegExp", "--Cookies", "-showdom", "-domain", "-name", "-hostcookie", "-access", "-create", "-secure", "-httponly", "-last_range", "-last_range", "-create_range", "--Permissions", "-host", "-type","-modif","-modif_range","--Addons", "--Downloads", "-range", "--Forms", "-value", "-forms_range", "--History", "-url", "-frequency", "-title", "-date", "-history_range", "--Bookmarks", "-bookmarks_range", "--Passwords", "--OfflineCache", "-cache_range", "-extract", "--Certoverride", "--Thumbnails", "-extract_thumb", "--Session", "--Watch", "-text", "--Session2", "-py3path"]

# TODO: Make a object with all parameters' info

# --Cookies 
cookie_filters = []
domain_filters = []
is_cookie_ok = False
is_dom_ok = False

# --Permissions
is_permissions_ok = False
permissions_filters = []
      
# --Preferences
is_preferences_ok = False

# --Addons
is_addon_ok = False

# --Downloads
is_downloads_ok = False
downloads_filters = []
downloads_history_filters = []

# --Forms
is_forms_ok = False
forms_filters = []

# --History
is_history_ok = False
is_frequency_ok = False
history_filters = []

# --Bookmarks
is_bookmarks_ok = False
bookmarks_filters = []

# --Passwords
is_passwords_ok = False

# --OfflineCache Cache
is_cacheoff_ok = False
is_cacheoff_extract_ok = False
cacheoff_filters = []
cacheoff_directory = None

# --Certoverride
is_cert_ok = False

# --Thumbnails
is_thump_ok = False
thumb_filters = []

# --RegExp
is_regexp_ok = False

# --Session
is_session_ok = False
is_session2_ok = False

# --Summary
is_summary_ok = False

# --Watch
is_watch_ok = False
watch_text = 1

# Debug messages list [message_type, message] (INFO, WARNING, ERROR)
message_list = [] 

watchsecond = 4 # --Watch option: Seconds update. (NO Windows)
python3_path = "" # Python 3.x path (NO Windows). Example: /usr/bin/python3.2

if sys.platform.startswith('win') == False:
   libnss = CDLL("libnss3.so")

########################################### GLOBAL DECODE VARIABLES ###########################################

class SECItem(Structure):
   _fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]

class secuPWData(Structure):
   _fields_ = [('source',c_ubyte),('data',c_char_p)]

(SECWouldBlock,SECFailure,SECSuccess)=(-2,-1,0)
(PW_NONE,PW_FROMFILE,PW_PLAINTEXT,PW_EXTERNAL)=(0,1,2,3)

pwdata = secuPWData()
pwdata.source = PW_NONE
pwdata.data=0

uname = SECItem()
passwd = SECItem()
dectext = SECItem()

###############################################################################################################

###############################################################################################################
#                                                                                                             #
#   AUX FUNCTIONS                                                                                             #
#                                                                                                             #
###############################################################################################################

def get_path_by_os(dir, file, cd_dir = None):
   delimiter = "/"
   if sys.platform.startswith('win') == True:
      delimiter = "\\"
   if cd_dir is not None:
      cd_dir = cd_dir + delimiter
   else:
      cd_dir = ""
   return dir+delimiter+cd_dir+file

def decode_reg(reg):
   try:
      if type(reg) is int:
         return reg
      elif reg is None:
         return None
      else:
         return reg.decode()
   except UnicodeDecodeError:
      save_message("ERROR","UnicodeDecodeError : "+str(sys.exc_info()[1]))
      return None

def save_message(_type, _text):
   print("[" + _type + "] " + _text )
   message_list.append([_type,_text])

def show_info_header(profile):
   if sys.version.startswith('2.') == True and is_session2_ok == False and is_passwords_ok == False:
      save_message("WARNING", "Python 2.x currently used, Python 3.x and UTF-8 is recommended!")
   elif is_session2_ok == False:
      save_message("INFO", "Execution time: " + str(datetime.now()))
      save_message("INFO", "Mozilla Profile: " + str(profile))

def show_title(varText,varSize):
   varText = "\n"+varText+"\n"
   print("")
   print(varText.center(varSize, "="))
   print("")

def regexp(expr, item):
   try:
      if item:
         reg = re.compile(expr, re.I)
         #Debug# print("expr: %s - %s - %s" % (expr, item, reg.match(item)) )
         return reg.search(item) is not None
      else:
         return None
   except: # catch *all* exceptions
      e = str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1])
      save_message("ERROR", "Error using RegExp " + e)
      return None

def validateDate(date_str):
   if not regexp('^[0-9_%:\- ]{1,19}$',date_str):
      save_message("WARNING","Erroneous date '"+date_str+"' : Check wildcards ('%' '_' '/') and format (YYYY-MM-DD hh:mi:ss)")
   return date_str
      
def executeQuery(cursor,sqlite_query,filters,orderby = None):
   sqlite_param = []
   cnt = 0
   for filter in filters:
      if cnt == 0:
         sqlite_query = sqlite_query + " where ("
      else:
         sqlite_query = sqlite_query + " and ("
      if filter[0] == "string":
         # SQL Query: [RegExp] column REGEXP ?
         #            [SQLike] column like ? escape '\'
         sqlite_query = sqlite_query + filter[1] + " " + query_str_f + " ? " + query_str_a
         sqlite_param.append(filter[2])
      elif filter[0] == "date":
         # SQL Query: column like ? escape '\'
         sqlite_query = sqlite_query + filter[1] + " like ? escape '\\'"
         sqlite_param.append(filter[2])
      elif filter[0] == "number":
         # SQL Query: column = ?
         sqlite_query = sqlite_query + filter[1] + " = ?"
         sqlite_param.append(filter[2])
      elif filter[0] == "range":
         # SQL Query: column between ? and ?
         sqlite_query = sqlite_query + filter[1] + " between ? and ?"
         sqlite_param.append(filter[2][0])
         sqlite_param.append(filter[2][1])
      elif filter[0] == "column":
         sqlite_query = sqlite_query + filter[1] + " = " + filter[2]
      sqlite_query = sqlite_query + ")"
      cnt = cnt + 1
   
   if orderby is not None:
      sqlite_query = sqlite_query + " " + orderby
   
   #debug# print("%s - %s" % (sqlite_query,sqlite_param))

   cursor.execute(sqlite_query,sqlite_param)

###############################################################################################################
### SHA256 HASHING                                                                                            #
###############################################################################################################

def show_sha256(filepath):
   sha256 = hashlib.sha256()
   f = open(filepath, 'rb')
   try:
      sha256.update(f.read())
   finally:
      f.close()
   return "[SHA256 hash: "+sha256.hexdigest()+"]"
   
#############################################################################################################
### DECODE PASSWORDS 
#############################################################################################################

def readsignonDB(dir):
   passwords_sources = ["signons.sqlite","logins.json"]
   decode_passwords_extraction_dict = {}
   
   if libnss.NSS_Init(dir)!=0:
      save_message("ERROR","Error Initializing NSS_Init, probably no useful results.")

   for a in passwords_sources:
      # Setting filename by OS
      bbdd = get_path_by_os(dir, a)

      # Checking source file
      if path.isfile(bbdd) == True:
         if a.endswith(".json") == True:
            # JSON 
            f = open(bbdd)
            jdata = json.loads(f.read())
            f.close()
            _extraction_list = []
            for l in jdata.get("logins"):
               _extraction_dict = {}
               if l.get("id") is not None:
                  uname.data  = cast(c_char_p(b64decode(l.get("encryptedUsername"))),c_void_p)
                  uname.len = len(b64decode(l.get("encryptedUsername")))
                  passwd.data = cast(c_char_p(b64decode(l.get("encryptedPassword"))),c_void_p)
                  passwd.len=len(b64decode(l.get("encryptedPassword")))
                  
                  if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
                     save_message("ERROR","Master Password used!")
                     return

                  _extraction_dict["0-Web"] = l.get("hostname").encode("utf-8")
                  _extraction_dict["1-Username"] = string_at(dectext.data,dectext.len)

                  if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
                     save_message("ERROR","Master Password used!")
                     return

                  _extraction_dict["2-Password"] = string_at(dectext.data,dectext.len)

                  _extraction_list.append(_extraction_dict)

            decode_passwords_extraction_dict[bbdd] = _extraction_list

            
         elif a.endswith(".sqlite"):
            # SQLITE
            conn = sqlite3.connect(bbdd)
            conn.text_factory = bytes  
            cursor = conn.cursor()
            cursor.execute("select hostname, encryptedUsername, encryptedPassword from moz_logins")
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               uname.data  = cast(c_char_p(b64decode(row[1])),c_void_p)
               uname.len = len(b64decode(row[1]))
               passwd.data = cast(c_char_p(b64decode(row[2])),c_void_p)
               passwd.len=len(b64decode(row[2]))

               if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
                  save_message("ERROR","Master Password used!")
                  return

               _extraction_dict["0-Web"] = row[0].encode("utf-8")
               _extraction_dict["1-Username"] = string_at(dectext.data,dectext.len)

               if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
                  save_message("ERROR","Master Password used!")
                  return

               _extraction_dict["2-Password"] = string_at(dectext.data,dectext.len)

               _extraction_list.append(_extraction_dict)

            decode_passwords_extraction_dict[bbdd] = _extraction_list

            conn.close()
            libnss.NSS_Shutdown()
         
   if len(decode_passwords_extraction_dict) == 0:
      save_message("WARNING","Passwords database not found! Please, check file " + '|'.join(passwords_sources))
   else:
      # Saving extraction to main extraction list
      total_extraction["decode"] = decode_passwords_extraction_dict 


  
###############################################################################################################
### PASSWORDS
###############################################################################################################

def show_passwords_firefox(dir):
   passwords_sources = ["signons.sqlite","logins.json"]
   passwords_extraction_dict = {}
   exception_extraction_dict = {}

   for a in passwords_sources:
      # Setting filename by OS
      bbdd = get_path_by_os(dir, a)

      # Checking source file
      if path.isfile(bbdd) == True:
         if a.endswith(".json") == True:
            # JSON 
            f = open(bbdd)
            jdata = json.loads(f.read())
            f.close()
            
            _extraction_list = []
            for l in jdata.get("logins"):
               _extraction_dict = {}
               if l.get("id") is not None:
                  _extraction_dict['0-Web'] = l.get("hostname")
                  _extraction_dict['1-User field'] = l.get("usernameField")
                  _extraction_dict['2-Password field'] = l.get("passwordField")
                  _extraction_dict['3-User login (crypted)'] = l.get("encryptedUsername")
                  _extraction_dict['4-Password login (crypted)'] = l.get("encryptedPassword")
                  #_extraction_dict['99-Encripton type'] = l.get("encType")
                  
                  create_date = datetime.fromtimestamp(int(l.get("timeCreated"))/1000).strftime('%Y-%m-%d %H:%M:%S')
                  _extraction_dict['5-Created'] = create_date
                  
                  lastuse_date = datetime.fromtimestamp(int(l.get("timeLastUsed"))/1000).strftime('%Y-%m-%d %H:%M:%S')
                  _extraction_dict['6-Last used'] = lastuse_date
                  
                  change_date = datetime.fromtimestamp(int(l.get("timePasswordChanged"))/1000).strftime('%Y-%m-%d %H:%M:%S')
                  _extraction_dict['7-Change'] = change_date
                  _extraction_dict['8-Frequency'] = l.get("timesUsed")
                  
                  _extraction_list.append(_extraction_dict)

            passwords_extraction_dict[bbdd] = _extraction_list

         elif a.endswith(".sqlite"):
            # SQLITE
            
            ### Exceptions
            conn = sqlite3.connect(bbdd)
            conn.text_factory = bytes
            cursor = conn.cursor()
            cursor.execute('select hostname from moz_disabledHosts')
            
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               _extraction_dict['0-Exception Web'] = decode_reg(row[0])
               _extraction_list.append(_extraction_dict)

            exception_extraction_dict[bbdd] = _extraction_list

            ### Passwords
            cursor.execute('select formSubMitURL,usernameField,passwordField ,encryptedUsername,encryptedPassword,encType,datetime(timeCreated/1000,"unixepoch","localtime"),datetime(timeLastUsed/1000,"unixepoch","localtime"),datetime(timePasswordChanged/1000,"unixepoch","localtime"),timesUsed FROM moz_logins')
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               _extraction_dict['0-Web'] = decode_reg(row[0])
               _extraction_dict['1-User field'] = decode_reg(row[1])
               _extraction_dict['2-Password field'] = decode_reg(row[2])
               _extraction_dict['3-User login (crypted)'] = decode_reg(row[3])
               _extraction_dict['4-Password login (crypted)'] = decode_reg(row[4])
               #_extraction_dict['99-Encripton type'] = decode_reg(row[5])
               _extraction_dict['5-Created'] = decode_reg(row[6])
               _extraction_dict['6-Last used'] = decode_reg(row[7])
               _extraction_dict['7-Change'] = decode_reg(row[8])
               _extraction_dict['8-Frequency'] = decode_reg(row[9])

               _extraction_list.append(_extraction_dict)

            passwords_extraction_dict[bbdd] = _extraction_list
            
            cursor.close()
            conn.close()
   
   if len(exception_extraction_dict) > 0:
      total_extraction["exceptions"] = exception_extraction_dict

   if len(passwords_extraction_dict) == 0:
      save_message("WARNING","Passwords database not found! Please, check file " + '|'.join(passwords_sources))
   else:
      # Saving extraction to main extraction list
      total_extraction["passwords"] = passwords_extraction_dict
      if sys.platform.startswith('win') == False and sys.version.startswith('2.') == True and count > 0:
         readsignonDB(dir)
      elif count == 0:
         save_message("WARNING","Users not found!")
      else:    
         save_message("ERROR","Decode password only in GNU/Linux with python 2.x! EXAMPLE: python2.7 dumpzilla.py yle8qt6e.default --Passwords")
   
###############################################################################################################
### SHOW ALL DATA                                                                                             #
###############################################################################################################

def All_execute(dir):
   show_cookies_firefox(dir)
   show_permissions_firefox(dir)
   show_preferences_firefox(dir)
   show_addons_firefox(dir)
   show_extensions_firefox(dir)
   show_search_engines(dir)
   show_info_addons(dir)
   show_downloads_firefox(dir)
   show_downloads_history_firefox(dir)
   show_downloadsdir_firefox(dir)
   show_forms_firefox(dir)
   show_history_firefox(dir)
   show_bookmarks_firefox(dir)
   show_passwords_firefox(dir)
   show_cache(dir)
   show_cert_override(dir)
   show_thumbnails(dir)
   show_session(dir)

###############################################################################################################
### COOKIES                                                                                                   #
###############################################################################################################
   
def show_cookies_firefox(dir):
   cookies_extraction_dict = {}
   dom_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'cookies.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","Cookies database not found! Please, check file cookies.sqlite")
      return
   
   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes
   
   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
   
   cursor = conn.cursor()
   sqlite_query = "select baseDomain, name, value, host, path, datetime(expiry, 'unixepoch', 'localtime'), datetime(lastAccessed/1000000,'unixepoch','localtime') as last ,datetime(creationTime/1000000,'unixepoch','localtime') as creat, isSecure, isHttpOnly FROM moz_cookies"
   executeQuery(cursor,sqlite_query,cookie_filters)
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['0-Domain'] = decode_reg(row[0])
      _extraction_dict['1-Host'] = decode_reg(row[3])
      _extraction_dict['2-Name'] = decode_reg(row[1])
      _extraction_dict['3-Value'] = decode_reg(row[2])
      _extraction_dict['4-Path'] = decode_reg(row[4])
      _extraction_dict['5-Expiry'] = decode_reg(row[5])
      _extraction_dict['6-Last Access'] = decode_reg(row[6])
      _extraction_dict['7-Creation Time'] = decode_reg(row[7])
      
      if decode_reg(row[8]) == 0:
         _extraction_dict['8-Secure'] =  'No'
      else:
         _extraction_dict['8-Secure'] =  'Yes'
      
      if decode_reg(row[9]) == 0:
         _extraction_dict['9-HttpOnly'] =  'No'
      else:
         _extraction_dict['9-HttpOnly'] =  'Yes'
      
      _extraction_list.append(_extraction_dict)

   cookies_extraction_dict[bbdd] = _extraction_list
      
   if len(cookies_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["cookies"] = cookies_extraction_dict

   cursor.close()
   conn.close()

   ####################################
   ### DOM STORAGE                    #
   ####################################
   if is_dom_ok == True:

      bbdd = get_path_by_os(dir, 'webappsstore.sqlite')

      if path.isfile(bbdd) == False:
         save_message("WARNING","Webappsstore database not found! Please, check file webappsstore.sqlite")
         return
      
      # WARNING! Only RegExp filter allowed!
      if len(domain_filters) > 0 and is_regexp_ok == False :
         save_message("WARNING","Showing all DOM storage, to filter please use RegExp parameter")
         
      conn = sqlite3.connect(bbdd)
      conn.text_factory = bytes
      cursor = conn.cursor()
      
      sqlite_query = "select scope, value from webappsstore2"      
      cursor.execute(sqlite_query)
      
      _extraction_list = []
      for row in cursor:
         _extraction_dict = {}
         fd = ""
         if decode_reg(row[0]).find("http") == -1:
            fd = path.split(decode_reg(row[0])[::-1])[1][1:]
         if decode_reg(row[0]).startswith("/") == False and decode_reg(row[0]).find("http") != -1:
            fd = path.split(decode_reg(row[0])[::-1])[1].rsplit(':.', 1)[1]
         # -domain filter
         show_this_domain = True
         if len(domain_filters) > 0 and  is_regexp_ok == True:
            show_this_domain = regexp(domain_filters[0][2],fd)

         if show_this_domain == True:
            _extraction_dict['0-Domain'] = fd
            _extraction_dict['1-DOM data'] = row[1].decode('utf-8', 'ignore')

         _extraction_list.append(_extraction_dict)

      dom_extraction_dict[bbdd] = _extraction_list
      
      total_extraction["dom"] = dom_extraction_dict

      cursor.close()
      conn.close()

###############################################################################################################
### PERMISSIONS                                                                                               #
###############################################################################################################

def show_permissions_firefox(dir):
   permissions_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'permissions.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","Permissions database not found! Please, check file permissions.sqlite")
      return

   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes
   
   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
   
   # Old table for permissions
   permissions_tables = ["moz_hosts"] 
   
   # New table for permissions (checking if exists)
   cursor = conn.cursor()
   sqlite_query = "select count(*) from sqlite_master"
   master_filters = [["string","type","table"],["string","name","moz_perms"]]
   executeQuery(cursor,sqlite_query,master_filters)
   for row in cursor:
      if row[0] > 0:
         permissions_tables.append("moz_perms")
   cursor.close()

   _extraction_list = []

   for table in permissions_tables:
      host_col = "host"
      if table == "moz_perms":
         host_col = "origin"
         for f in permissions_filters:
            if f[1] == "host":
               index = permissions_filters.index(f)
               permissions_filters[index][1] = "origin"

      # Checking if modificationTime column exists
      cursor = conn.cursor()
      sqlite_query = "pragma table_info("+table+")"

      modificationTime_found = False
      for row in cursor:
         if decode_reg(row[1]) == "modificationTime":
            modificationTime_found = True
      cursor.close()

      # Making sqlite query
      cursor = conn.cursor()
      sqlite_query = ""
      if modificationTime_found:
         sqlite_query = "select "+ host_col +",type,permission,expireType,datetime(expireTime/1000,'unixepoch','localtime') as expire, datetime(modificationTime/1000,'unixepoch','localtime') as modif from "+table
      else:
         sqlite_query = "select "+ host_col +",type,permission,expireType,datetime(expireTime/1000,'unixepoch','localtime') as expire from "+table
         for f in permissions_filters:
            if f[1] == "modif":
               permissions_filters.remove(f)
               save_message("WARNING","modificationTime : Column not found in permissions database")

      executeQuery(cursor,sqlite_query,permissions_filters)
   
      for row in cursor:
         _extraction_dict = {}
         _extraction_dict['0-Host'] = decode_reg(row[0])
         _extraction_dict['1-Type'] = decode_reg(row[1])
         _extraction_dict['2-Permission'] = decode_reg(row[2])
         if decode_reg(row[3]) == 0:
            _extraction_dict['3-Expire Time'] = 'Not expire'
         else:
            _extraction_dict['3-Expire Time'] = decode_reg(row[4])
         
         if modificationTime_found:
            _extraction_dict['4-Modification Time'] = decode_reg(row[5])
         _extraction_list.append(_extraction_dict)
      cursor.close()

   permissions_extraction_dict[bbdd] = _extraction_list
    
   total_extraction["permissions"] = permissions_extraction_dict

   cursor.close()
   conn.close()

###############################################################################################################
### PREFERENCES                                                                                               #
###############################################################################################################
   
def show_preferences_firefox(dir):
   preferences_extraction_dict = {}

   dirprefs = get_path_by_os(dir, 'prefs.js')

   if path.isfile(dirprefs) == False:
      save_message("WARNING","Preferences database not found! Please, check prefs.js")
      return

   firefox = 0
   seamonkey = 1
   count = 0
   _extraction_list = []
   for line in open(dirprefs):
      _extraction_dict = {}
      
      if "user_pref(" in line:
         count_alpha = str(count).zfill(6)
         code = line.split()[0][:-2].replace("\"", "").replace("user_pref(", "")
         value = line.split()[1][:-2].replace("\"", "")

         # Calculating Timestamp value
         if ( regexp('[Tt]ime',code) or regexp("[Ll]ast",code) ) and regexp("^[0-9]{10}$",value):
            tmstmp = datetime.fromtimestamp(int(value)/1000).strftime('%Y-%m-%d %H:%M:%S')
            if regexp("^197",tmstmp):
               tmstmp = datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')
            value = tmstmp
         
         # Transforming description
         code_list = code.split('.')
         cnt = 0
         for c in code_list:
            code_list[cnt] = c.capitalize().replace("_"," ")
            cnt = cnt + 1
         code = " ".join(code_list)
         _extraction_dict[count_alpha + "-" + code] = value
         count = count + 1

      # if "extensions.lastAppVersion" in line:
      #    seamonkey = line.split()[1][:-2].replace("\"", "")
      #    _extraction_dict["00-Browser Version"] = line.split()[1][:-2].replace("\"", "")
      # if "extensions.lastPlatformVersion" in line and seamonkey != line.split()[1][:-2].replace("\"", ""): # Only Seamonkey
      #    _extraction_dict["01-Firefox Version"] = line.split()[1][:-2].replace("\"", "")
      # if "browser.download.dir" in line:
      #    _extraction_dict["02-Download directory"] = line.split()[1][:-2].replace("\"", "")
      # elif "browser.download.lastDir" in line:
      #    _extraction_dict["03-Last Download directory"] = line.split()[1][:-2].replace("\"", "")
      # elif "browser.cache.disk.capacity" in line:
      #    _extraction_dict["04-Browser cache disk capacity"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.backup.ftp_port" in line:
      #    _extraction_dict["05-FTP backup proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.backup.ftp" in line:
      #    _extraction_dict["06-FTP backup proxy"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.backup.socks_port" in line:
      #    _extraction_dict["07-Socks backup proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.backup.socks" in line:
      #    _extraction_dict["08-Socks backup proxy"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.backup.ssl_port" in line:
      #    _extraction_dict["09-SSL backup proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.backup.ssl" in line:
      #    _extraction_dict["10-SSL backup proxy"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.ftp_port" in line:
      #    _extraction_dict["11-FTP proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.ftp" in line:
      #    _extraction_dict["12-FTP proxy"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.socks_port" in line:
      #    _extraction_dict["13-Socks proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.socks" in line:
      #    _extraction_dict["14-Socks proxy"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.ssl_port" in line:
      #    _extraction_dict["15-SSL proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.http_port" in line:
      #    _extraction_dict["16-Http proxy port"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.http" in line:
      #    _extraction_dict["17-Http proxy"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.share_proxy_settings" in line:
      #    _extraction_dict["18-Share proxy settings"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.autoconfig_url" in line:
      #    _extraction_dict["19-URL proxy autoconfig"] = line.split()[1][:-2].replace("\"", "")
      # elif "network.proxy.type" in line:
      #    _extraction_dict["20-Type Proxy"] = line.split()[1][:-2].replace("\"", "")+" (0: No proxy | 4: Auto detect settings | 1: Manual configuration | 2: URL autoconfig)"
      
      if len(_extraction_dict) > 0: 
         _extraction_list.append(_extraction_dict)

   preferences_extraction_dict[dirprefs] = _extraction_list
    
   total_extraction["preferences"] = preferences_extraction_dict

###############################################################################################################
### ADDONS                                                                                                    #
###############################################################################################################

def show_addons_firefox(dir):
   addons_extraction_dict = {}
   addons_found = False
   addons_sources = ["addons.sqlite","addons.json"]

   for a in addons_sources:
      # Setting filename by OS
      bbdd = get_path_by_os(dir, a)

      # Checking source file
      if path.isfile(bbdd) == True:
         addons_found = True

         if a.endswith(".json") == True:
            # JSON
            f = open(bbdd)
            jdata = json.loads(f.read())
            f.close()
            _extraction_list = []
            for addon in jdata.get("addons"):
               _extraction_dict = {}
               if addon.get("id") is not None:
                  _extraction_dict['0-Name'] = addon.get("name")
                  _extraction_dict['1-Version'] = addon.get("version")
                  _extraction_dict['2-Creator URL'] = addon.get("creator").get("url")
                  _extraction_dict['3-Homepage URL'] = addon.get("homepageURL")
                  _extraction_list.append(_extraction_dict)

            addons_extraction_dict[bbdd] = _extraction_list
            
         elif a.endswith(".sqlite"):
            # SQLITE
            conn = sqlite3.connect(bbdd)
            conn.text_factory = bytes  
            cursor = conn.cursor()
            cursor.execute("select name,version,creatorURL,homepageURL from addon")
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               _extraction_dict['0-Name'] = decode_reg(row[0])
               _extraction_dict['1-Version'] = decode_reg(row[3])
               _extraction_dict['2-Creator URL'] = decode_reg(row[1])
               _extraction_dict['3-Homepage URL'] = decode_reg(row[2])
               _extraction_list.append(_extraction_dict)
             
            addons_extraction_dict[bbdd] = _extraction_list

            cursor.close()
            conn.close()

   if len(addons_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["addons"] = addons_extraction_dict
   elif addons_found == False:
      save_message("WARNING","Addons database not found! Please, check file %s" % '|'.join(addons_sources))

###############################################################################################################
### ADDONS INFO                                                                                               #
###############################################################################################################

def show_info_addons(dir):
   addinfo_extraction_dict = {}
   addinfo_found = False
   addinfo_sources = ["xulstore.json","localstore.rdf"]  

   for a in addinfo_sources:
      # Setting filename by OS
      filepath = get_path_by_os(dir, a)
      
      # Checking source file
      if path.isfile(filepath) == True:

         addinfo_found = True

         if a.endswith(".json") == True:
            # JSON
            f = open(filepath)
            jdata = json.loads(f.read())
            f.close()
            # Fix compatibility python2-python3
            _extraction_list = []
            if sys.version.startswith('2.') == True:
               for key, value in jdata.iteritems():
                  _extraction_list.append({"0-URL/PATH":"\"" + key + "\""})
            else:
               for key, value in jdata.items():
                  _extraction_list.append({"0-URL/PATH":"\"" + key + "\""})
            
            addinfo_extraction_dict[filepath] = _extraction_list
                     
         if a.endswith(".rdf") == True:
            # RDF
            filead = open(filepath)
            lines = filead.readlines()
            i = 3
            y = 0
            _extraction_list = []
            while i != len(lines):
               if lines[i].find("tp://") != -1 or lines[i].find('label="/') != -1 or lines[i].find(':\\') != -1:
                  y = i - 1
                  while lines[y].find("RDF:Description RDF:about=") == -1:
                     y = y - 1
                  line_app = lines[y].replace('<RDF:Description RDF:about="', "")
                  line_app = line_app.replace('"', "").replace(" ","")
                  line_url = lines[i].replace('" />', "").replace('label="', " ").replace(" ","")
                  _extraction_list.append({"0-APP": line_app, "1-URL/PATH": line_url})
               i = i + 1

            addinfo_extraction_dict[filepath] = _extraction_list

            if y == 0:
               save_message("INFO","The Addons-Info database " + a + " does not contain URLs or paths!")
   
   if len(addinfo_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["addinfo"] = addinfo_extraction_dict
   elif addinfo_found == False:
      save_message("WARNING","Addons-Info database not found! Please, check file " + '|'.join(addinfo_sources))
   
###############################################################################################################
### EXTENSIONS                                                                                                #
###############################################################################################################

def show_extensions_firefox(dir):
   ext_extraction_dict = {}
   ext_found = False
   ext_sources = ["extensions.json","extensions.sqlite"]  
   
   for a in ext_sources:
      # Setting filename by OS
      filepath = get_path_by_os(dir, a)
      
      # Checking source file
      if path.isfile(filepath) == True:

         ext_found = True

         if a.endswith(".json") == True:
            # JSON
            if not sys.version.startswith('2.'):
               jdata = json.load(open(filepath, encoding='utf8')) 
            else:
               jdata = json.load(open(filepath))
            try:
               _extraction_list = []
               for ext in jdata.get("addons"):
                  _extraction_dict = {}
                  if ext.get("id") is not None:
                     _extraction_dict['0-Name'] = ext.get("defaultLocale").get("name")
                     _extraction_dict['1-Type'] = ext.get("type")
                     _extraction_dict['2-Id'] = ext.get("id")
                     _extraction_dict['3-Descriptor'] = ext.get("descriptor")
                     _extraction_dict['4-Version'] = ext.get("version")
                     _extraction_dict['5-Release'] = ext.get("release")
                     
                     install_date = datetime.fromtimestamp(int(ext.get("installDate"))/1000).strftime('%Y-%m-%d %H:%M:%S')
                     _extraction_dict['6-Install Date'] = install_date
                     
                     update_date = datetime.fromtimestamp(int(ext.get("updateDate"))/1000).strftime('%Y-%m-%d %H:%M:%S')
                     _extraction_dict['7-Update Date'] = update_date
                     
                     _extraction_dict['8-Active'] = ext.get("active")
                     _extraction_list.append(_extraction_dict)

               ext_extraction_dict[filepath] = _extraction_list

            except:
               e = str(sys.exc_info()[0])
               save_message("ERROR","Can't process file " + a + ":" + e )

         
         if a.endswith(".sqlite") == True:
            # SQLITE
            conn = sqlite3.connect(filepath)
            conn.text_factory = bytes   
            cursor = conn.cursor()
            ext_query = "select type, descriptor,version,releaseNotesURI,datetime(installDate/1000,'unixepoch','localtime'),"
            ext_query = ext_query + " datetime(UpdateDate/1000,'unixepoch','localtime'),active from addon"
            cursor.execute(ext_query)
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               _extraction_dict['0-Type'] = decode_reg(row[0])
               _extraction_dict['1-Descriptor'] = decode_reg(row[1])
               _extraction_dict['2-Version'] = decode_reg(row[2])
               _extraction_dict['3-Release'] = decode_reg(row[3])
               _extraction_dict['4-Install Date'] = decode_reg(row[4])
               _extraction_dict['5-Update Date'] = decode_reg(row[5])
               _extraction_dict['6-Active'] = decode_reg(row[6])
               _extraction_list.append(_extraction_dict)

            ext_extraction_dict[filepath] = _extraction_list

            cursor.close()
            conn.close()

   if len(ext_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["extensions"] = ext_extraction_dict
   elif ext_found == False:
      save_message("WARNING","Extensions database not found! Please, check file" + '|'.join(ext_sources))

###############################################################################################################
### SEARCH ENGINES                                                                                            #
###############################################################################################################

def show_search_engines(dir):
   se_found = False
   se_sources = ["search.json","search.sqlite"]
   se_extraction_dict = {}

   for a in se_sources:
      # Setting filename by OS
      filepath = get_path_by_os(dir, a)

      # Checking source file
      if path.isfile(filepath) == True:

         se_found = True

         if a.endswith(".json") == True:
            # JSON
            f = open(filepath)
            jdata = json.loads(f.read())
            f.close()
            try: 
               _extraction_list = []
               for search_dir in jdata.get("directories"):
                  for engine in jdata.get("directories").get(search_dir).get("engines"):
                     _extraction_dict = {}
                     _extraction_dict['0-Name'] = engine.get("_name")
                     _extraction_dict['1-Value'] = engine.get("description")
                     _extraction_dict['2-Hidden'] = engine.get("_hidden")
                     _extraction_list.append(_extraction_dict)
               
               se_extraction_dict[filepath] = _extraction_list

            except TypeError:
               e = str(sys.exc_info()[0])
               save_message("ERROR","Can't process file " + a + ":" + e )

         if a.endswith(".sqlite") == True:
            # SQLITE
            conn = sqlite3.connect(filepath)
            conn.text_factory = bytes   
            cursor = conn.cursor()
            cursor.execute("select name, value from engine_data")
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               _extraction_dict['0-Name'] = decode_reg(row[0])
               _extraction_dict['1-Value'] = str(decode_reg(row[1]))
               _extraction_list.append(_extraction_dict)
            
            se_extraction_dict[filepath] = _extraction_list

            cursor.close()
            conn.close()

   if len(se_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["engines"] = se_extraction_dict
   elif se_found == False:
      save_message("WARNING","Search Engines database not found! Please, check file" + '|'.join(se_sources))

###############################################################################################################
### DOWNLOADS                                                                                                 # 
###############################################################################################################

def show_downloads_firefox(dir):
   downloads_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'downloads.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","Recent downloads database not found! Please, check file downloads.sqlite")
      return

   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes   
   
   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
      
   cursor = conn.cursor()
   sqlite_query = "select name,mimeType,maxBytes/1024,source,target,referrer,tempPath, datetime(startTime/1000000,'unixepoch','localtime') as start,datetime(endTime/1000000,'unixepoch','localtime') as end,state,preferredApplication,preferredAction from moz_downloads"
   executeQuery(cursor,sqlite_query,downloads_filters)
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['00-Name'] = decode_reg(row[0])
      _extraction_dict['01-Mime'] = decode_reg(row[1])
      _extraction_dict['02-Size (KB)'] = decode_reg(row[2])
      _extraction_dict['03-Source'] = decode_reg(row[3])
      _extraction_dict['04-Directory'] = decode_reg(row[4])
      _extraction_dict['05-Referrer'] = decode_reg(row[5])
      _extraction_dict['06-Path temp'] = decode_reg(row[6])
      _extraction_dict['07-Start Time'] = decode_reg(row[7])
      _extraction_dict['08-End Time'] = decode_reg(row[8])
      _extraction_dict['09-State (4 pause, 3 cancell, 1 completed, 0 downloading)'] = decode_reg(row[9])
      _extraction_dict['10-Preferred application'] = decode_reg(row[10])
      _extraction_dict['11-Preferred action'] = decode_reg(row[11])
      _extraction_list.append(_extraction_dict)

   downloads_extraction_dict[bbdd] = _extraction_list

   total_extraction["downloads"] = downloads_extraction_dict

###############################################################################################################
### DOWNLOADS HISTORY                                                                                         # 
###############################################################################################################

def show_downloads_history_firefox(dir):
   download_hist_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'places.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","History Downloads database not found! Please, check file places.sqlite")
      return

   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes   
   
   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
   
   cursor = conn.cursor()
   sqlite_query = 'select datetime(ann.lastModified/1000000,"unixepoch","localtime") as modified, moz.url, ann.content from moz_annos ann, moz_places moz'
   
   # Default filters
   #~ where moz.id=ann.place_id and ann.content not like and ann.content not like "ISO-%"  and ann.content like "file%"
   downloads_history_filters.append(["column","moz.id","ann.place_id"])
   if is_regexp_ok:
      downloads_history_filters.append(["string","ann.content","^file.*"])
   else:
      downloads_history_filters.append(["string","ann.content","file%"])

   executeQuery(cursor,sqlite_query,downloads_history_filters)
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['0-Date'] = decode_reg(row[0])
      _extraction_dict['1-URL'] = decode_reg(row[1])
      _extraction_dict['2-Name'] = decode_reg(row[2])
      _extraction_list.append(_extraction_dict)
   
   download_hist_extraction_dict[bbdd] = _extraction_list

   total_extraction["downloads_history"] = download_hist_extraction_dict


###############################################################################################################
### DOWNLOADS DIRECTORIES                                                                                     #
###############################################################################################################

def show_downloadsdir_firefox(dir):
   download_dir_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'content-prefs.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","Download Directories database not found! Please, check file content-prefs.sqlite")
      return

   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes   
   cursor = conn.cursor()

   # Checking if timestamp column exists
   cursor = conn.cursor()
   sqlite_query = "pragma table_info(prefs)"
   executeQuery(cursor,sqlite_query,[])
   timestamp_found = False
   for row in cursor:
      if decode_reg(row[1]) == "timestamp":
         timestamp_found = True
   cursor.close()

   # Making sqlite query
   cursor = conn.cursor()
   sqlite_query = ""
   if timestamp_found:
      sqlite_query = 'select value, max(datetime(timestamp/1000,"unixepoch","localtime")) as oldtime, max(datetime(timestamp,"unixepoch","localtime")) as newtime from prefs where value like "/%" group by value'
   else:
      sqlite_query = 'select value from prefs where value like "/%" group by value'

   cursor.execute(sqlite_query)
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['0-Name'] = decode_reg(row[0])
      
      if timestamp_found:
         timestamp = decode_reg(row[1])
         if regexp('^197',timestamp):
            _extraction_dict['1-Last date'] = decode_reg(row[1])
         else:
            _extraction_dict['1-Last date'] = timestamp
      
      _extraction_list.append(_extraction_dict)
   
   download_dir_extraction_dict[bbdd] = _extraction_list

   total_extraction["downloads_dir"] = download_dir_extraction_dict

   cursor.close()
   conn.close()

###############################################################################################################
### FORMS                                                                                                     #
###############################################################################################################

def show_forms_firefox(dir):
   forms_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'formhistory.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","Forms database not found! Please, check file formhistory.sqlite")
      return

   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes
   
   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
      
   cursor = conn.cursor()
   sqlite_query = "select fieldname,value,timesUsed,datetime(firstUsed/1000000,'unixepoch','localtime') as last,datetime(lastUsed/1000000,'unixepoch','localtime') from moz_formhistory"
   executeQuery(cursor,sqlite_query,forms_filters)
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['0-Name'] = decode_reg(row[0])
      _extraction_dict['1-Value'] = decode_reg(row[1])
      _extraction_dict['2-Times Used'] = decode_reg(row[2])
      _extraction_dict['3-First Used'] = decode_reg(row[3])
      _extraction_dict['4-Last Used'] = decode_reg(row[4])
      _extraction_list.append(_extraction_dict)
   
   forms_extraction_dict[bbdd] = _extraction_list

   total_extraction["forms"] = forms_extraction_dict 
   
   cursor.close()
   conn.close()

###############################################################################################################
### HISTORY                                                                                                   #
###############################################################################################################

def show_history_firefox(dir):
   history_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'places.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","History database not found! Please, check file places.sqlite")
      return

   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes

   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
      
   cursor = conn.cursor()
   sqlite_query = "select datetime(last_visit_date/1000000,'unixepoch','localtime') as last, title, url, visit_count from moz_places"
   
   if is_frequency_ok == False:
      executeQuery(cursor,sqlite_query,history_filters,"ORDER BY last COLLATE NOCASE")
   else:
      executeQuery(cursor,sqlite_query,history_filters,"ORDER BY visit_count COLLATE NOCASE DESC")
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['0-Last Access'] = decode_reg(row[0])
      _extraction_dict['1-Title'] = decode_reg(row[1])
      _extraction_dict['2-URL'] = decode_reg(row[2])
      _extraction_dict['3-Frequency'] = decode_reg(row[3])
      _extraction_list.append(_extraction_dict)
      
   history_extraction_dict[bbdd] = _extraction_list

   total_extraction["history"] = history_extraction_dict 

   cursor.close()
   conn.close()

###############################################################################################################
### BOOKMARKS                                                                                                 #
###############################################################################################################

def show_bookmarks_firefox(dir):
   bookmarks_extraction_dict = {}

   bbdd = get_path_by_os(dir, 'places.sqlite')

   if path.isfile(bbdd) == False:
      save_message("WARNING","Bookmarks database not found! Please, check file places.sqlite")
      return
   
   conn = sqlite3.connect(bbdd)
   conn.text_factory = bytes
   
   if is_regexp_ok == True:
      conn.create_function("REGEXP", 2, regexp)
      
   cursor = conn.cursor()
   sqlite_query = 'select bm.title,pl.url,datetime(bm.dateAdded/1000000,"unixepoch","localtime"),datetime(bm.lastModified/1000000,"unixepoch","localtime") as last from moz_places pl,moz_bookmarks bm where pl.id = bm.id'
   executeQuery(cursor,sqlite_query,bookmarks_filters)
   
   _extraction_list = []
   for row in cursor:
      _extraction_dict = {}
      _extraction_dict['0-Title'] = decode_reg(row[0])
      _extraction_dict['1-URL'] = decode_reg(row[1])
      _extraction_dict['2-Creation Time'] = decode_reg(row[2])
      _extraction_dict['3-Last Modified'] = decode_reg(row[3])
      _extraction_list.append(_extraction_dict)
      
   bookmarks_extraction_dict[bbdd] = _extraction_list

   total_extraction["bookmarks"] = bookmarks_extraction_dict 

   cursor.close()
   conn.close()

###############################################################################################################
### OFFLINE CACHE                                                                                             #
###############################################################################################################

def show_cache(dir):
   # TODO: firefox-cache2-index-parser.py??
   offlinecache_extraction_dict = {}
   cache_found = False

   # [Default, Windows 7]
   cache_abs_sources = [get_path_by_os(dir,"index.sqlite","OfflineCache")]
   
   # For Windows 7 profile
   if dir.find("Roaming") > -1:
      cache_abs_sources.append(get_path_by_os(dir.replace("Roaming", "Local"),"index.sqlite","OfflineCache"))

   # For Linux profile
   if dir.find(".mozilla") > -1:
      cache_abs_sources.append(get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"index.sqlite","OfflineCache")) # Firefox
      cache_abs_sources.append(get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"index.sqlite","Cache")) # Seamonkey

   for d in cache_abs_sources:
      # Checking source file
      if path.isfile(d) == True:

         cache_found = True

         if d.endswith(".sqlite") == True:
            # SQLITE
            conn = sqlite3.connect(d)
            conn.text_factory = bytes
            if is_regexp_ok == True:
               conn.create_function("REGEXP", 2, regexp)
               
            cursor = conn.cursor()
            sqlite_query = "select ClientID,key,DataSize,FetchCount,datetime(LastFetched/1000000,'unixepoch','localtime'),datetime(LastModified/1000000,'unixepoch','localtime') as last,datetime(ExpirationTime/1000000,'unixepoch','localtime') from moz_cache"
            executeQuery(cursor,sqlite_query,cacheoff_filters)
            
            _extraction_list = []
            for row in cursor:
               _extraction_dict = {}
               _extraction_dict['0-Name'] = decode_reg(row[0])
               _extraction_dict['1-Value'] = str(decode_reg(row[1]))
               _extraction_dict['2-Last Modified'] = str(decode_reg(row[5]))
               _extraction_list.append(_extraction_dict)

            offlinecache_extraction_dict[d] = _extraction_list

            cursor.close()
            conn.close()
   
   if len(offlinecache_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["offlinecache"] = offlinecache_extraction_dict 
   elif cache_found == False:
      save_message("WARNING","Offline Cache database not found! Please check file OfflineCache/index.sqlite")

###############################################################################################################
### OFFLINE CACHE                                                                                             #
###############################################################################################################

def show_cache_extract(dir, directory): 
   # TODO: include firefox-cache2-file-parser.py
   offlinecache_ext_extraction_dict = {}
   cache_found = False

   try:
      import magic
   except:
      save_message("ERROR","Failed to import magic module!")
      return

   # [Default, Windows 7]
   cache_abs_sources = [get_path_by_os(dir,"OfflineCache")]
   
   # For Windows 7 profile
   if dir.find("Roaming") > -1:
      cache_abs_sources.append(get_path_by_os(dir.replace("Roaming", "Local"),"OfflineCache"))

   # For Linux profile
   if dir.find(".mozilla") > -1:
      cache_abs_sources.append(get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"OfflineCache")) # Firefox
      cache_abs_sources.append(get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"Cache")) # Seamonkey

   for d in cache_abs_sources:
      _extraction_list = []
      count = 0
      # Checking source directory
      if path.isdir(d) == True:

         cache_found = True
         
         if sys.platform.startswith('win') == True:         
            # Windows systems
            for dirname, dirnames, filenames in walk(d):
               for filename in filenames:
                  _extraction_dict = {}
                  file = path.join(dirname, filename)
                  mime = magic.Magic(magic_file=magicpath)
                  
                  if not path.exists(directory):
                     makedirs(directory)
                     
                  if mime.from_file(file).decode('unicode-escape').startswith("gzip"):
                     if not path.exists(directory+"\\gzip"):
                        makedirs(directory+"\\gzip")
                     shutil.copy2(file, directory+"\\gzip\\"+filename+".gz")
                     
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
                     if not path.exists(directory+"\\others"):
                        makedirs(directory+"\\others")
                     shutil.copy2(file, directory+"\\others\\"+filename)
                  
                  if filename != "index.sqlite":
                     count_alpha = str(count).zfill(6)
                     _extraction_dict = {count_alpha + "-Copying "+filename : mime.from_file(file).decode('unicode-escape')}

                  if len(_extraction_dict) > 0:
                     _extraction_list.append(_extraction_dict)

                  count = count + 1
            
            try:
               remove(directory+"\\index.sqlite")
            except:
               save_message("WARNING","Failed to remove index.sqlite from "+directory)

         else: 
            # Unix systems
            for dirname, dirnames, filenames in walk(d):
               for filename in filenames:
                  _extraction_dict = {}
                  file = path.join(dirname, filename)
                  mime = magic.Magic(mime=True)
                  if not path.exists(directory):
                     makedirs(directory)
                  if mime.from_file(file).decode('unicode-escape') == "application/x-gzip":
                     if not path.exists(directory+"/gzip/"):
                        makedirs(directory+"/gzip/")
                     shutil.copy2(file, directory+"/gzip/"+filename+".gz")
                  
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
                     if not path.exists(directory+"/others/"):
                        makedirs(directory+"/others/")
                     shutil.copy2(file, directory+"/others/"+filename)
                  
                  if filename != "index.sqlite":
                     count_alpha = str(count).zfill(6)
                     _extraction_dict = {count_alpha + "-Copying "+filename : mime.from_file(file).decode('unicode-escape')}

                  if len(_extraction_dict) > 0:
                     _extraction_list.append(_extraction_dict)

                  count = count + 1
            try:
               remove(directory+"/index.sqlite")
            except:
               save_message("WARNING","Failed to remove index.sqlite from "+directory)

         offlinecache_ext_extraction_dict[d] = _extraction_list

   total_extraction["offlinecache_extract"] = offlinecache_ext_extraction_dict

###############################################################################################################
### THUMBNAILS                                                                                                #
###############################################################################################################

def show_thumbnails(dir, directory = "null"):
   thumbnails_found = False
   thumbnails_extraction_dict = {}

   # [Default, Windows 7]
   thumbnails_sources = [get_path_by_os(dir,"thumbnails")]
      
   # For Windows 7 profile
   if dir.find("Roaming") > -1:
      thumbnails_sources.append(get_path_by_os(dir.replace("Roaming", "Local"),"thumbnails"))

   # For Linux profile
   if dir.find(".mozilla") > -1:
      thumbnails_sources.append(get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"thumbnails"))

   for d in thumbnails_sources:
      if path.exists(d):
         thumbnails_found = True
        
         _extraction_list = []
         for dirname, dirnames, filenames in walk(d):
            for filename in filenames:
               _extraction_dict = {}
               if directory == 'null':
                    nfile = get_path_by_os(dirname, filename)
                    _extraction_dict['0-File'] = nfile
               else:
                    nfile = get_path_by_os(dirname, filename)     
                    if not path.exists(directory):
                       makedirs(directory)
                    shutil.copy2(nfile, directory)
                    _extraction_dict['0-File'] = "Copy "+nfile+" to "+directory
               if len(_extraction_dict) > 0:
                  _extraction_list.append(_extraction_dict)

         thumbnails_extraction_dict[d] = _extraction_list

   if len(thumbnails_extraction_dict) > 0:
      # Saving extraction to main extraction list
      total_extraction["thumbnails"] = thumbnails_extraction_dict
   elif thumbnails_found == False:
      save_message("WARNING","No thumbnails found!")

###############################################################################################################
### CERT OVERRIDE                                                                                             #
###############################################################################################################

def show_cert_override(dir):
   cert_override_extraction_dict = {}

   bbdd = get_path_by_os(dir,"cert_override.txt")

   if path.isfile(bbdd):
      lineas = open(bbdd).readlines()
      
      nl = 0
      _extraction_list = []
      for certificado in lineas:
         if lineas[nl].split()[0].startswith("#") == False:
            _extraction_dict = {}
            _extraction_dict["0-Site"] = lineas[nl].split()[0]
            _extraction_dict["1-Hash Algorithm"] = lineas[nl].split()[1]
            _extraction_dict["2-Data"] = lineas[nl].split()[2] 
            _extraction_list.append(_extraction_dict)
         nl = nl + 1

      cert_override_extraction_dict[bbdd] = _extraction_list

      total_extraction["cert_override"] = cert_override_extraction_dict

   else:
      save_message("WARNING","Cert override file not found! Please, check file cert_override.txt")

###############################################################################################################
### WATCH                                                                                                     #
###############################################################################################################

def show_watch(dir,watch_text = 1):
   if sys.platform.startswith('win') == True:
      save_message("ERROR","--Watch option not supported on Windows!")
      return
   elif python3_path == "":
      save_message("ERROR","Edit the header of dumpzilla.py and add Python3 path into variable named 'python3_path' or use -py3path option to set it.")
      sys.exit()

   elif watch_text == 1:
      cmd = ["watch", "-n", "4",python3_path, path.abspath(__file__), dir, "--Session2"]
      call(cmd)
   else:
      cmd = ["watch", "-n", "4",python3_path, path.abspath(__file__), dir, "--Session2", "| grep --group-separator '' -A 2 -B 2 -i", "'"+watch_text+"'" ]
      call(cmd)   

def get_param_argurment(arg, num):
   rparam = ""
   try:
      rparam = sys.argv[num]
      return rparam
   except:
      save_message("ERROR","Missing argument for parameter " + arg)
      show_help()

###############################################################################################################
### SESSION                                                                                                   #
###############################################################################################################

def show_session(dir):
   session_extraction_dict = {}
   session_found = False
   session_sources = ["sessionstore.js","sessionstore.json","sessionstore.bak"]
   # Checking for more backup session sources (I)
   for s in os.listdir(dir):
      # Adding new source
      if path.isfile(path.join(dir,s)) and s.startswith("sessionstore") and s not in session_sources:
         session_sources.append(s)
   
   # Checking for more backup session sources (II)
   session_folder = path.join(dir,"sessionstore-backups")
   if path.isdir(session_folder):
      for s in os.listdir(session_folder):
         # Adding new source
         if path.isfile(path.join(session_folder,s)):
            session_sources.append(path.join("sessionstore-backups",s))

   # Extraction
   for a in session_sources:
      bbdd = os.path.join(dir,a) 
      # Checking source file
      if path.isfile(bbdd) == True:
         session_found = True
         f = open(bbdd)
         hashsession = show_sha256(bbdd)
         if a.endswith(".js") or a.endswith(".json"):
            filesession = "js"
         else:
            filesession = "bak"
         jdata = json.loads(f.read())
         f.close()

         _extraction_list = extract_data_session(jdata,filesession,hashsession,bbdd)
         
         session_extraction_dict[bbdd] = _extraction_list

   if len(session_extraction_dict) > 0:
         # Saving extraction to main extraction list
         total_extraction["session"] = session_extraction_dict
   elif not session_found:
      save_message("WARNING","No session info found!")

###############################################################################################################
### DATA SESSION                                                                                              #
###############################################################################################################

def extract_data_session(jdata,filesession,hashsession,namesession):

   if filesession == "js":
      tipo = "Last session"
   elif filesession == "bak":
      tipo = "Backup session"

   _extraction_list = []
   for win in jdata.get("windows"):
      for tab in win.get("tabs"):
         _extraction_dict = {}
         _extraction_dict["00-Session type"] = tipo
         _extraction_dict["01-Last update"] = str(time.ctime(jdata["session"]["lastUpdate"]/1000.0))
         _extraction_dict["02-Type"] = "Default"
         
         if tab.get("index") is not None:
            i = tab.get("index") - 1
         
         _extraction_dict["03-Title"] = tab.get("entries")[i].get("title")
         _extraction_dict["04-URL"] = tab.get("entries")[i].get("url")

         if tab.get("entries")[i].get("referrer") is not None:
            _extraction_dict["05-Referrer"] = tab.get("entries")[i].get("referrer")
         
         if tab.get("entries")[i].get("formdata") is not None and str(tab.get("entries")[i].get("formdata")) != "{}" :
            if str(tab.get("entries")[i].get("formdata").get("xpath")) == "{}" and str(tab.get("entries")[i].get("formdata").get("id")) != "{}":
               _extraction_dict["06-Form"] = tab.get("entries")[i].get("formdata").get("id")
            elif str(tab.get("entries")[i].get("formdata").get("xpath")) != "{}" and str(tab.get("entries")[i].get("formdata").get("id")) == "{}":
               _extraction_dict["06-Form"] = tab.get("entries")[i].get("formdata").get("xpath")
            else:
               _extraction_dict["06-Form"] = tab.get("entries")[i].get("formdata")
         
         _extraction_list.append(_extraction_dict)   
         
      # Closed tabs
      if win.get("_closedTabs") is not None and len(win.get("_closedTabs")) > 0:
         for closed_tab in win.get("_closedTabs")[0].get("state").get("entries"):
            _extraction_dict = {}
            _extraction_dict["07-Session type"] = tipo
            _extraction_dict["08-Last update"] = str(time.ctime(jdata["session"]["lastUpdate"]/1000.0))
            _extraction_dict["09-Type"] = "Closed tab"
            _extraction_dict["10-Title"] = closed_tab.get("title")
            _extraction_dict["11-URL"] = closed_tab.get("url")
            _extraction_list.append(_extraction_dict)  

   return _extraction_list

###############################################################################################################
### DATA SESSION WATCH                                                                                        #
###############################################################################################################

def extract_data_session_watch (dir):
   session_watch_found = False
   session_watch_sources = ["sessionstore.js","sessionstore.json"]
   # Checking for more backup session sources (I)
   for s in os.listdir(dir):
      # Adding new source
      if path.isfile(path.join(dir,s)) and s.startswith("sessionstore") and s not in session_watch_sources:
         session_watch_sources.append(s)
   # Checking for more backup session sources (II)
   session_watch_folder = path.join(dir,"sessionstore-backups")
   if path.isdir(session_watch_folder):
      for s in os.listdir(session_watch_folder):
         # Adding new source
         if path.isfile(path.join(session_watch_folder,s)):
            session_watch_sources.append(path.join("sessionstore-backups",s))
   
   higher_date = 0
   higher_source = ""
   for a in session_watch_sources:
      bbdd = os.path.join(dir,a) 
      # Checking source file
      if path.isfile(bbdd) == True:
         session_watch_found = True
         f = open(bbdd)
         jdata = json.loads(f.read())
         f.close()
         if jdata["session"]["lastUpdate"] > higher_date:
            higher_date=jdata["session"]["lastUpdate"]
            higher_source=bbdd
   
   # Showing last updated session data
   if session_watch_found == True:
      f = open(higher_source)
      hashsession = show_sha256(higher_source)
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
      print ("[INFO] Last update: %s " % time.ctime(jdata["session"]["lastUpdate"]/1000.0))
      print ("[INFO] Number of windows / tabs in use: %s" % count)
      print ("[INFO] Number of webs with forms in use: %s" % countform)
      print ("[INFO] Exit: Ctrl + C")

###############################################################################################################
### HELP                                                                                                      #
###############################################################################################################

def show_help():
   print ("""
Version: 2016/02/16

Usage: python dumpzilla.py browser_profile_directory [Options]

Options:

 --All (shows everything but the DOM data. Doesn't extract thumbnails or HTML 5 offline)
 --Cookies [-showdom -domain <string> -name <string> -hostcookie <string> -access <date> -create <date> -secure <0/1> -httponly <0/1> -last_range <start> <end> -create_range <start> <end>]
 --Permissions [-host <string>  -modif <date> -modif_range <start> <end>]
 --Downloads [-range <start> <end>]
 --Forms [-value <string> -forms_range <start> <end>]
 --History [-url <string> -title <string> -date <date> -history_range <start> <end> -frequency]
 --Bookmarks [-bookmarks_range <start> <end>]
 --OfflineCache [-cache_range <start> <end> -extract <directory>]
 --Thumbnails [-extract_thumb <directory>]
 --Addons
 --Preferences
 --Passwords (decode only in Unix)
 --Certoverride
 --Session
 --RegExp (uses Regular Expresions for string type filters instead of Wildcards)
 --Summary (only shows debug messages and summary report)
 --Watch [-text <string>] [-py3path <string>] (Shows in daemon mode the URLs and text form in real time)
         (-text Option allow filter, supports all grep Wildcards. Exit: Ctrl + C. only Unix)
          -py3path Option to set Python3 path instead off add the python3 path to the variable 'python3_path')

Wildcards: '%'  Any string of any length (Including zero length)
           '_'  Single character
           '\\'  Escape character

Date syntax: YYYY-MM-DD hh:mi:ss (Wildcards allowed)

Profile:       
   WinXP profile -> 'C:\\Documents and Settings\\xx\\Application Data\\Mozilla\\Firefox\\Profiles\\xxxx.default'
   Win7 profile  -> 'C:\\Users\\xx\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xxxx.default'
   Unix profile  -> '/home/xx/.mozilla/firefox/xxxx.default/'\n""")
   sys.exit()

###############################################################################################################
##                                                                                                            #
### MAIN                                                                                                      #
##                                                                                                            #
###############################################################################################################

if len(sys.argv) == 1:
      save_message("ERROR","Missing parameters...")
      show_help()
else:
   dir = sys.argv[1]
   if path.isdir(dir) == True and len(sys.argv) == 2:
      
      save_message("ERROR","Missing parameters...")
      show_help()

   elif path.isdir(dir) == True and len(sys.argv) > 2:
      
      dir = path.abspath(dir)
      
      ###############
      ### ARGUMENTS      
      ###############     
      for arg in sys.argv:
         # Checking parameter
         if arg.startswith("-") == True and count > 1:
            if arg not in parameters:  
               save_message("ERROR", str(arg)+" : Invalid argument!")
               show_help() 

         if arg.startswith("-"):    # and not arg == "--Export":
            arg_count = arg_count+1

         if arg == "--RegExp":
            is_regexp_ok = True
         #...........................................
         #... All parameter
         #...........................................
         if arg == "--All":
            is_showall_ok = True
         #...........................................
         #... Summary parameter
         #...........................................
         if arg == "--Summary":
            is_summary_ok = True
         #...........................................
         #... Cookie parameters
         #...........................................
         if arg == "--Cookies":
            is_cookie_ok = True
         elif arg == "-showdom" and is_cookie_ok == True:
            is_dom_ok = True
         elif arg == "-domain" and is_cookie_ok == True:
            cookie_domain = get_param_argurment(arg,count+1)
            cookie_filters.append(["string","baseDomain",cookie_domain])
            domain_filters.append(["string","scope",cookie_domain])
         elif arg == "-name" and is_cookie_ok == True:
            cookie_name = get_param_argurment(arg,count+1)
            cookie_filters.append(["string","name",cookie_name])
         elif arg == "-hostcookie" and is_cookie_ok == True:
            cookie_host = get_param_argurment(arg,count+1)
            cookie_filters.append(["string","host",cookie_host])
         elif arg == "-access" and is_cookie_ok == True:
            cookie_access_date = validateDate(get_param_argurment(arg,count+1))
            cookie_filters.append(["date","last",cookie_access_date]) 
         elif arg == "-create" and is_cookie_ok == True:
            cookie_create_date = validateDate(get_param_argurment(arg,count+1))
            cookie_filters.append(["date","creat",cookie_create_date]) 
         elif arg == "-secure" and is_cookie_ok == True:
            cookie_secure = get_param_argurment(arg,count+1)
            cookie_filters.append(["number","isSecure",cookie_secure]) 
         elif arg == "-httponly" and is_cookie_ok == True:
            cookie_httponly = get_param_argurment(arg,count+1)
            cookie_filters.append(["number","isHttpOnly",cookie_httponly]) 
         elif arg == "-last_range" and is_cookie_ok == True:
            cookie_access_range1 = validateDate(get_param_argurment(arg,count+1))
            cookie_access_range2 = validateDate(get_param_argurment(arg,count+2))
            cookie_filters.append(["range","last",[cookie_access_range1,cookie_access_range2]]) 
         elif arg == "-create_range" and is_cookie_ok == True:
            cookie_create_range1 = validateDate(get_param_argurment(arg,count+1))
            cookie_create_range2 = validateDate(get_param_argurment(arg,count+2))
            cookie_filters.append(["range","creat",[cookie_create_range1,cookie_create_range2]]) 
         #...........................................
         #... Permissions parameters
         #...........................................
         elif arg == "--Permissions":
            is_permissions_ok = True
         elif arg == "-host" and is_permissions_ok == True:
            permissions_host = get_param_argurment(arg,count+1)
            permissions_filters.append(["string","host",permissions_host]) 
         elif arg == "-type" and is_permissions_ok == True:
            permissions_type = get_param_argurment(arg,count+1)
            permissions_filters.append(["string","type",permissions_type]) 
         elif arg == "-modif" and is_cookie_ok == True:
            permissions_modif_date = validateDate(get_param_argurment(arg,count+1))
            permissions_filters.append(["date","modif",permissions_modif_date]) 
         elif arg == "-modif_range" and is_permissions_ok == True:
            permissions_modif_range1 = validateDate(get_param_argurment(arg,count+1))
            permissions_modif_range2 = validateDate(get_param_argurment(arg,count+2))
            permissions_filters.append(["range","modif",[permissions_modif_range1,permissions_modif_range2]]) 
         #...........................................
         #... Permissions parameters
         #...........................................
         elif arg == "--Preferences":
            is_preferences_ok = True
         #...........................................
         #... Addons parameters                                                                                                  
         #...........................................
         elif arg == "--Addons":
            is_addon_ok = True
         #...........................................
         #... Downloads parameters                                                                                                 
         #...........................................
         elif arg == "--Downloads":
            is_downloads_ok = True
         elif arg == "-range" and is_downloads_ok == True:
            downloads_range1 = validateDate(get_param_argurment(arg,count+1))
            downloads_range2 = validateDate(get_param_argurment(arg,count+2))
            downloads_filters.append(["range","start",[downloads_range1,downloads_range2]]) 
            downloads_history_filters.append(["range","modified",[downloads_range1,downloads_range2]]) 
         #...........................................
         #... Forms parameters                                                                                                 
         #...........................................
         elif arg == "--Forms":
            is_forms_ok = True
         elif arg == "-value" and is_forms_ok == True:
            forms_value = get_param_argurment(arg,count+1)
            forms_filters.append(["string","value",forms_value])   
         elif arg == "-forms_range" and is_forms_ok == True:
            forms_range1 = validateDate(get_param_argurment(arg,count+1))
            forms_range2 = validateDate(get_param_argurment(arg,count+2))
            forms_filters.append(["range","last",[forms_range1,forms_range2]]) 
         #...........................................
         #... History parameters
         #...........................................
         elif arg == "--History":
            is_history_ok = True
         elif arg == "-url" and is_history_ok == True:
            history_url =  get_param_argurment(arg,count+1)
            history_filters.append(["string","url",history_url])
         elif arg == "-frequency" and is_history_ok == True:
            is_frequency_ok = True
         elif arg == "-title" and is_history_ok == True:
            history_title = get_param_argurment(arg,count+1)
            history_filters.append(["string","title",history_title])
         elif arg == "-date" and is_history_ok == True:
            history_date = validateDate(get_param_argurment(arg,count+1))
            history_filters.append(["date","last",history_date])
         elif arg == "-history_range" and is_history_ok == True:
            history_range1 = validateDate(get_param_argurment(arg,count+1))
            history_range2 = validateDate(get_param_argurment(arg,count+2))
            history_filters.append(["range","last",[history_range1,history_range2]])
         #...........................................
         #... Bookmarks parameters
         #...........................................
         elif arg == "--Bookmarks":
            is_bookmarks_ok = True
         elif arg == "-bookmarks_range" and is_bookmarks_ok == True:
            bookmarks_range1 = validateDate(get_param_argurment(arg,count+1))
            bookmarks_range2 = validateDate(get_param_argurment(arg,count+2))
            bookmarks_filters.append(["range","last",[bookmarks_range1,bookmarks_range2]])
         #...........................................
         #... Passwords parameters
         #...........................................
         elif arg == "--Passwords":
            is_passwords_ok = True
         #...........................................
         #... Cache parameters
         #...........................................
         elif arg == "--OfflineCache":
            is_cacheoff_ok = True
         elif arg == "-cache_range" and is_cacheoff_ok == True:
            cacheoff_range1 = get_param_argurment(arg,count+1)
            cacheoff_range2 = get_param_argurment(arg,count+2)
            cacheoff_filters.append(["range","last",[cacheoff_range1,cacheoff_range2]])
         elif arg == "-extract" and is_cacheoff_ok == True:
            is_cacheoff_extract_ok = True
            cacheoff_directory = get_param_argurment(arg,count+1)
         #...........................................
         #... Certoverride parameters
         #...........................................
         elif arg == "--Certoverride":
            is_cert_ok = True
         #...........................................
         #... Thumbnails parameters
         #...........................................
         elif arg == "--Thumbnails":
            is_thump_ok = True
         elif arg == "-extract_thumb" and is_thump_ok == True:
            thumb_directory = get_param_argurment(arg,count+1)
         #...........................................
         #... Session parameters
         #...........................................
         elif arg == "--Session":
            is_session_ok = True
         #...........................................
         #... Session parameters          
         #...........................................
         elif arg == "--Session2":
            is_session2_ok = True
         #...........................................
         #... Watch parameters
         #...........................................
         elif arg == "--Watch":
            is_watch_ok = True
         elif arg == "-py3path" and is_watch_ok == True:
            python3_path = get_param_argurment(arg,count+1)
         elif arg == "-text" and is_watch_ok == True:
            watch_text = get_param_argurment(arg,count+1)
         count = count + 1
      
      if count == 0:
         show_help()
         sys.exit()

      ###############
      ### ACTIONS      
      ###############
      show_info_header(dir)
      
      if is_regexp_ok == True:
         query_str_f = "REGEXP"
         query_str_a = ""
      else:
         query_str_f = "like"
         query_str_a = "escape '\\'"
      
      if is_showall_ok == True:
         All_execute(dir)
      else:
         anyexec = False
         if is_cookie_ok == True:
            show_cookies_firefox(dir)
            anyexec = True
         if is_permissions_ok == True:
            show_permissions_firefox(dir)
            anyexec = True
         if is_preferences_ok == True:
            show_preferences_firefox(dir)
            anyexec = True
         if is_addon_ok == True:
            show_addons_firefox(dir)
            show_extensions_firefox(dir)
            show_info_addons(dir)
            show_search_engines(dir)
            anyexec = True
         if is_downloads_ok == True:
            show_downloads_firefox(dir)
            show_downloads_history_firefox(dir)
            show_downloadsdir_firefox(dir)
            anyexec = True
         if is_forms_ok == True:
            show_forms_firefox(dir)
            anyexec = True
         if is_history_ok == True:
            show_history_firefox(dir)
            anyexec = True
         if is_bookmarks_ok == True:
            show_bookmarks_firefox(dir)
            anyexec = True
         if is_passwords_ok == True:
            show_passwords_firefox(dir)   
            anyexec = True
         if is_cacheoff_ok == True:
            show_cache(dir)
            anyexec = True
         if is_cacheoff_ok == True and is_cacheoff_extract_ok == True: 
            show_cache_extract(dir, cacheoff_directory)
            anyexec = True
         if is_cert_ok == True:
            show_cert_override(dir)
            anyexec = True
         if is_thump_ok == True:
            show_thumbnails(dir, thumb_directory)
            anyexec = True
         if is_session_ok == True:
            show_session(dir)
            anyexec = True
         if is_session2_ok == True:
            extract_data_session_watch(dir)
            anyexec = True
         if is_watch_ok == True:
            show_watch(dir,watch_text)
            anyexec = True
         if is_summary_ok and not anyexec:
            All_execute(dir)

      ###############
      ### SUMMARY      
      ###############

      if is_regexp_ok == True:
         save_message("INFO","Using Regular Expression mode for string type filters")

      ### HEADERS
      titles = {
       "decode"              : "Decode Passwords     ",
       "passwords"           : "Passwords            ",
       "exceptions"          : "Exceptions/Passwords ",
       "cookies"             : "Cookies              ",
       "dom"                 : "DOM Storage          ",
       "permissions"         : "Permissions          ",
       "preferences"         : "Preferences          ",
       "addons"              : "Addons               ",
       "addinfo"             : "Addons (URLS/PATHS)  ",
       "extensions"          : "Extensions           ",
       "engines"             : "Search Engines       ",
       "downloads"           : "Downloads            ",
       "downloads_history"   : "Downloads history    ",
       "downloads_dir"       : "Directories          ",
       "forms"               : "Forms                ",
       "history"             : "History              ",
       "bookmarks"           : "Bookmarks            ",
       "offlinecache"        : "OfflineCache Html5   ",
       "offlinecache_extract": "OfflineCache Extract ",
       "thumbnails"          : "Thumbnails images    ",
       "cert_override"       : "Cert override        ",
       "session"             : "Sessions             "
      }

      info_headers = sorted(total_extraction.keys())
      summary = {}

      for header in info_headers:
         sources = total_extraction[header].keys()
         for source in sources:
            # INFO HEADER BY SOURCE
            if not is_summary_ok:
               if path.isfile(source):
                  show_title(titles[header] +show_sha256(source), 302)
               else:
                  show_title(titles[header], 243)

            if header in summary.keys():
               summary[header] = summary[header] + len(total_extraction[header][source])
            else:
               summary[header] = len(total_extraction[header][source])

            if summary[header] > 0:
               for i in total_extraction[header][source]:
                  tags = sorted(i.keys())
                  for tag in tags:
                     if not is_summary_ok:
                        if i[tag]:
                           print(tag.split('-',1)[1] + ": " + str(i[tag]))
                        else:
                           print(tag.split('-',1)[1] + ": ")
                  if not is_summary_ok:
                     print("")
            else:
               if not is_summary_ok:
                  print("No data found!")
               summary[header] = 0

      info_headers = sorted(summary.keys())

      if len(info_headers) == 0 and arg_count > 0:
         show_title("Total Information", 243)
         print("No data found!")
      elif len(info_headers) == 0:
         save_message("ERROR","Missing argument!")
         show_help()
      else:
         show_title("Total Information", 243)
         for header in info_headers:
            print("Total " + titles[header] + ": " + str(summary[header]))
      print("")

   else:
      save_message("ERROR","Failed to read profile directory")
      show_help()
      sys.exit()

# Site: www.dumpzilla.org
# Author: Busindre ( busilezas[@]gmail.com )
#         OsamaNehme ( onehdev[@]gmail.com )
# Version: 2016/02/22
