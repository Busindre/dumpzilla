#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3, sys, glob, shutil, json, time, hashlib, re, os, logging, lz4.block
from base64 import b64decode
from os import path,walk,makedirs,remove
from ctypes import (Structure, c_uint, c_void_p, c_ubyte,c_char_p, CDLL, cast,byref,string_at)
from datetime import datetime, timedelta
from subprocess import call
from collections import OrderedDict

import argparse

# Magic Module: https://github.com/ahupp/python-magic

class Dumpzilla():
    ########################################### GLOBAL VARIABLES ##################################################
    VERSION='v20180324'

    magicpath = 'C:\WINDOWS\system32\magic' # Only in Windows, path to magic file (Read Manual in www.dumpzilla.org)

    query_str_f = ""
    query_str_a = ""

    output_mode = 0 # Output modes: 0 - Standart output (default)
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

    # TODO: Make a object with all parameters' info

    # --Cookies
    cookie_filters = []
    domain_filters = []
    is_dom_ok = False

    # --Permissions
    permissions_filters = []

    # --Downloads
    downloads_filters = []
    downloads_history_filters = []

    # --Forms
    forms_filters = []

    # --History
    history_filters = []

    # --Bookmarks
    bookmarks_filters = []

    # --OfflineCache Cache
    is_cacheoff_extract_ok = False
    cacheoff_filters = []
    cacheoff_directory = None

    # --Keypinning
    keypinning_filters = []

    # --Thumbnails
    thumb_filters = []

    # --Watch
    watch_text = 1

    args = None

    watchsecond = 4 # --Watch option: Seconds update. (NO Windows)
    PYTHON3_DEF  = '/usr/bin/python3'
    PYTHON3_PATH = ''

    ######################################## NSS LOADING (PASWORD DECODE) #########################################

    if sys.platform.startswith('win') == True: # WINDOWS
        libnss_path =  "C:\Program Files (x86)\Mozilla Firefox\nss3.dll"
    elif sys.platform.endswith('win') == False: # LINUX
        libnss_path = "libnss3.so"
    elif sys.platform.endswith('win') == True: # MAC
        libnss_path = 'libnss3.dylib'
        # Example: /usr/local/Cellar/nss/3.28.1/lib/libnss3.dylib
        # libnss_path = False
        # if path.isdir("/usr/local/Cellar/nss"):
        #    for s in os.listdir("/usr/local/Cellar/nss"): # Iterate through versions
        #       libnss_version = path.join("/usr/local/Cellar/nss",s)
        #       if path.isdir(libnss_version): # Must be a folder (/usr/local/Cellar/nss/x.xx.x)
        #           libnss_check = path.join(libnss_version,'lib/libnss3.dylib')
        #           if path.isfile(libnss_check):
        #              libnss_path = libnss_check
        #              break
    else:
        libnss_path = False

    if libnss_path and path.isfile(libnss_path):
        libnss = CDLL(libnss_path)
    else:
        libnss = False

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

    ####################################################
    #                                                                                                             #
    #   AUX METHODS                                                                                   #
    #                                                                                                             #
    ####################################################

    def get_user_value(self, message):
        if sys.version.startswith('2.') == True:
            return raw_input(message);
        else:
            return input(message);

    def serial_date_to_string(self, srl_no):
        new_date = datetime(1970,1,1,0,0) + timedelta(srl_no - 1)
        return new_date.strftime("%Y-%m-%d %H:%M:%S")

    def log(self, type, message):
        # These are the sequences need to get colored ouput
        RESET_SEQ = "\033[0m"
        COLOR_SEQ = "\033[1;%dm"
        BOLD_SEQ = "\033[1m"

        BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

        LEVELS = {
            'DEBUG': {
                'color': BLUE,
                'funct': self.logger.debug
            },
            'WARNING': {
                'color': YELLOW,
                'funct': self.logger.warning
            },
            'INFO': {
                'color': GREEN,
                'funct': self.logger.info
            },
            'ERROR': {
                'color': RED,
                'funct': self.logger.error
            },
            'CRITICAL': {
                'color': RED,
                'funct': self.logger.critical
            }
        }
        # remove ch to logger
        if hasattr(self, 'ch'):
            self.logger.removeHandler(self.ch)

        # create console handler and set level to debug
        self.ch = logging.StreamHandler()

        # create formatter
        formatter = logging.Formatter('['+ COLOR_SEQ % (30 + LEVELS[type]['color']) + '%(levelname)s' + RESET_SEQ  + '] %(message)s')
        if (self.verbosity_level == "DEBUG"):
            formatter = logging.Formatter(COLOR_SEQ % (30 + LEVELS[type]['color']) + '%(levelname)s' + RESET_SEQ  + ' - %(asctime)s - ' + sys.argv[0] + ' - %(message)s')

        # add formatter to ch
        self.ch.setFormatter(formatter)

        # add ch to logger
        self.logger.addHandler(self.ch)
        LEVELS[type]['funct'](message)

    def get_path_by_os(self, dir, file, cd_dir = None):
       delimiter = "/"
       if sys.platform.startswith('win') == True:
          delimiter = "\\"
       if cd_dir is not None:
          cd_dir = cd_dir + delimiter
       else:
          cd_dir = ""
       return dir+delimiter+cd_dir+file

    def decode_reg(self, reg):
        try:
            if type(reg) is int or type(reg) is str:
                return reg
            elif reg is None:
                return None
            else:
                return reg.decode()
        except UnicodeDecodeError:
            #self.log("ERROR","UnicodeDecodeError : "+str(sys.exc_info()[1]))
            #return None
            return reg.decode('utf-8')

    def show_info_header(self,profile):
        if sys.version.startswith('2.') == True:
            self.log("WARNING","Python 2.x currently used, Python 3.x and UTF-8 is recommended!")
        self.log("INFO",  "Mozilla Profile: " + str(profile))

    def show_title(self,varText,source = False):
       varText = "\n== "+varText+"\n"
       print("")
       print(varText.center(243, "="))
       if (source):
           print("=> Source file: " + source)
           print("=> SHA256 hash: "+ self.show_sha256(source))
       print("")

    def regexp(self,expr, item):
       try:
          if item:
             reg = re.compile(expr, re.I)
             #Debug# print("expr: %s - %s - %s" % (expr, item, reg.match(item)) )
             return reg.search(item) is not None
          else:
             return None
       except: # catch *all* exceptions
          e = str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1])
          self.log("ERROR", "Error using RegExp " + e)
          return None

    def validate_date(self,date_str):
       if not self.regexp('^[0-9_%:\- ]{1,19}$',date_str):
          self.log("WARNING","Erroneous date '"+date_str+"' : Check wildcards ('%' '_' '/') and format (YYYY-MM-DD hh:mi:ss)")
       return date_str

    def execute_query(self,cursor,sqlite_query,filters,orderby = None):
       sqlite_param = []
       cnt = 0
       for filter in filters:
          if cnt == 0 and sqlite_query.find('where') == -1:
             sqlite_query = sqlite_query + " where ("
          else:
             sqlite_query = sqlite_query + " and ("
          if filter[0] == "string":
             # SQL Query: [RegExp] column REGEXP ?
             #            [SQLike] column like ? escape '\'
             sqlite_query = sqlite_query + filter[1] + " " + self.query_str_f + " ? " + self.query_str_a
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

       ### print("%s - %s" % (sqlite_query,sqlite_param))
       self.log('DEBUG', 'Execute query: ' + sqlite_query)
       cursor.execute(sqlite_query,sqlite_param)

    def decompressLZ4(self, file):
        lz4_headers = [ b"mozLz40\0", b"mozLz40p\0", b"mozLz40o\0"]

        for header in lz4_headers:
          value = file.read(len(header))
          if value == header:
              return lz4.block.decompress(file.read())
          file.seek(0)



        return None

    def getJSON(self, file):
        try:
          decompress = self.decompressLZ4(file)
          if decompress is None:
            return json.loads(file.read())
          else:
            return json.loads(decompress)

        except UnicodeDecodeError:
            self.log("ERROR", str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]) + ". Please check locale settings to verify UTF-8 is set!")

    ###############################################################################################################
    ### SHA256 HASHING                                                                                            #
    ###############################################################################################################

    def show_sha256(self,filepath):
        sha256 = hashlib.sha256()
        f = open(filepath, 'rb')
        try:
           sha256.update(f.read())
        finally:
           f.close()
        return sha256.hexdigest()

    def export_sha256(self,destination,header,sources):
        sha256_data = {}

        for source in sources:
           if path.isfile(source):
                sha256 = hashlib.sha256()
                f = open(source, 'rb')
                try:
                   sha256.update(f.read())
                finally:
                   f.close()
                sha256_data[source] = sha256.hexdigest()

        outputFilename = header + '.sha256.json';
        with open(destination + outputFilename, 'w') as fp:
            json.dump(sha256_data, fp)

    #############################################################################################################
    ### DECODE PASSWORDS
    #############################################################################################################

    def readsignonDB(self, dir):
       passwords_sources = ["signons.sqlite","logins.json"]
       decode_passwords_extraction_dict = {}
       if not self.libnss:
          if not self.libnss_path:
              self.log("ERROR","Error decoding passwords: libnss not found!")
          else:
              self.log("ERROR","Error decoding passwords: libnss not found (" + self.libnss_path + ")");

       # TODO: Make self method to decode
       if self.libnss and self.libnss.NSS_Init(dir.encode("utf8"))!=0:
          self.log("ERROR","Error Initializing NSS_Init, probably no useful results.")

       for a in passwords_sources:
          # Setting filename by OS
          bbdd = self.get_path_by_os(dir, a)

          # Checking source file
          if path.isfile(bbdd) == True:
             if a.endswith(".json") == True:
                # JSON
                f = open(bbdd)
                jdata = self.getJSON(f)
                f.close()
                _extraction_list = []
                try:
                    for l in jdata.get("logins"):
                        _extraction_dict = {}
                        if l.get("id") is not None:
                            self.uname.data  = cast(c_char_p(b64decode(l.get("encryptedUsername"))),c_void_p)
                            self.uname.len = len(b64decode(l.get("encryptedUsername")))
                            self.passwd.data = cast(c_char_p(b64decode(l.get("encryptedPassword"))),c_void_p)
                            self.passwd.len=len(b64decode(l.get("encryptedPassword")))

                            if self.libnss and self.libnss.PK11SDR_Decrypt(byref(self.uname), byref(self.dectext), byref(self.pwdata)) == -1:
                                self.log("INFO", "Master password required")
                                password = c_char_p(self.get_user_value(a + " password: ").encode("utf8"))
                                keyslot = self.libnss.PK11_GetInternalKeySlot()
                                if keyslot is None:
                                    # Something went wrong!
                                    self.log("ERROR","Failed to retrieve internal KeySlot")
                                    return
                                check_rc = self.libnss.PK11_CheckUserPassword(keyslot, password)
                                if check_rc != 0:
                                    # Something went wrong with given password
                                    self.log("ERROR","Password decoding failed! Check master password")
                                    return;

                            _extraction_dict["0-Web"] = self.decode_reg(l.get("hostname"))
                            _extraction_dict["1-Username"] = self.decode_reg(string_at(self.dectext.data,self.dectext.len))

                            if self.libnss and self.libnss.PK11SDR_Decrypt(byref(self.passwd),byref(self.dectext),byref(self.pwdata))==-1:
                                self.log("ERROR","Master password decryption failed!")
                                return

                            _extraction_dict["2-Password"] = self.decode_reg(string_at(self.dectext.data,self.dectext.len))

                            _extraction_list.append(_extraction_dict)

                except:
                   e = str(sys.exc_info()[0])
                   self.log("ERROR","Passwords database: Can't process file " + a + ": " + e )

                decode_passwords_extraction_dict[bbdd] = _extraction_list

             elif a.endswith(".sqlite"):
                # SQLITE
                conn = sqlite3.connect(bbdd)
                conn.text_factory = bytes
                cursor = conn.cursor()
                try:
                    self.execute_query(cursor,"select hostname, encryptedUsername, encryptedPassword from moz_logins",[])
                    _extraction_list = []
                    for row in cursor:
                        _extraction_dict = {}
                        self.uname.data  = cast(c_char_p(b64decode(row[1])),c_void_p)
                        self.uname.len = len(b64decode(row[1]))
                        self.passwd.data = cast(c_char_p(b64decode(row[2])),c_void_p)
                        self.passwd.len=len(b64decode(row[2]))

                        if self.libnss and self.libnss.PK11SDR_Decrypt(byref(self.uname),byref(self.dectext),byref(self.pwdata))==-1:
                            self.log("INFO", "Master password required")
                            password = c_char_p(self.get_user_value(a + " password: ").encode("utf8"))
                            keyslot = self.libnss.PK11_GetInternalKeySlot()
                            if keyslot is None:
                                # Something went wrong!
                                self.log("ERROR","Failed to retrieve internal KeySlot")
                                return
                            check_rc = self.libnss.PK11_CheckUserPassword(keyslot, password)
                            if check_rc != 0:
                                # Something went wrong with given password
                                self.log("ERROR","Password decoding failed! Check master password")
                                return;

                        _extraction_dict["0-Web"] = self.decode_reg(row[0])
                        _extraction_dict["1-Username"] = self.decode_reg(string_at(self.dectext.data,self.dectext.len))

                        if self.libnss and self.libnss.PK11SDR_Decrypt(byref(self.passwd),byref(self.dectext),byref(self.pwdata))==-1:
                           self.log("ERROR","Master password decryption failed!")
                           return

                        _extraction_dict["2-Password"] = self.decode_reg(string_at(self.dectext.data,self.dectext.len))

                        _extraction_list.append(_extraction_dict)

                    decode_passwords_extraction_dict[bbdd] = _extraction_list

                    conn.close()
                    if self.libnss:
                        self.libnss.NSS_Shutdown()
                except sqlite3.OperationalError:
                    self.log("WARNING",bbdd + ": no data found!")

       if len(decode_passwords_extraction_dict) == 0:
          self.log("INFO","Passwords database not found! Please, check file " + '|'.join(passwords_sources))

       # Saving extraction to main extraction list
       self.total_extraction["decode"] = decode_passwords_extraction_dict



    ###############################################################################################################
    ### PASSWORDS
    ###############################################################################################################

    def show_passwords(self,dir):
        passwords_sources = ["signons.sqlite","logins.json"]
        passwords_extraction_dict = {}
        exception_extraction_dict = {}

        for a in passwords_sources:
            # Setting filename by OS
            bbdd = self.get_path_by_os(dir, a)

            # Checking source file
            if path.isfile(bbdd) == True:
                if a.endswith(".json") == True:
                    # JSON
                    f = open(bbdd)
                    jdata = self.getJSON(f)
                    f.close()

                    _extraction_list = []
                    try:
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

                    except:
                       e = str(sys.exc_info()[0])
                       self.log("ERROR","Passwords database: Can't process file " + a + ": " + e )

                    passwords_extraction_dict[bbdd] = _extraction_list

                elif a.endswith(".sqlite"):
                    # SQLITE

                    conn = sqlite3.connect(bbdd)
                    conn.text_factory = bytes
                    cursor = conn.cursor()

                    try:
                        ### Exceptions
                        cursor.execute('select hostname from moz_disabledHosts')
                        _extraction_list = []
                        for row in cursor:
                            _extraction_dict = {}
                            _extraction_dict['0-Exception Web'] = self.decode_reg(row[0])
                            _extraction_list.append(_extraction_dict)

                        exception_extraction_dict[bbdd] = _extraction_list

                        ### Passwords
                        cursor.execute('select formSubMitURL,usernameField,passwordField ,encryptedUsername,encryptedPassword,encType,\
                                        datetime(timeCreated/1000,"unixepoch","localtime"),datetime(timeLastUsed/1000,"unixepoch","localtime"),\
                                        datetime(timePasswordChanged/1000,"unixepoch","localtime"),timesUsed FROM moz_logins')
                        _extraction_list = []
                        for row in cursor:
                            _extraction_dict = {}
                            _extraction_dict['0-Web'] = self.decode_reg(row[0])
                            _extraction_dict['1-User field'] = self.decode_reg(row[1])
                            _extraction_dict['2-Password field'] = self.decode_reg(row[2])
                            _extraction_dict['3-User login (crypted)'] = self.decode_reg(row[3])
                            _extraction_dict['4-Password login (crypted)'] = self.decode_reg(row[4])
                            #_extraction_dict['99-Encripton type'] = self.decode_reg(row[5])
                            _extraction_dict['5-Created'] = self.decode_reg(row[6])
                            _extraction_dict['6-Last used'] = self.decode_reg(row[7])
                            _extraction_dict['7-Change'] = self.decode_reg(row[8])
                            _extraction_dict['8-Frequency'] = self.decode_reg(row[9])
                            _extraction_list.append(_extraction_dict)

                        passwords_extraction_dict[bbdd] = _extraction_list
                    except:
                       e = str(sys.exc_info()[0])
                       self.log("ERROR","Passwords database: can't process file " + a + ": " + e )

                    cursor.close()
                    conn.close()

        self.total_extraction["exceptions"] = exception_extraction_dict

        if len(passwords_extraction_dict) == 0:
            self.log("INFO","Passwords database not found! Please, check file " + '|'.join(passwords_sources))
        else:
            if sys.platform.startswith('win') == False: # and sys.version.startswith('2.') == True and count > 0:
                self.readsignonDB(dir)
            else:
                self.log("ERROR","Decode password only works on GNU/Linux")

        # Saving extraction to main extraction list
        self.total_extraction["passwords"] = passwords_extraction_dict

    ###############################################################################################################
    ### SHOW ALL DATA                                                                                             #
    ###############################################################################################################

    def All_execute(self,dir):
        self.show_cookies(dir)
        self.show_permissions(dir)
        self.show_preferences(dir)
        self.show_addons(dir)
        self.show_extensions(dir)
        self.show_search_engines(dir)
        self.show_info_addons(dir)
        self.show_downloads(dir)
        self.show_downloads_history(dir)
        self.show_downloadsdir(dir)
        self.show_forms(dir)
        self.show_history(dir)
        self.show_bookmarks(dir)
        self.show_passwords(dir)
        self.show_key_pinning(dir)
        self.show_cache(dir)
        self.show_cert_override(dir)
        self.show_thumbnails(dir)
        self.show_session(dir)

    ###############################################################################################################
    ### COOKIES                                                                                                   #
    ###############################################################################################################

    def show_cookies(self,dir):
       cookies_extraction_dict = {}
       dom_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'cookies.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","Cookies database not found! Please, check file cookies.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       cursor = conn.cursor()
       sqlite_query = "select name, value, host, path, datetime(expiry, 'unixepoch', 'localtime'), datetime(lastAccessed/1000000,'unixepoch','localtime') as last ,datetime(creationTime/1000000,'unixepoch','localtime') as creat, isSecure, isHttpOnly FROM moz_cookies"
       self.execute_query(cursor,sqlite_query,self.cookie_filters)

       _extraction_list = []
       for row in cursor:
          _extraction_dict = {}
          _extraction_dict['1-Host'] = self.decode_reg(row[2])
          _extraction_dict['2-Name'] = self.decode_reg(row[0])
          _extraction_dict['3-Value'] = self.decode_reg(row[1])
          _extraction_dict['4-Path'] = self.decode_reg(row[3])
          _extraction_dict['5-Expiry'] = self.decode_reg(row[4])
          _extraction_dict['6-Last Access'] = self.decode_reg(row[5])
          _extraction_dict['7-Creation Time'] = self.decode_reg(row[6])

          if self.decode_reg(row[7]) == 0:
             _extraction_dict['8-Secure'] =  'No'
          else:
             _extraction_dict['8-Secure'] =  'Yes'

          if self.decode_reg(row[8]) == 0:
             _extraction_dict['9-HttpOnly'] =  'No'
          else:
             _extraction_dict['9-HttpOnly'] =  'Yes'

          _extraction_list.append(_extraction_dict)

       cookies_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["cookies"] = cookies_extraction_dict

       cursor.close()
       conn.close()

       ####################################
       ### DOM STORAGE                    #
       ####################################
       if self.is_dom_ok == True:

          bbdd = self.get_path_by_os(dir, 'webappsstore.sqlite')

          if path.isfile(bbdd) == False:
             self.log("INFO","Webappsstore database not found! Please, check file webappsstore.sqlite")
             return

          # WARNING! Only RegExp filter allowed!
          if len(self.domain_filters) > 0 and self.args.is_regexp_ok == False :
             self.log("WARNING","Showing all DOM storage, to filter please use RegExp parameter")

          conn = sqlite3.connect(bbdd)
          conn.text_factory = bytes
          cursor = conn.cursor()

          sqlite_query = "select scope, value from webappsstore2"
          cursor.execute(sqlite_query)

          _extraction_list = []
          for row in cursor:
             _extraction_dict = {}
             fd = ""
             if self.decode_reg(row[0]).find("http") == -1:
                fd = path.split(self.decode_reg(row[0])[::-1])[1][1:]
             if self.decode_reg(row[0]).startswith("/") == False and self.decode_reg(row[0]).find("http") != -1:
                fd = path.split(self.decode_reg(row[0])[::-1])[1].rsplit(':.', 1)[1]
             # -domain filter
             show_this_domain = True
             if len(self.domain_filters) > 0 and  self.args.is_regexp_ok == True:
                show_this_domain = self.regexp(self.domain_filters[0][2],fd)

             if show_this_domain == True:
                _extraction_dict['0-Domain'] = fd
                _extraction_dict['1-DOM data'] = row[1].decode('utf-8', 'ignore')

             _extraction_list.append(_extraction_dict)

          dom_extraction_dict[bbdd] = _extraction_list

          self.total_extraction["dom"] = dom_extraction_dict

          cursor.close()
          conn.close()

    ###############################################################################################################
    ### PERMISSIONS                                                                                               #
    ###############################################################################################################

    def show_permissions(self,dir):
       permissions_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'permissions.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","Permissions database not found! Please, check file permissions.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       # Old table for permissions
       permissions_tables = ["moz_hosts"]

       # New table for permissions (checking if exists)
       cursor = conn.cursor()
       sqlite_query = "select count(*) from sqlite_master"
       master_filters = [["string","type","table"],["string","name","moz_perms"]]
       self.execute_query(cursor,sqlite_query,master_filters)
       for row in cursor:
          if row[0] > 0:
             permissions_tables.append("moz_perms")
       cursor.close()

       _extraction_list = []

       for table in permissions_tables:
          host_col = "host"
          if table == "moz_perms":
             host_col = "origin"
             for f in self.permissions_filters:
                if f[1] == "host":
                   index = self.permissions_filters.index(f)
                   self.permissions_filters[index][1] = "origin"

          # Checking if modificationTime column exists
          cursor = conn.cursor()
          sqlite_query = "pragma table_info("+table+")"

          modificationTime_found = False
          for row in cursor:
             if self.decode_reg(row[1]) == "modificationTime":
                modificationTime_found = True
          cursor.close()

          # Making sqlite query
          cursor = conn.cursor()
          sqlite_query = ""
          if modificationTime_found:
             sqlite_query = "select "+ host_col +",type,permission,expireType,datetime(expireTime/1000,'unixepoch','localtime') as expire, datetime(modificationTime/1000,'unixepoch','localtime') as modif from "+table
          else:
             sqlite_query = "select "+ host_col +",type,permission,expireType,datetime(expireTime/1000,'unixepoch','localtime') as expire from "+table
             for f in self.permissions_filters:
                if f[1] == "modif":
                   self.permissions_filters.remove(f)
                   self.log("WARNING","modificationTime : Column not found in permissions database")

          self.execute_query(cursor,sqlite_query,self.permissions_filters)

          for row in cursor:
            _extraction_dict = {}
            _extraction_dict['0-Host'] = self.decode_reg(row[0])
            _extraction_dict['1-Type'] = self.decode_reg(row[1])
            permissionType = str( self.decode_reg(row[2]) )

            # Permission
            if permissionType == '1':
                _extraction_dict['2-Permission'] = permissionType + " (allow)"
            elif permissionType == '2':
                _extraction_dict['2-Permission'] = permissionType + " (block)"
            elif permissionType == '8':
                _extraction_dict['2-Permission'] = permissionType + " (allow for session only)"
            else:
                _extraction_dict['2-Permission'] = permissionType

            # Expire time
            if self.decode_reg(row[3]) == 0:
                _extraction_dict['3-Expire Time'] = 'Not expire'
            else:
                _extraction_dict['3-Expire Time'] = self.decode_reg(row[4])

            if modificationTime_found:
                _extraction_dict['4-Modification Time'] = self.decode_reg(row[5])
            _extraction_list.append(_extraction_dict)
          cursor.close()

       permissions_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["permissions"] = permissions_extraction_dict

       cursor.close()
       conn.close()

    ###############################################################################################################
    ### PREFERENCES                                                                                               #
    ###############################################################################################################

    def show_preferences(self,dir):
       preferences_extraction_dict = {}

       dirprefs = self.get_path_by_os(dir, 'prefs.js')

       if path.isfile(dirprefs) == False:
          self.log("INFO","Preferences database not found! Please, check prefs.js")
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
             if ( self.regexp('[Tt]ime',code) or self.regexp("[Ll]ast",code) ) and self.regexp("^[0-9]{10}$",value):
                tmstmp = datetime.fromtimestamp(int(value)/1000).strftime('%Y-%m-%d %H:%M:%S')
                if self.regexp("^197",tmstmp):
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

       self.total_extraction["preferences"] = preferences_extraction_dict

    ###############################################################################################################
    ### ADDONS                                                                                                    #
    ###############################################################################################################

    def show_addons(self,dir):
        addons_extraction_dict = {}
        addons_found = False
        addons_sources = ["addons.sqlite","addons.json"]

        for a in addons_sources:
            # Setting filename by OS
            bbdd = self.get_path_by_os(dir, a)

            # Checking source file
            if path.isfile(bbdd) == True:
                addons_found = True

                if a.endswith(".json") == True:
                    # JSON
                    f = open(bbdd)
                    jdata = self.getJSON(f)
                    f.close()
                    _extraction_list = []
                    try:
                        for addon in jdata.get("addons"):
                            _extraction_dict = {}
                            if addon.get("id") is not None:
                                _extraction_dict['0-Name'] = addon.get("name")
                                _extraction_dict['1-Version'] = addon.get("version")
                                _extraction_dict['2-Creator URL'] = addon.get("creator").get("url")
                                _extraction_dict['3-Homepage URL'] = addon.get("homepageURL")
                                _extraction_list.append(_extraction_dict)
                    except:
                       e = str(sys.exc_info()[0])
                       self.log("ERROR","Addons database: Can't process file " + a + ": " + e )

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
                       _extraction_dict['0-Name'] = self.decode_reg(row[0])
                       _extraction_dict['1-Version'] = self.decode_reg(row[3])
                       _extraction_dict['2-Creator URL'] = self.decode_reg(row[1])
                       _extraction_dict['3-Homepage URL'] = self.decode_reg(row[2])
                       _extraction_list.append(_extraction_dict)

                    addons_extraction_dict[bbdd] = _extraction_list

                    cursor.close()
                    conn.close()

        # Saving extraction to main extraction list
        self.total_extraction["addons"] = addons_extraction_dict
        if addons_found == False:
            self.log("INFO","Addons database not found! Please, check file %s" % '|'.join(addons_sources))

    ###############################################################################################################
    ### ADDONS INFO                                                                                               #
    ###############################################################################################################

    def show_info_addons(self,dir):
       addinfo_extraction_dict = {}
       addinfo_found = False
       addinfo_sources = ["xulstore.json","localstore.rdf"]

       for a in addinfo_sources:
          # Setting filename by OS
          filepath = self.get_path_by_os(dir, a)

          # Checking source file
          if path.isfile(filepath) == True:

             addinfo_found = True

             if a.endswith(".json") == True:
                # JSON
                f = open(filepath)
                jdata = self.getJSON(f)
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
                   self.log("INFO", "The Addons-Info database " + a + " does not contain URLs or paths!")

       # Saving extraction to main extraction list
       self.total_extraction["addinfo"] = addinfo_extraction_dict
       if addinfo_found == False:
          self.log("INFO","Addons-Info database not found! Please, check file " + '|'.join(addinfo_sources))

    ###############################################################################################################
    ### EXTENSIONS                                                                                                #
    ###############################################################################################################

    def show_extensions(self,dir):
       ext_extraction_dict = {}
       ext_found = False
       ext_sources = ["extensions.json","extensions.sqlite"]

       for a in ext_sources:
          # Setting filename by OS
          filepath = self.get_path_by_os(dir, a)

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
                   self.log("ERROR","Extensions database: can't process file " + a + ": " + e )


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
                   _extraction_dict['0-Type'] = self.decode_reg(row[0])
                   _extraction_dict['1-Descriptor'] = self.decode_reg(row[1])
                   _extraction_dict['2-Version'] = self.decode_reg(row[2])
                   _extraction_dict['3-Release'] = self.decode_reg(row[3])
                   _extraction_dict['4-Install Date'] = self.decode_reg(row[4])
                   _extraction_dict['5-Update Date'] = self.decode_reg(row[5])
                   _extraction_dict['6-Active'] = self.decode_reg(row[6])
                   _extraction_list.append(_extraction_dict)

                ext_extraction_dict[filepath] = _extraction_list

                cursor.close()
                conn.close()

       # Saving extraction to main extraction list
       self.total_extraction["extensions"] = ext_extraction_dict
       if ext_found == False:
          self.log("INFO","Extensions database not found! Please, check file" + '|'.join(ext_sources))

    ###############################################################################################################
    ### SEARCH ENGINES                                                                                            #
    ###############################################################################################################

    def show_search_engines(self,dir):
       se_found = False
       se_sources = ["search.json","search.sqlite","search.json.mozlz4"]
       se_extraction_dict = {}

       for a in se_sources:
          # Setting filename by OS
          filepath = self.get_path_by_os(dir, a)

          # Checking source file
          if path.isfile(filepath) == True:

             se_found = True

             if a.endswith(".json.mozlz4"):
                # LZ4 COMPRESSED JSON
                fo = open(filepath, "rb")
                jdata = json.loads(self.decompressLZ4(fo))
                try:
                    _extraction_list = []
                    for engine in jdata.get("engines"):
                        _extraction_dict = {}
                        _extraction_dict['0-Name'] = engine.get("_name")
                        _extraction_dict['1-Description'] = engine.get("description")
                        _extraction_dict['2-Path'] = engine.get("_loadPath")
                        _extraction_list.append(_extraction_dict)

                    se_extraction_dict[filepath] = _extraction_list

                except:
                   e = str(sys.exc_info()[0])
                   self.log("ERROR","Search Engines database: can't process file " + a + ": " + e )

             if a.endswith(".json"):
                # JSON
                f = open(filepath)
                jdata = self.getJSON(f)
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

                except:
                   e = str(sys.exc_info()[0])
                   self.log("ERROR","Search Engines database: can't process file " + a + ": " + e )

             if a.endswith(".sqlite") == True:
                # SQLITE
                conn = sqlite3.connect(filepath)
                conn.text_factory = bytes
                cursor = conn.cursor()
                cursor.execute("select name, value from engine_data")
                _extraction_list = []
                for row in cursor:
                   _extraction_dict = {}
                   _extraction_dict['0-Name'] = self.decode_reg(row[0])
                   _extraction_dict['1-Value'] = str(self.decode_reg(row[1]))
                   _extraction_list.append(_extraction_dict)

                se_extraction_dict[filepath] = _extraction_list

                cursor.close()
                conn.close()

       # Saving extraction to main extraction list
       self.total_extraction["engines"] = se_extraction_dict
       if se_found == False:
          self.log("INFO","Search Engines database not found! Please, check file " + '|'.join(se_sources))

    ###############################################################################################################
    ### DOWNLOADS                                                                                                 #
    ###############################################################################################################

    def show_downloads(self,dir):
       downloads_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'downloads.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","Recent downloads database (FF<21) not found! Please, check file downloads.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       cursor = conn.cursor()
       sqlite_query = "select name,mimeType,maxBytes/1024,source,target,referrer,tempPath, datetime(startTime/1000000,'unixepoch','localtime') as start,datetime(endTime/1000000,'unixepoch','localtime') as end,state,preferredApplication,preferredAction from moz_downloads"
       self.execute_query(cursor, sqlite_query ,self.downloads_filters)

       _extraction_list = []
       for row in cursor:
          _extraction_dict = {}
          _extraction_dict['00-Name'] = self.decode_reg(row[0])
          _extraction_dict['01-Mime'] = self.decode_reg(row[1])
          _extraction_dict['02-Size (KB)'] = self.decode_reg(row[2])
          _extraction_dict['03-Source'] = self.decode_reg(row[3])
          _extraction_dict['04-Directory'] = self.decode_reg(row[4])
          _extraction_dict['05-Referrer'] = self.decode_reg(row[5])
          _extraction_dict['06-Path temp'] = self.decode_reg(row[6])
          _extraction_dict['07-Start Time'] = self.decode_reg(row[7])
          _extraction_dict['08-End Time'] = self.decode_reg(row[8])
          _extraction_dict['09-State (4 pause, 3 cancell, 1 completed, 0 downloading)'] = self.decode_reg(row[9])
          _extraction_dict['10-Preferred application'] = self.decode_reg(row[10])
          _extraction_dict['11-Preferred action'] = self.decode_reg(row[11])
          _extraction_list.append(_extraction_dict)

       downloads_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["downloads"] = downloads_extraction_dict

    ###############################################################################################################
    ### DOWNLOADS HISTORY                                                                                         #
    ###############################################################################################################

    def show_downloads_history(self,dir):
       download_hist_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'places.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","History Downloads database not found! Please, check file places.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       cursor = conn.cursor()
       sqlite_query = 'select datetime(ann.lastModified/1000000,"unixepoch","localtime") as modified, moz.url, ann.content from moz_annos ann, moz_places moz'

       # Default filters
       #~ where moz.id=ann.place_id and ann.content not like and ann.content not like "ISO-%"  and ann.content like "file%"
       self.downloads_history_filters.append(["column","moz.id","ann.place_id"])
       if self.args.is_regexp_ok:
          self.downloads_history_filters.append(["string","ann.content","^file.*"])
       else:
          self.downloads_history_filters.append(["string","ann.content","file%"])

       self.execute_query(cursor,sqlite_query,self.downloads_history_filters)

       _extraction_list = []
       for row in cursor:
          _extraction_dict = {}
          _extraction_dict['0-Date'] = self.decode_reg(row[0])
          _extraction_dict['1-URL'] = self.decode_reg(row[1])
          _extraction_dict['2-Name'] = self.decode_reg(row[2])
          _extraction_list.append(_extraction_dict)

       download_hist_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["downloads_history"] = download_hist_extraction_dict


    ###############################################################################################################
    ### DOWNLOADS DIRECTORIES                                                                                     #
    ###############################################################################################################

    def show_downloadsdir(self,dir):
       download_dir_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'content-prefs.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","Download Directories database not found! Please, check file content-prefs.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes
       cursor = conn.cursor()

       # Checking if timestamp column exists
       cursor = conn.cursor()
       sqlite_query = "pragma table_info(prefs)"
       self.execute_query(cursor,sqlite_query,[])
       timestamp_found = False
       for row in cursor:
          if self.decode_reg(row[1]) == "timestamp":
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
          _extraction_dict['0-Name'] = self.decode_reg(row[0])

          if timestamp_found:
             timestamp = self.decode_reg(row[1])
             if self.regexp('^197',timestamp):
                _extraction_dict['1-Last date'] = self.decode_reg(row[1])
             else:
                _extraction_dict['1-Last date'] = timestamp

          _extraction_list.append(_extraction_dict)

       download_dir_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["downloads_dir"] = download_dir_extraction_dict

       cursor.close()
       conn.close()

    ###############################################################################################################
    ### FORMS                                                                                                     #
    ###############################################################################################################

    def show_forms(self,dir):
       forms_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'formhistory.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","Forms database not found! Please, check file formhistory.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       cursor = conn.cursor()
       sqlite_query = "select fieldname,value,timesUsed,datetime(firstUsed/1000000,'unixepoch','localtime') as last,datetime(lastUsed/1000000,'unixepoch','localtime') from moz_formhistory"
       self.execute_query(cursor,sqlite_query,self.forms_filters)

       _extraction_list = []
       for row in cursor:
          _extraction_dict = {}
          _extraction_dict['0-Name'] = self.decode_reg(row[0])
          _extraction_dict['1-Value'] = self.decode_reg(row[1])
          _extraction_dict['2-Times Used'] = self.decode_reg(row[2])
          _extraction_dict['3-First Used'] = self.decode_reg(row[3])
          _extraction_dict['4-Last Used'] = self.decode_reg(row[4])
          _extraction_list.append(_extraction_dict)

       forms_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["forms"] = forms_extraction_dict

       cursor.close()
       conn.close()

    ###############################################################################################################
    ### HISTORY                                                                                                   #
    ###############################################################################################################

    def show_history(self,dir):
       history_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'places.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","History database not found! Please, check file places.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       cursor = conn.cursor()
       sqlite_query = "select datetime(last_visit_date/1000000,'unixepoch','localtime') as last, title, url, visit_count from moz_places"

       if self.args.is_frequency_ok == False:
          self.execute_query(cursor,sqlite_query,self.history_filters,"ORDER BY last COLLATE NOCASE")
       else:
          self.execute_query(cursor,sqlite_query,self.history_filters,"ORDER BY visit_count COLLATE NOCASE DESC")

       _extraction_list = []
       for row in cursor:
          _extraction_dict = {}
          _extraction_dict['0-Last Access'] = self.decode_reg(row[0])
          _extraction_dict['1-Title'] = self.decode_reg(row[1])
          _extraction_dict['2-URL'] = self.decode_reg(row[2])
          _extraction_dict['3-Frequency'] = self.decode_reg(row[3])
          _extraction_list.append(_extraction_dict)

       history_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["history"] = history_extraction_dict

       cursor.close()
       conn.close()

    ###############################################################################################################
    ### BOOKMARKS                                                                                                 #
    ###############################################################################################################

    def show_bookmarks(self,dir):
       bookmarks_extraction_dict = {}

       bbdd = self.get_path_by_os(dir, 'places.sqlite')

       if path.isfile(bbdd) == False:
          self.log("INFO","Bookmarks database not found! Please, check file places.sqlite")
          return

       conn = sqlite3.connect(bbdd)
       conn.text_factory = bytes

       if self.args.is_regexp_ok == True:
          conn.create_function("REGEXP", 2, self.regexp)

       cursor = conn.cursor()
       sqlite_query = 'select bm.title,pl.url,datetime(bm.dateAdded/1000000,"unixepoch","localtime") as create_date,datetime(bm.lastModified/1000000,"unixepoch","localtime") as last from moz_places pl,moz_bookmarks bm where pl.id = bm.id'
       self.execute_query(cursor,sqlite_query,self.bookmarks_filters)

       _extraction_list = []
       for row in cursor:
          _extraction_dict = {}
          _extraction_dict['0-Title'] = self.decode_reg(row[0])
          _extraction_dict['1-URL'] = self.decode_reg(row[1])
          _extraction_dict['2-Creation Time'] = self.decode_reg(row[2])
          _extraction_dict['3-Last Modified'] = self.decode_reg(row[3])
          _extraction_list.append(_extraction_dict)

       bookmarks_extraction_dict[bbdd] = _extraction_list

       self.total_extraction["bookmarks"] = bookmarks_extraction_dict

       cursor.close()
       conn.close()

    ###############################################################################################################
    ### KEY PINNING                                                                                           #
    ###############################################################################################################

    def show_key_pinning(self,dir):
        keypinning_extraction_dict = {}

        bbdd = self.get_path_by_os(dir, 'SiteSecurityServiceState.txt')

        if path.isfile(bbdd) == False:
            self.log("INFO","Key pinning database not found! Please, check file SiteSecurityServiceState.txt")
            return

        lines = open(bbdd).readlines()

        nl = 0
        _extraction_list = []
        for entry in lines:
            if lines[nl].split()[0].startswith("#") == False:
                _extraction_dict = {}

                entry_type = lines[nl].split()[0].split(':')[1]
                entry_last = lines[nl].split()[2]
                entry_data = lines[nl].split()[3]
                entry_expiry = entry_data.split(',')[0]
                entry_state = entry_data.split(',')[1]
                entry_subdomain = entry_data.split(',')[2]

                if entry_state == '0':
                    entry_state_desc = "- Disabled"
                elif entry_state == '1':
                    entry_state_desc = "- Enabled"
                elif entry_state == '2':
                    entry_state_desc = "- Overwriten"
                else:
                    entry_state_desc = ""

                condition = True
                if len(self.keypinning_filters) > 0:
                    for f in self.keypinning_filters:
                        if f[1] == 'type':
                            condition = (entry_type == f[2])
                if condition:
                    _extraction_dict["0-Site"] = lines[nl].split()[0].split(':')[0]
                    _extraction_dict["1-Type"] = entry_type
                    _extraction_dict["2-Access-Score"] = lines[nl].split()[1]
                    _extraction_dict["3-Last-Access"] = self.serial_date_to_string( int(entry_last) )
                    _extraction_dict["4-Expiry-Date"] = datetime.fromtimestamp(int(entry_expiry)/1000).strftime('%Y-%m-%d %H:%M:%S')
                    _extraction_dict["5-Security-Property-State"] = entry_state + " "+ entry_state_desc

                    if entry_subdomain == '1':
                        _extraction_dict["6-Include-Subdomains"] = "Yes"
                    else:
                        _extraction_dict["6-Include-Subdomains"] = "No"

                    if entry_type == 'HPKP':
                        pins = entry_data.split(',')[3].split('=')
                        pin_cnt = 1
                        for pin in pins:
                            if pin != "":
                                _extraction_dict["7-Pin-" + str(pin_cnt)] = pin
                                pin_cnt += 1

                    _extraction_list.append(_extraction_dict)
            nl = nl + 1

        keypinning_extraction_dict[bbdd] = _extraction_list

        self.total_extraction["keypinning"] = keypinning_extraction_dict


    ###############################################################################################################
    ### OFFLINE CACHE                                                                                             #
    ###############################################################################################################

    def show_cache(self,dir):
       # TODO: firefox-cache2-index-parser.py??
       offlinecache_extraction_dict = {}
       cache_found = False

       # [Default, Windows 7]
       cache_abs_sources = [self.get_path_by_os(dir,"index.sqlite","OfflineCache")]

       # For Windows 7 profile
       if dir.find("Roaming") > -1:
          cache_abs_sources.append(self.get_path_by_os(dir.replace("Roaming", "Local"),"index.sqlite","OfflineCache"))

       # For Linux profile
       if dir.find(".mozilla") > -1:
          cache_abs_sources.append(self.get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"index.sqlite","OfflineCache")) # Firefox
          cache_abs_sources.append(self.get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"index.sqlite","Cache")) # Seamonkey

       for d in cache_abs_sources:
          # Checking source file
          if path.isfile(d) == True:

             cache_found = True

             if d.endswith(".sqlite") == True:
                # SQLITE
                conn = sqlite3.connect(d)
                conn.text_factory = bytes
                if self.args.is_regexp_ok == True:
                   conn.create_function("REGEXP", 2, self.regexp)

                cursor = conn.cursor()
                sqlite_query = "select ClientID,key,DataSize,FetchCount,datetime(LastFetched/1000000,'unixepoch','localtime'),datetime(LastModified/1000000,'unixepoch','localtime') as last,datetime(ExpirationTime/1000000,'unixepoch','localtime') from moz_cache"
                self.execute_query(cursor,sqlite_query,self.cacheoff_filters)

                _extraction_list = []
                for row in cursor:
                   _extraction_dict = {}
                   _extraction_dict['0-Name'] = self.decode_reg(row[0])
                   _extraction_dict['1-Value'] = str(self.decode_reg(row[1]))
                   _extraction_dict['2-Last Modified'] = str(self.decode_reg(row[5]))
                   _extraction_list.append(_extraction_dict)

                offlinecache_extraction_dict[d] = _extraction_list

                cursor.close()
                conn.close()

       # Saving extraction to main extraction list
       self.total_extraction["offlinecache"] = offlinecache_extraction_dict
       if cache_found == False:
          self.log("INFO","Offline Cache database not found! Please check file OfflineCache/index.sqlite")

    ###############################################################################################################
    ### OFFLINE CACHE                                                                                             #
    ###############################################################################################################

    def show_cache_extract(self,dir, directory):
       # TODO: include firefox-cache2-file-parser.py
       offlinecache_ext_extraction_dict = {}
       cache_found = False

       try:
          import magic
       except:
          self.log("ERROR","Failed to import magic module!")
          return

       # [Default, Windows 7]
       cache_abs_sources = [self.get_path_by_os(dir,"OfflineCache")]

       # For Windows 7 profile
       if dir.find("Roaming") > -1:
          cache_abs_sources.append(self.get_path_by_os(dir.replace("Roaming", "Local"),"OfflineCache"))

       # For Linux profile
       if dir.find(".mozilla") > -1:
          cache_abs_sources.append(self.get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"OfflineCache")) # Firefox
          cache_abs_sources.append(self.get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"Cache")) # Seamonkey

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
                   self.log("WARNING","Failed to remove index.sqlite from "+directory)

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
                   self.log("WARNING","Failed to remove index.sqlite from "+directory)

             offlinecache_ext_extraction_dict[d] = _extraction_list

       self.total_extraction["offlinecache_extract"] = offlinecache_ext_extraction_dict

    ###############################################################################################################
    ### THUMBNAILS                                                                                                #
    ###############################################################################################################

    def show_thumbnails(self,dir, directory = None):
       thumbnails_found = False
       thumbnails_extraction_dict = {}

       # [Default, Windows 7]
       thumbnails_sources = [self.get_path_by_os(dir,"thumbnails")]

       # For Windows 7 profile
       if dir.find("Roaming") > -1:
          thumbnails_sources.append(self.get_path_by_os(dir.replace("Roaming", "Local"),"thumbnails"))

       # For Linux profile
       if dir.find(".mozilla") > -1:
          thumbnails_sources.append(self.get_path_by_os(dir.replace(".mozilla", ".cache/mozilla"),"thumbnails"))

       for d in thumbnails_sources:
          if path.exists(d):
             thumbnails_found = True

             _extraction_list = []
             for dirname, dirnames, filenames in walk(d):
                for filename in filenames:
                   _extraction_dict = {}
                   if directory == None:
                        nfile = self.get_path_by_os(dirname, filename)
                        _extraction_dict['0-File'] = nfile
                   else:
                        nfile = self.get_path_by_os(dirname, filename)
                        if not path.exists(directory):
                           try:
                               makedirs(directory)
                           except:
                               self.log('ERROR', 'Can\'t create thumbnails folder: ' + directory)
                               return
                        try:
                            shutil.copy2(nfile, directory)
                        except:
                            self.log('ERROR', 'Can\'t copy thumbnail: ' + nfile)
                        _extraction_dict['0-File'] = "Copy "+nfile+" to "+directory
                   if len(_extraction_dict) > 0:
                      _extraction_list.append(_extraction_dict)

             thumbnails_extraction_dict[d] = _extraction_list

       # Saving extraction to main extraction list
       self.total_extraction["thumbnails"] = thumbnails_extraction_dict
       if thumbnails_found == False:
          self.log("INFO","No thumbnails found!")

    ###############################################################################################################
    ### CERT OVERRIDE                                                                                             #
    ###############################################################################################################

    def show_cert_override(self,dir):
        cert_override_extraction_dict = {}

        bbdd = self.get_path_by_os(dir,"cert_override.txt")

        if path.isfile(bbdd):
            lines = open(bbdd).readlines()

            nl = 0
            _extraction_list = []
            for cert in lines:
                if lines[nl].split()[0].startswith("#") == False:
                    _extraction_dict = {}
                    _extraction_dict["0-Site"] = lines[nl].split()[0]
                    _extraction_dict["1-Hash Algorithm"] = lines[nl].split()[1]
                    _extraction_dict["2-Data"] = lines[nl].split()[2]
                    _extraction_list.append(_extraction_dict)
                nl = nl + 1

            cert_override_extraction_dict[bbdd] = _extraction_list
        else:
            self.log("INFO","Cert override file not found! Please, check file cert_override.txt")

        self.total_extraction["cert_override"] = cert_override_extraction_dict

    ###############################################################################################################
    ### WATCH                                                                                                     #
    ###############################################################################################################

    def show_watch(self,dir,watch_text = 1):
       sw_py_path = self.PYTHON3_PATH
       print(sys.platform)
       if sys.platform.startswith('win'):
           self.log("CRITICAL","--Watch option not supported on Windows!")
           exit(2)
       elif sys.platform.endswith('win'):
           self.log("CRITICAL","--Watch option not supported on MacOS!")
           exit(2)
       elif sw_py_path == '':
          sw_py_path = self.get_user_value('Python 3 path (Press Enter for default - ' + self.PYTHON3_DEF + '): ').strip() # Python 3.x path (NO Windows). Example: /usr/bin/python3.4
          if sw_py_path == '':
            sw_py_path = self.PYTHON3_DEF

       if not path.isfile(sw_py_path):
           self.log("CRITICAL","Python path '" + sw_py_path + "' is not a valid file path.")
           sys.exit(1)

       elif watch_text == 1:
          cmd = ["watch", "-n", "4",sw_py_path, path.abspath(__file__), dir, "--Live"]
          call(cmd)
       else:
          cmd = ["watch", "-n", "4",sw_py_path, path.abspath(__file__), dir, "--Live", "| grep --group-separator '' -A 2 -B 2 -i", "'"+watch_text+"'" ]
          call(cmd)

    def get_param_argurment(arg, num):
       rparam = ""
       try:
          rparam = sys.argv[num]
          return rparam
       except:
          self.log("CRITICAL","Missing argument for parameter " + arg)
          self.show_help()

    ###############################################################################################################
    ### SESSION                                                                                                   #
    ###############################################################################################################

    def show_session(self,dir):
       session_extraction_dict = {}
       session_found = False
       session_sources = ["sessionstore.js","sessionstore.json","sessionstore.bak"]
       # Checking for more backup session sources (I)
       for s in os.listdir(dir):
          if not s.startswith('.'):
              # Adding new source
              if path.isfile(path.join(dir,s)) and s.startswith("sessionstore") and s not in session_sources:
                 session_sources.append(s)

       # Checking for more backup session sources (II)
       session_folder = path.join(dir,"sessionstore-backups")
       if path.isdir(session_folder):
          for s in os.listdir(session_folder):
             if not s.startswith('.'):
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
             jdata = self.getJSON(f)
             f.close()

             _extraction_list = self.extract_data_session(jdata, a)

             session_extraction_dict[bbdd] = _extraction_list

       # Saving extraction to main extraction list
       self.total_extraction["session"] = session_extraction_dict
       if not session_found:
          self.log("WARNING","No session info found!")

    ###############################################################################################################
    ### DATA SESSION                                                                                              #
    ###############################################################################################################

    def extract_data_session(self,jdata,source):
        _extraction_list = []
        try:
          nodes = [ "windows", "_closedWindows" ];

          for node in nodes:
            data = jdata.get(node)
            if len(data) > 0:
              for win in data:
                 for tab in win.get("tabs"):
                    _extraction_dict = {}
                    _extraction_dict["01-Last update"] = str(time.ctime(jdata["session"]["lastUpdate"]/1000.0))
                    _extraction_dict["02-Type"] = node

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
                      _extraction_dict["07-Last update"] = str(time.ctime(jdata["session"]["lastUpdate"]/1000.0))
                      _extraction_dict["08-Type"] = "_closedTabs"
                      _extraction_dict["09-Title"] = closed_tab.get("title")
                      _extraction_dict["10-URL"] = closed_tab.get("url")
                      _extraction_list.append(_extraction_dict)

        except:
           e = str(sys.exc_info()[0])
           self.log("ERROR","Sessions database: Can't process file " + source + ": " + e )

        return _extraction_list

    ###############################################################################################################
    ### DATA SESSION WATCH                                                                                        #
    ###############################################################################################################

    def extract_data_session_watch (self,dir):
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
                jdata = self.getJSON(f)
                f.close()
                if jdata["session"]["lastUpdate"] > higher_date:
                    higher_date=jdata["session"]["lastUpdate"]
                    higher_source=bbdd

        # Showing last updated session data
        if session_watch_found == True:
            f = open(higher_source)
            jdata = self.getJSON(f)
            f.close()
            count = 0
            countform = 0
            try:
                for win in jdata.get("windows"):
                  for tab in win.get("tabs"):
                    if tab.get("index") is not None:
                       i = tab.get("index") - 1
                    print ("\nTitle: %s" % tab.get("entries")[i].get("title"))
                    print ("URL: %s" % tab.get("entries")[i].get("url"))
                    #print(str(tab.get("entries")[i]))
                    if tab.get("entries")[i].get("formdata") is not None and str(tab.get("entries")[i].get("formdata")) != "{}" :
                       countform = countform + 1
                       if str(tab.get("entries")[i].get("formdata").get("xpath")) == "{}" and str(tab.get("entries")[i].get("formdata").get("id")) != "{}":
                          print ("Form: %s\n" % tab.get("entries")[i].get("formdata").get("id"))
                       elif str(tab.get("entries")[i].get("formdata").get("xpath")) != "{}" and str(tab.get("entries")[i].get("formdata").get("id")) == "{}":
                          print ("Form: %s\n" % tab.get("entries")[i].get("formdata").get("xpath"))
                       else:
                          print ("Form: %s\n" % tab.get("entries")[i].get("formdata"))
                    count = count + 1
            except:
                e = str(sys.exc_info()[0])
                self.log("ERROR","Can't process file " + higher_source + ": " + e )

            print ("\n[INFO] Last update: %s " % time.ctime(jdata["session"]["lastUpdate"]/1000.0))
            print ("[INFO] Number of windows / tabs in use: %s" % count)
            print ("[INFO] Number of webs with forms in use: %s" % countform)
            print ("[INFO] Exit: Ctrl + C")

    ###############################################################################################################
    ### HELP                                                                                                      #
    ###############################################################################################################

    def show_full_help(self):
        logo = """
                ./oyhhyo/-`  `..`
            :smMNdhyyyhdNMNNmmmNh-
         .omMNhsoshddyoohhhdmNMMMN`
       :hMMMNysoydNNoosdhhNdhdMMNMy:
    `+mMMMMMMhooooshoymNdsshsmmhmhhmNhs/.
   .+//smMMMdooooosyhdddhohmhsyysoooosydmNds-
    .yNNMMNddoooomoooooooodsNMmyoooooooooohMM-
  `+s/omMMdosooosMyoooooooNdMMMMMmyoooooooNmM/
    +yoyMMMsooooyMNdoooooohMMNNMMMmNmdhyssssMy
   ``-dNhMMMyooosdysshyooooshdyyhmNNMNmNMmNNN.
    `+--mNMMMhoooossoodNdhyyhddmNmhyyyhNMNmm:
      -/omNMNoooooooooosmMMMNh+::/+syddy/`
       `-hMMNmhsoooooosmmMN/
         +mNdysoooooohdydM-
           /hmhsoooooyyNMh            Dumpzilla Forensic Tool
             `/shddhhmNMM-               www.dumpzilla.org
                  `-:////.                   %s

Usage:

 """  % (self.VERSION)
        print(logo + self.get_help_msg())

    def show_help(self):
        print('Usage: ' + self.get_help_msg())

    def get_help_msg(self):
       return format("""python dumpzilla.py PROFILE_DIR [OPTIONS]

Options:

 --Addons
 --Search
 --Bookmarks [-bm_create_range <start> <end>][-bm_last_range <start> <end>]
 --Certoverride
 --Cookies [-showdom] [-domain <string>] [-name <string>] [-hostcookie <string>] [-access <date>] [-create <date>]
           [-secure <0|1>] [-httponly <0|1>] [-last_range <start> <end>] [-create_range <start> <end>]
 --Downloads [-range <start> <end>]
 --Export <directory> (export data as json)
 --Forms [-value <string>] [-forms_range <start> <end>]
 --Help (shows this help message and exit)
 --History [-url <string>] [-title <string>] [-date <date>] [-history_range <start> <end>] [-frequency]
 --Keypinning [-entry_type <HPKP|HSTS>]
 --OfflineCache [-cache_range <start> <end> -extract <directory>]
 --Preferences
 --Passwords
 --Permissions [-host <string>] [-modif <date>] [-modif_range <start> <end>]
 --RegExp (use Regular Expresions for string type filters instead of Wildcards)
 --Session
 --Summary (no data extraction, only summary report)
 --Thumbnails [-extract_thumb <directory>]
 --Verbosity (DEBUG|INFO|WARNING|ERROR|CRITICAL)
 --Watch [-text <string>] (shows in daemon mode the URLs and text form in real time; Unix only)

Wildcards (without RegExp option):

 '%%'  Any string of any length (including zero length)
 '_'  Single character
 '\\'  Escape character

Regular Expresions: https://docs.python.org/3/library/re.html

Date syntax:

 YYYY-MM-DD hh:mi:ss (wildcards allowed)

Profile location:

 WinXP profile -> 'C:\\Documents and Settings\\%%USERNAME%%\\Application Data\\Mozilla\\Firefox\\Profiles\\xxxx.default'
 Win7 profile  -> 'C:\\Users\\%%USERNAME%%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xxxx.default'
 MacOS profile -> '/Users/$USER/Library/Application\ Support/Firefox/Profiles/xxxx.default'
 Unix profile  -> '/home/$USER/.mozilla/firefox/xxxx.default'
   """)

    ###############################################################################################################
    ##                                                                                                            #
    ### MAIN                                                                                                      #
    ##                                                                                                            #
    ###############################################################################################################
    def __init__(self, argv):

        # Log Levels
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.WARNING)
        self.verbosity_level = "WARNING";
        self.log('DEBUG', 'Initialization')

        # Argparse init
        parser = argparse.ArgumentParser(usage=self.get_help_msg(), add_help=False)
        parser.add_argument('PROFILE_DIR')
        is_all_ok = False
        if len(argv) == 2:
            is_all_ok = True

        ###############
        ### ARG PARSER
        ###############
        parser.add_argument("--RegExp", action="store_true", default=False,  dest='is_regexp_ok',
                        help="(uses Regular Expresions for string type filters instead of Wildcards)")
        parser.add_argument("--Summary", action="store_true", default=False,  dest='is_summary_ok',
                        help="(only shows debug messages and summary report)")
        #...........................................
        #... Help message
        #...........................................
        parser.add_argument("--Help", action="store_true", default=False, dest='is_help_ok',
                        help="Shows this help message and exit")
        #...........................................
        #... Cookie parameters
        #...........................................
        parser.add_argument("--Cookies", action="store_true", default=is_all_ok,  dest='is_cookie_ok',
              help="--Cookies [-showdom -domain <string> -name <string> -hostcookie <string> -access <date> -create <date> -secure <0/1> -httponly <0/1> -last_range <start> <end> -create_range <start> <end>]")
        parser.add_argument("-showdom", action="store_true",
                  help="[-showdom]")
        parser.add_argument("-domain", nargs=1,
                  help="[-domain <string>]")
        parser.add_argument("-name", nargs=1,
                  help="[-name <string>]")
        parser.add_argument("-hostcookie", nargs=1,
                  help="[-hostcookie <string>]")
        parser.add_argument("-access", nargs=1,
                  help="[-access <date>]")
        parser.add_argument("-create", nargs=1,
                  help="[-create <date>]")
        parser.add_argument("-secure", nargs=1, type=int,
                  help="[-secure <0/1>]")
        parser.add_argument("-httponly", nargs=1, type=int,
                  help="[-httponly <0/1>]")
        parser.add_argument("-last_range", nargs='+',
                  help="[-last_range <start> <end>]")
        parser.add_argument("-create_range", nargs='+',
                  help="[-create_range <start> <end>]")
        #...........................................
        #... Permissions parameters
        #...........................................
        parser.add_argument("--Permissions", action="store_true", default=is_all_ok,  dest='is_permissions_ok',
                  help="--Permissions [-host <string> -type <string>  -modif <date> -modif_range <start> <end>]")
        parser.add_argument("-host", nargs=1,
                  help="[-host <string>")
        parser.add_argument("-type", nargs=1,
                  help="[-type <string>]")
        parser.add_argument("-modif", nargs=1,
                  help="[-modif <date>")
        parser.add_argument("-modif_range", nargs='+',
                help="[-modif_range <start> <end>]")
        #...........................................
        #... Preferences parameters
        #...........................................
        parser.add_argument("--Preferences", action="store_true", default=is_all_ok,  dest='is_preferences_ok',
                  help="")
        #...........................................
        #... Addons parameters
        #...........................................
        parser.add_argument("--Addons", action="store_true", default=is_all_ok,  dest='is_addon_ok',
                  help="")
        #...........................................
        #... Search engines parameters
        #...........................................
        parser.add_argument("--Search", action="store_true", default=is_all_ok,  dest='is_search_ok',
                  help="")
        #...........................................
        #... Downloads parameters
        #...........................................
        parser.add_argument("--Downloads", action="store_true", default=is_all_ok,  dest='is_downloads_ok',
                  help="--Downloads [-range <start> <end>]")
        parser.add_argument("-range", nargs=1,
                  help="[-range <start> <end>]")
        #...........................................
        #... Forms parameters
        #...........................................
        parser.add_argument("--Forms", action="store_true", default=is_all_ok,  dest='is_forms_ok',
                  help="--Forms [-value <string> -forms_range <start> <end>]")
        parser.add_argument("-value", nargs=1,
                  help="[-value <string>]")
        parser.add_argument("-forms_range", nargs='+',
                  help="[-forms_range <start> <end>]")
        #...........................................
        #... History parameters
        #...........................................
        parser.add_argument("--History", action="store_true", default=is_all_ok,  dest='is_history_ok',
                  help="--History [-url <string> -title <string> -date <date> -history_range <start> <end> -frequency]")
        parser.add_argument("-url", nargs=1,
                  help="[-url <string>]")
        parser.add_argument("-frequency", action="store_true", default=is_all_ok,  dest='is_frequency_ok',
                  help="[-frequency]")
        parser.add_argument("-title", nargs=1,
                  help="[-title <string>]")
        parser.add_argument("-date", nargs=1,
                  help="[-date <date>]")
        parser.add_argument("-history_range", nargs='+',
                  help="[-history_range <start> <end>]")
        #...........................................
        #... Bookmarks parameters
        #...........................................
        parser.add_argument("--Bookmarks", action="store_true", default=is_all_ok,  dest='is_bookmarks_ok',
                  help="--Bookmarks [-bm_create_range <start> <end>][-bm_last_range <start> <end>]")
        parser.add_argument("-bm_create_range", nargs='+',
                  help="[-bm_create_range <start> <end>]")
        parser.add_argument("-bm_last_range", nargs='+',
                  help="[-bm_last_range <start> <end>]")
        #...........................................
        #... Passwords parameters
        #...........................................
        parser.add_argument("--Passwords", action="store_true", default=is_all_ok,  dest='is_passwords_ok',
                  help="(decode only in Unix)")
        #...........................................
        #... Cache parameters
        #...........................................
        parser.add_argument("--OfflineCache", action="store_true", default=is_all_ok,  dest='is_cacheoff_ok',
                  help="--OfflineCache [-cache_range <start> <end> -extract <directory>]")
        parser.add_argument("-cache_range", nargs='+',
                  help="[-cache_range <start> <end>]")
        parser.add_argument("-extract", nargs=1,
                  help="[-extract <directory>]")
        #...........................................
        #... Key pinning parameters
        #...........................................
        parser.add_argument("--Keypinning", action="store_true", default=is_all_ok,  dest='is_keypinning_ok',
                  help="--Keypinning [-entry_type <HPKP|HSTS>]")
        parser.add_argument("-entry_type", nargs=1, type=str,
                  help="[-entry_type <HPKP/HSTS>]")
        #...........................................
        #... Certoverride parameters
        #...........................................
        parser.add_argument("--Certoverride", action="store_true", default=is_all_ok,  dest='is_cert_ok',
                  help="")
        #...........................................
        #... Thumbnails parameters
        #...........................................
        parser.add_argument("--Thumbnails", action="store_true", default=False,  dest='is_thump_ok',
                  help="--Thumbnails [-extract_thumb <directory>]")
        parser.add_argument("-extract_thumb", nargs=1,
                  help="[-extract_thumb <directory>]")
        #...........................................
        #... Session parameters
        #...........................................
        parser.add_argument("--Session", action="store_true", default=is_all_ok,  dest='is_session_ok', help="")
        #...........................................
        #... Export parameters
        #...........................................
        parser.add_argument("--Export" , nargs=1,
                  help="[--Export <directory>]")
        #...........................................
        #... Verbosity parameters
        #...........................................
        parser.add_argument("--Verbosity" , nargs=1,
                  help="[--Verbosity LEVEL]")
        #...........................................
        #... Live session parameters (watch)
        #...........................................
        parser.add_argument("--Live", action="store_true", default=False,  dest='is_live_ok', help="")
        #...........................................
        #... Watch parameters
        #...........................................
        parser.add_argument("--Watch", action="store_true", default=False,  dest='is_watch_ok',
                  help="--Watch  [-text <string>] (Shows in daemon mode the URLs and text form in real time)")
        parser.add_argument("-text", nargs=1,
                  help="[-text <string>] (-text Option allow filter, supports all grep Wildcards. Exit: Ctrl + C. only Unix)")

        self.args = parser.parse_args()

        #...........................................
        #...........................................
        dir = format(self.args.PROFILE_DIR)
        self.log('DEBUG', 'dir: '+ dir)

        if path.isdir(dir) and len(argv) >= 2:

            dir = path.abspath(dir)

            if self.args.is_help_ok:
                self.show_full_help();
                sys.exit(0);

            if self.args.is_cookie_ok:
                 if self.args.showdom:
                     self.is_dom_ok = True
                 if self.args.domain:
                     cookie_domain = format(self.args.domain[0])
                     self.domain_filters.append(["string","scope",cookie_domain])
                 if self.args.name:
                     cookie_name = format(self.args.name[0])
                     self.cookie_filters.append(["string","name",cookie_name])
                 if self.args.hostcookie:
                     cookie_host = format(self.args.hostcookie[0])
                     self.cookie_filters.append(["string","host",cookie_host])
                 if self.args.access:
                     cookie_access_date = self.validate_date(format(self.args.access[0]))
                     self.cookie_filters.append(["date","last",cookie_access_date])
                 if self.args.create:
                     cookie_create_date = self.validate_date(format(self.args.create[0]))
                     self.cookie_filters.append(["date","creat",cookie_create_date])
                 if self.args.secure:
                     cookie_secure = format(self.args.secure[0])
                     self.cookie_filters.append(["number","isSecure",cookie_secure])
                 if self.args.httponly:
                     cookie_httponly = format(self.args.httponly[0])
                     self.cookie_filters.append(["number","isHttpOnly",cookie_httponly])
                 if self.args.last_range:
                     cookie_access_range1 = self.validate_date(format(self.args.last_range[0]))
                     try:
                         cookie_access_range2 = self.validate_date(format(self.args.last_range[1]))
                     except IndexError:
                         cookie_access_range2 = self.validate_date(format('9999-12-31'))
                     self.cookie_filters.append(["range","last",[cookie_access_range1,cookie_access_range2]])
                 if self.args.create_range:
                     cookie_create_range1 = self.validate_date(format(self.args.create_range[0]))
                     try:
                         cookie_create_range2 = self.validate_date(format(self.args.create_range[1]))
                     except IndexError:
                         cookie_create_range2 = self.validate_date(format('9999-12-31'))
                     self.cookie_filters.append(["range","creat",[cookie_create_range1,cookie_create_range2]])


            if self.args.is_permissions_ok:
                 if self.args.host:
                     permissions_host = format(self.args.host[0])
                     self.permissions_filters.append(["string","host",permissions_host])
                 if self.args.type:
                     permissions_type = format(self.args.type[0])
                     self.permissions_filters.append(["string","type",permissions_type])
                 if self.args.modif:
                     permissions_modif_date = self.validate_date(format(self.args.modif[0]))
                     self.permissions_filters.append(["date","modif",permissions_modif_date])
                 if self.args.modif_range:
                     permissions_modif_range1 = self.validate_date(format(self.args.modif_range[0]))
                     try:
                         permissions_modif_range2 = self.validate_date(format(self.args.modif_range[1]))
                     except IndexError:
                         permissions_modif_range2 = self.validate_date(format('9999-12-31'))
                     self.permissions_filters.append(["range","modif",[permissions_modif_range1,permissions_modif_range2]])


            if self.args.is_downloads_ok:
                 if self.args.range:
                     downloads_range1 = self.validate_date(format(self.args.range[0]))
                     try:
                         downloads_range2 = self.validate_date(format(self.args.range[1]))
                     except IndexError:
                         downloads_range2 = self.validate_date(format('9999-12-31'))
                     self.downloads_filters.append(["range","start",[downloads_range1,downloads_range2]])
                     self.downloads_history_filters.append(["range","modified",[downloads_range1,downloads_range2]])


            if self.args.is_forms_ok:
                 if self.args.value:
                     forms_value = format(self.args.value[0])
                     self.forms_filters.append(["string","value",forms_value])
                 if self.args.forms_range:
                     forms_range1 = self.validate_date(format(self.args.forms_range[0]))
                     try:
                         forms_range2 = self.validate_date(format(self.args.forms_range[1]))
                     except IndexError:
                         forms_range2 = self.validate_date(format('9999-12-31'))
                     self.forms_filters.append(["range","last",[forms_range1,forms_range2]])


            if self.args.is_history_ok:
                 if self.args.url:
                     history_url =  format(self.args.url[0])
                     self.history_filters.append(["string","url",history_url])
                 if self.args.title:
                     history_title = format(self.args.title[0])
                     self.history_filters.append(["string","title",history_title])
                 if self.args.date:
                     history_date = self.validate_date(format(self.args.date[0]))
                     self.history_filters.append(["date","last",history_date])
                 if self.args.history_range:
                     history_range1 = self.validate_date(format(self.args.history_range[0]))
                     try:
                         history_range2 = self.validate_date(format(self.args.history_range[1]))
                     except IndexError:
                         history_range2 = self.validate_date(format('9999-12-31'))
                     self.history_filters.append(["range","last",[history_range1,history_range2]])


            if self.args.is_bookmarks_ok:
                if self.args.bm_last_range:
                    bm_last_range1 = self.validate_date(format(self.args.bm_last_range[0]))
                    try:
                        bm_last_range2 = self.validate_date(format(self.args.bm_last_range[1]))
                    except IndexError:
                        bm_last_range2 = self.validate_date(format('9999-12-31'))
                    self.bookmarks_filters.append(["range","last",[bm_last_range1,bm_last_range2]])
                if self.args.bm_create_range:
                    bm_create_range1 = self.validate_date(format(self.args.bm_create_range[0]))
                    try:
                        bm_create_range2 = self.validate_date(format(self.args.bm_create_range[1]))
                    except IndexError:
                        bm_create_range2 = self.validate_date(format('9999-12-31'))
                    self.bookmarks_filters.append(["range","create_date",[bm_create_range1,bm_create_range2]])


            if self.args.is_cacheoff_ok:
                 if self.args.cache_range:
                     cacheoff_range1 = self.validate_date(format(self.args.cache_range[0]))
                     try:
                         cacheoff_range2 = self.validate_date(format(self.args.cache_range[1]))
                     except IndexError:
                         cacheoff_range2 = self.validate_date(format('9999-12-31'))
                     self.cacheoff_filters.append(["range","last",[cacheoff_range1,cacheoff_range2]])
                 if self.args.extract:
                     self.is_cacheoff_extract_ok = True
                     cacheoff_directory = format(self.args.extract[0])

            if self.args.is_keypinning_ok:
                 if self.args.entry_type:
                     keypinning_type = format(self.args.entry_type[0])
                     self.keypinning_filters.append(["string","type",keypinning_type])

            if self.args.is_thump_ok:
                 if self.args.extract_thumb:
                     thumb_directory = format(self.args.extract_thumb[0])
                 else:
                     thumb_directory = None

            if self.args.Verbosity:
                level = self.args.Verbosity[0];
                self.verbosity_level = level;
                if level == 'DEBUG':
                    self.logger.setLevel(logging.DEBUG)
                elif level == 'INFO':
                    self.logger.setLevel(logging.INFO)
                elif level == 'WARNING':
                    self.logger.setLevel(logging.WARNING)
                elif level == 'ERROR':
                    self.logger.setLevel(logging.ERROR)
                elif level == 'CRITICAL':
                    self.logger.setLevel(logging.CRITICAL)
                else:
                    self.verbosity_level = 'WARNING';

            if self.args.is_watch_ok:
                 if self.args.text:
                     self.watch_text = format(self.args.text[0])


            if len(vars(self.args)) == 0:
                self.show_help()
                sys.exit()

            ###############
            ### ACTIONS
            ###############
            self.show_info_header(dir)

            if self.args.is_regexp_ok:
                self.query_str_f = "REGEXP"
                self.query_str_a = ""
                self.log("INFO", "Using Regular Expression mode for string type filters")
            else:
                self.query_str_f = "like"
                self.query_str_a = "escape '\\'"

            ### TODO: Find another way to make it  work without anyexec var
            anyexec = False
            if self.args.is_cookie_ok:
                self.show_cookies(dir)
                anyexec = True
            if self.args.is_permissions_ok:
                self.show_permissions(dir)
                anyexec = True
            if self.args.is_preferences_ok:
                self.show_preferences(dir)
                anyexec = True
            if self.args.is_addon_ok:
                self.show_addons(dir)
                self.show_extensions(dir)
                self.show_info_addons(dir)
            if self.args.is_search_ok:
                self.show_search_engines(dir)
                anyexec = True
            if self.args.is_downloads_ok:
                self.show_downloads(dir)
                self.show_downloads_history(dir)
                self.show_downloadsdir(dir)
                anyexec = True
            if self.args.is_forms_ok:
                self.show_forms(dir)
                anyexec = True
            if self.args.is_history_ok:
                self.show_history(dir)
                anyexec = True
            if self.args.is_bookmarks_ok:
                self.show_bookmarks(dir)
                anyexec = True
            if self.args.is_passwords_ok:
                self.show_passwords(dir)
                anyexec = True
            if self.args.is_cacheoff_ok:
                self.show_cache(dir)
                anyexec = True
            if self.args.is_keypinning_ok:
                self.show_key_pinning(dir)
                anyexec = True
            if self.args.is_cacheoff_ok and self.is_cacheoff_extract_ok:
                self.show_cache_extract(dir, cacheoff_directory)
                anyexec = True
            if self.args.is_cert_ok:
                self.show_cert_override(dir)
                anyexec = True
            if self.args.is_thump_ok:
                self.show_thumbnails(dir, thumb_directory)
                anyexec = True
            if self.args.is_session_ok:
                self.show_session(dir)
                anyexec = True
            if self.args.is_live_ok:
                self.extract_data_session_watch(dir)
                anyexec = True
            if self.args.is_watch_ok:
                self.show_watch(dir,self.watch_text)
                anyexec = True
            if not anyexec:
                if (len(argv) == 2) or (len(argv) > 2 and (self.args.is_summary_ok or self.args.Export)):
                    self.All_execute(dir)

            ###############
            ### SUMMARY
            ###############
            if not self.args.is_live_ok:

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
                   "keypinning"          : "Public Key Pinning   ",
                   "offlinecache"        : "OfflineCache Html5   ",
                   "offlinecache_extract": "OfflineCache Extract ",
                   "thumbnails"          : "Thumbnails images    ",
                   "cert_override"       : "Cert override        ",
                   "session"             : "Sessions             "
                }
                extraction_id = os.path.basename(dir) + '.' + time.strftime("%Y%m%d%H%M%S")
                export_folder = None

                if self.args.Export:
                    export_folder = self.args.Export[0] + '/' + extraction_id + '/'
                    self.log("INFO","Output folder: "+ self.args.Export[0])
                    if not os.path.exists(export_folder):
                        self.log("INFO","Creating folder: " + export_folder)
                        try:
                            makedirs(export_folder)
                        except:
                            self.log('CRITICAL', 'Can\'t create folder: ' + export_folder)
                            sys.exit(2)

                self.log('DEBUG', 'total_extraction length: ' + str(len(self.total_extraction.keys())))
                info_headers = sorted(self.total_extraction.keys())
                summary = {}
                for header in info_headers:
                    self.log('DEBUG', 'header: ' + header)
                    sources = self.total_extraction[header].keys()

                    if self.args.Export:
                        outputFilename = header + '.json';
                        for source in sources:
                            self.log("INFO","Saving " + os.path.basename(source) + " data to "+  outputFilename)
                        with open(export_folder + outputFilename, 'w') as fp:
                            json.dump(self.total_extraction[header], fp)
                        self.export_sha256(export_folder, header, sources);

                    for source in sources:

                        # INFO HEADER BY SOURCE
                        if not self.args.is_summary_ok and  not self.args.Export:
                            if path.isfile(source):
                                self.show_title(titles[header], source)
                            else:
                                self.show_title(titles[header])

                        if header in summary.keys():
                            summary[header] = summary[header] + len(self.total_extraction[header][source])
                        else:
                            summary[header] = len(self.total_extraction[header][source])

                        if not self.args.Export and  not self.args.is_summary_ok:
                            if summary[header] > 0:
                                for i in self.total_extraction[header][source]:
                                    tags = sorted(i.keys())
                                    for tag in tags:
                                        if i[tag]:
                                            try:
                                                print(tag.split('-',1)[1] + ": " + str(i[tag]))
                                            except UnicodeEncodeError:
                                                print(tag.split('-',1)[1] + ": " + str(i[tag].encode('utf8')))
                                        else:
                                            print(tag.split('-',1)[1] + ": ")
                                    print("")
                            else:
                                print("No data found!")
                                summary[header] = 0
                self.log("DEBUG", "summary length: " + str(len(summary.keys())))
                info_headers = sorted(summary.keys())

                if len(info_headers) == 0 and len(argv) == 2:
                     self.show_title("Total Information")
                     print("No data found!")
                elif len(info_headers) == 0 and len(argv) < 2:
                     self.log("CRITICAL","Missing argument!")
                     if self.args.Export and export_folder:
                        os.rmdir(export_folder)
                     self.show_help()
                else:
                     self.show_title("Total Information")
                     if len(info_headers) == 0:
                        print("No data found!")
                     else:
                        for header in info_headers:
                            print("Total " + titles[header] + ": " + str(summary[header]))
                print("")
        else:
            self.log("CRITICAL","Failed to read profile directory: " + dir)
            self.show_help()
            sys.exit()

if __name__ == '__main__':
    app = Dumpzilla(sys.argv)

# Site: www.dumpzilla.org
# Authors: Busindre ( busilezas[@]gmail.com )
#                   OsamaNehme ( onehdev[@]gmail.com )
