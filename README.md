# dumpzilla (Forensic Tool)

**Dumpzilla official site**: [www.dumpzilla.org] (http://www.dumpzilla.org "Mozilla browser forensic tool")

**Manual**: [Español] (http://dumpzilla.org/Manual_dumpzilla_es.txt "Manual en español de dumpzilla") / [English] (http://dumpzilla.org/Manual_dumpzilla_en.txt "Dumpzilla english Manual")

**SO**: Unix / Win

**Screenshots**: [Dummpzilla] (http://dumpzilla.org/Screenshots/screenshots.html "dumpzilla screenshots")

Dumpzilla application is developed in Python 3.x and has as purpose extract all forensic interesting information of Firefox, Iceweasel and Seamonkey browsers to be analyzed. Due to its Python 3.x developement, might not work properly in old Python versions, mainly with certain characters. Works under Unix and Windows 32/64 bits systems. Works in command line interface, so information dumps could be redirected by pipes with tools such as grep, awk, cut, sed... Dumpzilla allows to visualize following sections, search customization and extract certain content.

 - Cookies + DOM Storage (HTML 5).
 - User preferences (Domain permissions, Proxy settings...).
 - Downloads.
 - Web forms (Searches, emails, comments..).
 - Historial.
 - Bookmarks.
 - Cache HTML5 Visualization / Extraction (Offline cache).
 - visited sites "thumbnails" Visualization / Extraction .
 - Addons / Extensions and used paths or urls.
 - Browser saved passwords.
 - SSL Certificates added as a exception.
 - Session data (Webs, reference URLs and text used in forms).
 - Visualize live user surfing, Url used in each tab / window and use of forms. 

Dumpzilla will show SHA256 hash of each file to extract the information and finally a summary with totals.
Sections which date filter is not possible: DOM Storage, Permissions / Preferences, Addons, Extensions, Passwords/Exceptions, Thumbnails and Session. 
