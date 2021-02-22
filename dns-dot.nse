local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local strbuf = require "strbuf"

description = [[
Performs a DOT lookup against the target site
variables: t = <target of dns query>
           q = <dns query type>
]]

---
-- @usage
-- nmap <target> --script=doh <DNS server> --script-args query=<query type>,target=<DNS lookup value>
--
-- @output
-- 853/tcp open   https
-- | results of query
--
---

author = {"Rob VandenBrink","rob@coherentsecurity.com"}
license = "Creative Commons https://creativecommons.org/licenses/by-nc-sa/4.0/"
categories = { "discovery" }

-- check to ensure that port is ssl enabled
portrule = shortport.ssl


action = function(host,port)
     -- collect the command line arguments
     local query = stdnse.get_script_args('query')
     local target = stdnse.get_script_args('target')

     -- check that both arg values are present and non-zero
     if(query==nil or query == '') then
         return "DNS query operation is not defined (A,AAAA,MX,PTR,TXT etc)"
     end
     if(target==nil or target=='') then
         return "DNS target is not defined (host, domain, IP address etc)"
     end

     -- ensure that kdig is installed, error out and exit if not
     local f=io.open("/usr/bin/kdig","r") 
     if f~= nil then
        io.close(f)
     else
        print("SCRIPT ERROR: prerequisite kdig is not installed")
        return false
     end

     -- construct the query string, the path in the DOH HTTPS GET
     local tmpfile = os.tmpname()
     local qstring = '/usr/bin/kdig +short @'..host.ip..' '..target..' '..query..' +tls-ca >'..tmpfile
 
     -- Get some DOT answers!
     -- variable response is true/false, query results are in tmpfile
     local response = os.execute(qstring)

     -- collect query results
     lines = {}
     for line in io.lines(tmpfile) do 
        lines[#lines + 1] = line
     end

     -- be a good citizen and delete that tmpfile
     os.remove(tmpfile)

     return lines

end

