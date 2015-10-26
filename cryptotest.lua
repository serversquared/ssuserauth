--Test code, NOT FINAL!!!
--Written by Niko Geil.
--Copyright (c) 2015.
--To be released under GNU AGPL v3.

-- Installed with `luarocks install sha2'
require("hmac.sha2")
-- Installed with `luarocks install bcrypt'
bcrypt = require("bcrypt")



local rounds = 14
local passwordversion = 1
usertable = {}
local seed = os.time()
print("Seeding with " .. seed)
math.randomseed(seed)



-- Random Strings on Lua Users Wiki
-- <http://lua-users.org/wiki/RandomStrings>
-- Original author unknown.
local Chars = {}
for Loop = 0, 255 do
	Chars[Loop+1] = string.char(Loop)
end
local String = table.concat(Chars)

local Built = {['.'] = Chars}

local AddLookup = function(CharSet)
	local Substitute = string.gsub(String, '[^'..CharSet..']', '')
	local Lookup = {}
	for Loop = 1, string.len(Substitute) do
		 Lookup[Loop] = string.sub(Substitute, Loop, Loop)
	end
	Built[CharSet] = Lookup

	return Lookup
end

function string.random(Length, CharSet)
	-- Length (number)
	-- CharSet (string, optional); e.g. %l%d for lower case letters and digits

	local CharSet = CharSet or '.'

	if CharSet == '' then
		return ''
	else
		local Result = {}
		local Lookup = Built[CharSet] or AddLookup(CharSet)
		local Range = table.getn(Lookup)

		for Loop = 1,Length do
			Result[Loop] = Lookup[math.random(1, Range)]
		end

		return table.concat(Result)
	end
end
-- End Random Strings code.



function generatesalt()
	return string.random(128, "%l%u%d%p")
end


function hashsalt(password, salt, digest)
	if password:len() > 72 then
		return nil
	end
	if not digest then
		return bcrypt.digest(hmac.sha512(salt, password), rounds)
	else
		return bcrypt.verify(hmac.sha512(salt, password), digest)
	end
end



function adduser(username, password)
	if usertable[username] ~= nil then
		print("User already exists.")
		return nil
	end
	usertable[username] = {}
	usertable[username].version = passwordversion
	usertable[username].salt = generatesalt()
	usertable[username].password = hashsalt(password, usertable[username].salt)
	print("Created user " .. username .. ".")
end

function removeuser(username)
	if usertable[username] == nil then
		print("User does not exist.")
		return nil
	end
	usertable[username] = nil
end

function updateuser(username, password)
	if usertable[username] == nil then
		print("User does not exist.")
		return nil
	end
	usertable[username].version = passwordversion
	usertable[username].salt = generatesalt()
	usertable[username].password = hashsalt(password, usertable[username].salt)
end

function checkpassword(username, password)
	if hashsalt(password, usertable[username].salt, usertable[username].password) then
		print("Password match!")
	else
		print("Password mismatch!")
	end
end

function dumpusertable()
	for k, v in pairs(usertable) do
		print(k)
		if type(v) == "table" then
			for k2, v2 in pairs(usertable[k]) do 
				print("", k2, v2)
			end
		end
	end
end
