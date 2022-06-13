#
# FC1 algorithm code by Michele Fabbrini in Julia Programming Language is made available  
# under the Creative Commons Attribution license. The following is a human-readable 
# summary of (and not a substitute for) the full legal text of the CC BY 4.0 license
# https://creativecommons.org/licenses/by/4.0/.
#
# You are free:
#
#  to Share—copy and redistribute the material in any medium or format
#  to Adapt—remix, transform, and build upon the material
#
# for any purpose, even commercially.
#
# The licensor cannot revoke these freedoms as long as you follow the license terms.
#
# Under the following terms:
#
# ATTRIBUTION — You must give appropriate credit (mentioning that your work is derived 
# from work by Michele Fabbrini https://fabbrini.org/), provide a link to the license, 
# and indicate if changes were made.
# You may do so in any reasonable manner, but not in any way that suggests the licensor
# endorses you or your use.
#
# No additional restrictions — You may not apply legal terms or technological measures 
# that legally restrict others from doing anything the license permits. 
# With the understanding that:
#
# Notices:
#
# You do not have to comply with the license for elements of the material in the public 
# domain or where your use is permitted by an applicable exception or limitation.
# No warranties are given. The license may not give you all of the permissions necessary 
# for your intended use. For example, other rights such as publicity, privacy, or moral 
# rights may limit how you use the material.
#
# JULIA LICENCE
#     
# MIT License
#
# Copyright (c) 2009-2022: Jeff Bezanson, Stefan Karpinski, Viral B. Shah, and other 
# contributors: https://github.com/JuliaLang/julia/contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Softwareù
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so, subject to the following 
# conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR  OTHER DEALINGS IN THE SOFTWARE.
#
# end of terms and conditions
#
# Please see THIRDPARTY.md for license information for other software used in this 
# project https://github.com/JuliaLang/julia/blob/master/THIRDPARTY.md

# FC1Decryption - Version 1.0.0-beta

using SHA 

####################
# Input Validation #
####################

# Opening ciphertext.txt
cipher=open(f->read(f, String), "ciphertext.txt")

# Opening primarykey.txt
pkeybin=open(f->read(f, String), "primarykey.txt")

# Opening secondarykey.txt
skeystring=open(f->read(f, String), "secondarykey.txt")

#Checking plaintext
function fplainvalid()
    try
        parse(BigInt,plain,base=2)
    catch err
        if isa(err, ArgumentError)
            println("Plaintext MUST be a binary string!")
            sleep(10)
            exit()						 
        end
    end
end	
fplainvalid()

#Checking primarykey
function fpkeyvalid1()
    try
        parse(BigInt,plain,base=2)
    catch err
        if isa(err, ArgumentError)
            println("Primarykey MUST be a binary string!")
            sleep(10)
            exit()						 
        end
    end
end
fpkeyvalid1()

function fpkeyvalid2()
    if startswith(pkeybin, "0")
	    println("Primarykey MUST NOT start with '0'!")
		sleep(10)
        exit()		
    end
end
fpkeyvalid2()

#Checking secondarykey
function fskeyvalid()
    try
       parse(BigInt,skeystring,base=10)
    catch err
        if isa(err, ArgumentError)
            println("Skey MUST be an integer!")
            sleep(10)
            exit()
	end
    end
end							
fskeyvalid()

##############
# Sys. Init. #
##############

skey=parse(Int64,skeystring)
clen=length(cipher) 
remclen=clen-skey
remc=last(cipher,remclen)
pkeybinlen=length(pkeybin)
tplain=""

####################
# Decryption Start #
####################

function fdecrypt()

    # Case1
    if remclen >= pkeybinlen
        cblock=first(remc,pkeybinlen)
	inputbin=lstrip(cblock,['0'])		 
        input=parse(BigInt,inputbin,base=2)
        pkey=parse(BigInt,pkeybin,base=2)
         
        function finv(input,pkey)
	    try
               @time invmod(input,pkey)
	    catch err
                if isa(err, DomainError)
                    println("ATTENTION! CIPHERTEXT COULD BE CORRUPTED!")
                    sleep(10)
		    exit()
	        end
            end
        end   	
        output=finv(input,pkey)        
        outputbin=string(output,base=2)       
        tplain1=chop(outputbin, head = 1, tail = 1)        
		global remclen=remclen-pkeybinlen        
        global remc=last(remc,remclen)        
	global tplain=string(tplain,tplain1)
	fdecrypt()


    # Case 2
    elseif remclen < pkeybinlen
	global tplainlen=length(tplain)
	global plainlen=tplainlen-256
	plaincheck=first(tplain,plainlen)
		      				
########################
# Data Integrity Check #
########################

	tagcheck=last(tplain,256) 
        taghex= bytes2hex(sha256(plaincheck))
        println("This is the 256-bit hash of Plaintext check (hex): ", taghex)
        tagdec=parse(BigInt,taghex,base=16)       
        tagbintemp=string(tagdec,base=2)
        tagbintemplen = length(tagbintemp)
	global ikeylen=remclen

        function ftagbitscheck()
            if tagbintemplen == 256
                global tagbin = tagbintemp
            else
                global tagbin = lpad(tagbintemp,256,"0")
            end          
	end
	ftagbitscheck()
		 
	function fintegritycheck()
	    check=cmp(tagcheck::AbstractString, tagbin::AbstractString)
                  if check==0
                      function fwritetofile()
		          open("decryptedplaintext.txt", "w") do f
                               write(f, plaincheck)
                          end
	              end
		      fwritetofile()		  
                      println("Decrypted Plaintext has been generated.")
		      println("SUCCESS!!!")
		  else
                      println("DATA INTEGRITY ALERT: CORRUPTED CIPHERTEXT!")
                  end 
         end
	fintegritycheck()
    end
end

fdecrypt()

println(" ")
println("----------------- ")
println("Decryption Report")
println("----------------- ")
println("Primary Key Length: ", pkeybinlen)
println("Secondary Key: ", skey)
println("Inferred Key Length: ", ikeylen)
println("Tagged Plaintext Length: ", tplainlen)
println("Decrypted Plaintext Length: ", plainlen)
println("Ciphertext Length: ", clen)








