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
# from work by Michele Fabbrini), provide a link to the license, and indicate if 
# changes were made.
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

# FC1Encryption - Version 1.0.0-beta 

using SHA
using Random 

####################
# Input Validation #
####################

# Opening plaintext.txt 
plain=open(f->read(f, String), "plaintext.txt")

# Opening primarykey.txt 
pkeybin=open(f->read(f, String), "primarykey.txt")

# Opening secondarykey.txt 
skeystring=open(f->read(f, String), "secondarykey.txt")

# Checking plaintext
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

# Checking primarykey
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

# Checking secondarykey
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

###############
# Tag SHA-256 #
###############							
    
taghex = bytes2hex(sha256(plain))
println("This is the 256-bit hash of Plaintext (hex): ", taghex)
tagdec = parse(BigInt,taghex,base=16)
tagbintemp = string(tagdec,base=2)
tagbintemplen = length(tagbintemp)

function ftagbitscheck()
    if tagbintemplen == 256
        global tagbin = tagbintemp
    else
       global tagbin = lpad(tagbintemp,256,"0")
    end
end
ftagbitscheck()

##############
# Sys. Init. #
##############

# Tagged Plaintext
tplain=string(plain,tagbin)

skey=parse(BigInt,skeystring)

# Start random string whose length is the value of secondarykey
startpad=randstring("01",skey)

plainlen=length(plain)
tplainlen=length(tplain)

pkeybinlen=length(pkeybin)

#Checking tagged plaintext length: it must be greater than modulo length.
function ftplainlenvalid()
    if tplainlen < pkeybinlen
        println("Tagged plain text string must be longer than modulo string!")
        sleep(20)
        exit()
	end
end		
ftplainlenvalid()

# The start value of tplain is passed to remtplain
remtplain=tplain

# The start value of tplain length is passed to remtplain length
remtplainlen=tplainlen

# Start ciphertex
cipher=startpad

# Treshold value
theshold=3/2*pkeybinlen

####################
# Encryption Start #
####################

function fencrypt()

    # Case 1
    if remtplainlen >= theshold
		function frand1()
		    rand(1:pkeybinlen-3)
		end
		# Random integer generated by frand1 function
	    frand1value=frand1()	
		# First random length bits from tagged plaintext
        tplain1=first(remtplain,frand1value)
      		
        # Preparing the input for the modular multiplicative inverse function.
		# A leading e a trailing '1' are appended at each chunk of tagged plaintext
		# whose length is randomly selected by frand function. The leading 1 is meant 
		# to make sure that the input of finvmod is a positive integer since tplain1
		# could start with '0'. The trailing '1' serves to prevent the algorithm from 
		# blocking in the case of an even module and a text to be encrypted containing 
		# a long row of 0's.
        function fintgen1()
		    string(1,tplain1,1)
		end
		input1bin=fintgen1()		
		input1=parse(BigInt,input1bin,base=2)
        pkey=parse(BigInt,pkeybin,base=2)

        function finv1(input1,pkey)
            try
                @time invmod(input1,pkey)
            catch err
                if isa(err, DomainError)
                    println("Input1 and pkey are not coprime.")
                    fencrypt()
			    end
            end
        end
        c1=finv1(input1,pkey)		
	    c1bin=string(c1,base=2)        
		c1binlen=length(c1bin)

        function fc1blockgen()
            if c1binlen == pkeybinlen 
                global c1block = c1bin
            else
		       function fzerospad1()
		           lpad(c1bin,pkeybinlen,"0")
			   end
			   global c1block = fzerospad1()
			end
		end
		# Block of ciphertext whose length matches modulo length
        fc1blockgen()
        # Tagged plaintext length residue
        global remtplainlen=remtplainlen-frand1value
        # Remaining tagged plaintext
        global remtplain=last(tplain,remtplainlen)
        # Ciphertext genesis		 
		global cipher=string(cipher,c1block)
		
        fencrypt()


    # Case 2
    elseif pkeybinlen <= remtplainlen <= theshold
		function frand2()
		    rand(remtplainlen-pkeybinlen+3:pkeybinlen-3)
	    end
		# Random integer generated by frand2 function
		frand2value=frand2()
        # Inferred last block length    
		tplain2lastlen=remtplainlen-frand2value
         
		tplain2=first(remtplain,frand2value)
        input2bin=string(1,tplain2,1)
        input2=parse(BigInt,input2bin,base=2)
		pkey=parse(BigInt,pkeybin,base=2)
		
		function finv2(input2,pkey)
            try
                @time  invmod(input2,pkey)
            catch err
                if isa(err, DomainError)
                    println("Input2 and pkey are not coprime.")
                    fencrypt()
                end
            end
         end
         c2=finv2(input2,pkey)
         c2bin=string(c2,base=2)
         c2binlen=length(c2bin)

         function fc2blockgen()
            if c2binlen == pkeybinlen 
                global c2block = c2bin
            else
		       function fzerospad2()
		           lpad(c2bin,pkeybinlen,"0")
			   end
			   global c2block = fzerospad2() 
			end
		 end
         fc2blockgen()
       
		 tplain2last=last(tplain,tplain2lastlen)
         input2lastbin=string(1,tplain2last,1)
         input2last=parse(BigInt,input2lastbin,base=2)
         pkey=parse(BigInt,pkeybin,base=2)
		  
		 function finv2last(input2last,pkey)
             try
                 @time  invmod(input2last,pkey)
             catch err
                 if isa(err, DomainError)
                     println("Input2last and pkey are not coprime.")
                     fencrypt()
				 end
             end
         end
         c2last=finv2last(input2last,pkey)
         c2lastbin=string(c2last,base=2)
         c2lastbinlen=length(c2lastbin)

         function fc2lastblockgen()
             if c2lastbinlen == pkeybinlen 
                global c2lastblock = c2lastbin
             else
		        function fzerospad2last()
		            lpad(c2lastbin,pkeybinlen,"0")
			    end
			    global c2lastblock = fzerospad2last()
		 	 end
	   	 end
         fc2lastblockgen()
 
         function frandend2()  
             rand(0:pkeybinlen-1)
		 end
		 frandend2value=frandend2()
		 # End padding generated by a random function
         ikey=randstring("01",frandend2value)

         global ikeylen=length(ikey)
		 
         # Final ciphertext		 
		 global cipher=string(cipher,c2block,c2lastblock,ikey)
		 global clen=length(cipher)
		 
		 function fwritetofile2()	  
		     open("ciphertext.txt", "w") do f
                 write(f, cipher)
             end
		 end
		 fwritetofile2()
         println("Ciphertext has been generated and updated in 'ciphertext.txt'.")
					  
    # Case 3
    elseif remtplainlen == pkeybinlen - 1
		function frand3()
		    rand(2:pkeybinlen-2)
	    end
		frand3value=frand3()
            
        tplain3lastlen=remtplainlen-frand3value
        tplain3=first(remtplain,frand3value)
        input3bin=string(1,tplain3,1)
        input3=parse(BigInt,input3bin,base=2)
        pkey=parse(BigInt,pkeybin,base=2)
             
	    function finv3(a3,pkey)
            try
                @time  invmod(input3,pkey)
            catch err
                if isa(err, DomainError)
                    println("Input3 and pkey are not coprime.")
                    fencrypt()
			     end
            end
        end
        c3=finv3(input3,pkey)
        c3bin=string(c3,base=2)
        c3binlen=length(c3bin)
             
        function fc3blockgen()
            if c3binlen == pkeybinlen 
                global c3block = c3bin
            else
		        function fzerospad3()
		            lpad(c3bin,pkeybinlen,"0")
			    end
			    global c3block = fzerospad3() 
		 	end
	   	end
        fc3blockgen()

		tplain3last=last(tplain,tplain3lastlen)
		input3lastbin=string(1,tplain3last,1)
        input3last=parse(BigInt,input3lastbin,base=2)
        pkey=parse(BigInt,pkeybin,base=2)
       
		function finv3last(input3last,pkey)
            try
                @time invmod(input3last,pkey)
            catch err
                if isa(err, DomainError)
                    println("Input3last and pkey are not coprime.")
                     encrypt()
			    end
            end
        end
        c3last=finv3last(input3last,pkey)
        c3lastbin=string(c3last,base=2)
        c3lastbinlen=length(c3lastbin)
         
        function fc3lastblockgen()
            if c3lastbinlen == pkeybinlen 
                global c3lastblock = c3lastbin
            else
		        function fzerospad3last()
		            lpad(c3lastbin,pkeybinlen,"0")
			    end
			    global c3lastblock = fzerospad3last()
             end
	   	 end
         fc3lastblockgen()
          
         function frandend3()  
             rand(0:pkeybinlen-1)
		 end
		 frandend3value=frandend3()
		 # End padding generated by a random function
         ikey=randstring("01",frandend3value)
		 
		 global ikeylen=length(ikey)
		 
         # Final ciphertext 
         global cipher=string(cipher,c3block,c3lastblock,ikey)
		 global clen=length(cipher)
		 
		 function fwritetofile3()	  
		     open("ciphertext.txt", "w") do f
                  write(f, cipher)
			 end
         end
		 fwritetofile3()
		 println("Ciphertext has been generated and updated in 'ciphertext.txt'.")
	
    # Case 4
    elseif remtplainlen <= pkeybinlen - 2
		function frand4()
		    rand(1:remtplainlen-1)
		end
		frand4value=frand4()
        tplain4lastlen=remtplainlen-frand4value
        tplain4=first(remtplain,frand4value)
        input4bin=string(1,tplain4,1)
        input4=parse(BigInt,input4bin,base=2)
        pkey=parse(BigInt,pkeybin,base=2)
              
		function finv4(input4,pkey)
            try
                @time  invmod(input4,pkey)
            catch err
                if isa(err, DomainError)
                    println("Input4 and pkey are not coprime.")
                    fencrypt()
			    end
            end
        end
        c4=finv4(input4,pkey)
        c4bin=string(c4,base=2)
        c4binlen=length(c4bin)
              
        function fc4blockgen()
            if c4binlen == pkeybinlen 
                global c4block = c4bin
            else
		        function fzerospad4()
		            lpad(c4bin,pkeybinlen,"0")
		    	end
			    global c4block = fzerospad4()
            end
	   	end
        fc4blockgen()         
		tplain4last=last(tplain,tplain4lastlen)
		input4lastbin=string(1,tplain4last,1)
        input4last=parse(BigInt,input4lastbin,base=2)
        pkey=parse(BigInt,pkeybin,base=2)
             
		function finv4last(input4last,pkey)
            try
                @time  invmod(input4last,pkey)
            catch err
                if isa(err, DomainError)
                    println("Input4last and pkey are not coprime.")
                    fencrypt()
			    end
            end
        end
        c4last=finv4last(input4last,pkey)
        c4lastbin=string(c4last,base=2)             
        c4lastbinlen=length(c4lastbin)
               
        function fc4lastblockgen()
            if c4lastbinlen == pkeybinlen 
                global c4lastblock = c4lastbin                
            else
		        function fzerospad4last()
		            lpad(c4lastbin,pkeybinlen,"0")
			    end
			    global c4lastblock = fzerospad4last()                   
		 	end
	   	end
        fc4lastblockgen()
       
        function frandend4()  
            rand(0:pkeybinlen-1)
		end
		frandend4value=frandend4()
		# End padding generated by a random function
        ikey=randstring("01",frandend4value)
		
		global ikeylen=length(ikey)
		
		# Final ciphertext       
        global cipher=string(cipher,c4block,c4lastblock,ikey)
        global clen=length(cipher)		
		
        function fwritetofile4()
		    open("ciphertext.txt", "w") do f
                 write(f, cipher)
            end
	    end
		fwritetofile4()
		println("Ciphertext has been generated and updated in 'ciphertext.txt'.")		
			   
        end
end 

function fend()
     try 
        fencrypt() 
     catch err
         if isa(err, MethodError)           
	     end
     end
end 
fend()
println(" ")
println("----------------- ")
println("Encryption Report")
println("----------------- ")
println("Primary Key Length: ", pkeybinlen)
println("Secondary Key: ", skey)
println("Inferred Key Length: ", ikeylen)
println("Tagged Plaintext Length: ", tplainlen)
println("Plaintext Length: ", plainlen)
println("Ciphertext Length: ", clen)








