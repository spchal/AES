# AES
Nb:=4;
Nk:=8;
Nr:=Nk+6;

sbox := [
[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
[0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
[0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
[0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
[0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
[0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
[0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
[0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
[0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
[0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
[0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
[0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
[0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
[0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
[0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
[0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]];

 Rcon:= [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d];

SubWord:=function(word)
	tmp:=[];
	i:=1;
	while i lt #word+1 do
		tmp := tmp cat [sbox[StringToInteger(word[i],16)+1,StringToInteger(word[i+1],16)+1]];
		i:=i+2;
	end while;
	return tmp;
end function;

RotWord:=function(word)
	tmp:=[];
	tmp[1]:=word[3];
	tmp[2]:=word[4];
	tmp[3]:=word[5];
	tmp[4]:=word[6];
	tmp[5]:=word[7];
	tmp[6]:=word[8];
	tmp[7]:=word[1];
	tmp[8]:=word[2];
	
	return tmp;
end function;

keyExpansion:= function(key)
	//key is  a string of hex values.
	w:=[];
	i:=0;
	while i lt Nk do
		w[i+1]:= key[8*i+1] cat key[8*i+2] cat key[8*i+3] cat key[8*i+4] cat key[8*i+5] cat key[8*i+6] cat key[8*i+7] cat key[8*i+8];
		i:=i+1;	
	end while;
	i:=Nk+1;
	while i lt ((Nb *(Nr+1))+1) do
		temp:=w[i-1];
		temp1:=[];
		if (i-1) mod Nk eq 0 then
			val:=RotWord(temp);
			temp1:=SubWord(val); //SubWord() returns a sequence of 4 ints
			//printf "after subword: ";temp1;
			//printf "Rcon:"; Rcon[(i-1) div Nk];
			temp1[1]:=BitwiseXor(temp1[1],Rcon[((i-1) div Nk)+1]); 
			//temp:=temp1;
					
			y:=[];
			for i in [1..4] do
				z:=[];	
				val:= Eltseq(IntegerToString(temp1[i],16));
				z:= z cat val; 
				while #z lt 2 do
					z:=Insert(z,1,"0");;
				end while;
				y:=y cat z;
			end for;
			val:=y[1] cat y[2] cat y[3] cat y[4] cat y[5] cat y[6] cat y[7] cat y[8];
			q:=StringToInteger(val,16);
		
		elif (i-1) mod Nk eq 4 then
		
			temp1:=SubWord(temp);
			y:=[];
			for i in [1..4] do
				z:=[];	
				val:= Eltseq(IntegerToString(temp1[i],16));
				z:= z cat val; 
				while #z lt 2 do
					z:=Insert(z,1,"0");;
				end while;
				y:=y cat z;
			end for;
			val:=y[1] cat y[2] cat y[3] cat y[4] cat y[5] cat y[6] cat y[7] cat y[8];
			q:=StringToInteger(val,16);
	
		else
			q:=StringToInteger(temp,16);
			
		end if;
		ws:=w[i-Nk];
		b:= StringToInteger(ws,16);
		t:=[];
		
		t:=BitwiseXor(b,q); 
		
		var:=Eltseq(IntegerToString(t,16));
		while #var lt 8 do
			var:= Insert(var,1,"0");
		end while;
		a:= var[1] cat var[2] cat var[3] cat var[4] cat var[5] cat var[6] cat var[7] cat var[8];
		//printf "after xor: ";a;
		w[i]:= a;
		i:=i+1;
	end while;
	//printf "keyExpansion function returning...";
	return w;
	
end function;

AddRoundKeys:=function(state,w,round)
	state_new:=state;
	
	new_val:=[];
	for c in [1..4]do
		y:=[];
		temp1:=[state[1][c],state[2][c],state[3][c],state[4][c]];
		for i in [1..4] do
				
			z:=[];	
			val:= Eltseq(IntegerToString(temp1[i],16));
			z:= z cat val; 
			while #z lt 2 do
				z:=Insert(z,1,"0");
			end while;
			y:=y cat z;
		end for;
		
		val:=y[1] cat y[2] cat y[3] cat y[4] cat y[5] cat y[6] cat y[7] cat y[8];
		q:=StringToInteger(val,16);
		
		new_val[c]:=BitwiseXor(q,StringToInteger(w[round*4+c],16));
	end for;
	//printf "new_val is having four words which are the 4 coulums of the new state. " ;new_val;
	
	for i in [1..4] do
		hex:=[];
		hex:=Eltseq(IntegerToString(new_val[i],16));
		while #hex lt 8 do
			hex:=Insert(hex,1,"0");
		end while;
		//hex;
		c:=0;
		while c lt 4 do
			state_new[c+1][i]:= StringToInteger((hex[c*2+1] cat hex[c*2+2]),16);
			c:=c+1;
		end while;
	end for;
	
	return state_new;
	
end function;

SubBytes:=function(state)	
	state_new:= state;
	for r in [1..4]do
		for c in [1..4]do
		 hex:=Eltseq(IntegerToString(state[r][c],16));
		 while #hex lt 2 do
			hex:= Insert(hex,1,"0");
		 end while;
		 state_new[r][c]:= sbox[StringToInteger(hex[1],16)+1,StringToInteger(hex[2],16)+1];
		end for;
	end for;
	return state_new;
end function;

ShiftRows:=function(state)
//printf "state 2: ";state[2];
	state[2]:=Rotate(state[2],-1);
	state[3]:=Rotate(state[3],-2);
	state[4]:=Rotate(state[4],-3);
	return state;
end function;

byteMul:=function(a,b)
	r:=0;
	while a ne 0 do
		if BitwiseAnd(a,1) ne 0 then
			r:= BitwiseXor(r,b);
		end if;
		t:= BitwiseAnd(b,0x80);
		b:= ShiftLeft(b,1);
		if t ne 0 then
			b:= BitwiseXor(b,0x1b);
		end if;
		a:= ShiftRight(BitwiseAnd(a,0xff),1);
	end while;
	return r;
end function;

MixColumn:=function(state)
	state_new:=[];
	b2:= 0x02;
	b3:= 0x03;
	for c in [1..4]do
		state_new[1]:= BitwiseXor(BitwiseXor(BitwiseXor(byteMul(b2,state[1][c]),byteMul(b3,state[2][c])),state[3][c]),state[4][c]) mod 2^8;
		state_new[2]:= BitwiseXor(BitwiseXor(BitwiseXor(state[1][c],byteMul(b2,state[2][c])),byteMul(b3,state[3][c])),state[4][c]) mod 2^8;
		state_new[3]:= BitwiseXor(BitwiseXor(BitwiseXor(state[1][c],state[2][c]),byteMul(b2,state[3][c])),byteMul(b3,state[4][c])) mod 2^8;
		state_new[4]:= BitwiseXor(BitwiseXor(BitwiseXor(byteMul(b3,state[1][c]),state[2][c]),state[3][c]),byteMul(b2,state[4][c])) mod 2^8;
		for i in [1..4] do 
			state[i][c]:= state_new[i];
		end for; 
	end for;
	return state;
end function;

encryptAES:=function(key,input)
	w:=keyExpansion(key);
	
	inp:=[];
	for i in [1..#input/2] do
		inp:= inp cat [StringToInteger(input[i*2-1..i*2], 16)];      
	end for;
	//printf "input bytes:";inp;
	state:=[[inp[1]],[inp[2]],[inp[3]],[inp[4]]];
	//State represented as an array of columns
	for i in [1..3]do
		state[1] := state[1] cat [inp[1+4*i]];
		state[2] := state[2] cat [inp[2+4*i]];
		state[3] := state[3] cat [inp[3+4*i]];
		state[4] := state[4] cat [inp[4+4*i]];
	end for;
	
	//printf "State fresh: "; state;
	state:=AddRoundKeys(state,w,0);
	
	for i in [1..(Nr-1)]do
		state:=SubBytes(state);
		//printf " SubBytes():" ;state:Hex;
		state:=ShiftRows(state);
		//printf " ShiftRows():" ;state:Hex;
		state:=MixColumn(state);
		//printf " MixColumn():" ;state:Hex;
		state:=AddRoundKeys(state,w,i);
		//i;printf " AddRoundKeys():" ;state:Hex;
	end for;
	state:=SubBytes(state);
	state:=ShiftRows(state);
	state:=AddRoundKeys(state,w,Nr);
	
	out:=[];
	for r in [1..4]do
		for c in [1..4]do
			hex:=[];
			hex:=Eltseq(IntegerToString(state[c][r],16));
			while #hex lt 2 do
				hex:=Insert(hex,1,"0");
			end while;
			out cat:= hex;
		end for;
	end for;
	cipher:= out[1] cat out[2] cat out[3] cat out[4] cat out[5] cat out[6] cat out[7] cat out[8] cat out[9] cat out[10] cat out[11] cat out[12] cat out[13] cat out[14] cat out[15] cat out[16];
	cipher:= cipher cat out[17] cat out[18] cat out[19] cat out[20] cat out[21] cat out[22] cat out[23] cat out[24] cat out[25] cat out[26] cat out[27] cat out[28] cat out[29] cat out[30] cat out[31] cat out[32];
	return cipher;
end function;


tvAES :=
  [
  [* // test vector 1
  // key
  "0000000000000000000000000000000000000000000000000000000000000000",
  // plaintext
  "80000000000000000000000000000000",
  // ciphertext
  "DDC6BF790C15760D8D9AEB6F9A75FD4E"
  *],
  [* // test vector 2
  // key
  "0000000000000000000000000000000000000000000000000000000000000000",
  // plaintext
  "FFFFFFFFFFFFFFFFFC00000000000000",
  // ciphertext
  "811441CE1D309EEE7185E8C752C07557"
  *],
  [* // test vector 3
  // key
  "FFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000",
  // plaintext
  "00000000000000000000000000000000",
  // ciphertext
  "15C6BECF0F4CEC7129CBD22D1A79B1B8"
  *],
  [* // test vector 4
  // key
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
  // plaintext
  "00000000000000000000000000000000",
  // ciphertext
  "27936BD27FB1468FC8B48BC483321725"
  *]
  ];

procedure testAES(encryptAES,tvAES)

  alltest := true;
  for i in [1..#tvAES] do
    print "testing test vector #",i;
    tv := tvAES[i];
    a := encryptAES(tv[1],tv[2]);  
    thistest := (a eq tv[3]);
    print "  test passed = ", thistest;
    alltest := thistest and alltest;
  end for;
  print"All test passed? ", alltest;
  
end procedure;

function timeAES(encryptAES,tvAES)
  
  t := Cputime();

  for i in [1..100] do
    j := (i mod #tvAES) + 1;
    tv := tvAES[j];
    a := encryptAES(tv[1],tv[2]);
  end for;
  
  return Cputime(t);
  
end function;

testAES(encryptAES,tvAES);
timeAES(encryptAES,tvAES);
