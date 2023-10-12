
const cm = new CModule(`
#include <stdio.h>

unsigned int calcDecryptDataLen(unsigned long X0)
{
    unsigned int v0 = (X0 ^ 0x2CFCF86E);
    unsigned int v1 = 1514590667 * v0;

    unsigned int v12 = *(unsigned int *)(X0+0x28) + v1;
    
    unsigned int v770 = v12 - 0x44A75F25;
    
    unsigned int v24 = (v770 - ((2 * v770 + 274998170) & 0x66F8C006) - 0x44518E30) ^ 0xB37C6003;

    return v24;
}


unsigned int calcEncryptDataLen(unsigned long a1)
{
    unsigned int v2 = 2101767179 * (a1 ^ 0x4A16AFDC);
    
    unsigned long v5 = (unsigned int)(*(unsigned int *)(a1 + 0x28) - v2);
    unsigned long v7 = v5 - 1275503213 - ((2 * (v5 - 1275503213) - 441333462) & 0xB165B874) + 1267450063;
    unsigned int v13 = (v7 ^ 0xE74FB145) + (2 * v7 & 0x7FFADAFE ^ 0x31609874) + 2065611771;
    unsigned int  size = v13 - 0x3B1C297A;
    return size;
}


typedef unsigned long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned int bool;

void signEncryptArg(uint64_t pArg, int datalen)
{
    // int datalen = 0xD0;
    // uint64_t pArg = 0x16FA31798;

    uint64_t X13 = pArg;
    uint32_t W23 = 0x6B9A323B + datalen;

    uint32_t W13 = (X13 ^ 0x4A16AFDC) * 0x7D466C0B;
    uint32_t W11 = W13 + W23 + 0xED938B9D;

    printf("\n%p    %X   %X\n", X13, W13, W11); //DF239AEE 38515994

    *(uint32_t*)(pArg + 0x28) = W11;

  {
    bool flag=1; //10025DF3C   CMP W8, W9
    uint32_t __W13 = 5; //10025DF40   LDR  W13, [SP,#0x137C]

    uint32_t W9 = !flag;
    uint32_t W10 = flag;

    //uint32_t
        W9 = W9*0x6195 + __W13;

    uint32_t W22 = W10*0x6198 + W9;

    uint32_t W12 = W22 + 0xFFFF9E65;
        
    //uint32_t
        W9 = W12 ^ W13;

    printf("\n\n%X   %X   %X\n\n", W22, W12, W9);

    *(uint32_t*)(pArg + 0x2C) = W9;
  }
}

`);

// console.log(JSON.stringify(cm));

const calcDecryptDataLen = new NativeFunction(cm.calcDecryptDataLen, 'int', ["pointer"]);
const calcEncryptDataLen = new NativeFunction(cm.calcEncryptDataLen, 'int', ["pointer"]);
const signEncryptArg = new NativeFunction(cm.signEncryptArg, 'void', ["pointer","int"]);


    var base_addr = Module.findBaseAddress("fairplayd.H2");
    send("base_addr addr:" + base_addr);

    global.lastsinf = "";

    Interceptor.attach(base_addr.add(0x021F3E4), {
        onEnter: function(args) {

           let key = args[0].add(0x10).readPointer();
           let iv = args[0].add(0x30).readPointer();
           let priv = args[0].add(0x20).readPointer();
           let outbuf = args[0].add(0x8).readPointer();

           let len_enc = args[0].add(0x28).readUInt();

           let datalen = calcDecryptDataLen(args[0]);
           console.log("\ndecode***********", args[0], "len="+datalen.toString(16), "in="+priv, "out="+outbuf);

           send("\ncallstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
           send("return address: " + this.returnAddress.sub(base_addr));

           console.log("\n----key:\n", hexdump(key,{offset: 0,length: 16,header:false,ansi:false}), 
           "\n----iv:\n", hexdump(iv,{offset: 0,length: 16,header:false,ansi:false}),
           "\n----data:\n", hexdump(priv,{offset: 0,length: datalen})
           );

           this.datalen = datalen;
           this.outbuf = outbuf;
           this.key = key;
           this.iv = iv;
           
           //if(datalen==0x1B0) {
            // for(let i=0; i<16; i++) key.add(i).writeU8(0);
            // for(let i=0; i<16; i++) iv.add(i).writeU8(0);
            // for(let i=0; i<0x1B0; i++) priv.add(i).writeU8(0);
           //}

       },
       onLeave: function(retval){ 
           //retval.replace(0);

           for(let i=0; i<this.datalen; i++)
           {
                let p = this.outbuf.add(i);
                p.writeU8(p.readU8() ^ 0x45);
           }
            
            console.log("\n----decrypted:\n", 
                hexdump(this.outbuf, {offset: 0, length: this.datalen})
            );

            var savefile = "/tmp/"+this.outbuf+"."+this.datalen;
            var file = new File(savefile, "wb");
            file.write(this.outbuf.readByteArray(this.datalen));
            file.flush()
            file.close();

           for(let i=0; i<this.datalen; i++)
           {
                let p = this.outbuf.add(i);
                p.writeU8(p.readU8() ^ 0x45);
           }


           if(this.datalen==0x1B0)
           {
            console.log("lastsinf="+global.lastsinf);

            let datalen=this.datalen;

            let inbuf = Memory.dup(this.outbuf, datalen);

            inbuf.add(0xA6).writeU8(0 ^ 0x45); //mode=0

            let outbuf = Memory.alloc(datalen);

            let arg = Memory.alloc(0x30);
            arg.add(0x00).writePointer(this.key);
            arg.add(0x10).writePointer(this.iv);
            arg.add(0x18).writePointer(outbuf);
            arg.add(0x20).writePointer(inbuf);

            signEncryptArg(arg, datalen);

            const funcEncrypt = new NativeFunction(base_addr.add(0x7790F8), 'void', ["pointer"]);

            funcEncrypt(arg);

            console.log("ret="+arg.add(8).readUInt().toString(16), "datalen="+datalen.toString(16), "\n", hexdump(outbuf,{offset: 0,length: datalen}) );

            let fopen = new NativeFunction(Module.findExportByName(null,"fopen"), 'pointer', ["pointer", "pointer"]);
            let fwrite = new NativeFunction(Module.findExportByName(null,"fwrite"), 'int', ["pointer", "int", "int", "pointer"]);
            let fclose = new NativeFunction(Module.findExportByName(null,"fclose"), 'void', ["pointer"]);
            let fseek = new NativeFunction(Module.findExportByName(null,"fseek"), 'void', ["pointer", "int", "int"]);

            const SEEK_SET=0;
            let fp = fopen(Memory.allocUtf8String(global.lastsinf),  Memory.allocUtf8String("rb+"));
            console.log("fp=", fp);

            fseek(fp, 0xC6, SEEK_SET);
            let mode = Memory.alloc(1); mode.writeU8(0);
            fwrite(mode, 1, 1, fp);

            fseek(fp, 0x1E0, SEEK_SET); //priv
            fwrite(outbuf, datalen, 1, fp);

            fclose(fp);
           }
       }
   });



let data = [ 
    0x69, 0x74, 0x75, 0x6e, 0x00, 0x00, 0x00, 0x0c, 0x76, 0x65, 0x72, 0x73, 0x00, 0x00, 0x00, 0x01,  
    0x00, 0x00, 0x00, 0x18, 0x6b, 0x65, 0x79, 0x20, 0x17, 0x5b, 0xc7, 0x3d, 0x91, 0xaf, 0x0e, 0x52,  
    0x64, 0xe1, 0xa7, 0xea, 0x64, 0x28, 0x7c, 0x07, 0x00, 0x00, 0x00, 0x18, 0x69, 0x76, 0x69, 0x76,  
    0x4e, 0xac, 0xfd, 0xaa, 0xb1, 0x87, 0xf6, 0x84, 0x0f, 0x37, 0x25, 0x8e, 0xc7, 0x42, 0xab, 0xfc,  
    0x00, 0x00, 0x00, 0x18, 0x74, 0x6d, 0x70, 0x72, 0xb3, 0xc6, 0xb9, 0xf9, 0x73, 0x06, 0x9b, 0xbf,  
    0xdb, 0xf6, 0x67, 0x84, 0x5a, 0x50, 0x86, 0x8e, 0x00, 0x00, 0x00, 0x58, 0x72, 0x69, 0x67, 0x68,  
    0x76, 0x65, 0x49, 0x44, 0x00, 0x21, 0x4d, 0xae, 0x70, 0x6c, 0x61, 0x74, 0x00, 0x00, 0x00, 0x02,  
    0x61, 0x76, 0x65, 0x72, 0x01, 0x01, 0x01, 0x00, 0x74, 0x72, 0x61, 0x6e, 0xdf, 0x4a, 0x6c, 0x1f,  
    0x73, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x00, 0x73, 0x6f, 0x6e, 0x67, 0x27, 0xd8, 0x83, 0x43,  
    0x74, 0x6f, 0x6f, 0x6c, 0x50, 0x36, 0x30, 0x35, 0x6d, 0x65, 0x64, 0x69, 0x00, 0x00, 0x00, 0x80,  
    0x6d, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x20, 0x00, 0x68, 0x69, 0x33, 0x32, 0x00, 0x00, 0x00, 0x04,  
    0x00, 0x00, 0x01, 0x08, 0x6e, 0x61, 0x6d, 0x65, 0xe7, 0x9b, 0x9b, 0x20, 0xe5, 0xbc, 0xa0, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   
    ];

//let data = [0x69,0x74,0x75,0x6e,0x00,0x00,0x00,0x0c,0x76,0x65,0x72,0x73,0x00,0x00,0x00,0x01];
let datalen=data.length;

let iv = Memory.alloc(0x10);
let key = Memory.alloc(0x10);
let inbuf = Memory.alloc(datalen);
let outbuf = Memory.alloc(datalen);

for(let i=0; i<16; i++) key.add(i).writeU8([0xD7,0x8D,0x1A,0xB7,0x9B,0xD1,0x50,0xD2,0x45,0x60,0xE2,0x33,0xA8,0x71,0xBB,0xA2][i]);

for(let i=0; i<16; i++) iv.add(i).writeU8([0x04,0xAA,0x10,0xE4,0x13,0xE9,0x94,0x2E,0xC0,0x7D,0x28,0x5C,0xBE,0xCD,0xA4,0x15][i]);

for(let i=0; i<datalen; i++) inbuf.add(i).writeU8(data[i] ^ 0x45);

let arg = Memory.alloc(0x30);
arg.add(0x00).writePointer(key);
arg.add(0x10).writePointer(iv);
arg.add(0x18).writePointer(outbuf);
arg.add(0x20).writePointer(inbuf);

signEncryptArg(arg, datalen);

const funcEncrypt = new NativeFunction(base_addr.add(0x7790F8), 'void', ["pointer"]);

funcEncrypt(arg);

console.log("ret="+arg.add(8).readUInt().toString(16), "datalen="+datalen.toString(16), "\n", hexdump(outbuf,{offset: 0,length: datalen}) );

if(0)
   Interceptor.attach(base_addr.add(0x7790F8), {
       onEnter: function(args) {
            let key = args[0].add(0).readPointer();
            let iv = args[0].add(0x10).readPointer();
            let outbuf = args[0].add(0x18).readPointer();
            let inbuf = args[0].add(0x20).readPointer();

            //signEncryptArg(args[0], 16);

            let datalen = calcEncryptDataLen(args[0]);
            console.log("\x07*********** encode ***********", args[0], "len="+datalen.toString(16), "in="+inbuf, "out="+outbuf);

            //send("\ncallstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
            send("return address: " + this.returnAddress.sub(base_addr));

            //!auto dealloc by frida!
            //Memory.protect(iv, 16, "rw-");
            
            iv=this.iv=Memory.dup(iv, 16); args[0].add(0x10).writePointer(this.iv);
            key=this.key=Memory.dup(key, 16); args[0].add(0).writePointer(this.key);
            //inbuf=this.inbuf=Memory.dup(inbuf, datalen); args[0].add(0x20).writePointer(this.inbuf);

            //make sure inbuf < outbuf
            this.newbuf = Memory.alloc(datalen*2);
            Memory.copy(this.newbuf, inbuf, datalen);
            inbuf = this.newbuf;  args[0].add(0x20).writePointer(inbuf);
            outbuf = this.newbuf.add(datalen); args[0].add(0x18).writePointer(outbuf);

            // for(let i=0; i<16; i++) key.add(i).writeU8(0);
            // for(let i=0; i<16; i++) iv.add(i).writeU8(0);
            // for(let i=0; i<16; i++) inbuf.add(i).writeU8([0x02,0x01,0x3A,0xB2,0xFC,0x21,0x68,0xCD,0x43,0x7D,0x27,0xB0,0x10,0x42,0x9B,0xD4][i]);
            
            for(let i=0; i<16; i++) key.add(i).writeU8([0xD7,0x8D,0x1A,0xB7,0x9B,0xD1,0x50,0xD2,0x45,0x60,0xE2,0x33,0xA8,0x71,0xBB,0xA2][i]);

            for(let i=0; i<16; i++) iv.add(i).writeU8([0x04,0xAA,0x10,0xE4,0x13,0xE9,0x94,0x2E,0xC0,0x7D,0x28,0x5C,0xBE,0xCD,0xA4,0x15][i]);

            for(let i=0; i<16; i++) inbuf.add(i).writeU8([0x69,0x74,0x75,0x6e,0x00,0x00,0x00,0x0c,0x76,0x65,0x72,0x73,0x00,0x00,0x00,0x01][i] ^ 0x45);


            //args[0].add(0x28).writeInt(datalen + 0x3B1C297A);
 
            console.log("\n----key:\n", hexdump(key,{offset: 0,length: 16,header:false,ansi:false}), 
            "\n----iv:\n", hexdump(iv,{offset: 0,length: 16,header:false,ansi:false}),
            "\n----data:\n", hexdump(inbuf,{offset: 0,length: datalen})
            );

            this.datalen = datalen;
            this.outbuf = outbuf;
       },
       onLeave: function(retval){ 
           //retval.replace(0);
            
            console.log("\n-------------encrypted:\n", 
                hexdump(this.outbuf, {offset: 0, length: this.datalen})
            );
       }
    });


global.fds = [];

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","open"), {
    onEnter: function(args) {
       //send("hookfunc: "+args[0] + " " +args[1] + " " +args[2] + " " +args[3] + " " +args[4] + " " +args[5] + " " +args[6] + " " +args[7] + " ");
       send("\n******** open "+args[1]+"\t"+args[0].readCString());
        this.fname = args[0].readCString();
       send("callstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
       send("return address: " + this.returnAddress.sub(base_addr));

       if(/\.sinf$/.test(this.fname)) global.lastsinf = this.fname;
   },
   onLeave: function(retval){ 
       send("func return: "+retval+"\n");
       global.fds[retval] = this.fname;
       //send(hexdump(retval, {offset: 0,length: 64,header: true,ansi: true}));
       //retval.replace(0); 
   }
});

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","open_dprotected_np"), {
    onEnter: function(args) {
       //send("hookfunc: "+args[0] + " " +args[1] + " " +args[2] + " " +args[3] + " " +args[4] + " " +args[5] + " " +args[6] + " " +args[7] + " ");
       send("\n******** open_dprotected_np "+args[1]+"\t"+args[0].readCString());
        this.fname = args[0].readCString();
       send("callstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
       send("return address: " + this.returnAddress.sub(base_addr));
   },
   onLeave: function(retval){ 
       send("func return: "+retval+"\n");
       global.fds[retval] = this.fname;
       //send(hexdump(retval, {offset: 0,length: 64,header: true,ansi: true}));
       //retval.replace(0); 
   }
});


const lseek = new NativeFunction(Module.findExportByName("libSystem.B.dylib","lseek"), 'int', ["int", "int", "int"]);

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","write"), {
    onEnter: function(args) {
        const SEEK_CUR=1;
        let off = lseek(Number(args[0]),  0, SEEK_CUR);
       console.log("\x07\n******** write "+args[0], args[1], args[2], "off="+off, "name="+global.fds[args[0]], "\n");

       send("callstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
       send("return address: " + this.returnAddress.sub(base_addr));

       console.log("\n", args[1].readByteArray(Number(args[2])));

    //    if(Number(args[2])==0xE4) {
    //         args[1].writeInt(0);
    //    }
   }
});

// Interceptor.attach(Module.findExportByName("fairplayd.H2", "malloc"), {
//     onEnter: function(args) {
//        //send("hookfunc: "+args[0] + " " +args[1] + " " +args[2] + " " +args[3] + " " +args[4] + " " +args[5] + " " +args[6] + " " +args[7] + " ");
//        console.log("malloc", args[0], Number(args[0]));

//        this.allocsize = Number(args[0]);

//        send("callstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
//        send("return address: " + this.returnAddress.sub(base_addr));
//    },
//    onLeave: function(retval) { 
//         for(let i=0; i<this.allocsize; i++) retval.add(i).writeU8(0);
//        send("buffer= "+retval+" ~" + retval.add(this.allocsize) + "\n\n");
//        //global.malloc[retval] = this.allocsize;
//        //send(hexdump(retval, {offset: 0,length: 64,header: true,ansi: true}));
//        //retval.replace(0); 
//    }
// });