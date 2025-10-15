// This file contains a flat high-level programming interface for dokucrypt2.
// This interface is specific for the module's syntax. All functions defined
// here work synchronously.

/* DOKUWIKI:include_once crypto_low-level.js */

var tag_enc="ENCRYPTED";
var tag_pt="SECRET";
var crypt_keys=[];

function getKeyForLock(lock) {
	return crypt_keys[lock];
}

function setKeyForLock(lock,key) {
	crypt_keys[lock]=key;
}

/* decrypt the text between <ENCRYPTED> and </ENCRYPTED> */
function decryptMixedText(x) {
  var tag=tag_enc;
  var ret="", key="", ctext="";
  var tagend=0, opentag=0, blockend=0, pos=0;
  while((cur=x.indexOf("<" + tag,pos))!=-1) {
    if((opentag_end=x.indexOf(">",cur))==-1) {
      alert("unable to close to open tag"); return(false);
    }
    if((closetag=x.indexOf("</" + tag + ">",opentag_end))==-1) {
      alert("unable to find closing of " + tag + " tag"); return(false);
    }
    if(!(ctext=decryptBlock(x.substring(cur,closetag+tag.length+3)))) {
      return(false);
    }
    ret+=x.substring(pos,cur) + ctext;
    pos=closetag+tag.length+3;
  }
  ret+=x.substring(pos);
  return(ret);
}

/**
 * Tries to encrypt a given text with <SECRET>s contained. Works and returns synchronously.
 *
 * @param  string   x   The text to be encrypted (usually that's the content of the
 *                      textfield containing the wiki pages text source).
 *
 * @return string       The encrypted mixed text, if all <SECRET>s could be encrypted with
 *                      an already cached key or if there were no <SECRET>s contained.
 *                      Returns null, if a key still must be provided.
 */
function encryptMixedText(x) {
  var tag=tag_pt;
  var ret="", kctext="";
  var tagend=0, opentag=0, blockend=0, pos=0;
  while((cur=x.indexOf("<" + tag,pos))!=-1) {
    if((opentag_end=x.indexOf(">",cur))==-1) {
      alert("unable to find closing angle bracked of <SECRET> tag"); return(null);
    }
    if((closetag=x.indexOf("</" + tag + ">",opentag_end))==-1) {
      x=x+"</" + tag + ">";
      // if there is no close tag, add one to the end.
      //closetag=x.indexOf("</" + tag + ">",opentag_end); // removed this because it can cause the loss of plaintext that was not intended to be encrypted (e.g. unvoluntarily encrypting <SECRET>1<(SECRET>... would encrypt more text than intended just because of a syntax error.
      alert("unable to find close of " + tag + " tag"); return(false);
    }
    if(!(ctext=encryptBlock(x.substring(cur,closetag+tag.length+3)))) {
      return(null);
    }
    ret+=x.substring(pos,cur) + ctext;
    pos=closetag+tag.length+3;
  }
  ret+=x.substring(pos);
  return(ret);
}

function decryptBlock(data) {
  var tagend=0, ptend=0, lock=null, ptext;
  if((tagend=data.indexOf(">"))==-1) {
    //crypt_debug("no > in " + data);
    return(false);
  }
  if((ptend=data.lastIndexOf("</"))==-1) {
    //crypt_debug(" no </ in " + data);
    return(false);
  }
  lock=getTagAttr(data.substring(0,tagend+1),"LOCK");
  if(lock===null) { lock="default"; }

  collapsed=getTagAttr(data.substring(0,tagend+1),"COLLAPSED");
  if(collapsed===null || collapsed=="null") { collapsed="1"; }

  var key=getKeyForLock(lock);
  if(key===false) {
    return(false);
  } else {
    if(!(ptext=decryptTextString(data.substring(tagend+1,ptend),key))) {
      return(false);
    }
  }
  return("<" + tag_pt + " LOCK=" + lock + " " +
     "COLLAPSED=" + collapsed + ">" + ptext + "</" + tag_pt + ">");
}

// for getTagAttr("<FOO ATTR=val>","ATTR"), return "val"
function getTagAttr(opentag,attr) {
  var loff=0;
  if((loff=opentag.indexOf(attr + "=" ))!=-1) {
    if((t=opentag.indexOf(" ",loff+attr.length+1))!=-1) {
      return(opentag.substring(loff+attr.length+1,t));
    } else {
      return(opentag.substring(loff+attr.length+1,opentag.length-1));
    }
  }
  return(null);
}

/**
 * Tries to encrypt a given <SECRET> block. Works and returns synchronously.
 *
 * @param string   data   A block of text to be encrypted. This should be a text enclosed by a <SECRET> tag, which also contains arguments LOCK and COLLAPSED.
 *
 * @return string The encrypted block as a string value. Returns null if there was no key chached for the LOCK specified in the given block.
 */
function encryptBlock(data) {
  var tagend=0, ptend=0, lock=null, ctext;
  var collapsed = "1";

  if((tagend=data.indexOf(">"))==-1) {
    //crypt_debug("no > in " + data);
    return(null);
  }
  if((ptend=data.lastIndexOf("</"))==-1) {
    //crypt_debug(" no </ in " + data);
    return(null);
  }
  lock=getTagAttr(data.substring(0,tagend+1),"LOCK");
  if(lock===null) { lock="default"; }

  collapsed=getTagAttr(data.substring(0,tagend+1),"COLLAPSED");
  if(collapsed===null || collapsed=="null") { collapsed="1"; }

  var key=getKeyForLock(lock);
  if(key===false) {
    return(null);
  } else {
    if(!(ctext=encryptTextString(data.substring(tagend+1,ptend),key))) {
      return(null);
    }
    return("<"+tag_enc+" LOCK=" + lock + " " + "COLLAPSED=" + collapsed + ">" + ctext + "</"+tag_enc+">");
  }
}


/* encrypt the string in text with ascii key in akey
  modified from Encrypt_Text to expect ascii key and take input params
  and to return base64 encoded
*/
function encryptTextString(ptext,akey) {
  var v, i, ret, key;
  var prefix = "#####  Encrypted: decrypt with ";
  prefix+="http://www.fourmilab.ch/javascrypt/\n";
  suffix = "#####  End encrypted message\n";

  if (akey.length === 0) {
    alert("Please specify a key with which to encrypt the message.");
    return;
  }
  if (ptext.length === 0) {
    alert("No plain text to encrypt!");
    return;
  }
  ret="";
  key=setKeyFromAscii(akey);

  // addEntroptyTime eventually results in setting of global entropyData
  // which is used by keyFromEntropy
  addEntropyTime();
  prng = new AESprng(keyFromEntropy());
  var plaintext = encode_utf8(ptext);

  //  Compute MD5 sum of message text and add to header

  md5_init();
  for (i = 0; i < plaintext.length; i++) {
    md5_update(plaintext.charCodeAt(i));
  }
  md5_finish();
  var header = "";
  for (i = 0; i < digestBits.length; i++) {
    header += String.fromCharCode(digestBits[i]);
  }

  //  Add message length in bytes to header

  i = plaintext.length;
  header += String.fromCharCode(i >>> 24);
  header += String.fromCharCode(i >>> 16);
  header += String.fromCharCode(i >>> 8);
  header += String.fromCharCode(i & 0xFF);

  /*  The format of the actual message passed to rijndaelEncrypt
  is:
     Bytes  Content
     0-15   MD5 signature of plaintext
     16-19  Length of plaintext, big-endian order
     20-end Plaintext

  Note that this message will be padded with zero bytes
  to an integral number of AES blocks (blockSizeInBits / 8).
  This does not include the initial vector for CBC
  encryption, which is added internally by rijndaelEncrypt.
  */

  var ct = rijndaelEncrypt(header + plaintext, key, "CBC");
  delete prng;
  return(prefix + armour_base64(ct) + suffix);
}

function decryptTextString(ctext,akey) {
  key=setKeyFromAscii(akey);
  var ct=[];

  // remove line breaks
  ct=disarm_base64(ctext);
  var result=rijndaelDecrypt(ct,key,"CBC");
  var header=result.slice(0,20);
  result=result.slice(20);
  var dl=(header[16]<<24)|(header[17]<<16)|(header[18]<<8)|header[19];

  if((dl<0)||(dl>result.length)) {
   // alert("Message (length "+result.length+") != expected (" + dl + ")");
   dl=result.length;
  }

  var i,plaintext="";
  md5_init();

  for(i=0;i<dl;i++) {
    plaintext+=String.fromCharCode(result[i]);
    md5_update(result[i]);
  }

  md5_finish();

  successful = true;

  for(i=0;i<digestBits.length;i++) {
    if(digestBits[i]!=header[i]) {
      //crypt_debug("Invalid decryption key.");
      return(false);
    }
  }
  return(decode_utf8(plaintext));
}
