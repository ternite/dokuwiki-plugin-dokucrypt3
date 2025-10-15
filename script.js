/* DOKUWIKI:include_once crypto_high-level.js */


/**
 * Handles necessary actions before submitting the 'wikitext' edit form.
 */
var currentSubmitter = null;

function editFormOnSubmit(e) {
  if (e && e.submitter) {
    let curSub = e.submitter;
	if (curSub.name.length==0) return false;
	if (curSub.name.includes("cancel")) return true;
    
	// only store the submitter if we got this far
	currentSubmitter = curSub;
  }
  
  if (async_getKey_active) return false;

  if(hasUnencryptedSecrets()) {
    askForEncryptPasswordWithVerification();
    return false;
  } else {
    // there is no unencrypted content, so we can prepare submitting the form, now

    // Move the original wiki_text element out of the form like we used to do in decryptEditSetup().
    // To prevent accidental submission of unencrypted text.
    var wikitext=document.getElementById('wiki__text');
    var editform=document.getElementById('dw__editform');
    editform.parentNode.insertBefore(wikitext,editform);
    
    // Now, get the wikitext content to our hidden field
    var hiddentext=document.getElementById('wiki__text_submit');
    hiddentext.value=wikitext.value;

    return true;
  }
}

/**
 * Setup the edit form: add the decrypt button and necessary functionality.
 */
function decryptEditSetup(msg) {
    //alert('setting up');
    var editform=null, wikitext=null, hiddentext=null, preview=null;
    if(!(editform=document.getElementById('dw__editform'))) {
      // alert("no form dw__editform\n");
      return(true);
    }
    if(!(wikitext=document.getElementById('wiki__text'))) {
     // alert("no wiki__text");
     return(false);
    }
    // if there is no preview button, then assume this is a
    // "Recover draft" page, dont do anything.
    if(!(preview=document.getElementById('edbtn__preview'))) {
      return(false);
    }
    
    if(!(save=document.getElementById('edbtn__save'))) {
      return(false);
    }

    // Create a hidden element with id 'wiki__text_submit' and
    // name wikitext (same as the wiki__text).

    if(!(hiddentext=document.createElement('input'))) {
     return(false);
    }

    hiddentext.setAttribute('id', 'wiki__text_submit');
    hiddentext.setAttribute('name', 'wikitext');
    hiddentext.setAttribute('type','hidden');
    editform.insertBefore(hiddentext,null);

    if(!(decryptButton=document.createElement('input'))) {
     return(false);
    }
    decryptButton.setAttribute('id', 'decryptButton');
    decryptButton.setAttribute('name', 'decryptButton');
    decryptButton.setAttribute('type','Button');
    decryptButton.setAttribute('value','DecryptSecret');
    decryptButton.onclick=decryptButtonOnClick;
    decryptButton.setAttribute('class','button');
    decryptButton.setAttribute('className','button'); // required for IE
    preview.parentNode.insertBefore(decryptButton,preview);
	
    editform.onsubmit = function() {return editFormOnSubmit(event);};

    // The following is taken from lib/scripts/locktimer.js (state of 2018-06-08) to make drafts work.
    // We override the locktimer refresh function to abort saving of drafts with unencrypted content.
    dw_locktimer.refresh = function(){

        var now = new Date(),
                params = 'call=lock&id=' + dw_locktimer.pageid + '&';

            // refresh every half minute only
            if(now.getTime() - dw_locktimer.lasttime.getTime() <= 30*1000) {
                return;
            }

            // POST everything necessary for draft saving
            if(dw_locktimer.draft && jQuery('#dw__editform').find('textarea[name=wikitext]').length > 0){

                // *** BEGIN dokucrypt modified code
                // Do not allow saving of a draft, if this page needs some content to be encrypted on save.
                // Basically abort saving of drafts if this page has some content that needs encrypting.
                if (hasUnencryptedSecrets()) { return(false); }
                // *** END dokucrypt modified code

                params += jQuery('#dw__editform').find(dw_locktimer.fieldsToSaveAsDraft.join(', ')).serialize();
            }

            jQuery.post(
                DOKU_BASE + 'lib/exe/ajax.php',
                params,
                dw_locktimer.refreshed,
                'json'
            );
            dw_locktimer.lasttime = now;
    };
}

/**
 * Checks of there are <SECRET> blocks in the wikitext by trying to encrypt a given text
 * with <SECRET>s contained. Works and returns synchronously.
 *
 * @param  string   x   The text to be encrypted (usually that's the content of the
 *                      textfield containing the wiki pages text source).
 *
 * @return boolean      true, if there are <SECRET> blocks contained. Otherwise false.
 */
function hasUnencryptedSecrets() {
  var wikitext=null, hiddentext=null;
  if(!(wikitext=document.getElementById('wiki__text'))) {
    alert("failed to get wiki__text");
    return(false);
  }
  if (wikitext.value.includes("<" + tag_pt))
    return true;
  else
    return false;
}

/**
 * Adds an input dialog to the edit page to ask the user for the encryption password. Works with callbacks and therefore represents an asynchronous workflow.
 */
function askForEncryptPasswordWithVerification() {
  var wikitext = document.getElementById('wiki__text');
  var hiddentext=document.getElementById('wiki__text_submit');
  
  lock = "default";
  
  // callback manages what to do and where to insert the decrypted text to
  // call pw_prompt and let the callback call the next pw_prompt for input verification (repeat passwort)
  do_verification = function(key) {
    
    do_encryption = function(key2) {
      if (key != key2) {
        alert("Die Passwörter stimmen nicht überein!");
        return;
      }
      
      // important: cache the key first, then try to do the encryption!
      setKeyForLock(lock,key);
      
      var encrypted_text = encryptMixedText(wikitext.value);
      if (encrypted_text) {
        wikitext.value=encrypted_text;
        hiddentext.value=encrypted_text;
		
		// retry submit
		currentSubmitter.click();
      } else {
        setKeyForLock(lock,null);
        alert("Der Text konnte nicht verschlüsselt werden!");
		currentSubmitter = null;
      }
    };
	
    pw_prompt({
      lm:"Bitte Kennwort erneut eingeben", // "Enter passphrase for lock " + lock);
      elem:wikitext,
      submit_callback:do_encryption
    });
	
  };
  
  pw_prompt({
    lm:"Bitte Kennwort eingeben", // "Enter passphrase for lock " + lock);
    elem:wikitext,
    submit_callback:do_verification
  });
}

function askForDecryptPassword() {
  var wikitext = document.getElementById('wiki__text');
  var hiddentext=document.getElementById('wiki__text_submit');
  
  lock = "default";
  
  // callback manages what to do and where to insert the decrypted text to
  do_decryption = function(key) {
    // important: cache the key first, then try to do the decryption!
    setKeyForLock(lock,key);
      
    var decrypted_text = decryptMixedText(wikitext.value);
    if (decrypted_text) {
      wikitext.value=decrypted_text;
      hiddentext.value=decrypted_text;
    } else {
      setKeyForLock(lock,null);
      alert("Der Text konnte nicht entschlüsselt werden!");
    }
  };
  
  pw_prompt({
    lm:"Bitte Kennwort eingeben", // "Enter passphrase for lock " + lock);
    elem:wikitext,
    submit_callback:do_decryption
  });
  
}

/**
 * Handles the actions after clicking the Decrypt button in the edit form. Tries to
 * decrypt any <ENCRYPTED> blocks.
 */
function decryptButtonOnClick() {
  askForDecryptPassword();
  return(true);
}

function toggleElemVisibility(elemid) {
   elem=document.getElementById(elemid);
   if(elem.style.visibility=="visible") {
      elem.style.visibility="hidden";
      elem.style.position="absolute";
   } else {
      elem.style.visibility="visible";
      elem.style.position="relative";
   }
}

/*
  this is called from <A HREF=> links to decrypt the inline html
*/
function toggleCryptDiv(elemid,lock,ctext) {
   var elem=null, atab=null, ptext="";
   var ctStr="anzeigen", ptStr="verstecken";
   elem=document.getElementById(elemid);
   atag=document.getElementById(elemid + "_atag");
   if(elem===null || atag===null) {
      alert("failed to find element id " + elemid);
   }
   if(atag.innerHTML==ptStr) {
      // encrypt text (set back to ctext, and forget key)
      elem.innerHTML=ctext;
      atag.innerHTML=ctStr;
      elem.style.visibility="hidden";
      elem.style.position="absolute";
      setKeyForLock(lock,undefined);
   } else if (atag.innerHTML==ctStr) {
      // decrypt text
      
      // callback manages what to do and where to insert the decrypted text to
      do_decryption = function(given_key) {
		//try the decryption
        if(!(ptext=decryptTextString(ctext,given_key))) {
          alert("Kein passendes Kennwort eingegeben");
          return;
        }

        elem.textContent=ptext;
        atag.innerHTML=ptStr;
        // make it visible
        elem.style.visibility="visible";
        elem.style.position="relative";
        
        //store the key that was used
        setKeyForLock(lock,given_key);
          
        if (JSINFO["plugin_dokucrypt3_CONFIG_copytoclipboard"] == 1) {
          //put it into the clipboard
          copyToClipboard(ptext).then(() => {
            if (JSINFO['plugin_dokucrypt3_CONFIG_hidepasswordoncopytoclipboard']) {
              elem.textContent = "{" + JSINFO['plugin_dokucrypt3_TEXT_copied_to_clipboard'] + "}";
            } else {
              elem.textContent += " {" + JSINFO['plugin_dokucrypt3_TEXT_copied_to_clipboard'] + "}";
            };
            console.log('Das Passwort wurde in die Zwischenablage kopiert.');
          }).catch(() => {
            console.log('Das Passwort konnte nicht in die Zwischenablage kopiert.');
          });
        }
      };
		
      // now test if there is a key cached for the given lock - if no key can be determined, show password prompt
      var key = getKeyForLock(lock);
      if(key===false || key===undefined || key === null || !decryptTextString(ctext,key)) {
		pw_prompt({
          lm:"Bitte Kennwort eingeben", // "Enter passphrase for lock " + lock);
          lock:lock,
          elem:elem,
          submit_callback:do_decryption
        });

      } else {
        do_decryption(key);
      }
   } else { alert("Broken"); return; }
}

//copy to clipboard from: https://stackoverflow.com/questions/51805395/navigator-clipboard-is-undefined

function copyToClipboard(textToCopy) {
    // navigator clipboard api needs a secure context (https)
    if (navigator.clipboard && window.isSecureContext) {
        // navigator clipboard api method'
        return navigator.clipboard.writeText(textToCopy);
    } else {
        // text area method
        let textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        // make the textarea out of viewport
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        return new Promise((res, rej) => {
            // here the magic happens
            document.execCommand('copy') ? res() : rej();
            textArea.remove();
        });
    }
}

// protected password prompt adapted from: https://stackoverflow.com/a/28461750/19144619
var promptElem = null;
var label = null;
var input = null;
var submit_button = null;
var cancel_button = null;
var submit_event = null;
var cancel_event = null;
var enter_event = null;
var async_getKey_active = false; // tracks whether the user is currently being asked for a key
  
window.pw_prompt = function(options) {
    var lm = options.lm || "Passwort:",
        bm = options.bm || "OK",
        cm = options.cm || "Abbrechen",
        elem = options.elem || document.body,
		submit_callback = options.submit_callback;

    if(!submit_callback) { // callback manages what to do and where to insert the decrypted text to  
        alert("No callback function for submitting provided! Please provide one - it should handle the actions after submitting the pw_prompt.") 
    };

    if (promptElem == null) {
        promptElem = document.createElement("div");
        promptElem.className = "dokucrypt3pw_prompt";
        
        label = document.createElement("label");
        label.textContent = lm;
        label.for = "pw_prompt_input";
        promptElem.appendChild(label);
    
        input = document.createElement("input");
        input.id = "pw_prompt_input";
        input.type = "password";
        promptElem.appendChild(input);
    
        submit_button = document.createElement("button");
        promptElem.appendChild(submit_button);
    
        cancel_button = document.createElement("button");
        promptElem.appendChild(cancel_button);
    } else {
        //remove event listeners
        submit_button.removeEventListener("click", submit_event);
        cancel_button.removeEventListener("click", cancel_event);
    }
    
    submit_event = function() {
        if (promptElem.parentNode)
            promptElem.parentNode.removeChild(promptElem);
        async_getKey_active = false;
        submit_callback(input.value);
    };
    cancel_event = function() {
        if (promptElem.parentNode)
            promptElem.parentNode.removeChild(promptElem);
        async_getKey_active = false;
    };
	
    label.textContent = lm;
    input.value = "";
    submit_button.textContent = bm;
    submit_button.addEventListener("click", submit_event, false);
    cancel_button.textContent = cm;
    cancel_button.addEventListener("click", cancel_event, false);

    if(elem.nextSibling){
        elem.parentNode.insertBefore(promptElem,elem.nextSibling);
    } else {
        elem.parentNode.appendChild(promptElem);
    }
    
    async_getKey_active = true;
    input.focus();
};
