
const CryptoHelper = new (class {
    base64ToArrayBuffer(base64) {
        var binary_string = window.atob(base64);
        var len = binary_string.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }
  
    arrayBufferToBase64(buffer) {
        var binary = '';
        var bytes = new Uint8Array( buffer );
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode( bytes[ i ] );
        }
        return window.btoa( binary );
    }
  
    // async exportCryptoKey(key) {
    //   const exported = await window.crypto.subtle.exportKey(
    //     "spki",
    //     key
    //   );
    //   const exportedAsString = CryptoHelper.arrayBufferToBase64(exported);
    //   const exportedAsBase64 = window.btoa(exportedAsString);
    //   const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  
    //   return pemExported;
    // }
  
    // async generateKey(){
    //   return await window.crypto.subtle.generateKey(
    //     {
    //       name: "RSA-OAEP",
    //       modulusLength: 4096,
    //       publicExponent: new Uint8Array([1, 0, 1]),
    //       hash: "SHA-256"
    //     },
    //     true,
    //     ["encrypt", "decrypt"]
    //   );
    // }
  
    async importPrivateKey(spki){
      const pemHeader = "-----BEGIN PRIVATE KEY-----";
      const pemFooter = "-----END PRIVATE KEY-----";
      const pemContents = spki.substring(pemHeader.length, spki.length - pemFooter.length - 1).replaceAll('\n','');
      const binaryDer = this.base64ToArrayBuffer(pemContents);
      var cryptoPriKey = await window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
          name: 'RSA-OAEP',
          modulusLength: 256,
          hash:  { name: 'sha-256' }
        },
        false,
        ["decrypt"]
      );
      this.cryptoPriKey = cryptoPriKey;
    }
    
    async importPublicKey(spki){
      const pemHeader = "-----BEGIN PUBLIC KEY-----";
      const pemFooter = "-----END PUBLIC KEY-----";
      const pemContents = spki.substring(pemHeader.length, spki.length - pemFooter.length - 1).replaceAll('\n','');
      const binaryDer = this.base64ToArrayBuffer(pemContents);
      var cryptoPubKey = await window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
          name: 'RSA-OAEP',
          modulusLength: 256,
          hash:  { name: 'sha-256' }
        },
        false,
        ["encrypt"]
      );
      this.cryptoPubKey = cryptoPubKey;
    }
  
    async encryptData(message){
      let enc = new TextEncoder();
      let encodedMessage = enc.encode(message);
      var encryptedData = await window.crypto.subtle.encrypt(
        {name: "RSA-OAEP"},
        this.cryptoPubKey,
        encodedMessage
      );
      var encodedData = this.arrayBufferToBase64(encryptedData);
      return encodedData;
    }
  
    async decryptData(message){
      let enc = new TextEncoder();
      let encodedMessage = enc.encode(message);
      var decryptedData = await window.crypto.subtle.decrypt(
        {name: "RSA-OAEP"},
        this.cryptoPriKey,
        encodedMessage
      );
      var encodedData = this.arrayBufferToBase64(decryptedData);
      return encodedData;
    }
  
})();
  