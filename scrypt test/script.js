
document.addEventListener('DOMContentLoaded', () => {
    // Card Click Handlers for Home Page
    const classicalCiphersCard = document.getElementById('classical-ciphers-card');
    const streamBlockCiphersCard = document.getElementById('stream-block-ciphers-card');
    const asymmetricEncryptionCard = document.getElementById('asymmetric-encryption-card');
    const hashFunctionsCard = document.getElementById('hash-functions-card');

    if (classicalCiphersCard) {
        classicalCiphersCard.addEventListener('click', () => {
            window.location.href = 'classical-ciphers.html'; // Redirect to classical-ciphers.html
        });
    }

    // Add similar listeners for other cards when you have their target pages
    if (streamBlockCiphersCard) {
        streamBlockCiphersCard.addEventListener('click', () => {
            console.log("Clicked Stream & Block Ciphers. (Page not yet defined)");
             window.location.href = 'stream-block-ciphers.html'; 
        });
    }
    if (asymmetricEncryptionCard) {
        asymmetricEncryptionCard.addEventListener('click', () => {
            console.log("Clicked Asymmetric Encryption. (Page not yet defined)");
             window.location.href = 'asymmetric-encryption.html'; 
        });
    }
    if (hashFunctionsCard) {
        hashFunctionsCard.addEventListener('click', () => {
            console.log("Clicked Hash Functions. (Page not yet defined)");
             window.location.href = 'hash-functions.html'; 
        });
    }
     
        const caesarCipherCard = document.getElementById('caesar-cipher-card');

    if (caesarCipherCard) {
        console.log("Caesar Cipher card element found on classical-ciphers.html!"); // DEBUG LOG
        caesarCipherCard.addEventListener('click', () => {
            console.log("Caesar Cipher card CLICKED! Navigating to caesar-cipher.html"); // DEBUG LOG
            window.location.href = 'caesar-cipher.html';
        });
    }

    const vigenereCipherCard = document.getElementById('vigenere-cipher-card');
    if (vigenereCipherCard) {
        vigenereCipherCard.addEventListener('click', () => {
            window.location.href = 'vigenere-cipher.html';
        });
    }

    // Rail Fence Cipher Card Handler
    const railFenceCipherCard = document.getElementById('rail-fence-cipher-card');
    if (railFenceCipherCard) {
        railFenceCipherCard.addEventListener('click', () => { 
            window.location.href = 'rail-fence-cipher.html';
        }); 
    }
    const playfairCipherCard = document.getElementById('playfair-cipher-card');
    if (playfairCipherCard) {
        playfairCipherCard.addEventListener('click', () => {
            console.log("Playfair Cipher card CLICKED! (Page not yet created)");
             window.location.href = 'playfair-cipher.html'; // 
        });
    }
       const aesCipherCard = document.getElementById('aes-cipher-card');
    if (aesCipherCard) {
        aesCipherCard.addEventListener('click', () => {
            window.location.href = 'aes-cipher.html'; // Redirect to aes-cipher.html
        });
    }

    const rc4CipherCard = document.getElementById('rc4-cipher-card');
    if (rc4CipherCard) {
        rc4CipherCard.addEventListener('click', () => {
            alert("RC4 is a stream cipher, but it's largely considered insecure for new applications due to known vulnerabilities.");
             window.location.href = 'rc4-cipher.html';
        });
    }

    const desCipherCard = document.getElementById('des-cipher-card');
    if (desCipherCard) {
        desCipherCard.addEventListener('click', () => {
            alert("DES is an older block cipher and is considered insecure due to its small key size. It has been replaced by AES.");
            // You can uncomment the line below if you create a specific page for DES:
             window.location.href = 'des-cipher.html';
        });
    }
    // --- Home Icon Functionality ---
    const homeIcon = document.querySelector('.home-icon-link'); 
    if (homeIcon && window.location.pathname.endsWith('/index.html') || window.location.pathname === '/') {
        // If on the index page, clicking home icon could refresh or just log
        homeIcon.addEventListener('click', (event) => {
            event.preventDefault(); 
            console.log("Home icon clicked on main page.");
        });
    }


    //  Search Bar Functionality (Basic Example) 
    const searchInput = document.querySelector('.search-bar input');
    const searchIcon = document.querySelector('.search-bar .search-icon');

    if (searchIcon && searchInput) {
        searchIcon.addEventListener('click', () => {
            performSearch(searchInput.value);
        });
        searchInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                performSearch(searchInput.value);
            }
        });
    }

    function performSearch(query) {
        if (query.trim() !== '') {
            console.log(`Searching for: ${query}`);
          
            alert(`Performing search for: "${query}"`); // For demonstration
        } else {
            console.log("Search query is empty.");
        }
    }

    // Cipher-Specific Logic (Caesar Cipher Example) 
    if (window.location.pathname.includes('caesar-cipher.html')) {
        const inputText = document.getElementById('inputText');
        const caesarKey = document.getElementById('caesarKey');
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        const outputText = document.getElementById('outputText');

        encryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const shift = parseInt(caesarKey.value);
            if (isNaN(shift) || shift < 1 || shift > 25) {
                alert("Please enter a valid shift key between 1 and 25.");
                return;
            }
            outputText.value = caesarEncrypt(text, shift);
        });

        decryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const shift = parseInt(caesarKey.value);
            if (isNaN(shift) || shift < 1 || shift > 25) {
                alert("Please enter a valid shift key between 1 and 25.");
                return;
            }
            outputText.value = caesarDecrypt(text, shift);
        });

        function caesarEncrypt(text, shift) {
            let result = '';
            for (let i = 0; i < text.length; i++) {
                let char = text.charCodeAt(i);
                if (char >= 65 && char <= 90) { // Uppercase letters (A-Z)
                    result += String.fromCharCode(((char - 65 + shift) % 26) + 65);
                } else if (char >= 97 && char <= 122) { // Lowercase letters (a-z)
                    result += String.fromCharCode(((char - 97 + shift) % 26) + 97);
                } else { // Non-alphabetic characters
                    result += text[i];
                }
            }
            return result;
        }

        function caesarDecrypt(text, shift) {
            // Decrypting is simply encrypting with a negative shift (or 26 - shift)
            return caesarEncrypt(text, (26 - shift) % 26);
        }
    }
     if (window.location.pathname.includes('vigenere-cipher.html')) {
        const inputText = document.getElementById('inputText');
        const vigenereKeyInput = document.getElementById('vigenereKey'); // Changed ID to match HTML
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        const outputText = document.getElementById('outputText');

        encryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const keyword = vigenereKeyInput.value;
            outputText.value = vigenereEncrypt(text, keyword);
        });

        decryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const keyword = vigenereKeyInput.value;
            outputText.value = vigenereDecrypt(text, keyword);
        });

        function vigenereEncrypt(text, keyword) {
            let result = '';
            keyword = keyword.toUpperCase().replace(/[^A-Z]/g, ''); // Clean and uppercase keyword
            if (keyword.length === 0) {
                alert("Please enter a valid keyword.");
                return text;
            }

            let keywordIndex = 0;
            for (let i = 0; i < text.length; i++) {
                let char = text.charCodeAt(i);
                let encryptedChar = char;

                if (char >= 65 && char <= 90) { // Uppercase
                    let keyShift = keyword.charCodeAt(keywordIndex % keyword.length) - 65;
                    encryptedChar = ((char - 65 + keyShift) % 26) + 65;
                    keywordIndex++;
                } else if (char >= 97 && char <= 122) { // Lowercase
                    let keyShift = keyword.charCodeAt(keywordIndex % keyword.length) - 65;
                    encryptedChar = ((char - 97 + keyShift) % 26) + 97;
                    keywordIndex++;
                }
                result += String.fromCharCode(encryptedChar);
            }
            return result;
        }

        function vigenereDecrypt(text, keyword) {
            let result = '';
            keyword = keyword.toUpperCase().replace(/[^A-Z]/g, ''); // Clean and uppercase keyword
            if (keyword.length === 0) {
                alert("Please enter a valid keyword.");
                return text;
            }

            let keywordIndex = 0;
            for (let i = 0; i < text.length; i++) {
                let char = text.charCodeAt(i);
                let decryptedChar = char;

                if (char >= 65 && char <= 90) { // Uppercase
                    let keyShift = keyword.charCodeAt(keywordIndex % keyword.length) - 65;
                    decryptedChar = ((char - 65 - keyShift + 26) % 26) + 65; // Add 26 for negative results
                    keywordIndex++;
                } else if (char >= 97 && char <= 122) { // Lowercase
                    let keyShift = keyword.charCodeAt(keywordIndex % keyword.length) - 65;
                    decryptedChar = ((char - 97 - keyShift + 26) % 26) + 97; // Add 26 for negative results
                    keywordIndex++;
                }
                result += String.fromCharCode(decryptedChar);
            }
            return result;
        }
    }
    if (window.location.pathname.includes('rail-fence-cipher.html')) {
        const inputText = document.getElementById('inputText');
        const railsKeyInput = document.getElementById('railsKey');
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        const outputText = document.getElementById('outputText');

        encryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const rails = parseInt(railsKeyInput.value);
            if (isNaN(rails) || rails < 2) {
                alert("Please enter a valid number of rails (2 or more).");
                return;
            }
            outputText.value = railFenceEncrypt(text, rails);
        });

        decryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const rails = parseInt(railsKeyInput.value);
            if (isNaN(rails) || rails < 2) {
                alert("Please enter a valid number of rails (2 or more).");
                return;
            }
            outputText.value = railFenceDecrypt(text, rails);
        });

        function railFenceEncrypt(text, rails) {
            if (rails === 1 || text.length === 0) return text;

            const fence = Array.from({ length: rails }, () => []);
            let rail = 0;
            let direction = 1; // 1 for down, -1 for up

            for (let i = 0; i < text.length; i++) {
                fence[rail].push(text[i]);
                rail += direction;

                if (rail === rails - 1 || rail === 0) {
                    direction *= -1; // Reverse direction
                }
            }

            return fence.map(r => r.join('')).join('');
        }

        function railFenceDecrypt(text, rails) {
            if (rails === 1 || text.length === 0) return text;

            const len = text.length;
            const fence = Array.from({ length: rails }, () => []);
            const decrypted = new Array(len);
            let rail = 0;
            let direction = 1;

            // Mark positions where chars would go in the fence
            const positions = Array.from({ length: rails }, () => []);
            for (let i = 0; i < len; i++) {
                positions[rail].push(i);
                rail += direction;
                if (rail === rails - 1 || rail === 0) {
                    direction *= -1;
                }
            }

            // Fill the fence with characters from the ciphertext
            let charIndex = 0;
            for (let r = 0; r < rails; r++) {
                for (let c = 0; c < positions[r].length; c++) {
                    fence[r].push(text[charIndex++]);
                }
            }

            // Reconstruct the plaintext by going back through the zigzag pattern
            rail = 0;
            direction = 1;
            for (let i = 0; i < len; i++) {
                // Get the character from the correct position in the current rail's queue
                decrypted[positions[rail][0]] = fence[rail].shift();
                
                rail += direction;
                if (rail === rails - 1 || rail === 0) {
                    direction *= -1;
                }
            }
            return decrypted.join('');
        }
    }
    if (window.location.pathname.includes('playfair-cipher.html')) {
        const inputText = document.getElementById('inputText');
        const playfairKeyInput = document.getElementById('playfairKey');
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        const outputText = document.getElementById('outputText');

        let playfairSquare = []; // Store the 5x5 key square

        // Function to build the 5x5 Playfair key square
        function buildPlayfairSquare(keyword) {
            const alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // Note: J is omitted, treated as I
            let key = keyword.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, ''); // Clean keyword, replace J with I
            let uniqueKey = '';

            // Get unique characters from keyword
            for (let char of key) {
                if (uniqueKey.indexOf(char) === -1) {
                    uniqueKey += char;
                }
            }

            let combinedString = uniqueKey + alphabet;
            let squareChars = '';
            for (let char of combinedString) {
                if (squareChars.indexOf(char) === -1) {
                    squareChars += char;
                }
            }

            playfairSquare = [];
            for (let i = 0; i < 5; i++) {
                playfairSquare.push(squareChars.substring(i * 5, (i * 5) + 5).split(''));
            }
        }

        // Function to find the row and column of a character in the square
        function findChar(char) {
            char = char.toUpperCase();
            if (char === 'J') char = 'I'; // Treat J as I
            for (let r = 0; r < 5; r++) {
                for (let c = 0; c < 5; c++) {
                    if (playfairSquare[r][c] === char) {
                        return { row: r, col: c };
                    }
                }
            }
            return null; // Should not happen with valid input
        }

        // Function to prepare plaintext (remove non-alphabetic, replace J, handle double letters and odd length)
        function preparePlayfairText(text) {
            text = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
            let preparedText = '';
            for (let i = 0; i < text.length; i++) {
                preparedText += text[i];
                if (i + 1 < text.length && text[i] === text[i + 1]) {
                    preparedText += 'X'; // Insert 'X' for double letters
                }
            }
            if (preparedText.length % 2 !== 0) {
                preparedText += 'X'; // Pad with 'X' if odd length
            }
            return preparedText;
        }

        // Playfair Encryption Logic
        function playfairEncrypt(text, keyword) {
            buildPlayfairSquare(keyword);
            if (playfairSquare.length === 0 || playfairSquare[0].length === 0) {
                alert("Invalid keyword for Playfair cipher.");
                return "";
            }
            let preparedText = preparePlayfairText(text);
            let ciphertext = '';

            for (let i = 0; i < preparedText.length; i += 2) {
                let char1 = preparedText[i];
                let char2 = preparedText[i + 1];

                let pos1 = findChar(char1);
                let pos2 = findChar(char2);

                if (!pos1 || !pos2) { // Should not happen if preparePlayfairText is correct
                    ciphertext += char1 + char2;
                    continue;
                }

                // Same row
                if (pos1.row === pos2.row) {
                    ciphertext += playfairSquare[pos1.row][(pos1.col + 1) % 5];
                    ciphertext += playfairSquare[pos2.row][(pos2.col + 1) % 5];
                }
                // Same column
                else if (pos1.col === pos2.col) {
                    ciphertext += playfairSquare[(pos1.row + 1) % 5][pos1.col];
                    ciphertext += playfairSquare[(pos2.row + 1) % 5][pos2.col];
                }
                // Different row and column (rectangle)
                else {
                    ciphertext += playfairSquare[pos1.row][pos2.col];
                    ciphertext += playfairSquare[pos2.row][pos1.col];
                }
            }
            return ciphertext;
        }

        // Playfair Decryption Logic
        function playfairDecrypt(text, keyword) {
            buildPlayfairSquare(keyword);
            if (playfairSquare.length === 0 || playfairSquare[0].length === 0) {
                alert("Invalid keyword for Playfair cipher.");
                return "";
            }

            // Decryption requires cleaning, but not padding or inserting X for doubles
            let preparedText = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
            if (preparedText.length % 2 !== 0) {
                alert("Ciphertext length must be even for Playfair decryption.");
                return "";
            }
            let plaintext = '';

            for (let i = 0; i < preparedText.length; i += 2) {
                let char1 = preparedText[i];
                let char2 = preparedText[i + 1];

                let pos1 = findChar(char1);
                let pos2 = findChar(char2);

                if (!pos1 || !pos2) {
                    plaintext += char1 + char2;
                    continue;
                }

                // Same row
                if (pos1.row === pos2.row) {
                    plaintext += playfairSquare[pos1.row][(pos1.col - 1 + 5) % 5];
                    plaintext += playfairSquare[pos2.row][(pos2.col - 1 + 5) % 5];
                }
                // Same column
                else if (pos1.col === pos2.col) {
                    plaintext += playfairSquare[(pos1.row - 1 + 5) % 5][pos1.col];
                    plaintext += playfairSquare[(pos2.row - 1 + 5) % 5][pos2.col];
                }
                // Different row and column (rectangle)
                else {
                    plaintext += playfairSquare[pos1.row][pos2.col];
                    plaintext += playfairSquare[pos2.row][pos1.col];
                }
            }
            // Optional: Remove padding 'X' and inserted 'X's if they weren't part of original plaintext
            // This can be complex and may require user discretion. For simplicity, we'll return raw.
            return plaintext;
        }

        // Event listeners for the Playfair tool buttons
        encryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const keyword = playfairKeyInput.value;
            if (!keyword.trim()) {
                alert("Please enter a keyword for Playfair cipher.");
                return;
            }
            outputText.value = playfairEncrypt(text, keyword);
        });

        decryptBtn.addEventListener('click', () => {
            const text = inputText.value;
            const keyword = playfairKeyInput.value;
            if (!keyword.trim()) {
                alert("Please enter a keyword for Playfair cipher.");
                return;
            }
            outputText.value = playfairDecrypt(text, keyword);
        });
    }
   

    // --- Helper functions for ArrayBuffer to Base64/String conversion ---
    // These functions are generally useful for Web Crypto API interactions.
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function stringToArrayBuffer(str) {
        return new TextEncoder().encode(str).buffer;
    }

    function arrayBufferToString(buffer) {
        return new TextDecoder().decode(buffer);
    }

    // --- AES Cipher-Specific Logic (ADD THIS NEW BLOCK) ---
    // This logic will only run if we are on the aes-cipher.html page
    if (window.location.pathname.includes('aes-cipher.html')) {
        const inputText = document.getElementById('inputText');
        const aesKeyInput = document.getElementById('aesKey');
        const aesIVInput = document.getElementById('aesIV');
        const generateKeyBtn = document.getElementById('generateKeyBtn');
        const generateIVBtn = document.getElementById('generateIVBtn');
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        const outputText = document.getElementById('outputText');

        // Generate a random AES-256 key (256 bits = 32 bytes)
        generateKeyBtn.addEventListener('click', async () => {
            try {
                const key = await crypto.subtle.generateKey(
                    {
                        name: "AES-GCM",
                        length: 256, // 128, 192, or 256 bits
                    },
                    true, // whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] // can be used for these operations
                );
                const exportedKey = await crypto.subtle.exportKey("raw", key);
                aesKeyInput.value = arrayBufferToBase64(exportedKey);
            } catch (error) {
                console.error("Error generating key:", error);
                alert("Error generating key. Check console for details.");
            }
        });

        // Generate a random 12-byte IV (for AES-GCM)
        generateIVBtn.addEventListener('click', () => {
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV is standard for GCM
            aesIVInput.value = arrayBufferToBase64(iv.buffer);
        });

        // Encrypt functionality
        encryptBtn.addEventListener('click', async () => {
            try {
                const text = inputText.value;
                const base64Key = aesKeyInput.value;
                const base64IV = aesIVInput.value;

                if (!text || !base64Key || !base64IV) {
                    alert("Please enter text, key, and IV.");
                    return;
                }

                const keyBuffer = base64ToArrayBuffer(base64Key);
                const ivBuffer = base64ToArrayBuffer(base64IV);
                const textBuffer = stringToArrayBuffer(text);

                const importedKey = await crypto.subtle.importKey(
                    "raw",
                    keyBuffer,
                    { name: "AES-GCM" },
                    true,
                    ["encrypt"]
                );

                const encryptedBuffer = await crypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv: ivBuffer,
                    },
                    importedKey,
                    textBuffer
                );

                outputText.value = arrayBufferToBase64(encryptedBuffer);
            } catch (error) {
                console.error("Encryption error:", error);
                alert("Encryption failed. Make sure key/IV are valid Base64 and correct length. Check console for details.");
            }
        });

        // Decrypt functionality
        decryptBtn.addEventListener('click', async () => {
            try {
                const base64Ciphertext = inputText.value;
                const base64Key = aesKeyInput.value;
                const base64IV = aesIVInput.value;

                if (!base64Ciphertext || !base64Key || !base64IV) {
                    alert("Please enter ciphertext, key, and IV.");
                    return;
                }

 // --- ADD THESE CONSOLE.LOGS FOR DEBUGGING ---
                console.log("Decrypting...");
                console.log("Input Ciphertext (Base64):", base64Ciphertext);
                console.log("Input Key (Base64):", base64Key);
                console.log("Input IV (Base64):", base64IV);
                // --- END DEBUG LOGS ---


                const keyBuffer = base64ToArrayBuffer(base64Key);
                const ivBuffer = base64ToArrayBuffer(base64IV);
                const ciphertextBuffer = base64ToArrayBuffer(base64Ciphertext);
 //adding these consoles to remove the error after checking the console on that page
                console.log("Key Buffer Length (bytes):", keyBuffer.byteLength);
                console.log("IV Buffer Length (bytes):", ivBuffer.byteLength);
                console.log("Ciphertext Buffer Length (bytes):", ciphertextBuffer.byteLength);
                //END DEBUG LOGS 

                const importedKey = await crypto.subtle.importKey(
                    "raw",
                    keyBuffer,
                    { name: "AES-GCM" },
                    true,
                    ["decrypt"]
                );

                const decryptedBuffer = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: ivBuffer,
                    },
                    importedKey,
                    ciphertextBuffer
                );

                outputText.value = arrayBufferToString(decryptedBuffer);
            } catch (error) {
                console.error("Decryption error:", error);
                alert("Decryption failed. Make sure key/IV are valid Base64 and correct length, and ciphertext is correct. Check console for details.");
            }
        });
    }
    


    if (window.location.pathname.includes('rc4-cipher.html')) {
    // Get HTML elements (RC4 specific)
    const plaintextInput = document.getElementById('plaintextInput');
    const encryptionKeyInput = document.getElementById('encryptionKey');
    const encryptButton = document.getElementById('encryptButton');
    const outputCiphertext = document.getElementById('outputCiphertext');

    const ciphertextInput = document.getElementById('ciphertextInput');
    const decryptionKeyInput = document.getElementById('decryptionKey');
    const decryptButton = document.getElementById('decryptButton');
    const outputDecryptedText = document.getElementById('outputDecryptedText');


    function rc4KSA(key) {
        let S = new Uint8Array(256);
        for (let i = 0; i < 256; i++) {
            S[i] = i;
        }

        let j = 0;
        for (let i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.length]) % 256;
            // Swap S[i] and S[j]
            [S[i], S[j]] = [S[j], S[i]];
        }
        return S;
    }


    function rc4PRGA(S, state) {
        let i = state.i;
        let j = state.j;

        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        // Swap S[i] and S[j]
        [S[i], S[j]] = [S[j], S[i]];

        let t = (S[i] + S[j]) % 256;
        let keystreamByte = S[t];

        return { keystreamByte, i, j };
    }

    function rc4(inputString, keyString) {
        const inputBytes = new TextEncoder().encode(inputString);
        const keyBytes = new TextEncoder().encode(keyString);

        if (keyBytes.length === 0) {
            throw new Error("Key cannot be empty for RC4.");
        }

        let S = rc4KSA(keyBytes);
        let i = 0;
        let j = 0;
        let outputBytes = new Uint8Array(inputBytes.length);

        for (let k = 0; k < inputBytes.length; k++) {
            ({ keystreamByte: outputBytes[k], i, j } = rc4PRGA(S, { i, j }));
            outputBytes[k] ^= inputBytes[k]; // XOR with keystream
        }
        return outputBytes;
    }

    // Event Listeners for RC4 
    encryptButton.addEventListener('click', () => {
        const plaintext = plaintextInput.value;
        const key = encryptionKeyInput.value;

        if (!plaintext || !key) {
            alert('Please enter both plaintext and a key for encryption.');
            return;
        }

        try {
            const encryptedBytes = rc4(plaintext, key);
            outputCiphertext.value = arrayBufferToBase64(encryptedBytes); // Reuse your existing helper
        } catch (error) {
            console.error("RC4 Encryption error:", error);
            alert("Encryption failed: " + error.message);
        }
    });

    decryptButton.addEventListener('click', () => {
        const ciphertextBase64 = ciphertextInput.value;
        const key = decryptionKeyInput.value;

        if (!ciphertextBase64 || !key) {
            alert('Please enter both ciphertext and a key for decryption.');
            return;
        }

        try {
            // Decode Base64 ciphertext into bytes
            const decodedBytes = new Uint8Array(base64ToArrayBuffer(ciphertextBase64));

            // To decrypt with RC4, you apply the 'rc4' function again with the *same key*.
            // The rc4 function expects a string input, so we convert decodedBytes back to a string.
            // This string is then passed to rc4 to generate the keystream and XOR it.
            const intermediateString = new TextDecoder().decode(decodedBytes); // This assumes the ciphertext bytes can be meaningfully decoded to a string for the RC4 function's input parameter.
            const decryptedBytes = rc4(intermediateString, key); // Apply RC4 (which also decrypts)

            outputDecryptedText.value = new TextDecoder().decode(decryptedBytes);

        } catch (error) {
            console.error("RC4 Decryption error:", error);
            alert("Decryption failed. Make sure key is correct and ciphertext is valid Base64. Check console for details.");
        }
    });
 
}
// END OF NEW RC4 CIPHER LOGIC
 // DES Cipher Logic
    if (window.location.pathname.includes('des-cipher.html')) {
        const plaintextInput = document.getElementById('desPlaintextInput');
        const encryptionKeyInput = document.getElementById('desEncryptionKey');
        const encryptionIVInput = document.getElementById('desEncryptionIV');
        const encryptButton = document.getElementById('desEncryptButton');
        const outputCiphertext = document.getElementById('desOutputCiphertext');

        const ciphertextInput = document.getElementById('desCiphertextInput');
        const decryptionKeyInput = document.getElementById('desDecryptionKey');
        const decryptionIVInput = document.getElementById('desDecryptionIV');
        const decryptButton = document.getElementById('desDecryptButton');
        const outputDecryptedText = document.getElementById('desOutputDecryptedText');

        // Helper function for Base64 encoding (from your existing script.js)
        // Ensure arrayBufferToBase64 and base64ToArrayBuffer are accessible here if they're not global
        function arrayBufferToBase64(buffer) {
            let binary = '';
            const bytes = new Uint8Array(buffer);
            const len = bytes.byteLength;
            for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }

        function base64ToArrayBuffer(base64) {
            const binary_string = window.atob(base64);
            const len = binary_string.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        }


        // DES Encryption
        encryptButton.addEventListener('click', () => {
            const plaintext = plaintextInput.value;
            const key = encryptionKeyInput.value;
            const iv = encryptionIVInput.value;

            if (!plaintext || !key || !iv) {
                alert('Please enter plaintext, key, and IV for encryption.');
                return;
            }

            if (key.length !== 8) {
                alert('DES Key must be exactly 8 characters long.');
                return;
            }
            if (iv.length !== 8) {
                alert('DES IV must be exactly 8 characters long.');
                return;
            }

            try {
                // Convert key and IV strings to WordArrays for CryptoJS
                const parsedKey = CryptoJS.enc.Utf8.parse(key);
                const parsedIV = CryptoJS.enc.Utf8.parse(iv);

                // Encrypt using DES with CBC mode (default for CryptoJS DES)
                const encrypted = CryptoJS.DES.encrypt(plaintext, parsedKey, {
                    iv: parsedIV,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7 // Common padding scheme
                });

                // Output Base64 encoded ciphertext
                outputCiphertext.value = encrypted.toString(); // CryptoJS toString() returns Base64
            } catch (error) {
                console.error("DES Encryption error:", error);
                alert("Encryption failed: " + error.message);
            }
        });

        // DES Decryption
        decryptButton.addEventListener('click', () => {
            const ciphertextBase64 = ciphertextInput.value;
            const key = decryptionKeyInput.value;
            const iv = decryptionIVInput.value;

            if (!ciphertextBase64 || !key || !iv) {
                alert('Please enter ciphertext, key, and IV for decryption.');
                return;
            }

            if (key.length !== 8) {
                alert('DES Key must be exactly 8 characters long.');
                return;
            }
            if (iv.length !== 8) {
                alert('DES IV must be exactly 8 characters long.');
                return;
            }

            try {
                // Convert key and IV strings to WordArrays for CryptoJS
                const parsedKey = CryptoJS.enc.Utf8.parse(key);
                const parsedIV = CryptoJS.enc.Utf8.parse(iv);

                // Decrypt
                const decrypted = CryptoJS.DES.decrypt(ciphertextBase64, parsedKey, {
                    iv: parsedIV,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });

                // Convert decrypted WordArray to UTF-8 string
                outputDecryptedText.value = decrypted.toString(CryptoJS.enc.Utf8);

            } catch (error) {
                console.error("DES Decryption error:", error);
                alert("Decryption failed. Make sure key/IV are correct and ciphertext is valid Base64. Check console for details.");
            }
        });
    }
 // Hash Functions Logic
    if (window.location.pathname.includes('hash-functions.html')) {
        const hashInput = document.getElementById('hashInput');

        const md5Button = document.getElementById('md5Button');
        const md5Output = document.getElementById('md5Output');

        const sha1Button = document.getElementById('sha1Button');
        const sha1Output = document.getElementById('sha1Output');

        const sha256Button = document.getElementById('sha256Button');
        const sha256Output = document.getElementById('sha256Output');

        const sha512Button = document.getElementById('sha512Button');
        const sha512Output = document.getElementById('sha512Output');

        // MD5 Hash Calculation
        md5Button.addEventListener('click', () => {
            const input = hashInput.value;
            if (!input) {
                alert('Please enter text to hash.');
                return;
            }
            try {
                const hash = CryptoJS.MD5(input);
                md5Output.value = hash.toString(CryptoJS.enc.Hex);
            } catch (error) {
                console.error("MD5 Hashing error:", error);
                alert("MD5 Hashing failed: " + error.message);
            }
        });

        // SHA-1 Hash Calculation
        sha1Button.addEventListener('click', () => {
            const input = hashInput.value;
            if (!input) {
                alert('Please enter text to hash.');
                return;
            }
            try {
                const hash = CryptoJS.SHA1(input);
                sha1Output.value = hash.toString(CryptoJS.enc.Hex);
            } catch (error) {
                console.error("SHA-1 Hashing error:", error);
                alert("SHA-1 Hashing failed: " + error.message);
            }
        });

        // SHA-256 Hash Calculation
        sha256Button.addEventListener('click', () => {
            const input = hashInput.value;
            if (!input) {
                alert('Please enter text to hash.');
                return;
            }
            try {
                const hash = CryptoJS.SHA256(input);
                sha256Output.value = hash.toString(CryptoJS.enc.Hex);
            } catch (error) {
                console.error("SHA-256 Hashing error:", error);
                alert("SHA-256 Hashing failed: " + error.message);
            }
        });

        // SHA-512 Hash Calculation
        sha512Button.addEventListener('click', () => {
            const input = hashInput.value;
            if (!input) {
                alert('Please enter text to hash.');
                return;
            }
            try {
                const hash = CryptoJS.SHA512(input);
                sha512Output.value = hash.toString(CryptoJS.enc.Hex);
            } catch (error) {
                console.error("SHA-512 Hashing error:", error);
                alert("SHA-512 Hashing failed: " + error.message);
            }
        });
    }
 // Asymmetric Encryption Logic (RSA and Diffie-Hellman)
    if (window.location.pathname.includes('asymmetric-encryption.html')) {
        //  RSA ELEMENTS 
        const generateKeyPairButton = document.getElementById('generateKeyPairButton');
        const publicKeyOutput = document.getElementById('publicKeyOutput');
        const privateKeyOutput = document.getElementById('privateKeyOutput');

        const rsaPlaintextInput = document.getElementById('rsaPlaintextInput');
        const rsaEncryptionPublicKeyInput = document.getElementById('rsaEncryptionPublicKeyInput');
        const rsaEncryptButton = document.getElementById('rsaEncryptButton');
        const rsaOutputCiphertext = document.getElementById('rsaOutputCiphertext');

        const rsaCiphertextInput = document.getElementById('rsaCiphertextInput');
        const rsaDecryptionPrivateKeyInput = document.getElementById('rsaDecryptionPrivateKeyInput');
        const rsaDecryptButton = document.getElementById('rsaDecryptButton');
        const rsaOutputDecryptedText = document.getElementById('rsaOutputDecryptedText');

        // DIFFIE-HELLMAN ELEMENTS 
        const generateAliceKeysButton = document.getElementById('generateAliceKeysButton');
        const alicePrivateKeyOutput = document.getElementById('alicePrivateKeyOutput');
        const alicePublicKeyOutput = document.getElementById('alicePublicKeyOutput');
        const aliceBobsPublicKeyInput = document.getElementById('aliceBobsPublicKeyInput');
        const deriveAliceSharedSecretButton = document.getElementById('deriveAliceSharedSecretButton');
        const aliceSharedSecretOutput = document.getElementById('aliceSharedSecretOutput');

        const generateBobKeysButton = document.getElementById('generateBobKeysButton');
        const bobPrivateKeyOutput = document.getElementById('bobPrivateKeyOutput');
        const bobPublicKeyOutput = document.getElementById('bobPublicKeyOutput');
        const bobAlicesPublicKeyInput = document.getElementById('bobAlicesPublicKeyInput');
        const deriveBobSharedSecretButton = document.getElementById('deriveBobSharedSecretButton');
        const bobSharedSecretOutput = document.getElementById('bobSharedSecretOutput');


        // RSA FUNCTIONS 

        // Generate RSA Key Pair
        generateKeyPairButton.addEventListener('click', async () => {
            try {
                const keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048, // Can be 1024, 2048, 4096
                        publicExponent: new Uint8Array([1, 0, 1]), // 65537
                        hash: "SHA-256",
                    },
                    true,
                    ["encrypt", "decrypt"]
                );

                const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
                const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

                publicKeyOutput.value = JSON.stringify(publicKeyJwk, null, 2);
                privateKeyOutput.value = JSON.stringify(privateKeyJwk, null, 2);

            } catch (error) {
                console.error("RSA Key Generation error:", error);
                alert("Failed to generate RSA key pair: " + error.message);
            }
        });

        // RSA Encryption
        rsaEncryptButton.addEventListener('click', async () => {
            const plaintext = rsaPlaintextInput.value;
            const publicKeyJwkStr = rsaEncryptionPublicKeyInput.value;

            if (!plaintext || !publicKeyJwkStr) {
                alert("Please enter plaintext and a public key.");
                return;
            }

            try {
                const publicKeyJwk = JSON.parse(publicKeyJwkStr);
                const publicKey = await window.crypto.subtle.importKey(
                    "jwk",
                    publicKeyJwk,
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-256",
                    },
                    true, 
                    ["encrypt"]
                );

                const encodedPlaintext = new TextEncoder().encode(plaintext);

                // RSA-OAEP has plaintext length limitations. For 2048-bit key (256 bytes), the max plaintext is around 190 bytes.
                // If plaintext is too long, the encrypt method will throw an error.
                if (encodedPlaintext.byteLength > 190) { // Rough estimate for 2048-bit RSA-OAEP SHA-256
                    alert("Plaintext is too long for RSA-OAEP 2048-bit encryption. Max ~190 characters for English text. Please shorten it.");
                    return;
                }

                const ciphertextBuffer = await window.crypto.subtle.encrypt(
                    {
                        name: "RSA-OAEP"
                    },
                    publicKey,
                    encodedPlaintext
                );

                rsaOutputCiphertext.value = arrayBufferToBase64(ciphertextBuffer);

            } catch (error) {
                console.error("RSA Encryption error:", error);
                alert("RSA Encryption failed: " + error.message + ". Check if public key is valid and plaintext is not too long.");
            }
        });

        // RSA Decryption
        rsaDecryptButton.addEventListener('click', async () => {
            const ciphertextBase64 = rsaCiphertextInput.value;
            const privateKeyJwkStr = rsaDecryptionPrivateKeyInput.value;

            if (!ciphertextBase64 || !privateKeyJwkStr) {
                alert("Please enter ciphertext and a private key.");
                return;
            }

            try {
                const privateKeyJwk = JSON.parse(privateKeyJwkStr);
                const privateKey = await window.crypto.subtle.importKey(
                    "jwk",
                    privateKeyJwk,
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-256",
                    },
                    true, 
                    ["decrypt"]
                );

                const ciphertextBuffer = base64ToArrayBuffer(ciphertextBase64);

                const decryptedBuffer = await window.crypto.subtle.decrypt(
                    {
                        name: "RSA-OAEP"
                    },
                    privateKey,
                    ciphertextBuffer
                );

                rsaOutputDecryptedText.value = new TextDecoder().decode(decryptedBuffer);

            } catch (error) {
                console.error("RSA Decryption error:", error);
                alert("RSA Decryption failed: " + error.message + ". Make sure private key and ciphertext are correct.");
            }
        });


        // DIFFIE-HELLMAN FUNCTIONS (ECDH using P-256 curve) 

        let aliceKeys = null; // Store Alice's generated keys
        let bobKeys = null;   // Store Bob's generated keys

        // Generate Alice's DH Keys
        generateAliceKeysButton.addEventListener('click', async () => {
            try {
                aliceKeys = await window.crypto.subtle.generateKey(
                    {
                        name: "ECDH",
                        namedCurve: "P-256", // Standard curve (e.g., P-256, P-384, P-521)
                    },
                    true, // extractable
                    ["deriveKey", "deriveBits"] // Usages for DH
                );

                const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", aliceKeys.privateKey);
                const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", aliceKeys.publicKey);

                alicePrivateKeyOutput.value = JSON.stringify(privateKeyJwk, null, 2);
                alicePublicKeyOutput.value = JSON.stringify(publicKeyJwk, null, 2);

            } catch (error) {
                console.error("Alice DH Key Generation error:", error);
                alert("Failed to generate Alice's DH key pair: " + error.message);
            }
        });

        // Derive Alice's Shared Secret
        deriveAliceSharedSecretButton.addEventListener('click', async () => {
            const bobsPublicKeyJwkStr = aliceBobsPublicKeyInput.value;

            if (!aliceKeys || !aliceKeys.privateKey) {
                alert("Please generate Alice's keys first.");
                return;
            }
            if (!bobsPublicKeyJwkStr) {
                alert("Please paste Bob's Public Key.");
                return;
            }

            try {
                const bobsPublicKeyJwk = JSON.parse(bobsPublicKeyJwkStr);
                const bobsPublicKey = await window.crypto.subtle.importKey(
                    "jwk",
                    bobsPublicKeyJwk,
                    {
                        name: "ECDH",
                        namedCurve: "P-256",
                    },
                    false, // Not extractable for public key import (unless specifically needed later)
                    [] // No usages needed for importing a public key for derivation
                );

                // Derive the shared secret bits using Alice's private key and Bob's public key
                const sharedSecretBuffer = await window.crypto.subtle.deriveBits(
                    {
                        name: "ECDH",
                        public: bobsPublicKey
                    },
                    aliceKeys.privateKey, // Alice's private key
                    256 // Length of the derived bits in bits (e.g., 256 for a SHA-256-sized secret)
                );

                // Hash the derived bits to get a fixed-size secret (good practice for shared secrets)
                const hashedSecretBuffer = await window.crypto.subtle.digest("SHA-256", sharedSecretBuffer);

                aliceSharedSecretOutput.value = arrayBufferToBase64(hashedSecretBuffer);

            } catch (error) {
                console.error("Alice DH Shared Secret Derivation error:", error);
                alert("Failed to derive Alice's shared secret: " + error.message + ". Ensure Bob's public key is valid and matches the curve.");
            }
        });


        // Generate Bob's DH Keys
        generateBobKeysButton.addEventListener('click', async () => {
            try {
                bobKeys = await window.crypto.subtle.generateKey(
                    {
                        name: "ECDH",
                        namedCurve: "P-256", // Standard curve
                    },
                    true, // extractable
                    ["deriveKey", "deriveBits"]
                );

                const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", bobKeys.privateKey);
                const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", bobKeys.publicKey);

                bobPrivateKeyOutput.value = JSON.stringify(privateKeyJwk, null, 2);
                bobPublicKeyOutput.value = JSON.stringify(publicKeyJwk, null, 2);

            } catch (error) {
                console.error("Bob DH Key Generation error:", error);
                alert("Failed to generate Bob's DH key pair: " + error.message);
            }
        });

        // Derive Bob's Shared Secret
        deriveBobSharedSecretButton.addEventListener('click', async () => {
            const alicesPublicKeyJwkStr = bobAlicesPublicKeyInput.value;

            if (!bobKeys || !bobKeys.privateKey) {
                alert("Please generate Bob's keys first.");
                return;
            }
            if (!alicesPublicKeyJwkStr) {
                alert("Please paste Alice's Public Key.");
                return;
            }

            try {
                const alicesPublicKeyJwk = JSON.parse(alicesPublicKeyJwkStr);
                const alicesPublicKey = await window.crypto.subtle.importKey(
                    "jwk",
                    alicesPublicKeyJwk,
                    {
                        name: "ECDH",
                        namedCurve: "P-256",
                    },
                    false, // Not extractable
                    []
                );

                // Derive the shared secret bits using Bob's private key and Alice's public key
                const sharedSecretBuffer = await window.crypto.subtle.deriveBits(
                    {
                        name: "ECDH",
                        public: alicesPublicKey
                    },
                    bobKeys.privateKey, // Bob's private key
                    256 // Length of the derived bits in bits (e.g., 256 for a SHA-256-sized secret)
                );

                // Hash the derived bits to get a fixed-size secret
                const hashedSecretBuffer = await window.crypto.subtle.digest("SHA-256", sharedSecretBuffer);

                bobSharedSecretOutput.value = arrayBufferToBase64(hashedSecretBuffer);

            } catch (error) {
                console.error("Bob DH Shared Secret Derivation error:", error);
                alert("Failed to derive Bob's shared secret: " + error.message + ". Ensure Alice's public key is valid and matches the curve.");
            }
        });
    } // la fin te3 asymmetric-encryption.html block
});
 
