function mod(n, m) {
    return ((n % m) + m) % m;
}

function findModInverse(a, m) {
    for (let i = 0; i < m; i++) {
        if ((a * i) % m === 1) return i;
    }
    throw "No modular inverse!";
}
//  =====================VIGENERE CIPHER=======================

function vigenereEncrypt(text, key) {
    text = text.toUpperCase().replace(/[^A-Z]/g, "");
    key = key.toUpperCase();
    let result = "";
    for (let i = 0; i < text.length; i++) {
        const t = text.charCodeAt(i) - 65;
        const k = key.charCodeAt(i % key.length) - 65;
        result += String.fromCharCode((t + k) % 26 + 65);
    }
    return result;
}

function vigenereDecrypt(cipher, key) {
    cipher = cipher.toUpperCase().replace(/[^A-Z]/g, "");
    key = key.toUpperCase();
    let result = "";
    for (let i = 0; i < cipher.length; i++) {
        const c = cipher.charCodeAt(i) - 65;
        const k = key.charCodeAt(i % key.length) - 65;
        result += String.fromCharCode(mod(c - k, 26) + 65);
    }
    return result;
}

//  =====================AFFINE CIPHER=======================
function affineEncrypt(text, key) {
    const [a, b] = key.split(",").map(Number);
    text = text.toUpperCase().replace(/[^A-Z]/g, "");
    return text.split("").map(ch => {
        const x = ch.charCodeAt(0) - 65;
        return String.fromCharCode(((a * x + b) % 26) + 65);
    }).join("");
}

function affineDecrypt(cipher, key) {
    const [a, b] = key.split(",").map(Number);
    const m = 26;
    const a_inv = findModInverse(a, m);
    cipher = cipher.toUpperCase().replace(/[^A-Z]/g, "");
    return cipher.split("").map(ch => {
        const y = ch.charCodeAt(0) - 65;
        return String.fromCharCode(mod(a_inv * (y - b), 26) + 65);
    }).join("");
}

//  =====================PLAYFAIR CIPHER=======================
function playfairEncrypt(plaintext, key) {
    key = key.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
    let matrix = "";
    for (let char of key) if (!matrix.includes(char)) matrix += char;
    for (let i = 65; i <= 90; i++) {
        let ch = String.fromCharCode(i);
        if (ch === "J") continue;
        if (!matrix.includes(ch)) matrix += ch;
    }
    let pairs = [];
    plaintext = plaintext.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
    for (let i = 0; i < plaintext.length; i += 2) {
        let a = plaintext[i];
        let b = plaintext[i + 1] || "X";
        if (a === b) b = "X";
        pairs.push([a, b]);
    }
    let cipher = "";
    for (let [a, b] of pairs) {
        const ia = matrix.indexOf(a);
        const ib = matrix.indexOf(b);
        const ra = Math.floor(ia / 5), ca = ia % 5;
        const rb = Math.floor(ib / 5), cb = ib % 5;
        if (ra === rb) {
            cipher += matrix[ra * 5 + ((ca + 1) % 5)];
            cipher += matrix[rb * 5 + ((cb + 1) % 5)];
        } else if (ca === cb) {
            cipher += matrix[((ra + 1) % 5) * 5 + ca];
            cipher += matrix[((rb + 1) % 5) * 5 + cb];
        } else {
            cipher += matrix[ra * 5 + cb];
            cipher += matrix[rb * 5 + ca];
        }
    }
    return cipher;
}

function playfairDecrypt(cipher, key) {
    key = key.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
    let matrix = "";
    for (let char of key) if (!matrix.includes(char)) matrix += char;
    for (let i = 65; i <= 90; i++) {
        let ch = String.fromCharCode(i);
        if (ch === "J") continue;
        if (!matrix.includes(ch)) matrix += ch;
    }
    let pairs = [];
    cipher = cipher.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
    for (let i = 0; i < cipher.length; i += 2) {
        pairs.push([cipher[i], cipher[i + 1]]);
    }
    let plain = "";
    for (let [a, b] of pairs) {
        const ia = matrix.indexOf(a);
        const ib = matrix.indexOf(b);
        const ra = Math.floor(ia / 5), ca = ia % 5;
        const rb = Math.floor(ib / 5), cb = ib % 5;
        if (ra === rb) {
            plain += matrix[ra * 5 + mod(ca - 1, 5)];
            plain += matrix[rb * 5 + mod(cb - 1, 5)];
        } else if (ca === cb) {
            plain += matrix[mod(ra - 1, 5) * 5 + ca];
            plain += matrix[mod(rb - 1, 5) * 5 + cb];
        } else {
            plain += matrix[ra * 5 + cb];
            plain += matrix[rb * 5 + ca];
        }
    }
    return plain;
}

//  =====================HILL CIPHER=======================
function hillEncrypt(text, key) {
    text = text.toUpperCase().replace(/[^A-Z]/g, "");
    // pad to multiple of 3
    while (text.length % 3 !== 0) text += "X";
    const k = key.split(",").map(Number); // expect 9 values
    let result = "";
    for (let i = 0; i < text.length; i += 3) {
        const a = text.charCodeAt(i) - 65;
        const b = text.charCodeAt(i + 1) - 65;
        const c = text.charCodeAt(i + 2) - 65;
        const r1 = mod(k[0] * a + k[1] * b + k[2] * c, 26);
        const r2 = mod(k[3] * a + k[4] * b + k[5] * c, 26);
        const r3 = mod(k[6] * a + k[7] * b + k[8] * c, 26);
        result += String.fromCharCode(r1 + 65) + String.fromCharCode(r2 + 65) + String.fromCharCode(r3 + 65);
    }
    return result;
}

function hillDecrypt(cipher, key) {
    const k = key.split(",").map(Number);
    const det = mod(
        k[0] * (k[4] * k[8] - k[5] * k[7])
        - k[1] * (k[3] * k[8] - k[5] * k[6])
        + k[2] * (k[3] * k[7] - k[4] * k[6])
    , 26);
    const detInv = findModInverse(det, 26);
    const adj = [
        (k[4] * k[8] - k[5] * k[7]),
        -(k[1] * k[8] - k[2] * k[7]),
        (k[1] * k[5] - k[2] * k[4]),
        -(k[3] * k[8] - k[5] * k[6]),
        (k[0] * k[8] - k[2] * k[6]),
        -(k[0] * k[5] - k[2] * k[3]),
        (k[3] * k[7] - k[4] * k[6]),
        -(k[0] * k[7] - k[1] * k[6]),
        (k[0] * k[4] - k[1] * k[3])
    ];
    const inv = adj.map(v => mod(v * detInv, 26));

    cipher = cipher.toUpperCase().replace(/[^A-Z]/g, "");
    let result = "";
    for (let i = 0; i < cipher.length; i += 3) {
        const a = cipher.charCodeAt(i) - 65;
        const b = cipher.charCodeAt(i + 1) - 65;
        const c = cipher.charCodeAt(i + 2) - 65;
        const p1 = mod(inv[0] * a + inv[1] * b + inv[2] * c, 26);
        const p2 = mod(inv[3] * a + inv[4] * b + inv[5] * c, 26);
        const p3 = mod(inv[6] * a + inv[7] * b + inv[8] * c, 26);
        result += String.fromCharCode(p1 + 65) + String.fromCharCode(p2 + 65) + String.fromCharCode(p3 + 65);
    }
    return result;
}

//  =====================ENIGMA CIPHER=======================
function parseEnigmaConfig(keyStr) {
    const lines = keyStr.trim().split(/\n/).map(l => l.trim()).filter(l => l.length > 0);
    if (lines.length < 3) throw "Enigma requires: # rotors, initial position, rotor keys";
    
    const numRotors = parseInt(lines[0], 10);
    const initialPos = parseInt(lines[1], 10);
    if (isNaN(numRotors) || isNaN(initialPos)) throw "First two lines must be numeric";
    if (numRotors <= 0) throw "Number of rotors must be > 0";
    
    const rotors = [];
    for (let i = 0; i < numRotors; i++) {
        const rotor = lines[i + 2] ? lines[i + 2].toUpperCase() : "";
        if (rotor.length === 0) throw `Rotor ${i} is missing`;
        rotors.push(rotor);
    }
    return { numRotors, initialPos, rotors };
}

function findInRotor(char, rotor) {
    return rotor.indexOf(char);
}

function enigmaEncrypt(text, keyStr) {
    const config = parseEnigmaConfig(keyStr);
    const { numRotors, initialPos, rotors } = config;
    text = text.toUpperCase().replace(/[^A-Z]/g, "");
    
    let result = "";
    let position = initialPos;
    
    for (let i = 0; i < text.length; i++) {
        const charIdx = text.charCodeAt(i) - 65;
        const currentRotor = rotors[position % numRotors];
        
        if (charIdx < currentRotor.length) {
            result += currentRotor[charIdx];
        } else {
            throw `Character index ${charIdx} exceeds rotor length ${currentRotor.length}`;
        }
        
        position = (position + 1) % numRotors;
    }
    return result;
}

function enigmaDecrypt(cipherStr, keyStr) {
    const config = parseEnigmaConfig(keyStr);
    const { numRotors, initialPos, rotors } = config;
    cipherStr = cipherStr.toUpperCase().replace(/[^A-Z]/g, "");
    
    let result = "";
    let position = initialPos;
    
    for (let i = 0; i < cipherStr.length; i++) {
        const cipherChar = cipherStr[i];
        const currentRotor = rotors[position % numRotors];
        
        const charIdx = findInRotor(cipherChar, currentRotor);
        if (charIdx === -1) {
            throw `Character '${cipherChar}' not found in rotor ${position % numRotors}`;
        }
        result += String.fromCharCode(charIdx + 65);
        
        position = (position + 1) % numRotors;
    }
    return result;
}

//  =====================UTIL=======================
function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);
    while (b) {
        [a, b] = [b, a % b];
    }
    return a;
}

function getKeyString(algo) {
    switch (algo) {
        case "affine": {
            const a = parseInt(document.getElementById("affineA").value, 10);
            const b = parseInt(document.getElementById("affineB").value, 10);
            if (isNaN(a) || isNaN(b)) throw "Affine key requires numeric a and b";
            if (gcd(a, 26) !== 1) throw "Value 'a' must be coprime with 26";
            if (b < 0 || b > 99) throw "Value 'b' must be in range 0–99";
            return `${a},${b}`;
        }
        case "hill": {
            let cells = [];
            for (let i = 0; i < 3; i++) {
                for (let j = 0; j < 3; j++) {
                    const val = parseInt(document.getElementById(`hill${i}${j}`).value, 10);
                    if (isNaN(val)) throw "All Hill matrix entries must be numbers";
                    cells.push(val);
                }
            }
            return cells.join(",");
        }
        case "enigma": {
            const numRotors = document.getElementById("enigmaNumRotors").value;
            const initialPos = document.getElementById("enigmaInitialPos").value;
            const rotorKeys = document.getElementById("enigmaRotorKeys").value;
            return `${numRotors}\n${initialPos}\n${rotorKeys}`;
        }
        default:
            return document.getElementById("key").value;
    }
}

function updateKeyInputs() {
    const algo = document.getElementById("algorithm").value;
    const container = document.getElementById("keyContainer");
    let html = "";
    if (algo === "affine") {
        html = `
            <label>a:</label><br>
            <input type="number" id="affineA" step="1" placeholder="1"><br>
            <label>b:</label><br>
            <input type="number" id="affineB" min="0" max="99" step="1" placeholder="1"><br>
        `;
    } else if (algo === "hill") {
        html = `<label>Key matrix (3×3):</label><br>
                <div style="display: inline-block; text-align: center;">
                    ${[0,1,2].map(i =>
                        `<div>${[0,1,2].map(j =>
                            `<input type="number" id="hill${i}${j}" style="width:50px; margin:2px;" placeholder="0">`
                        ).join('')}</div>`
                    ).join('')}
                </div><br>`;
    } else if (algo === "enigma") {
        html = `
            <label>Number of Rotors:</label><br>
            <input type="number" id="enigmaNumRotors" min="1" value="3" step="1"><br>
            <label>Initial Rotor Position:</label><br>
            <input type="number" id="enigmaInitialPos" min="0" value="0" step="1"><br>
            <label>Rotor Keys (one per line):</label><br>
            <textarea id="enigmaRotorKeys" font-family:monospace;" placeholder="Enter Keys Here&#10;Enter Keys Here&#10;Enter Keys Here"></textarea><br>
        `;
    } else {
        html = `
            <label>Key:</label><br>
            <input type="text" id="key" placeholder="Enter key here"><br>
        `;
    }
    container.innerHTML = html;
    attachValidation();
}

function attachValidation() {
    const aInput = document.getElementById("affineA");
    if (aInput) {
        aInput.addEventListener("input", function () {
            const v = parseInt(this.value, 10);
            if (!isNaN(v) && gcd(v, 26) !== 1) {
                this.setCustomValidity("a must be coprime with 26");
            } else {
                this.setCustomValidity("");
            }
        });
    }
}

//  =====================BUTTON LOGIC=======================
function encrypt() {
    const algo = document.getElementById("algorithm").value;
    const text = document.getElementById("plainText").value;
    const key = getKeyString(algo);
    let result = "";
    try {
        switch (algo) {
            case "vigenere": result = vigenereEncrypt(text, key); break;
            case "affine": result = affineEncrypt(text, key); break;
            case "playfair": result = playfairEncrypt(text, key); break;
            case "hill": result = hillEncrypt(text, key); break;
            case "enigma": result = enigmaEncrypt(text, key); break;
        }
    } catch (err) { result = "Error: " + err; }
    document.getElementById("cipherText").value = result;
}

function decrypt() {
    const algo = document.getElementById("algorithm").value;
    const text = document.getElementById("cipherText").value;
    const key = getKeyString(algo);
    let result = "";
    try {
        switch (algo) {
            case "vigenere": result = vigenereDecrypt(text, key); break;
            case "affine": result = affineDecrypt(text, key); break;
            case "playfair": result = playfairDecrypt(text, key); break;
            case "hill": result = hillDecrypt(text, key); break;
            case "enigma": result = enigmaDecrypt(text, key); break;
        }
    } catch (err) { result = "Error: " + err; }
    document.getElementById("plainText").value = result;
}