// ------------------------- Utilities -------------------------
const text = (el, v) => (el.textContent = v);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");
const hex = (buf) => Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => new Uint8Array(h.match(/.{1,2}/g).map((x) => parseInt(x, 16)));

// Copy helper
async function copyToClipboard(str) {
    try {
        await navigator.clipboard.writeText(str);
        return true;
    } catch {
        return false;
    }
}

// ------------------------- Base58Check -------------------------
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHABET_MAP = Object.fromEntries([...ALPHABET].map((c, i) => [c, i]));

function base58Decode(str) {
    if (!str || /[0OIl+\-\s]/.test(str)) throw new Error("Invalid Base58 characters");
    let bytes = [0];
    for (const ch of str) {
        const val = ALPHABET_MAP[ch];
        if (val === undefined) throw new Error("Invalid Base58 character: " + ch);
        let carry = val;
        for (let j = 0; j < bytes.length; j++) {
            const x = bytes[j] * 58 + carry;
            bytes[j] = x & 0xff;
            carry = x >> 8;
        }
        while (carry) {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }
    // Deal with leading zeros
    let leading = 0;
    for (const ch of str) {
        if (ch === "1") leading++;
        else break;
    }
    const arr = new Uint8Array(leading + bytes.length);
    for (let i = 0; i < bytes.length; i++) arr[arr.length - 1 - i] = bytes[i];
    return arr;
}

async function sha256(buf) {
    const h = await crypto.subtle.digest("SHA-256", buf);
    return new Uint8Array(h);
}

async function base58checkDecode(addr) {
    const data = base58Decode(addr);
    if (data.length < 5) throw new Error("Too short for Base58Check");
    const payload = data.slice(0, -4);
    const checksum = data.slice(-4);
    const h1 = await sha256(payload);
    const h2 = await sha256(h1);
    const calc = h2.slice(0, 4);
    const ok = calc.every((b, i) => b === checksum[i]);
    if (!ok) throw new Error("Bad checksum for Base58Check");
    const version = payload[0];
    const body = payload.slice(1);
    let network = "Unknown",
        type = "Unknown";
    if (version === 0x00) {
        network = "mainnet";
        type = body.length === 20 ? "P2PKH (legacy)" : "Unknown";
    } else if (version === 0x05) {
        network = "mainnet";
        type = body.length === 20 ? "P2SH" : "Unknown";
    } else if (version === 0x6f) {
        network = "testnet";
        type = body.length === 20 ? "P2PKH (legacy)" : "Unknown";
    } else if (version === 0xc4) {
        network = "testnet/signet";
        type = body.length === 20 ? "P2SH" : "Unknown";
    }
    return {
        encoding: "Base58Check",
        network,
        type,
        valid: true,
        payloadHex: hex(body),
        extra: { versionByte: "0x" + version.toString(16).padStart(2, "0") },
    };
}

// ------------------------- Bech32 / Bech32m -------------------------
// Based on BIP-173/350
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHARKEY = Object.fromEntries([...CHARSET].map((c, i) => [c, i]));

function bech32Polymod(values) {
    const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
        const top = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GENERATORS[i];
    }
    return chk >>> 0;
}

function bech32HrpExpand(hrp) {
    const ret = [];
    for (const c of hrp) ret.push(c.charCodeAt(0) >>> 5);
    ret.push(0);
    for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
    return ret;
}

function verifyChecksum(hrp, data) {
    const pm = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
    if (pm === 1) return "bech32";
    if (pm === 0x2bc830a3) return "bech32m";
    return null;
}

function bech32Decode(str) {
    const lower = str.toLowerCase();
    if (str !== lower && str !== str.toUpperCase()) throw new Error("Mixed case not allowed");
    const pos = lower.lastIndexOf("1");
    if (pos < 1 || pos + 7 > lower.length) throw new Error("Invalid separator position");
    const hrp = lower.slice(0, pos);
    const dataPart = lower.slice(pos + 1);
    const data = [];
    for (const c of dataPart) {
        const v = CHARKEY[c];
        if (v === undefined) throw new Error("Invalid Bech32 character: " + c);
        data.push(v);
    }
    const spec = verifyChecksum(hrp, data);
    if (!spec) throw new Error("Invalid Bech32/Bech32m checksum");
    const withoutChecksum = data.slice(0, -6);
    return { hrp, data: withoutChecksum, checksumSpec: spec };
}

function convertBits(data, from, to, pad) {
    let acc = 0,
        bits = 0;
    const ret = [];
    const maxv = (1 << to) - 1;
    for (const value of data) {
        if (value < 0 || (value >> from) !== 0) return null;
        acc = (acc << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            ret.push((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) ret.push((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
        return null;
    }
    return new Uint8Array(ret);
}

function decodeSegwit(addr) {
    const { hrp, data, checksumSpec } = bech32Decode(addr);
    const network =
        hrp === "bc" ? "mainnet" : hrp === "tb" ? "testnet" : hrp === "bcrt" ? "regtest" : "Unknown";
    if (network === "Unknown") throw new Error("Unknown HRP: " + hrp);
    if (data.length === 0) throw new Error("Empty data");
    const witver = data[0];
    if (witver > 16) throw new Error("Invalid witness version");
    const program = convertBits(data.slice(1), 5, 8, false);
    if (!program) throw new Error("Invalid witness program");
    if (program.length < 2 || program.length > 40) throw new Error("Invalid program length");
    // Checksum rule per BIP-173/350
    const expected = witver === 0 ? "bech32" : "bech32m";
    if (checksumSpec !== expected)
        throw new Error("Wrong checksum type for v" + witver + " (expected " + expected + ")");

    // Classify type
    let type = "Unknown";
    if (witver === 0) {
        if (program.length === 20) type = "P2WPKH (v0)";
        else if (program.length === 32) type = "P2WSH (v0)";
    } else if (witver === 1 && program.length === 32) {
        type = "P2TR (Taproot, v1)";
    } else {
        type = "Witness v" + witver + " (" + program.length + " bytes)";
    }

    return {
        encoding: checksumSpec.toUpperCase(),
        network,
        type,
        valid: true,
        payloadHex: hex(program),
        extra: { hrp, witnessVersion: witver },
    };
}

// ------------------------- Orchestrator -------------------------
async function decodeAddress(addr) {
    addr = addr.trim();
    if (!addr) throw new Error("Please enter an address");
    if (addr.toLowerCase().startsWith("bc1") || addr.toLowerCase().startsWith("tb1") || addr.toLowerCase().startsWith("bcrt1")) {
        return decodeSegwit(addr);
    }
    return await base58checkDecode(addr);
}

function renderResult(r) {
    text(document.getElementById("enc"), r.encoding);
    text(document.getElementById("net"), r.network);
    text(document.getElementById("typ"), r.type);
    text(document.getElementById("ok"), r.valid ? "Yes" : "No");

    const details = document.getElementById("details");
    details.innerHTML = "";
    const rows = [];
    for (const [k, v] of Object.entries(r.extra || {})) {
        rows.push(
            `<div class="flex justify-between gap-6 py-1"><div class="text-zinc-500 dark:text-zinc-400">${k}</div><div class="font-mono">${v}</div></div>`
        );
    }
    details.innerHTML = rows.join("") || '<p class="text-zinc-500 dark:text-zinc-400">(No extra fields)</p>';

    text(document.getElementById("payload"), r.payloadHex);
}

function renderError(msg) {
    text(document.getElementById("err"), msg);
}

document.addEventListener("DOMContentLoaded", () => {
    const addrEl = document.getElementById("addr");
    const decodeBtn = document.getElementById("decodeBtn");
    const resultWrap = document.getElementById("resultWrap");
    const errorWrap = document.getElementById("errorWrap");
    const copyBtn = document.getElementById("copyBtn");

    async function onDecode() {
        hide(resultWrap);
        hide(errorWrap);
        try {
            const r = await decodeAddress(addrEl.value);
            renderResult(r);
            show(resultWrap);
        } catch (e) {
            renderError(e.message || String(e));
            show(errorWrap);
        }
    }

    decodeBtn.addEventListener("click", onDecode);
    addrEl.addEventListener("keydown", (e) => {
        if (e.key === "Enter") onDecode();
    });
    copyBtn.addEventListener("click", async () => {
        const v = document.getElementById("payload").textContent;
        const ok = await copyToClipboard(v);
        copyBtn.textContent = ok ? "Copied" : "Copy failed";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
    });

    // Demo value for convenience
    addrEl.value = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
});