const MAGIC_BYTE = 0xDC;
const VERSION_BYTE = 0x03;
const SIGNATURE_TLV_TAG = 0xFF;
const EXPIRY_TLV_TAG = 0x80;

function parseQRPayload(payload) {
  const issues = [];
  let isValid = true;
  let cursor = 0;
  let header = null;
  let signatureRaw = null;
  let signedDataRange = null;
  let dataExpiryText = null;
  const bodyTlvs = [];
  const knownFields = [];
  const data = {
    documentNumber: null,
    birthDate: null,
    givenName: null,
    surnames: null,
    sex: null,
    documentExpiry: null,
    nationality: null,
    parents: null,
    supportNumber: null,
    isAdult: null,
    dataExpiry: null,
    addressFull: null,
    addressLines: [],
    placeOfBirthLines: [],
    thumbnailBase64: null,
  };

  function addIssue(severity, message, offset) {
    if (severity === "error") {
      isValid = false;
    }
    issues.push({ severity, message, offset });
  }

  if (!Buffer.isBuffer(payload)) {
    addIssue("error", "Payload must be a Buffer", cursor);
    return buildResult();
  }

  if (payload.length < 4) {
    addIssue("error", "Payload too short for header", cursor);
    return buildResult();
  }

  const magic = payload[0];
  const version = payload[1];
  if (magic !== MAGIC_BYTE) {
    addIssue("error", "Invalid magic byte (0xDC expected)", 0);
  }
  if (version !== VERSION_BYTE) {
    addIssue("error", "Invalid version byte (0x03 expected)", 1);
  }

  const issuerCountryC40 = payload.subarray(2, 4);
  const issuerCountry = decodeC40String(issuerCountryC40, 2, issues);
  if (issuerCountry && issuerCountry !== "ES") {
    addIssue("warning", `Unexpected issuer country: ${issuerCountry}`, 2);
  }

  cursor = 4;

  const signerParse = parseSignerField(payload, cursor, issues);
  if (signerParse) {
    cursor += signerParse.bytesConsumed;

    const fixedHeaderBytes = 8;
    if (cursor + fixedHeaderBytes > payload.length) {
      addIssue("error", "Header truncated after signer identifier", cursor);
    } else {
      const issueDateRaw = payload.subarray(cursor, cursor + 3);
      cursor += 3;
      const signatureDateRaw = payload.subarray(cursor, cursor + 3);
      cursor += 3;
      const profile = payload[cursor];
      cursor += 1;
      const documentCategory = payload[cursor];
      cursor += 1;

      header = {
        magic,
        version,
        signerCountry: signerParse.signerCountry,
        signerEntity: signerParse.signerEntity,
        certReferenceHex: signerParse.certReferenceHex,
        issueDateRaw,
        signatureDateRaw,
        profile,
        documentCategory,
      };
    }
  } else {
    const fallback = parseHeaderFallback(payload, cursor, issues);
    if (fallback) {
      addIssue("warning", "Header reconstructed using fallback heuristic", fallback.profileOffset);
      header = fallback.header;
      cursor = fallback.tlvStartOffset;
    } else {
      addIssue("error", "Signer identifier could not be parsed", cursor);
      const tlvStart = findTLVStart(payload, cursor);
      if (tlvStart !== null) {
        addIssue("warning", `TLV start found by heuristic at offset ${tlvStart}`, tlvStart);
        cursor = tlvStart;
      }
    }
  }

  while (cursor < payload.length) {
    const tagOffset = cursor;
    const tag = payload[cursor];
    cursor += 1;

    const length = parseTLVLength(payload, { cursorRef: () => cursor, setCursor: (v) => { cursor = v; } }, issues);
    if (length === null) {
      addIssue("error", "Invalid TLV length", cursor);
      break;
    }

    const valueStart = cursor;
    const valueEnd = cursor + length;
    if (valueEnd > payload.length) {
      addIssue("error", `Truncated TLV for tag 0x${tag.toString(16).padStart(2, "0").toUpperCase()}`, tagOffset);
      break;
    }

    const value = payload.subarray(valueStart, valueEnd);
    cursor = valueEnd;

    if (tag === SIGNATURE_TLV_TAG) {
      signatureRaw = value;
      signedDataRange = { start: 0, end: tagOffset };
      if (cursor !== payload.length) {
        addIssue("warning", "Trailing bytes found after signature TLV", cursor);
      }
      break;
    }

    const tlv = { tag, length, value, offset: tagOffset };
    bodyTlvs.push(tlv);

    if (tag === EXPIRY_TLV_TAG) {
      dataExpiryText = value.toString("latin1");
    }

    const field = decodeKnownField(tag, value);
    if (field) {
      knownFields.push(field);
      applyFieldToData(data, field);
    }
  }

  if (!signatureRaw) {
    addIssue("error", "Signature TLV (0xFF) not found", cursor);
  }

  return buildResult();

  function buildResult() {
    return {
      header,
      signatureRaw,
      signedDataRange,
      dataExpiryText,
      bodyTlvs,
      knownFields,
      data,
      issues,
      isValid,
    };
  }
}

function parseTLVLength(payload, cursorManager, issues) {
  let cursor = cursorManager.cursorRef();
  if (cursor >= payload.length) {
    return null;
  }

  const first = payload[cursor];
  cursor += 1;

  if (first < 0x80) {
    cursorManager.setCursor(cursor);
    return first;
  }

  const lengthBytes = first & 0x7F;
  if (lengthBytes === 0 || lengthBytes > 4) {
    issues.push({ severity: "error", message: "Invalid TLV length byte count", offset: cursor - 1 });
    cursorManager.setCursor(cursor);
    return null;
  }

  if (cursor + lengthBytes > payload.length) {
    issues.push({ severity: "error", message: "Truncated TLV length", offset: cursor });
    cursorManager.setCursor(cursor);
    return null;
  }

  let length = 0;
  for (let i = 0; i < lengthBytes; i += 1) {
    length = (length << 8) | payload[cursor];
    cursor += 1;
  }

  cursorManager.setCursor(cursor);
  return length;
}

function parseSignerField(payload, offset, issues) {
  let cursor = offset;
  let decodedBytes = [];
  let requiredChars = null;
  let shiftState = "none";
  let pairsConsumed = 0;
  let targetPairs = null;

  while (cursor + 1 < payload.length) {
    const pairStart = cursor;
    const value = payload[cursor] * 256 + payload[cursor + 1];
    cursor += 2;
    pairsConsumed += 1;

    const c1 = Math.floor((value - 1) / 1600);
    const c2 = Math.floor(((value - 1) % 1600) / 40);
    const c3 = (value - 1) % 40;

    decodedBytes = decodedBytes.concat(decodeC40ValueBytes(c1, issues, () => shiftState, (v) => { shiftState = v; }));
    decodedBytes = decodedBytes.concat(decodeC40ValueBytes(c2, issues, () => shiftState, (v) => { shiftState = v; }));
    decodedBytes = decodedBytes.concat(decodeC40ValueBytes(c3, issues, () => shiftState, (v) => { shiftState = v; }));

    if (requiredChars === null && decodedBytes.length >= 6) {
      const lengthHexBytes = decodedBytes.slice(4, 6);
      const lengthHex = Buffer.from(lengthHexBytes).toString("ascii");
      const certLength = Number.parseInt(lengthHex, 16);
      if (Number.isNaN(certLength)) {
        issues.push({ severity: "error", message: "Invalid certificate length hex", offset: pairStart });
        return null;
      }
      requiredChars = 2 + 2 + 2 + certLength * 2;
      const neededBytes = bytesForC40Chars(requiredChars);
      targetPairs = neededBytes / 2;
    }

    if (requiredChars !== null && targetPairs !== null && pairsConsumed >= targetPairs) {
      if (decodedBytes.length < requiredChars) {
        issues.push({ severity: "error", message: "Signer identifier truncated (C40)", offset });
        return null;
      }
      if (decodedBytes.length > requiredChars) {
        decodedBytes = decodedBytes.slice(0, requiredChars);
      }

      const bytesConsumed = targetPairs * 2;
      if (bytesConsumed > payload.length - offset) {
        issues.push({ severity: "error", message: "Signer identifier truncated", offset });
        return null;
      }

      if (requiredChars < 6) {
        issues.push({ severity: "error", message: "Signer identifier too short", offset });
        return null;
      }

      const signerCountry = Buffer.from(decodedBytes.slice(0, 2)).toString("ascii");
      const signerEntity = Buffer.from(decodedBytes.slice(2, 4)).toString("ascii");
      const certReferenceHex = Buffer.from(decodedBytes.slice(6, requiredChars)).toString("ascii");

      if (!/^[0-9A-F]+$/.test(certReferenceHex)) {
        issues.push({ severity: "warning", message: "Certificate reference does not look like hex", offset });
      }

      return {
        signerCountry,
        signerEntity,
        certReferenceHex,
        bytesConsumed,
      };
    }
  }

  issues.push({ severity: "error", message: "Signer identifier incomplete", offset });
  return null;
}

function bytesForC40Chars(count) {
  return Math.floor((count + 2) / 3) * 2;
}

function decodeC40String(bytes, maxChars, issues) {
  const values = c40Values(bytes);
  let decoded = "";
  let shiftState = "none";

  for (const value of values) {
    decoded += decodeC40Value(value, issues, () => shiftState, (v) => { shiftState = v; });
    if (maxChars && decoded.length >= maxChars) {
      break;
    }
  }

  if (maxChars && decoded.length > maxChars) {
    decoded = decoded.slice(0, maxChars);
  }

  return decoded;
}

function c40Values(bytes) {
  const buffer = Array.from(bytes);
  const values = [];
  let index = 0;

  while (index + 1 < buffer.length) {
    const v = buffer[index] * 256 + buffer[index + 1];
    const temp = v - 1;
    const c1 = Math.floor(temp / 1600);
    const c2 = Math.floor((temp % 1600) / 40);
    const c3 = temp % 40;
    values.push(c1, c2, c3);
    index += 2;
  }

  return values;
}

function decodeC40Value(value, issues, getShift, setShift) {
  const shiftState = getShift();

  if (shiftState === "none") {
    if (value === 0) { setShift("shift1"); return ""; }
    if (value === 1) { setShift("shift2"); return ""; }
    if (value === 2) { setShift("shift3"); return ""; }
    if (value === 3) { return " "; }
    if (value >= 4 && value <= 13) { return String(value - 4); }
    if (value >= 14 && value <= 39) { return String.fromCharCode(65 + value - 14); }
    issues.push({ severity: "warning", message: "C40 value out of range", offset: null });
    return "?";
  }

  setShift("none");

  if (shiftState === "shift1") {
    if (value >= 0 && value <= 31) {
      return String.fromCharCode(value);
    }
    return "?";
  }

  if (shiftState === "shift2") {
    const mapping = {
      0: "!",
      1: '"',
      2: "#",
      3: "$",
      4: "%",
      5: "&",
      6: "'",
      7: "(",
      8: ")",
      9: "*",
      10: "+",
      11: ",",
      12: "-",
      13: ".",
      14: "/",
      15: ":",
    };
    return mapping[value] ?? "?";
  }

  if (shiftState === "shift3") {
    if (value === 0) { return "`"; }
    if (value >= 1 && value <= 26) { return String.fromCharCode(96 + value); }
    const mapping = { 27: "{", 28: "|", 29: "}", 30: "~" };
    return mapping[value] ?? "?";
  }

  return "?";
}

function decodeC40ValueBytes(value, issues, getShift, setShift) {
  const text = decodeC40Value(value, issues, getShift, setShift);
  return Array.from(Buffer.from(text, "utf8"));
}

function decodeC40Bytes(bytes) {
  const buffer = Array.from(bytes);
  const result = [];
  let shiftState = "none";
  let index = 0;

  while (index + 1 < buffer.length) {
    const v = buffer[index] * 256 + buffer[index + 1];
    const temp = v - 1;
    const c1 = Math.floor(temp / 1600);
    const c2 = Math.floor((temp % 1600) / 40);
    const c3 = temp % 40;
    result.push(...decodeC40ValueBytes(c1, [], () => shiftState, (v2) => { shiftState = v2; }));
    result.push(...decodeC40ValueBytes(c2, [], () => shiftState, (v2) => { shiftState = v2; }));
    result.push(...decodeC40ValueBytes(c3, [], () => shiftState, (v2) => { shiftState = v2; }));
    index += 2;
  }

  return result;
}

function parseHeaderFallback(payload, startOffset, issues) {
  const profileCandidates = new Set([0x07, 0x08, 0x09]);
  let i = startOffset + 6;

  while (i + 1 < payload.length) {
    const profile = payload[i];
    const documentCategory = payload[i + 1];
    if (profileCandidates.has(profile) && documentCategory === 0x09 && i >= 6) {
      const signerEnd = i - 6;
      if (signerEnd >= startOffset) {
        const signerData = payload.subarray(startOffset, signerEnd);
        const decoded = decodeC40Bytes(signerData);
        const signerCountry = decoded.length >= 2 ? Buffer.from(decoded.slice(0, 2)).toString("ascii") : "";
        const signerEntity = decoded.length >= 4 ? Buffer.from(decoded.slice(2, 4)).toString("ascii") : "";

        let certReferenceHex = "";
        if (decoded.length >= 6) {
          const lengthHex = Buffer.from(decoded.slice(4, 6)).toString("ascii");
          const certLength = Number.parseInt(lengthHex, 16);
          if (!Number.isNaN(certLength)) {
            const needed = 6 + certLength * 2;
            if (decoded.length >= needed) {
              certReferenceHex = Buffer.from(decoded.slice(6, needed)).toString("ascii");
            } else if (decoded.length > 6) {
              certReferenceHex = Buffer.from(decoded.slice(6)).toString("ascii");
            }
          } else if (decoded.length > 4) {
            certReferenceHex = Buffer.from(decoded.slice(4)).toString("ascii");
          }
        }

        const issueDateRaw = payload.subarray(i - 6, i - 3);
        const signatureDateRaw = payload.subarray(i - 3, i);

        const header = {
          magic: payload[0],
          version: payload[1],
          signerCountry,
          signerEntity,
          certReferenceHex,
          issueDateRaw,
          signatureDateRaw,
          profile,
          documentCategory,
        };

        return { header, tlvStartOffset: i + 2, profileOffset: i };
      }
    }
    i += 1;
  }

  issues.push({ severity: "error", message: "Header fallback failed", offset: startOffset });
  return null;
}

function findTLVStart(payload, startOffset) {
  const knownTags = new Set([
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4C, 0x50, 0x60, 0x62, 0x64,
    0x66, 0x68, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x80, 0xFF,
  ]);

  let i = startOffset;
  while (i < payload.length) {
    const tag = payload[i];
    if (knownTags.has(tag)) {
      let tempCursor = i + 1;
      const length = parseTLVLength(payload, { cursorRef: () => tempCursor, setCursor: (v) => { tempCursor = v; } }, []);
      if (length !== null) {
        const valueEnd = tempCursor + length;
        if (valueEnd <= payload.length) {
          return i;
        }
      }
    }
    i += 1;
  }

  return null;
}

function decodeKnownField(tag, value) {
  const base = { tag, rawLength: value.length };

  switch (tag) {
    case 0x40:
      return { ...base, name: "Document number", value: decodeLatin1(value) };
    case 0x42:
      return { ...base, name: "Date of birth", value: decodeLatin1(value) };
    case 0x44:
      return { ...base, name: "Given name", value: decodeLatin1(value) };
    case 0x46:
      return { ...base, name: "Surname", value: decodeLatin1(value) };
    case 0x48:
      return { ...base, name: "Sex", value: decodeLatin1(value) };
    case 0x4C:
      return { ...base, name: "Document expiry date", value: decodeLatin1(value) };
    case 0x50:
      return buildThumbnailField(base, value);
    case 0x60:
      return { ...base, name: "Address (full)", value: decodeLatin1(value) };
    case 0x72:
      return { ...base, name: "Address line 1", value: decodeLatin1(value) };
    case 0x74:
      return { ...base, name: "Address line 2", value: decodeLatin1(value) };
    case 0x76:
      return { ...base, name: "Address line 3", value: decodeLatin1(value) };
    case 0x62:
      return { ...base, name: "Place of birth line 1", value: decodeLatin1(value) };
    case 0x78:
      return { ...base, name: "Place of birth line 2", value: decodeLatin1(value) };
    case 0x7A:
      return { ...base, name: "Place of birth line 3", value: decodeLatin1(value) };
    case 0x64:
      return { ...base, name: "Nationality", value: decodeLatin1(value) };
    case 0x66:
      return { ...base, name: "Parents", value: decodeLatin1(value) };
    case 0x68:
      return { ...base, name: "DNI support number", value: decodeLatin1(value) };
    case 0x70:
      return { ...base, name: "Is adult", value: value[0] === 0x01 };
    case 0x80:
      return { ...base, name: "Data expiry", value: decodeLatin1(value) };
    default:
      return null;
  }
}

function decodeLatin1(data) {
  return data.toString("latin1");
}

function buildThumbnailField(base, value) {
  const includeBase64 = (process.env.INCLUDE_THUMBNAIL_BASE64 || "true").toLowerCase() === "true";
  if (!includeBase64) {
    return { ...base, name: "Thumbnail (JPEG2000)", value: null };
  }

  return {
    ...base,
    name: "Thumbnail (JPEG2000)",
    value: value.toString("base64"),
  };
}

function applyFieldToData(data, field) {
  switch (field.tag) {
    case 0x40:
      data.documentNumber = field.value;
      break;
    case 0x42:
      data.birthDate = field.value;
      break;
    case 0x44:
      data.givenName = field.value;
      break;
    case 0x46:
      data.surnames = field.value;
      break;
    case 0x48:
      data.sex = field.value;
      break;
    case 0x4C:
      data.documentExpiry = field.value;
      break;
    case 0x50:
      if (field.value) {
        data.thumbnailBase64 = field.value;
      }
      break;
    case 0x60:
      data.addressFull = field.value || null;
      break;
    case 0x72:
    case 0x74:
    case 0x76:
      if (field.value) {
        data.addressLines.push(field.value);
      }
      break;
    case 0x62:
    case 0x78:
    case 0x7A:
      if (field.value) {
        data.placeOfBirthLines.push(field.value);
      }
      break;
    case 0x64:
      data.nationality = field.value;
      break;
    case 0x66:
      data.parents = field.value;
      break;
    case 0x68:
      data.supportNumber = field.value;
      break;
    case 0x70:
      data.isAdult = field.value === true;
      break;
    case 0x80:
      data.dataExpiry = field.value;
      break;
    default:
      break;
  }
}

module.exports = {
  parseQRPayload,
};
