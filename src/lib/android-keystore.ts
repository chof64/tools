export interface KeyProperties {
  storePassword?: string;
  keyAlias?: string;
  storeFile?: string;
}

export interface SigningFingerprints {
  format: "JKS" | "PKCS#12";
  alias: string;
  sha1: string;
  sha256: string;
}

type CertificateEntry = { alias: string | null; certificate: Uint8Array };
type Asn1Node = { tag: number; value: Uint8Array };

const MAX_KEYSTORE_BYTES = 10 * 1024 * 1024;
const JKS_MAGIC = 0xfeedfeed;
const DATA_OID = "1.2.840.113549.1.7.1";
const ENCRYPTED_DATA_OID = "1.2.840.113549.1.7.6";
const CERT_BAG_OID = "1.2.840.113549.1.12.10.1.3";
const X509_CERT_OID = "1.2.840.113549.1.9.22.1";
const FRIENDLY_NAME_OID = "1.2.840.113549.1.9.20";
const PBES2_OID = "1.2.840.113549.1.5.13";
const PBKDF2_OID = "1.2.840.113549.1.5.12";

export function parseKeyProperties(text: string): KeyProperties {
  const values = new Map<string, string>();
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const unescape = (input: string) =>
    input.replace(/\\(u[0-9a-fA-F]{4}|.)/g, (_, character: string) => {
      if (character[0] === "u") return String.fromCharCode(parseInt(character.slice(1), 16));
      return character === "t" ? "\t" : character === "n" ? "\n" : character === "r" ? "\r" : character === "f" ? "\f" : character;
    });

  for (let index = 0; index < lines.length; index++) {
    let line = lines[index].replace(/^\s+/, "");
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    while (/(^|[^\\])(\\\\)*\\$/.test(line) && index + 1 < lines.length) {
      line = line.slice(0, -1) + lines[++index].replace(/^\s+/, "");
    }
    let separator = 0;
    while (separator < line.length) {
      if (line[separator] === "\\") { separator += 2; continue; }
      if (/[=:\s]/.test(line[separator])) break;
      separator++;
    }
    const key = unescape(line.slice(0, separator));
    let valueStart = separator;
    while (valueStart < line.length && /\s/.test(line[valueStart])) valueStart++;
    if (line[valueStart] === "=" || line[valueStart] === ":") valueStart++;
    while (valueStart < line.length && /\s/.test(line[valueStart])) valueStart++;
    values.set(key, unescape(line.slice(valueStart)));
  }
  return {
    storePassword: values.get("storePassword"),
    keyAlias: values.get("keyAlias"),
    storeFile: values.get("storeFile"),
  };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}

function toFingerprint(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

async function hash(algorithm: "SHA-1" | "SHA-256", bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(algorithm, new Uint8Array(bytes)));
}

class BinaryReader {
  offset = 0;
  private view: DataView;

  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  private require(length: number) {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) {
      throw new Error("The keystore is truncated or malformed.");
    }
  }

  uint16(): number {
    this.require(2);
    const result = this.view.getUint16(this.offset);
    this.offset += 2;
    return result;
  }

  uint32(): number {
    this.require(4);
    const result = this.view.getUint32(this.offset);
    this.offset += 4;
    return result;
  }

  read(length: number): Uint8Array {
    this.require(length);
    const result = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  utf(): string {
    const value = this.read(this.uint16());
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  }
}

async function parseJks(bytes: Uint8Array, password: string): Promise<CertificateEntry[]> {
  if (bytes.length < 32) throw new Error("The JKS file is too short.");
  const suppliedDigest = bytes.subarray(bytes.length - 20);
  const data = bytes.subarray(0, bytes.length - 20);
  const passwordBytes = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    passwordBytes[i * 2] = password.charCodeAt(i) >>> 8;
    passwordBytes[i * 2 + 1] = password.charCodeAt(i) & 0xff;
  }
  const label = new TextEncoder().encode("Mighty Aphrodite");
  const input = new Uint8Array(passwordBytes.length + label.length + data.length);
  input.set(passwordBytes);
  input.set(label, passwordBytes.length);
  input.set(data, passwordBytes.length + label.length);
  if (!sameBytes(await hash("SHA-1", input), suppliedDigest)) {
    throw new Error("Incorrect store password or damaged JKS file.");
  }

  const reader = new BinaryReader(data);
  if (reader.uint32() !== JKS_MAGIC) throw new Error("Invalid JKS header.");
  const version = reader.uint32();
  if (version !== 1 && version !== 2) throw new Error("Unsupported JKS version.");
  const count = reader.uint32();
  if (count > 1000) throw new Error("The keystore contains too many entries.");
  const certificates: CertificateEntry[] = [];
  for (let i = 0; i < count; i++) {
    const tag = reader.uint32();
    const alias = reader.utf();
    reader.read(8);
    if (tag === 1) {
      reader.read(reader.uint32());
      const chainLength = reader.uint32();
      if (chainLength > 1000) throw new Error("The JKS certificate chain is too long.");
      for (let j = 0; j < chainLength; j++) {
        if (version === 2) reader.utf();
        const certificate = reader.read(reader.uint32());
        if (j === 0) certificates.push({ alias, certificate });
      }
    } else if (tag === 2) {
      if (version === 2) reader.utf();
      certificates.push({ alias, certificate: reader.read(reader.uint32()) });
    } else {
      throw new Error("Unsupported JKS entry type.");
    }
  }
  if (reader.offset !== data.length) throw new Error("Unexpected data in JKS file.");
  return certificates;
}

function readDer(bytes: Uint8Array): Asn1Node {
  const reader = new BinaryReader(bytes);
  const tag = reader.read(1)[0];
  const first = reader.read(1)[0];
  let length = first;
  if (first >= 0x80) {
    const count = first & 0x7f;
    if (count === 0 || count > 4) throw new Error("Unsupported ASN.1 length encoding.");
    length = 0;
    for (const byte of reader.read(count)) length = length * 256 + byte;
  }
  const value = reader.read(length);
  if (reader.offset !== bytes.length) throw new Error("Unexpected data after ASN.1 value.");
  return { tag, value };
}

function children(node: Asn1Node, tag = 0x30): Asn1Node[] {
  if (node.tag !== tag) throw new Error("Invalid PKCS#12 structure.");
  const reader = new BinaryReader(node.value);
  const values: Asn1Node[] = [];
  while (reader.offset < node.value.length) {
    const start = reader.offset;
    reader.read(1);
    const first = reader.read(1)[0];
    let length = first;
    if (first >= 0x80) {
      const count = first & 0x7f;
      if (!count || count > 4) throw new Error("Unsupported ASN.1 length encoding.");
      length = 0;
      for (const byte of reader.read(count)) length = length * 256 + byte;
    }
    reader.read(length);
    values.push(readDer(node.value.subarray(start, reader.offset)));
  }
  return values;
}

function single(node: Asn1Node, tag = 0xa0): Asn1Node {
  const values = children(node, tag);
  if (values.length !== 1) throw new Error("Invalid PKCS#12 wrapper.");
  return values[0];
}

function oid(node: Asn1Node): string {
  if (node.tag !== 0x06 || !node.value.length) throw new Error("Invalid ASN.1 object identifier.");
  const result = [Math.floor(node.value[0] / 40), node.value[0] % 40];
  let component = 0;
  for (let i = 1; i < node.value.length; i++) {
    component = component * 128 + (node.value[i] & 0x7f);
    if (!Number.isSafeInteger(component)) throw new Error("Invalid ASN.1 object identifier.");
    if ((node.value[i] & 0x80) === 0) {
      result.push(component);
      component = 0;
    }
  }
  if (node.value[node.value.length - 1] & 0x80) throw new Error("Invalid ASN.1 object identifier.");
  return result.join(".");
}

function integer(node: Asn1Node): number {
  if (node.tag !== 0x02 || !node.value.length || node.value[0] & 0x80) {
    throw new Error("Invalid ASN.1 integer.");
  }
  let value = 0;
  for (const byte of node.value) {
    value = value * 256 + byte;
    if (!Number.isSafeInteger(value)) throw new Error("ASN.1 integer is too large.");
  }
  return value;
}

function octets(node: Asn1Node): Uint8Array {
  if (node.tag === 0x04 || node.tag === 0x80) return node.value;
  if (node.tag === 0x24 || node.tag === 0xa0) {
    const chunks = children(node, node.tag).map(octets);
    const result = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
  }
  throw new Error("Invalid ASN.1 octet string.");
}

function unicodeName(node: Asn1Node): string {
  if (node.tag === 0x1e) {
    if (node.value.length % 2) throw new Error("Invalid PKCS#12 friendly name.");
    let result = "";
    for (let i = 0; i < node.value.length; i += 2) {
      result += String.fromCharCode((node.value[i] << 8) | node.value[i + 1]);
    }
    return result;
  }
  if (node.tag === 0x0c) return new TextDecoder().decode(node.value);
  return "";
}

function getFriendlyName(attributes?: Asn1Node): string | null {
  if (!attributes) return null;
  for (const attribute of children(attributes, 0x31)) {
    const [identifier, values] = children(attribute);
    if (oid(identifier) === FRIENDLY_NAME_OID) {
      return unicodeName(children(values, 0x31)[0]) || null;
    }
  }
  return null;
}

function passwordUtf16(password: string): Uint8Array {
  const bytes = new Uint8Array((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++) {
    bytes[i * 2] = password.charCodeAt(i) >>> 8;
    bytes[i * 2 + 1] = password.charCodeAt(i) & 0xff;
  }
  return bytes;
}

function repeatToBlock(input: Uint8Array, blockLength: number): Uint8Array {
  if (!input.length) return new Uint8Array();
  const output = new Uint8Array(Math.ceil(input.length / blockLength) * blockLength);
  for (let i = 0; i < output.length; i++) output[i] = input[i % input.length];
  return output;
}

async function derivePkcs12MacKey(
  password: string, salt: Uint8Array, iterations: number, algorithm: "SHA-1" | "SHA-256"
): Promise<Uint8Array> {
  const blockLength = 64;
  const diversifier = new Uint8Array(blockLength).fill(3);
  const saltBytes = repeatToBlock(salt, blockLength);
  const passwordBytes = repeatToBlock(passwordUtf16(password), blockLength);
  const input = new Uint8Array(saltBytes.length + passwordBytes.length);
  input.set(saltBytes);
  input.set(passwordBytes, saltBytes.length);
  let result = new Uint8Array(diversifier.length + input.length);
  result.set(diversifier);
  result.set(input, diversifier.length);
  for (let i = 0; i < iterations; i++) result = await hash(algorithm, result);
  return result;
}

async function validatePkcs12Mac(
  authSafe: Uint8Array, macData: Asn1Node, password: string
): Promise<void> {
  const [digestInfo, salt, rounds] = children(macData);
  const [algorithmIdentifier, expectedDigest] = children(digestInfo);
  const digestOid = oid(children(algorithmIdentifier)[0]);
  const algorithm = digestOid === "1.3.14.3.2.26" ? "SHA-1" :
    digestOid === "2.16.840.1.101.3.4.2.1" ? "SHA-256" : null;
  if (!algorithm) throw new Error("Unsupported PKCS#12 integrity algorithm.");
  const iterations = rounds ? integer(rounds) : 1;
  if (iterations < 1 || iterations > 1_000_000) throw new Error("Invalid PKCS#12 MAC iteration count.");
  const key = await derivePkcs12MacKey(password, octets(salt), iterations, algorithm);
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: algorithm }, false, ["sign"]);
  const calculated = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new Uint8Array(authSafe)));
  if (!sameBytes(calculated, octets(expectedDigest))) {
    throw new Error("Incorrect store password or damaged PKCS#12 file.");
  }
}

async function decryptSafeContents(encryptedData: Asn1Node, password: string): Promise<Uint8Array> {
  const [, encryptedContentInfo] = children(encryptedData);
  const [, algorithmIdentifier, ciphertext] = children(encryptedContentInfo);
  if (!ciphertext) throw new Error("PKCS#12 encrypted certificates are missing.");
  const [algorithmOid, algorithmParams] = children(algorithmIdentifier);
  if (oid(algorithmOid) !== PBES2_OID) {
    throw new Error("This PKCS#12 file uses legacy encryption. Re-export it with PBES2/AES or JKS.");
  }
  const [kdfIdentifier, cipherIdentifier] = children(algorithmParams);
  const [kdfOid, kdfParams] = children(kdfIdentifier);
  if (oid(kdfOid) !== PBKDF2_OID) throw new Error("Unsupported PKCS#12 key derivation.");
  const params = children(kdfParams);
  const salt = octets(params[0]);
  const iterations = integer(params[1]);
  if (iterations < 1 || iterations > 1_000_000) throw new Error("Invalid PKCS#12 PBKDF2 iteration count.");
  let hashAlgorithm: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512" = "SHA-1";
  const prf = params.find((node) => node.tag === 0x30);
  if (prf) {
    const prfOid = oid(children(prf)[0]);
    const hashes: Record<string, "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"> = {
      "1.2.840.113549.2.7": "SHA-1",
      "1.2.840.113549.2.9": "SHA-256",
      "1.2.840.113549.2.10": "SHA-384",
      "1.2.840.113549.2.11": "SHA-512",
    };
    if (!hashes[prfOid]) throw new Error("Unsupported PKCS#12 PBKDF2 hash.");
    hashAlgorithm = hashes[prfOid];
  }
  const [cipherOid, iv] = children(cipherIdentifier);
  const keySizes: Record<string, number> = {
    "2.16.840.1.101.3.4.1.2": 128,
    "2.16.840.1.101.3.4.1.22": 192,
    "2.16.840.1.101.3.4.1.42": 256,
  };
  const keySize = keySizes[oid(cipherOid)];
  if (!keySize) throw new Error("Unsupported PKCS#12 encryption (expected AES-CBC).");
  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const derivedKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: new Uint8Array(salt), iterations, hash: hashAlgorithm },
    baseKey, { name: "AES-CBC", length: keySize }, false, ["decrypt"]
  );
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: new Uint8Array(octets(iv)) }, derivedKey, new Uint8Array(octets(ciphertext))
    ));
  } catch {
    throw new Error("Unable to decrypt PKCS#12 certificates with this password.");
  }
}

async function parsePkcs12(bytes: Uint8Array, password: string): Promise<CertificateEntry[]> {
  const pfx = children(readDer(bytes));
  if (integer(pfx[0]) !== 3) throw new Error("Unsupported PKCS#12 version.");
  const [type, wrapped] = children(pfx[1]);
  if (oid(type) !== DATA_OID) throw new Error("Unsupported PKCS#12 authentication container.");
  const authSafe = octets(single(wrapped));
  if (!pfx[2]) throw new Error("The PKCS#12 keystore has no password integrity check.");
  await validatePkcs12Mac(authSafe, pfx[2], password);
  const certificates: CertificateEntry[] = [];
  for (const item of children(readDer(authSafe))) {
    const [contentType, content] = children(item);
    const typeOid = oid(contentType);
    let safeContents: Uint8Array;
    if (typeOid === DATA_OID) {
      safeContents = octets(single(content));
    } else if (typeOid === ENCRYPTED_DATA_OID) {
      safeContents = await decryptSafeContents(single(content), password);
    } else {
      throw new Error("Unsupported PKCS#12 content type.");
    }
    for (const bag of children(readDer(safeContents))) {
      const [bagId, bagValue, attributes] = children(bag);
      if (oid(bagId) !== CERT_BAG_OID) continue;
      const [certId, certValue] = children(single(bagValue));
      if (oid(certId) !== X509_CERT_OID) continue;
      const certificate = octets(single(certValue));
      if (readDer(certificate).tag !== 0x30) throw new Error("Invalid X.509 certificate.");
      certificates.push({ alias: getFriendlyName(attributes), certificate });
    }
  }
  return certificates;
}

export async function getSigningFingerprints(
  fileBuffer: ArrayBuffer, storePassword: string, keyAlias = ""
): Promise<SigningFingerprints> {
  const bytes = new Uint8Array(fileBuffer);
  if (bytes.length > MAX_KEYSTORE_BYTES) throw new Error("Maximum supported keystore size is 10 MB.");
  if (bytes.length < 4) throw new Error("The selected file is not a keystore.");
  const isJks = new DataView(fileBuffer).getUint32(0) === JKS_MAGIC;
  const format = isJks ? "JKS" : "PKCS#12";
  const certificates = isJks ? await parseJks(bytes, storePassword) : await parsePkcs12(bytes, storePassword);
  if (!certificates.length) throw new Error("No X.509 signing certificates were found in the keystore.");
  const wantedAlias = keyAlias.trim().toLowerCase();
  const found = wantedAlias ? certificates.find((entry) => entry.alias?.toLowerCase() === wantedAlias) : null;
  if (wantedAlias && !found) {
    throw new Error("Alias '" + keyAlias + "' not found. Available aliases: " + certificates.map((entry) => entry.alias ?? "(unnamed)").join(", ") + ".");
  }
  if (!wantedAlias && certificates.length !== 1) {
    throw new Error("Multiple certificates found. Supply keyAlias from key.properties.");
  }
  const entry = found ?? certificates[0];
  if (readDer(entry.certificate).tag !== 0x30) throw new Error("Invalid X.509 certificate.");
  const [sha1, sha256] = await Promise.all([
    hash("SHA-1", entry.certificate),
    hash("SHA-256", entry.certificate),
  ]);
  return { format, alias: entry.alias || keyAlias || "(unnamed)", sha1: toFingerprint(sha1), sha256: toFingerprint(sha256) };
}
