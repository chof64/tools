# tools

A static, client-side collection of developer tools that run directly in the browser. Everything is computed locally — nothing leaves your device.

## Features

- **Client-Side Only**: All processing happens in your browser, ensuring your data never leaves your device.
- **JWT Key Generation**: Generates keys compatible with Convex Auth setup for secure authentication.
- **Android Keystore Fingerprints**: Extract SHA-1 and SHA-256 certificate fingerprints from JKS and modern PKCS#12 keystores, using an optional `key.properties` file. All parsing and password handling stay in the browser.
- **Base64 Encoder/Decoder**: Encode and decode text or files to and from Base64 (UTF-8 safe, files handled locally in the browser).
- **Simple UI**: Clean, focused interface for each tool.
- **No Installation Required**: Access directly via the hosted version – no dependencies to install.
- **Privacy-Focused**: Static site with no server-side processing or data collection.

## Live Demo

Try it out at: [https://chof64.github.io/tools](https://chof64.github.io/tools)

## Tools

### JWKS Generator

Generates a JWT private key and matching JWKS (JSON Web Key Set) for your Convex deployment. This wraps the key generation logic from [Convex Auth's manual setup guide](https://labs.convex.dev/auth/setup/manual).

The underlying process uses the `jose` library to:
1. Generate an RSA key pair (RS256 algorithm).
2. Export the private key in PKCS#8 format.
3. Create a JWKS with the public key.
4. Output the values for copying into your Convex environment variables.

### Android Keystore Fingerprints

Open `/keystore/`, select your Android `upload-keystore.jks` (or `.keystore`, `.p12`, `.pfx`), then optionally select `key.properties` with `storePassword` and `keyAlias`. You can enter these two values manually instead. Click **Get fingerprints** to display copyable SHA-1 and SHA-256 values for the signing certificate. The key password is not required; the tool never exports private key material.

- Supports Java JKS and modern PBES2/AES PKCS#12 stores (which may still have `.jks` extensions).
- Validates the store password and selects the certificate by alias when provided.
- Legacy PKCS#12 encryption formats are not supported; use JKS or re-export with PBES2/AES if needed.
- These are *upload certificate* fingerprints; Google Play App Signing may use a different signing certificate.
- No keystore data, passwords, or properties are sent to a server or persisted by the app.

### Base64 Encoder/Decoder

Encode text into Base64 or decode Base64 back into text. Uses the `TextEncoder`/`TextDecoder` APIs, so non-ASCII characters (accented letters, emoji, etc.) are handled correctly.

You can also convert files:

- **Encode a file**: Pick any file — it is read locally and converted to a Base64 string you can copy or download as a `.b64` file.
- **Decode to a file**: Paste Base64 (or load a `.b64`/`.txt` file), optionally adjust the output file name, and download the decoded file. The file type (e.g. image, PDF, ZIP) is auto-detected from the binary signature so the output is saved with a sensible extension.

## Usage

1. Visit the live demo: [https://chof64.github.io/tools](https://chof64.github.io/tools)
2. Choose a tool from the navigation.
3. Follow the on-screen instructions for the selected tool.

### JWKS Generator

1. Click "Generate Keys" to create a new JWT private key and JWKS.
2. Copy the generated `JWT_PRIVATE_KEY` and `JWKS` values.
3. Paste them into your Convex deployment's [Environment Variables](https://dashboard.convex.dev/deployment/settings/environment-variables) page.
4. Follow the remaining steps in the [Convex Auth setup guide](https://labs.convex.dev/auth/setup/manual).

## Privacy & Security

- No data is transmitted or stored externally.
- Keys are generated and displayed only in your browser.
- The application is a static site hosted on GitHub Pages.
- Refresh the page to clear all generated data from memory.

## Tech Stack

- **Frontend**: Astro with React.js
- **Crypto Library**: [jose](https://github.com/panva/jose) for JWT/JWK operations
- **Hosting**: GitHub Pages for static deployment

## License

[MIT License](LICENSE) - Feel free to use and modify as needed.

## Related Links

- [Convex Auth Documentation](https://labs.convex.dev/auth)
- [Convex Auth Manual Setup](https://labs.convex.dev/auth/setup/manual)
- [JOSE Library](https://github.com/panva/jose)
