# Bitcoin Address Decoder

A simple, mobile-friendly static web app for decoding any Bitcoin address into its network, type, payload, and checksum details — all entirely in your browser.

## Features

- Supports Base58Check (P2PKH, P2SH) and Bech32/Bech32m (P2WPKH, P2WSH, Taproot, and custom witness versions)
- Detects network (mainnet, testnet, regtest, or unknown HRP/version byte)
- Validates checksums per BIP-173, BIP-350, and Base58Check rules
- Displays payload in hex with copy-to-clipboard
- Works fully offline (no data ever leaves your browser)
- Responsive, clean interface optimized for desktop and mobile

## How to Use

1. Paste or type any Bitcoin address (mainnet, testnet, or regtest) into the input field
2. Click **Decode** or press **Enter**
3. View the encoding, network, type, checksum validity, and payload
4. Copy the raw payload if needed for further analysis

## Installation

1. Clone this repository
2. Open `index.html` in a modern web browser
3. (Optional) Add to home screen for quick offline use

## Technologies Used

- HTML5
- Tailwind CSS (CDN build)
- Vanilla JavaScript
- BIP-173 / BIP-350 Bech32 & Bech32m decoding
- Base58Check decoding and checksum validation

## Development

1. Clone the repository
2. Edit `index.html` in your code editor
3. Open `index.html` in a browser to test changes
4. No build step required — it's pure HTML, CSS, and JavaScript

## License

[The Unlicense](./LICENSE) for more information.

## Support

PRs are welcome! I’m open to any/all suggestions.