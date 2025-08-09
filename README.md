# speakaddr — speak your crypto address safely

**speakaddr** turns any crypto address (EVM, Bitcoin, Solana) into a short,
**pronounceable 3-word fingerprint** you can read aloud, verify over the phone,
or display as a tiny badge. It also verifies that a phrase matches an address.

No RPC. No internet. Completely offline.

## Why this exists

Hex is awful for human verification, emojis are hard to read aloud, and checksums
(EIP-55) don’t help over voice. **speakaddr** uses a compact consonant-vowel syllable
system with a checksum syllable so a single misheard sound makes verification fail.

Example:  
`0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db` → `kavo-tari-meco`

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
