// minerdrip.js: MinerDrip helpers for the Kozmic bridge. No dependencies (BigInt, Buffer).
// Pure functions lifted from the SilverScript Studio's routes/kcc20-endow.js (proven on mainnet Oct 10-11, 2026).
// Building, signing and submitting transactions stays with the bridge's own Kaspa SDK code.

'use strict';

const CLAIM_TAG = '26aa3fc0';    // dispatch tag of claim(), same for every drip (it hashes the entry signature)
const REVEAL_TAG = 'fcffbcc1';   // dispatch tag of reveal()
const DAA_PER_DAY = 864000;      // mainnet, ~10 DAA per second
const SOMPI = 100000000n;

// The launcher's three choices -> the covenant's constants. All amounts sompi (BigInt). Throws Error with a readable message.
//   endow       KAS (sompi) the genesis puts into the drip
//   firstPrize  what the first scheduled claim pays
//   halvingDays how long until a claim pays half of firstPrize
function schedule(endow, firstPrize, halvingDays) {
    endow = BigInt(endow); firstPrize = BigInt(firstPrize);
    if (endow < SOMPI) throw new Error('Endowment: at least 1 KAS (smaller outputs are too heavy for the network)');
    if (firstPrize < 1000000n) throw new Error('Starting prize: at least 0.01 KAS');
    if (firstPrize * 10n > endow) throw new Error('Starting prize: at most a tenth of the endowment');
    if (!(halvingDays >= 7 && halvingDays <= 2922)) throw new Error('Halving time: 7 days to 8 years');
    const divisor = BigInt(Math.max(2, Math.round(Number(endow) / Number(firstPrize))));
    const perHalving = Math.LN2 / -Math.log1p(-1 / Number(divisor));        // claims until the prize halves
    const period = Math.round(halvingDays * DAA_PER_DAY / perHalving);
    if (period < 600) throw new Error('A claim more often than once a minute; pick a smaller starting prize or a longer halving time');
    if (period >= 2 ** 32) throw new Error('Claims too far apart; pick a bigger starting prize or a shorter halving time');
    let minPrize = firstPrize / 20n; if (minPrize < 1000000n) minPrize = 1000000n;
    return { period: BigInt(period), divisor, minPrize, endowment: endow, firstPrize: endow / divisor, claimEveryHours: period / DAA_PER_DAY * 24, perHalving };
}

// Constructor arguments in declaration order, as silverc ArtifactValue JSON (--constructor-args file):
// MinerDrip(int period, int divisor, int minPrize, byte[32] tokenId, int endowment)
function ctorArgs(s, tokenIdHex) {
    const id = cleanHex(tokenIdHex);
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('tokenId must be the token covenant ID, 64 hex characters');
    const num = v => { const n = Number(v); if (!Number.isSafeInteger(n)) throw new Error('value out of JSON-safe range: ' + v); return n; };
    return [{ kind: 'int', value: num(s.period) }, { kind: 'int', value: num(s.divisor) }, { kind: 'int', value: num(s.minPrize) },
            { kind: 'bytes', value: [...Buffer.from(id, 'hex')] }, { kind: 'int', value: num(s.endowment) }];
}

// The compiled redeem script must open with the claim guard and carry the stamp. Same check the Studio runs before funding.
function checkRedeem(redeemHex, tokenIdHex) {
    const hex = cleanHex(redeemHex), id = cleanHex(tokenIdHex);
    if (!hex.startsWith('7604' + CLAIM_TAG)) throw new Error('not the MinerDrip program (claim guard missing at the start)');
    if (!hex.includes('04' + REVEAL_TAG)) throw new Error('not the MinerDrip program (reveal entry missing)');
    if (hex.length > 900) throw new Error('MinerDrip script longer than expected');
    if (!hex.includes(id)) throw new Error('the token covenant ID is not stamped into the script');
    return true;
}

// Minimal data push
function pushData(b) {
    const n = b.length;
    if (n <= 75) return Buffer.concat([Buffer.from([n]), b]);
    if (n <= 255) return Buffer.concat([Buffer.from([0x4c, n]), b]);
    const l = Buffer.alloc(2); l.writeUInt16LE(n); return Buffer.concat([Buffer.from([0x4d]), l, b]);
}

// Signature scripts. Nobody signs: <push tag> <push redeem>. Set the input's sigOpCount to 0.
const sigScript = (tag, redeemHex) => Buffer.concat([pushData(Buffer.from(tag, 'hex')), pushData(Buffer.from(cleanHex(redeemHex), 'hex'))]).toString('hex');
const revealSigScript = redeemHex => sigScript(REVEAL_TAG, redeemHex);
const claimSigScript = redeemHex => sigScript(CLAIM_TAG, redeemHex);

// What a spend must look like. Each returns the single output (back to the drip's own address) and the fee it leaves.
//   reveal: valid only while the coin holds the whole endowment, no age requirement, input sequence 0.
//   claim:  input sequence = period, the coin at least `period` DAA old.
function revealSpend(balance, s) {
    balance = BigInt(balance);
    if (balance < BigInt(s.endowment)) return null;                       // already revealed
    return { sequence: 0n, keepSompi: balance - BigInt(s.minPrize), feeSompi: BigInt(s.minPrize) };
}
function prizeOf(balance, s) { let p = BigInt(balance) / BigInt(s.divisor); const m = BigInt(s.minPrize); return p < m ? m : p; }
function claimSpend(balance, s) {
    balance = BigInt(balance);
    const prize = prizeOf(balance, s);
    if (balance - prize < BigInt(s.minPrize)) return null;                // finished: the last sliver stays
    return { sequence: BigInt(s.period), keepSompi: balance - prize, feeSompi: prize };
}

const cleanHex = h => String(h || '').replace(/^0x/i, '').toLowerCase();

module.exports = { CLAIM_TAG, REVEAL_TAG, DAA_PER_DAY, schedule, ctorArgs, checkRedeem, pushData,
                   revealSigScript, claimSigScript, revealSpend, claimSpend, prizeOf };
