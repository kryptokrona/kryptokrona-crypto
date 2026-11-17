#!/usr/bin/env node
// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * Differential check of the functions this package implements in rust/extra (not in the
 * shared crypto core, whose own comparison is xkr's crates/xkr-crypto-ffi/compat/compare.js):
 * the multisig helpers, scalarmultKey, tree_hash_from_branch and Chukwa, on seeded inputs,
 * against a built kryptokrona-crypto 1.x (its C++ addon).
 *
 *   node tests/compare-1x.js <built kryptokrona-crypto 1.x directory> [seed] [count]
 *
 * Needs `npm run build && npm run build-napi` here. Exit code 0: identical; 1: differences;
 * 2: usage or loading problem.
 */
'use strict';

const path = require('path');

const [oldDir, seedArg, countArg] = process.argv.slice(2);

if (!oldDir) {
    console.error('usage: node tests/compare-1x.js <kryptokrona-crypto 1.x dir> [seed] [count]');
    process.exit(2);
}

const seed = BigInt(seedArg || 1);
const count = Number(countArg || 500);

const current = require(path.join(__dirname, '..', 'dist', 'index.js'));
const previous = require(path.resolve(oldDir, 'dist', 'index.js'));

const now = new current.Crypto();
const old = new previous.Crypto();

if (now.type !== current.CryptoType.NAPI) {
    console.error('the Node-API addon of this checkout is not loaded (npm run build-napi)');
    process.exit(2);
}

if (old.type !== previous.CryptoType.NODEADDON) {
    console.error('the C++ addon of ' + oldDir + ' is not loaded (backend ' + old.type + ')');
    process.exit(2);
}

/* splitmix64 */
let state = seed;
const MASK = (1n << 64n) - 1n;

function next () {
    state = (state + 0x9e3779b97f4a7c15n) & MASK;
    let z = state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;
    return z ^ (z >> 31n);
}

function below (n) {
    return Number(next() % BigInt(n));
}

function bytes (len) {
    let out = '';
    while (out.length < 2 * len) {
        out += next().toString(16).padStart(16, '0');
    }
    return out.substr(0, 2 * len);
}

async function scalar () {
    return now.scReduce32(bytes(32));
}

async function point () {
    return now.secretKeyToPublicKey(await scalar());
}

async function points (n) {
    const out = [];
    for (let i = 0; i < n; i++) {
        out.push(await point());
    }
    return out;
}

async function scalars (n) {
    const out = [];
    for (let i = 0; i < n; i++) {
        out.push(await scalar());
    }
    return out;
}

const results = {};
const differences = [];

/* A result, or { rejected: <message> }. The 1.x wrapper rejects with the addon's error flag
   (`true`) rather than an Error, so the reason is printed as given. Two rejections count as the
   same outcome whatever their messages. */
async function outcome (lib, fn, args) {
    try {
        return await lib[fn](...args);
    } catch (e) {
        return { rejected: e instanceof Error ? e.message : String(e) };
    }
}

function same (a, b) {
    const rejected = (x) => x !== null && typeof x === 'object' && 'rejected' in x;
    if (rejected(a) || rejected(b)) {
        return rejected(a) && rejected(b);
    }
    return JSON.stringify(a) === JSON.stringify(b);
}

async function compare (fn, args) {
    const a = await outcome(now, fn, args);
    const b = await outcome(old, fn, args);
    results[fn] = results[fn] || { total: 0, different: 0, rejected: 0 };
    results[fn].total++;
    if (same(a, b) && a !== null && typeof a === 'object' && 'rejected' in a) {
        results[fn].rejected++;
    }
    if (!same(a, b)) {
        results[fn].different++;
        differences.push({ fn, args, now: a, previous: b });
    }
}

async function main () {
    for (let i = 0; i < count; i++) {
        /* key lists of every length the functions take, the empty one included */
        await compare('calculateMultisigPrivateKeys', [await scalar(), await points(below(4))]);
        await compare('calculateSharedPrivateKey', [await scalars(below(5))]);
        await compare('calculateSharedPublicKey', [await points(below(5))]);

        const signature = (await scalar()) + bytes(32);
        await compare('generatePartialSigningKey', [signature, await scalar()]);

        const publicEphemeral = await point();
        const derivation = await now.generateKeyDerivation(await point(), await scalar());
        const outputIndex = below(16);
        await compare('restoreKeyImage', [publicEphemeral, derivation, outputIndex, await points(below(4))]);

        const ringSize = 1 + below(4);
        const real = below(ringSize);
        const signatures = [];
        for (let j = 0; j < ringSize; j++) {
            signatures.push((await scalar()) + (await scalar()));
        }
        await compare('restoreRingSignatures',
            [derivation, outputIndex, await scalars(below(4)), real, await scalar(), signatures]);

        /* multipliers of every size, also with the top bit set */
        await compare('scalarmultKey', [await point(), bytes(32)]);
        await compare('scalarmultKey', [await point(), await scalar()]);

        const leafCount = 1 + below(9);
        const hashes = [];
        for (let j = 0; j < leafCount; j++) {
            hashes.push(bytes(32));
        }
        const branch = await now.tree_branch(hashes);
        await compare('tree_hash_from_branch', [branch, hashes[0], 0]);
    }

    for (let i = 0; i < Math.max(1, Math.floor(count / 50)); i++) {
        const data = bytes(16 + below(64));
        await compare('chukwa_slow_hash_v1', [data]);
        await compare('chukwa_slow_hash_v2', [data]);
        await compare('chukwa_slow_hash_base', [data, 1 + below(3), 16 * (1 + below(64)), 1 + below(2)]);
    }

    for (const fn of Object.keys(results).sort()) {
        const r = results[fn];
        console.log((r.different === 0 ? 'ok   ' : 'DIFF ') + fn + ' ' + (r.total - r.different) + '/' + r.total +
            (r.rejected > 0 ? ' (' + r.rejected + ' rejected by both)' : ''));
    }
    for (const d of differences.slice(0, 10)) {
        console.log(JSON.stringify(d));
    }
    process.exit(differences.length === 0 ? 0 : 1);
}

main().catch((e) => {
    console.error(e);
    process.exit(2);
});
