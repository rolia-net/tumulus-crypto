const assert = require('node:assert');
const fs = require("fs");
const { Buffer } = require('buffer');
const { 
	hybridDecryptHexKey,
	hybridEncryptHexKey,
	hybridDecryptHex,
	hybridEncryptHex,
	hybridDecrypt, 
	hybridEncrypt } = require('./crypto.js');

const publicKey = fs.readFileSync("./public_key", "utf8");
const privateKey = {
	key: fs.readFileSync("./private_key", "utf8"),
	passphrase: ''
};

const salt = "abcdsalt";
const prk1 = "571da607eba8e7abccbed499bb3624e716c04b182685c01102c8871dedf3ab1f";
const prk2 = "0x571da607eba8e7abccbed499bb3624e716c04b182685c01102c8871dedf3ab1f";

async function t1() {
	const srcBuf = Buffer.from(prk1, 'hex');
	const hybridBuf = await hybridEncrypt(srcBuf, publicKey, salt);
	const decBuf = await hybridDecrypt(hybridBuf, privateKey, salt);
	assert.equal(srcBuf.toString('hex'), decBuf.toString('hex'));
}
async function t2() {
	const hybrid = await hybridEncryptHex(prk1, publicKey, salt);
	const dec = await hybridDecryptHex(hybrid, privateKey, salt);
	assert.equal(prk1, dec);
}
async function t3() {
	const hybrid = await hybridEncryptHexKey(prk2, publicKey, salt);
	const dec = await hybridDecryptHexKey(hybrid, privateKey, salt);
	assert.equal(prk2, dec);
}


t1();
t2();
t3();