const crypto = require('crypto');
const fs = require("fs");
const { waitFor, WritableBufferStream } = require("rolia-util");
const { Buffer } = require('buffer');
const { pipeline, Readable } = require('stream');

const debugging = false;

function logBuf(buf, name) {
	if (debugging) {
		console.log(name + ": " + buf.toString('hex'));
		console.log(buf);
	}
}

function genRandomBuf(size = 23) {
	if (size <= 0) return null;
	let buf = Buffer.alloc(size);
	for (let i = 0; i < size; i++) {
		buf[i] = Math.random() * 256;
	}
	return buf;
}

async function extractPassword(inBuf, privateKey) {
	const pswdRsaBuf = inBuf.subarray(0, 65);
	const pswd = crypto.privateDecrypt(privateKey, pswdRsaBuf);
	return pswd;
}

async function extractPasswordFromFile(hybridFilePath, privateKey) {
	var pswdRsaBuf;
	// length of pswdRsaBuf is always 65
	const input0 = fs.createReadStream(hybridFilePath, { start: 0, end: 64 }); // start&end inclusive.  Totally 65
	var reading = { done: false };
	input0.on('data', chunk => {
		pswdRsaBuf = chunk;
		reading.done = true;
	});
	await waitFor(reading);
	const pswd = crypto.privateDecrypt(privateKey, pswdRsaBuf);
	return pswd;
}


async function hybridEncrypt(srcBuf, publicKey, salt) {
	const password = genRandomBuf();
	const pswdRsaBuf = crypto.publicEncrypt(publicKey, password);
	logBuf(pswdRsaBuf, "pswdRsaBuf");

	const key = crypto.scryptSync(password, salt, 32);
	const iv = Buffer.alloc(16, 0); // Initialization vector.
	const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

	const in1 = Readable.from(srcBuf);
	const out1 = new WritableBufferStream();
	var jobC = { done: false };
	pipeline(in1, cipher, out1, (err) => {
		jobC.done = true;
		if (err) throw err;
	});
	await waitFor(jobC);
	const encBuf = out1.toBuffer();
	logBuf(encBuf, "encrypted");

	const hybridBuf = Buffer.concat([pswdRsaBuf, encBuf]);
	logBuf(hybridBuf, "Hybrid encrypted");
	return hybridBuf;
}

async function hybridDecrypt(hybridBuf, privateKey, salt) {
	const password = await extractPassword(hybridBuf, privateKey);
	logBuf(password, "Extracted pswd");
	const key = crypto.scryptSync(password, salt, 32);
	const iv = Buffer.alloc(16, 0); // Initialization vector.
	const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

	const encBuf = hybridBuf.subarray(65);
	logBuf(encBuf, "input of buf for decryption:");

	const in2 = Readable.from(encBuf);
	const out2 = new WritableBufferStream();
	var jobD = { done: false };
	pipeline(in2, decipher, out2, (err) => {
		jobD.done = true;
		if (err) throw err;
	});
	await waitFor(jobD);
	const decBuf = out2.toBuffer();
	logBuf(decBuf, "decrypted");
	return decBuf;
}


async function hybridEncryptHex(hexStr, publicKey, salt) {
	const srcBuf = Buffer.from(hexStr, 'hex');
	const hybridBuf = await hybridEncrypt(srcBuf, publicKey, salt);
	return hybridBuf.toString('hex');
}

async function hybridDecryptHex(hybridHex, privateKey, salt) {
	const hybridBuf = Buffer.from(hybridHex, 'hex');
	const decBuf = await hybridDecrypt(hybridBuf, privateKey, salt);
	return decBuf.toString('hex');
}

async function hybridEncryptHexKey(hexKey, publicKey, salt) {
	const hexStr = hexKey.startsWith("0x") ? hexKey.substring(2) : hexKey;
	return await hybridEncryptHex(hexStr, publicKey, salt);
}

async function hybridDecryptHexKey(hybridHex, privateKey, salt) {
	const decHex = await hybridDecryptHex(hybridHex, privateKey, salt);
	return "0x".concat(decHex);
}

async function hybridEncryptFile(srcFilePath, fileName, tmpDir, publicKey, salt) {
	const password = genRandomBuf();
	const key = crypto.scryptSync(password, salt, 32);
	const iv = Buffer.alloc(16, 0); // Initialization vector.
	const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

	const tmpSubfolder = Math.random().toString().substring(2, 8) + "_enc";
	fs.mkdirSync(`${tmpDir}/${tmpSubfolder}`);
	const outputFilePath = `${tmpDir}/${tmpSubfolder}/${fileName}`;

	const input = fs.createReadStream(srcFilePath);
	const output = fs.createWriteStream(outputFilePath);

	const pswdRsaBuf = crypto.publicEncrypt(publicKey, password);
	output.write(pswdRsaBuf);

	var encrypting = { done: false };
	pipeline(input, cipher, output, (err) => {
		encrypting.done = true;
		if (err) throw err;
	});
	await waitFor(encrypting);
	return outputFilePath;
}

async function hybridDecryptFile(hybridFilePath, tmpDir, privateKey, salt) {
	const password = await extractPasswordFromFile(hybridFilePath, privateKey);
	const key = crypto.scryptSync(password, salt, 32);
	const iv = Buffer.alloc(16, 0); // Initialization vector.
	const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

	const tmpFileName = Math.random().toString().substring(2, 5) + "_dec";
	const outputFilePath = `${tmpDir}/${tmpFileName}`;

	var decrypting = { done: false };
	const input = fs.createReadStream(hybridFilePath, { start: 65 }); // length of bufPswdRsa is always 65
	const output = fs.createWriteStream(outputFilePath);
	const stream = input.pipe(decipher).pipe(output);
	stream.on('finish', () => { decrypting.done = true; });
	await waitFor(decrypting);
	return outputFilePath;
}

module.exports = {
	hybridDecryptFile,
	hybridEncryptFile,
	hybridDecryptHexKey,
	hybridEncryptHexKey,
	hybridDecryptHex,
	hybridEncryptHex,
	hybridDecrypt,
	hybridEncrypt,
	genRandomBuf
};