import fs from "node:fs";
import dgram from "node:dgram";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

function blocked(name) {
  return (...args) => {
    const trace = process.env.SOMA_NETWORK_TRACE;
    if (trace) fs.appendFileSync(trace, `${name}\n`, "utf8");
    throw new Error(`network access blocked by Soma test sentinel: ${name}; args=${args.length}`);
  };
}

globalThis.fetch = blocked("fetch");
net.connect = blocked("net.connect");
net.createConnection = blocked("net.createConnection");
tls.connect = blocked("tls.connect");
http.request = blocked("http.request");
http.get = blocked("http.get");
https.request = blocked("https.request");
https.get = blocked("https.get");
dns.lookup = blocked("dns.lookup");
dns.resolve = blocked("dns.resolve");
dgram.createSocket = blocked("dgram.createSocket");
