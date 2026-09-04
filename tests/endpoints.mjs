import assert from "node:assert/strict";
import { buildStandardEndpoint, normalizeStandardEndpoint, validateStandardEndpoint } from "../modules/endpoints.js";

const privateKey = "QEkbUOD7+9ROtG4HRvsWG8ddIp8tQZg8nVq6UBLdk1o=";
const publicKey = "sLupvbHfve+mEfOCiTG7CXp3xvV52YRDZZsj1RLA/SU=";

const wireguard = normalizeStandardEndpoint({
  type: "wireguard",
  id: "wg",
  tag: "wg-test",
  address: "10.7.0.2/32",
  privateKey,
  peersJson: JSON.stringify([{ address: "127.0.0.1", port: 51820, public_key: publicKey, allowed_ips: ["0.0.0.0/0"] }]),
  udpMapping: "address_dependent"
});
assert.equal(validateStandardEndpoint(wireguard), "");
assert.deepEqual(buildStandardEndpoint(wireguard).address, ["10.7.0.2/32"]);
assert.equal(buildStandardEndpoint(wireguard).udp_mapping, "address_dependent");

const openconnect = normalizeStandardEndpoint({ type: "openconnect", id: "oc", tag: "oc-test", server: "vpn.example.com", flavor: "gp" });
assert.equal(validateStandardEndpoint(openconnect), "");
assert.equal(buildStandardEndpoint(openconnect).type, "openconnect");

const openvpnClient = normalizeStandardEndpoint({
  type: "openvpn-client",
  id: "ovpn-client",
  tag: "ovpn-client-test",
  server: "127.0.0.1",
  serverPort: "1194",
  tlsPeerFingerprint: "a".repeat(64)
});
assert.equal(validateStandardEndpoint(openvpnClient), "");
assert.equal(buildStandardEndpoint(openvpnClient).mode, "tls");

const openvpnServer = normalizeStandardEndpoint({
  type: "openvpn-server",
  id: "ovpn-server",
  tag: "ovpn-server-test",
  listenPort: "1194",
  address: "10.8.0.1/24",
  tlsCertificatePath: "/path/to/server.crt",
  tlsKeyPath: "/path/to/server.key",
  tlsVerifyClientCertificate: "none"
});
assert.equal(validateStandardEndpoint(openvpnServer), "");
assert.equal(buildStandardEndpoint(openvpnServer).mode, "tls");

const deprecated = normalizeStandardEndpoint({
  ...openvpnClient,
  advancedJson: JSON.stringify({ static_key: ["legacy"] })
});
assert.match(validateStandardEndpoint(deprecated), /已弃用/);
