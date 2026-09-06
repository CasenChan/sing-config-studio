// 浏览器和服务端使用同一种摘要输入；签名时无需上传配置或节点凭据。
export function subscriptionPayload({ data, enc = "", name = "", interval = "60" }) {
  return JSON.stringify([data, enc, name, interval]);
}
