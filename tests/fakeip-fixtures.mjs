import { normalizeDnsState, normalizeDnsServer, dnsModule, defaultDomainResolverTag } from "../modules/dns.js";
import { normalizeRouteState, routeModule } from "../modules/route.js";
import { normalizeServiceState, serviceModule } from "../modules/services.js";
import { inboundModule } from "../modules/inbound.js";
import { outboundModule } from "../modules/outbound.js";
import { tailscaleModule } from "../modules/tailscale.js";
import { endpointFamilyModule } from "../modules/endpoints.js";

export const fakeServer = (overrides = {}) => normalizeDnsServer({ id: "fake-test", type: "fakeip", tag: "fakeip", ...overrides });
export const emptyState = () => ({
  settings: { profileName: "FakeIP 测试", logLevel: "info" }, subscriptions: [], nodes: [], groups: [], inbounds: [], endpoints: [],
  dns: normalizeDnsState({ servers: [], rules: [] }), route: normalizeRouteState({ rules: [], ruleSets: [], autoDetectInterface: "off" }),
  serviceState: normalizeServiceState({ cacheEnabled: false, cacheStoreFakeip: false, cachePath: "custom-cache.db", clashEnabled: false })
});

export function configFromState(state) {
  let config = outboundModule.extendConfig({ log: { level: "info" } }, state);
  const context = {
    outboundTags: [...config.outbounds, ...state.endpoints].map((item) => item.tag),
    tunEnabled: state.inbounds.some((item) => item.enabled !== false && item.type === "tun"),
    defaultDomainResolver: defaultDomainResolverTag(state.dns),
    fallbackFinal: (config.outbounds.find((item) => item.type === "selector") || config.outbounds[0])?.tag
  };
  for (const module of [inboundModule, dnsModule, routeModule, tailscaleModule, endpointFamilyModule, serviceModule]) config = module.extendConfig(config, state, context);
  return config;
}
