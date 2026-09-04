export class ConfigModuleRegistry {
  #modules = [];

  register(module) {
    if (!module?.key || typeof module.extendConfig !== "function") {
      throw new TypeError("配置模块必须提供 key 与 extendConfig");
    }
    if (this.#modules.some((entry) => entry.key === module.key)) {
      throw new Error(`配置模块重复注册：${module.key}`);
    }
    this.#modules.push(module);
    return this;
  }

  build(baseConfig, state, context = {}) {
    return this.#modules.reduce(
      (config, module) => module.extendConfig(config, state, context) || config,
      baseConfig
    );
  }
}
