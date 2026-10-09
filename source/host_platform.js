/** Host identity is about the process executing tools, never the browser device. */
export function hostPlatform(options = {}) {
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const environment = options.env ?? process.env;
  let glibcVersion = options.glibcVersion;
  if (glibcVersion === undefined && platform === 'linux' && !options.platform) {
    try { glibcVersion = process.report?.getReport()?.header?.glibcVersionRuntime; } catch {}
  }
  const androidRootfs = platform === 'linux' && arch === 'arm64'
    && !!(environment.ANDROID_ROOT || environment.ANDROID_DATA || environment.IG5_ANDROID_ROOTFS === '1');
  const id = `${platform}-${arch}`;
  const supported = id === 'win32-x64' || id === 'linux-arm64';
  return {
    platform, arch, id, supported,
    execution: platform === 'ios' ? 'unsupported-native-host' : androidRootfs ? 'android-linux-rootfs' : 'local-node-host',
    androidRootfs,
    ...(platform === 'linux' ? { libc: glibcVersion ? 'glibc' : 'unknown', glibcVersion: glibcVersion || null } : {}),
    ...(!supported ? { reason: platform === 'ios'
      ? 'No validated iOS native DSH worker host is available'
      : platform === 'android'
        ? 'Android Bionic native hosts require a separate runtime; Linux packs require an ARM64 glibc rootfs host'
        : `No matching IG5 runtime is supported for ${id}` } : {}),
  };
}

export function runtimePlatform(pack, host) {
  // Version-1 Windows manifests predate the platform field. They are never Linux packs.
  const platform = pack.platform ?? 'win32-x64';
  if (platform !== host.id) throw new Error(`Runtime platform ${platform} does not match host ${host.id}`);
  if (!host.supported) throw new Error(host.reason);
  if (platform === 'linux-arm64' && (pack.libc !== 'glibc' || host.libc !== 'glibc')) {
    throw new Error('Linux ARM64 runtimes require a confirmed glibc host and libc=glibc manifest');
  }
  if (platform === 'linux-arm64' && pack.minGlibc) {
    const parse = value => /^\d+\.\d+$/.test(String(value)) ? String(value).split('.').map(Number) : null;
    const required = parse(pack.minGlibc), actual = parse(host.glibcVersion);
    if (!required || !actual || actual[0] < required[0] || actual[0] === required[0] && actual[1] < required[1]) {
      throw new Error(`Runtime requires glibc ${pack.minGlibc}; host reports ${host.glibcVersion || 'unknown'}`);
    }
  }
  return platform;
}
