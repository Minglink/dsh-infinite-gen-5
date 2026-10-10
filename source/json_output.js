// DSH validates lossless JSON before rendering a tool response. Optional host
// fields may be absent; unsupported values must never be silently serialized.
export function jsonToolOutput(value) {
  const ancestors = new WeakSet();
  function invalid(at, reason) {
    const error = new TypeError(`IG5 tool output at ${at} is not JSON: ${reason}`);
    error.code = 'INVALID_IG5_OUTPUT';
    throw error;
  }
  function visit(item, at, depth) {
    if (depth > 128) invalid(at, 'maximum nesting exceeded');
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || Object.is(item, -0)) invalid(at, 'non-lossless number');
      return item;
    }
    if (typeof item !== 'object') invalid(at, `unsupported ${typeof item}`);
    if (ancestors.has(item)) invalid(at, 'circular reference');
    ancestors.add(item);
    try {
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || Reflect.ownKeys(item).length !== item.length + 1)
          invalid(at, 'non-plain or decorated array');
        const result = [];
        for (let index = 0; index < item.length; index++) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (!descriptor || !('value' in descriptor)) invalid(`${at}[${index}]`, 'missing or accessor array item');
          result.push(visit(descriptor.value, `${at}[${index}]`, depth + 1));
        }
        if (Object.keys(item).some(key => !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= item.length))
          invalid(at, 'extra array properties');
        return result;
      }
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== null && prototype !== Object.prototype) invalid(at, 'non-plain object');
      if (Reflect.ownKeys(item).some(key => typeof key !== 'string' || !Object.getOwnPropertyDescriptor(item, key).enumerable))
        invalid(at, 'symbol or non-enumerable field');
      const result = {};
      for (const key of Object.keys(item)) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!('value' in descriptor)) invalid(`${at}.${key}`, 'accessor field');
        if (descriptor.value === undefined) continue;
        Object.defineProperty(result, key, { value: visit(descriptor.value, `${at}.${key}`, depth + 1),
          enumerable: true, writable: true, configurable: true });
      }
      return result;
    } finally { ancestors.delete(item); }
  }
  return visit(value, '$', 0);
}
