import { parentPort, workerData } from 'node:worker_threads';

try {
  if (workerData.kind === 'crypto') {
    const { analyzeCrypto } = await import('./crypto_analysis.js');
    const value = analyzeCrypto(workerData.request);
    parentPort.postMessage({ ok: true, value });
  } else if (workerData.kind === 'protocol') {
    const { analyzeProtocol } = await import('./protocol_analysis.js');
    parentPort.postMessage({ ok: true, value: { result: analyzeProtocol(workerData.request) } });
  } else throw new Error('Unknown data analysis kind');
} catch (error) {
  const known = error.name === 'CryptoAnalysisError' || /^(INVALID_PROTOCOL_(ARGUMENT|SCHEMA|ENCODING)|PROTOCOL_INPUT_LIMIT|UNSUPPORTED_CAPTURE_FORMAT)$/.test(error.code || '');
  parentPort.postMessage({ ok: false, error: { code: known ? error.code : 'ANALYSIS_FAILED', message: known ? String(error.message).slice(0, 512) : 'Data analysis failed; no output was committed' } });
}
