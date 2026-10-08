import { parentPort, workerData } from 'node:worker_threads';
import { compareSemantics } from './semantic_diff.js';
try { parentPort.postMessage({ result: compareSemantics(workerData.left, workerData.right, workerData.options) }); }
catch (error) { parentPort.postMessage({ error: error.message }); }
