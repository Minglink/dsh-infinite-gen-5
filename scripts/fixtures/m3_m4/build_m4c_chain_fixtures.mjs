import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { buildNativeHelperPe64 } from './build_m3_fixtures.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const CSC_EXE = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe';

export function materializeProcessChainFixture(rootDir, {
  stage1Constants = [0x25, 0x7e, 0xb3, 0x48],
  stage1Rot = 1,
  stage2Constants = [0x61, 0xd2, 0x19, 0x8f],
  stage2Rot = 3,
  stage2CascadeXor = 0x17,
} = {}) {
  fs.mkdirSync(rootDir, { recursive: true });

  const worker1 = buildNativeHelperPe64({
    binaryName: 'worker_stage1.exe',
    mode: 'cli',
    flag1: '--stage=one',
    argPrefix: 'S1=',
    inputIsHex8: true,
    constants: stage1Constants,
    rot: stage1Rot,
    outBufRva: 0x3190,
  });
  const worker2 = buildNativeHelperPe64({
    binaryName: 'worker_stage2.exe',
    mode: 'stdin',
    stdinMagic: [0x57, 0x32], // 'W2'
    constants: stage2Constants,
    rot: stage2Rot,
    cascadeXor: stage2CascadeXor,
    outBufRva: 0x31a8,
  });

  const worker1Path = path.join(rootDir, worker1.binaryName);
  const worker2Path = path.join(rootDir, worker2.binaryName);
  fs.writeFileSync(worker1Path, worker1.image);
  fs.writeFileSync(worker2Path, worker2.image);

  const brokerCsPath = path.join(rootDir, 'chain_broker.cs');
  const brokerExePath = path.join(rootDir, 'chain_broker.exe');
  fs.writeFileSync(brokerCsPath, `using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

class ChainBroker {
  static byte[] HexToBytes(string h) {
    byte[] b = new byte[h.Length / 2];
    for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
    return b;
  }
  static int Main(string[] args) {
    if (args.Length > 0 && args[0] == "--bystander-sleep") {
      Thread.Sleep(60000);
      return 0;
    }
    string line = Console.In.ReadLine();
    if (string.IsNullOrEmpty(line)) return 2;
    string[] parts = line.Trim().Split('|');
    if (parts.Length < 4) return 2;
    string corrId = parts[0];
    string payloadHex = parts[1].ToLowerInvariant();
    bool restartW1 = parts[2] == "1";
    int holdMs = int.Parse(parts[3]);
    string baseDir = AppDomain.CurrentDomain.BaseDirectory;
    string w1Exe = Path.Combine(baseDir, "worker_stage1.exe");
    string w2Exe = Path.Combine(baseDir, "worker_stage2.exe");

    int abortedW1Pid = 0;
    if (restartW1) {
      ProcessStartInfo psiFail = new ProcessStartInfo(w1Exe, "--stage=abort S1=00000000");
      psiFail.UseShellExecute = false;
      psiFail.CreateNoWindow = true;
      psiFail.WorkingDirectory = baseDir;
      using (Process pFail = Process.Start(psiFail)) {
        abortedW1Pid = pFail.Id;
        pFail.WaitForExit(5000);
      }
    }

    int w1Pid = 0;
    string s1Hex = "";
    ProcessStartInfo psi1 = new ProcessStartInfo(w1Exe, "--stage=one S1=" + payloadHex);
    psi1.UseShellExecute = false;
    psi1.RedirectStandardOutput = true;
    psi1.CreateNoWindow = true;
    psi1.WorkingDirectory = baseDir;
    using (Process p1 = Process.Start(psi1)) {
      w1Pid = p1.Id;
      s1Hex = p1.StandardOutput.ReadToEnd().Trim().ToLowerInvariant();
      p1.WaitForExit(5000);
      if (p1.ExitCode != 0 || s1Hex.Length != 8) return 3;
    }

    if (holdMs > 0) Thread.Sleep(holdMs);

    int w2Pid = 0;
    string s2Hex = "";
    ProcessStartInfo psi2 = new ProcessStartInfo(w2Exe);
    psi2.UseShellExecute = false;
    psi2.RedirectStandardInput = true;
    psi2.RedirectStandardOutput = true;
    psi2.CreateNoWindow = true;
    psi2.WorkingDirectory = baseDir;
    using (Process p2 = Process.Start(psi2)) {
      w2Pid = p2.Id;
      byte[] s1Bytes = HexToBytes(s1Hex);
      byte[] frame = new byte[6];
      frame[0] = 0x57; frame[1] = 0x32; // 'W2'
      Buffer.BlockCopy(s1Bytes, 0, frame, 2, 4);
      p2.StandardInput.BaseStream.Write(frame, 0, 6);
      p2.StandardInput.BaseStream.Flush();
      p2.StandardInput.Close();
      s2Hex = p2.StandardOutput.ReadToEnd().Trim().ToLowerInvariant();
      p2.WaitForExit(5000);
      if (p2.ExitCode != 0 || s2Hex.Length != 8) return 4;
    }

    Console.Out.WriteLine(string.Format(
      "{{\\"ok\\":true,\\"corrId\\":\\"{0}\\",\\"brokerPid\\":{1},\\"abortedStage1Pid\\":{2},\\"stage1Pid\\":{3},\\"stage1OutHex\\":\\"{4}\\",\\"stage2Pid\\":{5},\\"finalOutHex\\":\\"{6}\\"}}",
      corrId, Process.GetCurrentProcess().Id, abortedW1Pid, w1Pid, s1Hex, w2Pid, s2Hex));
    return 0;
  }
}
`, 'utf8');

  const entryCsPath = path.join(rootDir, 'entry_app.cs');
  const entryExePath = path.join(rootDir, 'entry_app.exe');
  fs.writeFileSync(entryCsPath, `using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

class EntryApp {
  static int Main(string[] args) {
    if (args.Length > 0 && args[0] == "--bystander-sleep") {
      Thread.Sleep(60000);
      return 0;
    }
    string corrId = "req-default";
    string payloadHex = "";
    string restartW1 = "0";
    string holdMs = "0";
    foreach (string a in args) {
      if (a.StartsWith("--req=")) corrId = a.Substring(6);
      else if (a.StartsWith("--payload=")) payloadHex = a.Substring(10);
      else if (a == "--restart-worker1") restartW1 = "1";
      else if (a.StartsWith("--hold-ms=")) holdMs = a.Substring(10);
    }
    if (payloadHex.Length != 8) return 1;
    string baseDir = AppDomain.CurrentDomain.BaseDirectory;
    string brokerExe = Path.Combine(baseDir, "chain_broker.exe");
    ProcessStartInfo psi = new ProcessStartInfo(brokerExe);
    psi.UseShellExecute = false;
    psi.RedirectStandardInput = true;
    psi.RedirectStandardOutput = true;
    psi.CreateNoWindow = true;
    psi.WorkingDirectory = baseDir;
    using (Process p = Process.Start(psi)) {
      p.StandardInput.WriteLine(corrId + "|" + payloadHex + "|" + restartW1 + "|" + holdMs);
      p.StandardInput.Close();
      string outLine = p.StandardOutput.ReadToEnd().Trim();
      p.WaitForExit(30000);
      if (p.ExitCode != 0 || string.IsNullOrEmpty(outLine)) return 2;
      Console.Out.WriteLine("IG5_CHAIN_RESULT=" + outLine);
      return 0;
    }
  }
}
`, 'utf8');

  execFileSync(CSC_EXE, ['/nologo', '/platform:x64', '/optimize+', `/out:${brokerExePath}`, brokerCsPath], { cwd: rootDir, windowsHide: true });
  execFileSync(CSC_EXE, ['/nologo', '/platform:x64', '/optimize+', `/out:${entryExePath}`, entryCsPath], { cwd: rootDir, windowsHide: true });
  // Remove .cs sources from runtime dir so blind workspace only contains compiled binaries!
  fs.unlinkSync(brokerCsPath);
  fs.unlinkSync(entryCsPath);

  const computeChainExpectedHex = (in4Buf) => {
    const s1Hex = worker1.computeHelperHex(in4Buf);
    return worker2.computeHelperHex(Buffer.from(s1Hex, 'hex'));
  };

  return {
    rootDir,
    entryExePath,
    entrySha256: sha256(fs.readFileSync(entryExePath)),
    brokerExePath,
    brokerSha256: sha256(fs.readFileSync(brokerExePath)),
    worker1Path,
    worker1,
    worker2Path,
    worker2,
    computeChainExpectedHex,
  };
}
