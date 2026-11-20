import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const rol8 = (v, s) => (((v & 0xff) << (s & 7)) | ((v & 0xff) >>> (8 - (s & 7)))) & 0xff;

const ANDROID_SDK = process.env.ANDROID_SDK_ROOT
  || process.env.ANDROID_HOME
  || 'C:\\Users\\Administrator\\AppData\\Local\\Android\\Sdk';
const BUILD_TOOLS = path.join(ANDROID_SDK, 'build-tools', '36.0.0');
const PLATFORM_JAR = path.join(ANDROID_SDK, 'platforms', 'android-36', 'android.jar');

/**
 * Build a clean, standards-compliant ELF64 x86_64 shared library (`libcodec_jni.so`)
 * exporting `codec_core_4b` and `Java_com_ig5_fixture_NativeBridge_nativeTransform`.
 */
export function buildJniElf64X64({
  constants = [0x1c, 0x73, 0xa8, 0x45],
  rot = 3,
} = {}) {
  // File layout (0x2000 = 8192 bytes):
  // 0x0000..0x01ff: ELF64 Header + 2 Program Headers (PT_LOAD RX @ 0x0..0xfff, PT_LOAD RW @ 0x1000..0x13ff)
  // 0x0200..0x02ff: .text (codec_core_4b @ 0x200, Java_com_ig5_fixture_NativeBridge_nativeTransform @ 0x250)
  // 0x0300..0x033f: .rodata (constants @ 0x300)
  // 0x0400..0x04ff: .dynsym (3 entries * 24 = 72 bytes)
  // 0x0500..0x05ff: .dynstr
  // 0x0600..0x06ff: .shstrtab
  // 0x1000..0x10ff: .data
  // 0x1400..0x17ff: Section Header Table (8 entries * 64 = 512 bytes)
  const buf = Buffer.alloc(0x1800, 0);
  const u16 = (o, v) => buf.writeUInt16LE(v, o);
  const u32 = (o, v) => buf.writeUInt32LE(v >>> 0, o);
  const u64 = (o, v) => buf.writeBigUInt64LE(BigInt(v), o);

  // ELF64 Header (64 bytes)
  buf.write('\x7fELF', 0, 'binary');
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // ELFDATA2LSB
  buf[6] = 1; // EV_CURRENT
  u16(16, 3); // ET_DYN (.so)
  u16(18, 0x3e); // EM_X86_64
  u32(20, 1);
  u64(24, 0x200); // e_entry
  u64(32, 64);    // e_phoff
  u64(40, 0x1400); // e_shoff
  u32(48, 0);
  u16(52, 64);    // e_ehsize
  u16(54, 56);    // e_phentsize
  u16(56, 2);     // e_phnum
  u16(58, 64);    // e_shentsize
  u16(60, 7);     // e_shnum
  u16(62, 6);     // e_shstrndx = 6

  // Program Header 0: PT_LOAD (RX) 0x0000..0x0fff -> vaddr 0x0000
  const ph0 = 64;
  u32(ph0 + 0, 1); // PT_LOAD
  u32(ph0 + 4, 5); // PF_R | PF_X
  u64(ph0 + 8, 0);
  u64(ph0 + 16, 0);
  u64(ph0 + 24, 0);
  u64(ph0 + 32, 0x1000);
  u64(ph0 + 40, 0x1000);
  u64(ph0 + 48, 0x1000);

  // Program Header 1: PT_LOAD (RW) 0x1000..0x10ff -> vaddr 0x2000
  const ph1 = 64 + 56;
  u32(ph1 + 0, 1); // PT_LOAD
  u32(ph1 + 4, 6); // PF_R | PF_W
  u64(ph1 + 8, 0x1000);
  u64(ph1 + 16, 0x2000);
  u64(ph1 + 24, 0x2000);
  u64(ph1 + 32, 0x100);
  u64(ph1 + 40, 0x100);
  u64(ph1 + 48, 0x1000);

  // .rodata @ 0x300: constants[4]
  Buffer.from(constants).copy(buf, 0x300);

  // .text @ 0x200:
  // Function 1 @ 0x200: uint32_t codec_core_4b(const uint8_t* in4 [rdi], uint8_t* out4 [rsi])
  //   lea r8, [rip + (0x300 - nextPc)]
  //   xor ecx, ecx
  // loop:
  //   movzx eax, byte ptr [rdi + rcx]
  //   add al, byte ptr [r8 + rcx]
  //   rol al, rot
  //   mov byte ptr [rsi + rcx], al
  //   inc ecx
  //   cmp ecx, 4
  //   jb loop
  //   mov eax, dword ptr [rsi]
  //   ret
  const fn1Chunks = [];
  let pc1 = 0x200;
  const emit1 = (h) => { const b = Buffer.from(h, 'hex'); fn1Chunks.push(b); pc1 += b.length; };
  emit1('4c8d05'); // lea r8, [rip + disp32]
  const dispConst = Buffer.alloc(4);
  dispConst.writeInt32LE(0x300 - (pc1 + 4), 0);
  fn1Chunks.push(dispConst); pc1 += 4;
  emit1('31c9'); // xor ecx, ecx
  const loop1 = pc1;
  emit1('0fb6040f'); // movzx eax, byte ptr [rdi + rcx]
  emit1('41020408'); // add al, byte ptr [r8 + rcx]
  emit1('c0c0' + Buffer.from([rot & 7]).toString('hex')); // rol al, rot
  emit1('88040e');   // mov [rsi + rcx], al
  emit1('ffc1');     // inc ecx
  emit1('83f904');   // cmp ecx, 4
  const jbRel = loop1 - (pc1 + 2);
  emit1('72' + Buffer.from([jbRel & 0xff]).toString('hex'));
  emit1('8b06');     // mov eax, [rsi]
  emit1('c3');       // ret
  const fn1Bytes = Buffer.concat(fn1Chunks);
  fn1Bytes.copy(buf, 0x200);

  // Function 2 @ 0x250: jint Java_com_ig5_fixture_NativeBridge_nativeTransform(JNIEnv* rdi, jclass rsi, jint edx)
  //   sub rsp, 24
  //   mov dword ptr [rsp], edx      ; [rsp+0..3] = in4
  //   lea rdi, [rsp]
  //   lea rsi, [rsp + 8]
  //   call 0x200 (codec_core_4b)
  //   add rsp, 24
  //   ret
  const fn2Chunks = [];
  let pc2 = 0x250;
  const emit2 = (h) => { const b = Buffer.from(h, 'hex'); fn2Chunks.push(b); pc2 += b.length; };
  emit2('4883ec18'); // sub rsp, 24
  emit2('891424');   // mov [rsp], edx
  emit2('488d3c24'); // lea rdi, [rsp]
  emit2('488d742408'); // lea rsi, [rsp + 8]
  emit2('e8');
  const callDisp = Buffer.alloc(4);
  callDisp.writeInt32LE(0x200 - (pc2 + 4), 0);
  fn2Chunks.push(callDisp); pc2 += 4;
  emit2('4883c418'); // add rsp, 24
  emit2('c3');
  const fn2Bytes = Buffer.concat(fn2Chunks);
  fn2Bytes.copy(buf, 0x250);

  // .dynstr @ 0x500
  const sym1Name = 'codec_core_4b';
  const sym2Name = 'Java_com_ig5_fixture_NativeBridge_nativeTransform';
  let strOff = 0x500;
  buf[strOff++] = 0;
  const sym1StrIdx = strOff - 0x500;
  buf.write(sym1Name + '\0', strOff, 'ascii'); strOff += sym1Name.length + 1;
  const sym2StrIdx = strOff - 0x500;
  buf.write(sym2Name + '\0', strOff, 'ascii'); strOff += sym2Name.length + 1;
  const dynstrSize = strOff - 0x500;

  // .dynsym @ 0x400 (24 bytes per Elf64_Sym: null, sym1, sym2)
  const writeSym = (idx, nameIdx, value, size) => {
    const o = 0x400 + idx * 24;
    u32(o + 0, nameIdx);
    buf[o + 4] = 0x12; // STB_GLOBAL (1<<4) | STT_FUNC (2)
    buf[o + 5] = 0;    // STV_DEFAULT
    u16(o + 6, 1);     // st_shndx = 1 (.text)
    u64(o + 8, value);
    u64(o + 16, size);
  };
  writeSym(1, sym1StrIdx, 0x200, fn1Bytes.length);
  writeSym(2, sym2StrIdx, 0x250, fn2Bytes.length);

  // .shstrtab @ 0x600
  const shNames = ['', '.text', '.rodata', '.dynsym', '.dynstr', '.data', '.shstrtab'];
  const shNameOffsets = [];
  let shCur = 0x600;
  for (const n of shNames) {
    shNameOffsets.push(shCur - 0x600);
    buf.write(n + '\0', shCur, 'ascii');
    shCur += n.length + 1;
  }
  const shstrSize = shCur - 0x600;

  // Section Headers @ 0x1400 (64 bytes each)
  const writeShdr = (idx, { nameIdx, type, flags, addr, offset, size, link = 0, info = 0, align = 1, entsize = 0 }) => {
    const o = 0x1400 + idx * 64;
    u32(o + 0, nameIdx);
    u32(o + 4, type);
    u64(o + 8, flags);
    u64(o + 16, addr);
    u64(o + 24, offset);
    u64(o + 32, size);
    u32(o + 40, link);
    u32(o + 44, info);
    u64(o + 48, align);
    u64(o + 56, entsize);
  };
  writeShdr(1, { nameIdx: shNameOffsets[1], type: 1, flags: 6, addr: 0x200, offset: 0x200, size: 0x100, align: 16 }); // .text
  writeShdr(2, { nameIdx: shNameOffsets[2], type: 1, flags: 2, addr: 0x300, offset: 0x300, size: 0x40, align: 4 });   // .rodata
  writeShdr(3, { nameIdx: shNameOffsets[3], type: 11, flags: 2, addr: 0x400, offset: 0x400, size: 72, link: 4, info: 1, align: 8, entsize: 24 }); // .dynsym
  writeShdr(4, { nameIdx: shNameOffsets[4], type: 3, flags: 2, addr: 0x500, offset: 0x500, size: dynstrSize, align: 1 }); // .dynstr
  writeShdr(5, { nameIdx: shNameOffsets[5], type: 1, flags: 3, addr: 0x2000, offset: 0x1000, size: 0x100, align: 8 }); // .data
  writeShdr(6, { nameIdx: shNameOffsets[6], type: 3, flags: 0, addr: 0, offset: 0x600, size: shstrSize, align: 1 });   // .shstrtab

  const computeJniCoreHex = (in4Buf) => {
    const out = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) out[i] = rol8((in4Buf[i] + constants[i]) & 0xff, rot);
    return out.toString('hex');
  };

  return {
    fileName: 'libcodec_jni.so',
    image: buf,
    sha256: sha256(buf),
    exports: {
      codec_core_4b: '0x200',
      Java_com_ig5_fixture_NativeBridge_nativeTransform: '0x250',
    },
    computeJniCoreHex,
  };
}

/**
 * Build and sign two owned Android APK fixtures using installed JDK + Android SDK build-tools:
 *   1. `CodecJavaDemo.apk` (Java-only deterministic codec in `com.ig5.fixture.JavaCodec`)
 *   2. `CodecJniDemo.apk` (Java -> JNI cross-layer codec: `com.ig5.fixture.NativeBridge` XORs with `javaPreXorByte`
 *      then passes 4B `jint` to `lib/x86_64/libcodec_jni.so` `Java_com_ig5_fixture_NativeBridge_nativeTransform`)
 */
export function buildSignedAndroidFixtures(outDir, {
  javaPreXorByte = 0x2d,
  jniConstants = [0x1c, 0x73, 0xa8, 0x45],
  jniRot = 3,
} = {}) {
  fs.mkdirSync(outDir, { recursive: true });
  const workRoot = path.join(outDir, '_apk_build_work');
  fs.mkdirSync(workRoot, { recursive: true });

  const aapt2 = path.join(BUILD_TOOLS, 'aapt2.exe');
  const d8Jar = path.join(BUILD_TOOLS, 'lib', 'd8.jar');
  const zipalign = path.join(BUILD_TOOLS, 'zipalign.exe');
  const apksignerJar = path.join(BUILD_TOOLS, 'lib', 'apksigner.jar');
  const keystorePath = path.join(workRoot, 'fixture-test.keystore');

  execFileSync('keytool', [
    '-genkeypair', '-v',
    '-keystore', keystorePath,
    '-storepass', 'ig5testpass',
    '-keypass', 'ig5testpass',
    '-alias', 'ig5fixture',
    '-keyalg', 'RSA', '-keysize', '2048', '-validity', '3650',
    '-dname', 'CN=IG5 Synthetic Fixture, OU=QA, O=IG5, L=Local, S=Local, C=US',
  ], { stdio: 'pipe', windowsHide: true });

  function buildOneApk({ apkName, pkgName, javaFiles, nativeSo = null }) {
    const dir = path.join(workRoot, apkName.replace(/\.apk$/i, ''));
    const srcDir = path.join(dir, 'src');
    const clsDir = path.join(dir, 'classes');
    const resDir = path.join(dir, 'res', 'values');
    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(clsDir, { recursive: true });
    fs.mkdirSync(resDir, { recursive: true });

    const manifestPath = path.join(dir, 'AndroidManifest.xml');
    fs.writeFileSync(manifestPath, `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${pkgName}"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
    <application android:label="IG5CodecFixture" android:extractNativeLibs="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`, 'utf8');
    fs.writeFileSync(path.join(resDir, 'strings.xml'), `<?xml version="1.0" encoding="utf-8"?><resources><string name="app_name">IG5CodecFixture</string></resources>\n`, 'utf8');

    const javaPaths = [];
    for (const [relPath, content] of Object.entries(javaFiles)) {
      const full = path.join(srcDir, relPath);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, 'utf8');
      javaPaths.push(full);
    }

    execFileSync('javac', ['--release', '11', '-cp', PLATFORM_JAR, '-d', clsDir, ...javaPaths], { stdio: 'pipe', windowsHide: true });

    // Collect all .class files for d8
    const classFiles = [];
    const walkCls = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walkCls(p);
        else if (e.name.endsWith('.class')) classFiles.push(p);
      }
    };
    walkCls(clsDir);
    execFileSync('java', ['-cp', d8Jar, 'com.android.tools.r8.D8', '--min-api', '26', '--lib', PLATFORM_JAR, '--output', dir, ...classFiles], { stdio: 'pipe', windowsHide: true });

    const compiledResZip = path.join(dir, 'compiled_res.zip');
    const baseUnsignedApk = path.join(dir, 'unsigned_base.apk');
    execFileSync(aapt2, ['compile', '--dir', path.join(dir, 'res'), '-o', compiledResZip], { stdio: 'pipe', windowsHide: true });
    execFileSync(aapt2, ['link', '-I', PLATFORM_JAR, '--manifest', manifestPath, '-o', baseUnsignedApk, compiledResZip], { stdio: 'pipe', windowsHide: true });

    // Add classes.dex (and optional lib/x86_64/libcodec_jni.so) into baseUnsignedApk using Python zipfile (STORED for .so, DEFLATED for classes.dex)
    const stageExtra = path.join(dir, 'extra');
    fs.mkdirSync(stageExtra, { recursive: true });
    fs.copyFileSync(path.join(dir, 'classes.dex'), path.join(stageExtra, 'classes.dex'));
    if (nativeSo) {
      const libDir = path.join(stageExtra, 'lib', 'x86_64');
      fs.mkdirSync(libDir, { recursive: true });
      fs.writeFileSync(path.join(libDir, nativeSo.fileName), nativeSo.image);
    }
    execFileSync('python', [
      '-c',
      [
        'import os, sys, zipfile',
        'apk, extra = sys.argv[1], sys.argv[2]',
        'with zipfile.ZipFile(apk, "a") as z:',
        '  z.write(os.path.join(extra, "classes.dex"), "classes.dex", compress_type=zipfile.ZIP_DEFLATED)',
        '  so = os.path.join(extra, "lib", "x86_64", "libcodec_jni.so")',
        '  if os.path.exists(so): z.write(so, "lib/x86_64/libcodec_jni.so", compress_type=zipfile.ZIP_STORED)',
      ].join('\n'),
      baseUnsignedApk,
      stageExtra,
    ], { stdio: 'pipe', windowsHide: true });

    const alignedApk = path.join(dir, 'aligned.apk');
    const finalApk = path.join(outDir, apkName);
    execFileSync(zipalign, ['-f', '-p', '4', baseUnsignedApk, alignedApk], { stdio: 'pipe', windowsHide: true });
    execFileSync('java', [
      '-jar', apksignerJar,
      'sign', '--ks', keystorePath, '--ks-pass', 'pass:ig5testpass', '--key-pass', 'pass:ig5testpass', '--out', finalApk, alignedApk,
    ], { stdio: 'pipe', windowsHide: true });
    execFileSync('java', ['-jar', apksignerJar, 'verify', '--verbose', finalApk], { stdio: 'pipe', windowsHide: true });

    return {
      apkPath: finalApk,
      apkSha256: sha256(fs.readFileSync(finalApk)),
      dexSha256: sha256(fs.readFileSync(path.join(dir, 'classes.dex'))),
    };
  }

  const javaOnly = buildOneApk({
    apkName: 'CodecJavaDemo.apk',
    pkgName: 'com.ig5.javaonly',
    javaFiles: {
      'com/ig5/javaonly/MainActivity.java': `package com.ig5.javaonly;
import android.app.Activity;
import android.os.Bundle;
public class MainActivity extends Activity {
  @Override protected void onCreate(Bundle b) { super.onCreate(b); JavaCodec.encode(new byte[]{1,2,3,4}); }
}
`,
      'com/ig5/javaonly/JavaCodec.java': `package com.ig5.javaonly;
public final class JavaCodec {
  private static final int[] KEY = {0x52, 0x19, 0xc4, 0x87};
  public static byte[] encode(byte[] in4) {
    byte[] out = new byte[4];
    for (int i = 0; i < 4; i++) {
      int v = ((in4[i] & 0xff) ^ KEY[i] ^ (i * 13 + 5)) & 0xff;
      out[i] = (byte)(((v << 2) | (v >>> 6)) & 0xff);
    }
    return out;
  }
}
`,
    },
  });

  const jniElf = buildJniElf64X64({ constants: jniConstants, rot: jniRot });
  const javaJni = buildOneApk({
    apkName: 'CodecJniDemo.apk',
    pkgName: 'com.ig5.fixture',
    nativeSo: jniElf,
    javaFiles: {
      'com/ig5/fixture/MainActivity.java': `package com.ig5.fixture;
import android.app.Activity;
import android.os.Bundle;
public class MainActivity extends Activity {
  @Override protected void onCreate(Bundle b) { super.onCreate(b); NativeBridge.encodeFrame(new byte[]{0x41,0x42,0x43,0x44}); }
}
`,
      'com/ig5/fixture/NativeBridge.java': `package com.ig5.fixture;
public final class NativeBridge {
  static { System.loadLibrary("codec_jni"); }
  public static native int nativeTransform(int preMaskedLittleEndian4B);
  public static byte[] encodeFrame(byte[] in4) {
    int packed = 0;
    for (int i = 0; i < 4; i++) {
      int pre = ((in4[i] & 0xff) ^ 0x${javaPreXorByte.toString(16)}) & 0xff;
      packed |= (pre << (i * 8));
    }
    int res = nativeTransform(packed);
    return new byte[]{
      (byte)(res & 0xff),
      (byte)((res >>> 8) & 0xff),
      (byte)((res >>> 16) & 0xff),
      (byte)((res >>> 24) & 0xff)
    };
  }
}
`,
    },
  });

  const extractedSoPath = path.join(outDir, 'libcodec_jni.so');
  fs.writeFileSync(extractedSoPath, jniElf.image);
  fs.rmSync(workRoot, { recursive: true, force: true });

  const computeJavaJniEndToEndHex = (in4Buf) => {
    const pre = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) pre[i] = (in4Buf[i] ^ javaPreXorByte) & 0xff;
    return jniElf.computeJniCoreHex(pre);
  };

  return {
    javaOnlyApk: javaOnly,
    javaJniApk: javaJni,
    extractedSoPath,
    jniElf,
    javaPreXorByte,
    keystoreNote: 'Signed with disposable synthetic QA RSA-2048 key (alias=ig5fixture) verified by apksigner',
    computeJavaJniEndToEndHex,
  };
}
